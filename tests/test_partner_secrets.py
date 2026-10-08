import copy
import json
import os
import sys
import tempfile
import ssl
import subprocess
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'));sys.path.insert(0,str(ROOT/'tools'))
from hosting_api.partner_secrets import validate
from hosting_api.partner_intents import evaluate
from hosting_api.secrets import OpenBao,NoRedirect,SecretError,partner_secret_path
from partner_secret_control import private_json
from tests.secret_fixtures import binding_fixture
from tests.intent_fixtures import intent_fixture,evidence_fixture
from hosting_cli import parser,request_for


class PartnerSecretTests(unittest.TestCase):
    def test_actual_tls_requests_refuse_redirects_oversized_and_ambiguous_responses(self):
        class FixtureHandler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.path=='/v1/redirect':
                    self.send_response(307);self.send_header('Location','/v1/after');self.end_headers();return
                if self.path=='/v1/after':self.server.redirect_followed=True
                body={'/v1/oversized':b'{"padding":"'+b'x'*262145+b'"}',
                      '/v1/duplicate':b'{"data":{},"data":{"password":"fixture-value"}}',
                      '/v1/array':b'[]'}.get(self.path,b'{}')
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except OSError:pass
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);key=root/'key';cert=root/'cert'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),
                            '-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],
                           check=True,capture_output=True,timeout=30)
            server=ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler);server.redirect_followed=False
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            bao=OpenBao(f'https://127.0.0.1:{server.server_port}',str(cert),'unused-role','unused-secret')
            try:
                for path in ('redirect','oversized','duplicate','array'):
                    with self.subTest(path=path),self.assertRaises(SecretError):bao.request('GET',path,token='disposable-test-token')
                self.assertFalse(server.redirect_followed)
            finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_binding_contract_revision_authority_and_time_limits(self):
        value=binding_fixture();self.assertEqual(validate(value),value)
        for changes in ({'kv_version':1.0},{'kv_version':True},{'secret_ref':'secret://private-marker/password#2'},
                        {'bao_address':'https://bao.example.org/path'},{'bao_address':'https://user@bao.example.org'},
                        {'bao_address':'https://bao.example.org:99999'},{'bao_mount':'../resources'},
                        {'value_key':'../../key'},{'authorization_ref':'arbitrary-proof'},
                        {'valid_until':value['valid_from']},{'valid_until':'2099-01-01T00:00:00Z'},
                        {'valid_from':'2026-10-08T24:00:00Z'},{'plaintext':'secret'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):validate({**value,**changes})

    def test_private_binding_inputs_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'binding';v=binding_fixture();p.write_text(json.dumps(v));p.chmod(0o600)
            self.assertEqual(private_json(p),v)
            link=Path(temp)/'link';link.symlink_to(p)
            with self.assertRaises(OSError):private_json(link)
            p.chmod(0o644)
            with self.assertRaises(ValueError):private_json(p)
            p.chmod(0o600);p.write_text('{"id":"one","id":"two"}')
            with self.assertRaises(ValueError):private_json(p)

    def test_namespace_is_scoped_and_exact_version_is_pinned(self):
        org,app,resource=(uuid.uuid4() for _ in range(3))
        self.assertEqual(partner_secret_path(org,app,resource),f'partner-applications/{org}/{app}/{resource}')
        with self.assertRaises(ValueError):partner_secret_path(org,app,'../resources/elsewhere')
        with patch('hosting_api.secrets.ssl.create_default_context',return_value=object()):
            bao=OpenBao('https://bao.example.org','ca','role','secret')
        bao.login=lambda:'fixture-token';calls=[]
        def request(method,path,payload=None,token=None):
            calls.append((method,path,payload,token))
            return {'data':{'metadata':{'version':2,'destroyed':False,'deletion_time':''},'data':{'password':'private-secret-value'}}}
        bao.request=request
        self.assertEqual(bao.get_partner(org,app,resource,2)[0],2)
        self.assertEqual(calls[0][1],f'dial/data/partner-applications/{org}/{app}/{resource}?version=2')
        for metadata in ({'version':1},{'version':2,'destroyed':True},{'version':2,'deletion_time':'2026-10-08T00:00:00Z'}):
            bao.request=lambda *a,**kw:{'data':{'metadata':metadata,'data':{'password':'private-secret-value'}}}
            with self.assertRaises(SecretError):bao.get_partner(org,app,resource,2)
        with self.assertRaises(SecretError):NoRedirect().redirect_request(None,None,307,None,{},'https://another.example')

    def test_readback_does_not_allow_incomplete_or_borrowed_checks_to_promote(self):
        intent=intent_fixture();evidence=evidence_fixture(intent)
        evidence['partner_secrets']={'state':'MATCHED','requested_count':1,'matched_count':1}
        result=evaluate(intent,'a'*64,evidence)
        self.assertEqual(result['stages'][4]['state'],'MATCHED');self.assertEqual(result['state'],'NOT_QUALIFIED')
        self.assertFalse(result['resource_mutations_performed']);self.assertEqual(result['stages'][5]['state'],'BLOCKED')
        for changes in ({'state':'CHECK_FAILED'},{'requested_count':2},{'matched_count':0}):
            altered=copy.deepcopy(evidence);altered['partner_secrets'].update(changes)
            self.assertEqual(evaluate(intent,'a'*64,altered)['stages'][4]['state'],'BLOCKED')
        args=parser().parse_args(['--base-url','https://control.example.org','intent-secrets',str(uuid.uuid4()),str(uuid.uuid4()),str(uuid.uuid4())])
        self.assertTrue(request_for(args)[0].endswith('/secrets'));self.assertEqual(request_for(args)[1:],(None,None))
