"""Scoped authority and live-check receipts on disposable PostgreSQL."""
import copy
import http.client
import json
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import psycopg
from psycopg.types.json import Jsonb
from jsonschema import Draft202012Validator

import tests.test_partner_intent_integration as fixtures
from tests.secret_fixtures import binding_fixture,FakeBao
from hosting_api.__main__ import Handler,Identity
from hosting_api.partner_secrets import handle
from hosting_api.intent_contract import validate as intent_digest
from hosting_api.openapi import document
from hosting_api.secrets import SecretError
from partner_secret_control import import_binding,check_binding


@unittest.skipUnless(os.environ.get('TEST_ADMIN_DSN'),'requires disposable PostgreSQL')
class PartnerSecretIntegration(unittest.TestCase):
    setUpClass=classmethod(fixtures.PartnerIntentIntegration.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.PartnerIntentIntegration.tearDownClass.__func__)
    admin=fixtures.PartnerIntentIntegration.admin
    api=fixtures.PartnerIntentIntegration.api
    request=fixtures.PartnerIntentIntegration.request
    record=fixtures.PartnerIntentIntegration.record
    recheck=fixtures.PartnerIntentIntegration.recheck
    counts=fixtures.PartnerIntentIntegration.counts

    def setUp(self):
        fixtures.PartnerIntentIntegration.setUp(self)
        self.intent_id=uuid.UUID(self.intent['request_id']);self.record()
        self.binding=binding_fixture(self.org,self.app)

    def imported(self,value=None,operator='secret-test-operator'):
        with self.admin() as conn:return import_binding(conn,value or self.binding,operator)

    def checked(self,bao=None,key=None,binding=None,operator='secret-test-operator'):
        with self.admin() as conn:return check_binding(conn,binding or self.binding['id'],operator,key,bao or FakeBao())

    def readback(self,actor=None,kind='human',org=None,app=None,intent=None):
        with self.api(actor,kind) as conn:return handle(conn,org or self.org,app or self.app,intent or self.intent_id)

    def replace(self,**changes):
        self.binding={**self.binding,'id':str(uuid.uuid4()),**changes}
        return self.imported()

    def test_match_is_private_audited_and_never_delivers_values_or_provisions(self):
        before=self.counts();self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED')
        self.imported();self.assertEqual(self.readback()[1]['state'],'CHECK_REQUIRED')
        bao=FakeBao();self.assertEqual(self.checked(bao)['state'],'AVAILABLE')
        row=self.readback()[1];self.assertEqual(row['state'],'MATCHED');self.assertEqual(row['requested_count'],1);self.assertEqual(row['matched_count'],1)
        self.assertEqual(bao.calls,[(str(self.org),str(self.app),self.binding['resource_id'],1)])
        schema=document()['paths']['/v1/organizations/{organization_id}/applications/{application_id}/intents/{intent_id}/secrets']['get']['responses']['200']['content']['application/json']['schema']
        Draft202012Validator(schema).validate(row)
        self.assertEqual(row['intent_sha256'],intent_digest(self.intent))
        receipt=self.recheck()[1]['evaluation']['receipt'];self.assertEqual(receipt['stages'][4]['state'],'MATCHED')
        self.assertEqual(receipt['stages'][5]['state'],'BLOCKED');self.assertEqual(receipt['state'],'NOT_QUALIFIED');self.assertFalse(receipt['resource_mutations_performed'])
        after=self.counts()
        for table in ('releases','jobs','capacity_intervals','postgres_instances','valkey_instances','object_storage_instances'):self.assertEqual(before[table],after[table])
        self.assertEqual(after['audit_events']-before['audit_events'],3);self.assertEqual(after['event_outbox']-before['event_outbox'],3)
        with self.admin() as conn:
            audit=conn.execute('SELECT action,resource_id FROM hosting.audit_events WHERE organization_id=%s',(self.org,)).fetchall()
            checks=conn.execute('SELECT * FROM hosting.partner_secret_checks WHERE organization_id=%s',(self.org,)).fetchall()
        for private in ('private-secret-value','private-secret-proof','secret://','bao.example.org','value_key',self.binding['resource_id']):
            self.assertNotIn(private,str((row,receipt,audit,checks)))

    def test_tenant_human_role_and_parent_isolation(self):
        self.imported();self.checked();self.assertEqual(self.readback(actor=self.admin_actor)[0],200)
        for changes in ({'actor':self.viewer},{'kind':'service'},{'org':uuid.uuid4()},{'app':uuid.uuid4()},{'intent':uuid.uuid4()}):
            with self.subTest(changes=changes):self.assertEqual(self.readback(**changes),(404,{'error':'not_found'}))
        with self.admin() as conn:conn.execute('DELETE FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s',(self.org,self.owner))
        self.assertEqual(self.readback()[0],404)

    def test_latest_binding_withdrawal_and_historical_retry_never_restore_match(self):
        self.imported();old=copy.deepcopy(self.binding);key=uuid.uuid4();self.checked(key=key)
        self.replace(enabled=False);self.assertEqual(self.readback()[1]['state'],'BINDING_DISABLED')
        before=self.counts();self.assertFalse(self.imported(old)['current']);self.assertTrue(self.checked(key=key,binding=old['id'])['replayed']);self.assertEqual(before,self.counts())
        with self.assertRaises(ValueError):self.checked(binding=old['id'])
        self.replace(enabled=True);self.assertEqual(self.readback()[1]['state'],'CHECK_REQUIRED');self.checked();self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_future_expired_binding_and_new_reference_revision_cannot_borrow(self):
        self.imported();self.checked();now=datetime.now(timezone.utc)
        self.replace(valid_from=(now+timedelta(hours=1)).isoformat(),valid_until=(now+timedelta(hours=2)).isoformat())
        self.assertEqual(self.readback()[1]['state'],'NOT_YET_VALID')
        with self.assertRaises(ValueError):self.checked()
        self.replace(valid_from=(now-timedelta(hours=2)).isoformat(),valid_until=(now-timedelta(hours=1)).isoformat())
        self.assertEqual(self.readback()[1]['state'],'EXPIRED')
        with self.assertRaises(ValueError):self.checked()
        another=binding_fixture(self.org,self.app,secret_ref=self.binding['secret_ref'].rsplit('#',1)[0]+'#2',kv_version=2)
        self.imported(another);self.checked(binding=another['id']);self.assertEqual(self.readback()[1]['state'],'EXPIRED')

    def test_failed_check_overrides_success_without_fallback_and_errors_are_redacted(self):
        self.imported();self.checked()
        bao=FakeBao();bao.get_partner=lambda *a:(_ for _ in ()).throw(SecretError('private-secret-value arbitrary server error'))
        self.assertEqual(self.checked(bao)['state'],'UNAVAILABLE');row=self.readback()[1]
        self.assertEqual(row['state'],'CHECK_FAILED');self.assertIsNone(row['oldest_checked_at']);self.assertIsNone(row['valid_until'])
        self.assertNotIn('private-secret-value',str(row));self.assertEqual(self.recheck()[1]['evaluation']['receipt']['stages'][4]['state'],'BLOCKED')
        self.checked();self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_wrong_authority_key_type_and_revision_are_unavailable(self):
        self.imported()
        for bao in (FakeBao({}),FakeBao({'password':0}),FakeBao({'password':''}),FakeBao({'password':'x'*8193})):
            self.assertEqual(self.checked(bao)['state'],'UNAVAILABLE')
        bao=FakeBao();bao.address='https://another.example.org';self.assertEqual(self.checked(bao)['state'],'UNAVAILABLE');self.assertEqual(bao.calls,[])
        bao=FakeBao();bao.mount='other';self.assertEqual(self.checked(bao)['state'],'UNAVAILABLE');self.assertEqual(bao.calls,[])
        bao=FakeBao();bao.get_partner=lambda *a:(2,{'password':'private-secret-value'});self.assertEqual(self.checked(bao)['state'],'UNAVAILABLE')

    def test_all_requested_references_must_match_within_exact_scope(self):
        second='secret://another/password#1';self.intent={**self.intent,'request_id':str(uuid.uuid4()),'secret_refs':[self.binding['secret_ref'],second]}
        self.intent_id=uuid.UUID(self.intent['request_id']);self.record();self.imported();self.checked()
        row=self.readback()[1];self.assertEqual((row['state'],row['requested_count'],row['matched_count']),('UNCONFIGURED',2,1))
        self.assertIsNone(row['oldest_checked_at']);self.assertEqual(self.recheck()[1]['evaluation']['receipt']['stages'][4]['state'],'BLOCKED')
        other=binding_fixture(self.org,self.app,secret_ref=second);self.imported(other);self.checked(binding=other['id'])
        self.assertEqual(self.readback()[1]['state'],'MATCHED')
        with self.admin() as conn:
            other_app=uuid.uuid4();conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) VALUES (%s,%s,%s,'development','second')",(other_app,self.org,self.project))
        self.intent={**self.intent,'request_id':str(uuid.uuid4())};self.intent_id=uuid.UUID(self.intent['request_id'])
        self.assertEqual(self.request(app=other_app)[0],201);self.assertEqual(self.readback(app=other_app)[1]['state'],'UNCONFIGURED')

    def test_no_requested_secrets_is_explicit_without_configuration(self):
        self.intent={**self.intent,'request_id':str(uuid.uuid4()),'secret_refs':[]};self.intent_id=uuid.UUID(self.intent['request_id']);self.record()
        row=self.readback()[1];self.assertEqual((row['state'],row['requested_count'],row['matched_count']),('NOT_REQUESTED',0,0))
        self.assertIsNone(row['valid_until']);self.assertEqual(self.recheck()[1]['evaluation']['receipt']['stages'][4]['state'],'NOT_REQUESTED')

    def test_concurrent_import_and_check_retries_are_exactly_once(self):
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:self.imported(),range(2)))
        self.assertEqual(sorted(r['replayed'] for r in results),[False,True]);key=uuid.uuid4()
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:self.checked(key=key),range(2)))
        self.assertEqual(sorted(r['replayed'] for r in results),[False,True]);self.assertEqual(self.readback()[1]['state'],'MATCHED')
        with self.assertRaises(ValueError):self.imported({**self.binding,'value_key':'another'})
        with self.assertRaises(ValueError):self.checked(key=key,operator='different-operator')

    def test_tables_helpers_and_imports_are_private_immutable_and_direct_sql_validated(self):
        self.imported();self.checked()
        for table in ('partner_secret_bindings','partner_secret_checks'):
            for statement in ('SELECT * FROM hosting.'+table,'DELETE FROM hosting.'+table):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege),self.api() as conn:conn.execute(statement)
            with self.assertRaises(psycopg.Error),self.admin() as conn:conn.execute('UPDATE hosting.'+table+' SET issued_by=issued_by WHERE organization_id=%s',(self.org,))
        with self.api() as conn:
            for signature in ('hosting.partner_secret_binding_valid(jsonb)','hosting.partner_secret_insert()','hosting.partner_secret_audit()','hosting.partner_intent_profile_evidence_v1(uuid,uuid,uuid)'):
                self.assertFalse(conn.execute("SELECT has_function_privilege(current_user,%s,'EXECUTE') AS allowed",(signature,)).fetchone()['allowed'])
        with self.admin() as conn:
            for role in ('hosting_api','hosting_worker','hosting_admitter','hosting_hook','hosting_buildworker'):
                for table in ('partner_secret_bindings','partner_secret_checks'):
                    for privilege in ('SELECT','INSERT','UPDATE','DELETE'):
                        self.assertFalse(conn.execute('SELECT has_table_privilege(%s,%s,%s) AS allowed',(role,'hosting.'+table,privilege)).fetchone()['allowed'])
        with self.assertRaises(PermissionError),self.api() as conn:import_binding(conn,self.binding,'secret-test-operator')
        for changes in ({'kv_version':1.0},{'bao_address':'https://bao.example.org:99999'},{'value_key':'../secret'},
                        {'kv_version':2},{'authorization_ref':'arbitrary'},{'extra':'private-secret-value'}):
            with self.admin() as conn:
                value={**self.binding,**changes}
                self.assertFalse(conn.execute('SELECT hosting.partner_secret_binding_valid(%s) AS valid',(Jsonb(value),)).fetchone()['valid'])
        with self.assertRaises(psycopg.Error),self.admin() as conn:
            changed={**self.binding,'id':str(uuid.uuid4()),'organization_id':str(uuid.uuid4())}
            conn.execute("SELECT set_config('hosting.entitlement_operator','secret-test-operator',true)")
            conn.execute('INSERT INTO hosting.partner_secret_bindings(id,organization_id,application_id,payload,issued_by) VALUES (%s,%s,%s,%s,%s)',(changed['id'],changed['organization_id'],changed['application_id'],Jsonb(changed),'secret-test-operator'))

    def test_audit_outbox_and_checks_roll_back_atomically(self):
        before=self.counts()
        with self.assertRaises(RuntimeError),self.admin() as conn,conn.transaction():
            self.assertTrue(import_binding(conn,self.binding,'secret-test-operator')['current']);raise RuntimeError('rollback')
        self.assertEqual(before,self.counts());self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED')
        self.imported();before=self.counts()
        with self.assertRaises(RuntimeError),self.admin() as conn,conn.transaction():
            check_binding(conn,self.binding['id'],'secret-test-operator',bao=FakeBao());raise RuntimeError('rollback')
        self.assertEqual(before,self.counts());self.assertEqual(self.readback()[1]['state'],'CHECK_REQUIRED')

    def test_operator_supplied_check_time_cannot_extend_freshness(self):
        self.imported()
        with self.admin() as conn:
            conn.execute("SELECT set_config('hosting.entitlement_operator','secret-test-operator',true)")
            row=conn.execute("INSERT INTO hosting.partner_secret_checks(id,organization_id,application_id,binding_id,state,issued_by,checked_at) VALUES (%s,%s,%s,%s,'AVAILABLE','secret-test-operator',now()+interval '1 day') RETURNING checked_at<clock_timestamp() AS current",(uuid.uuid4(),self.org,self.app,self.binding['id'])).fetchone()
            self.assertTrue(row['current'])
        self.assertEqual(self.readback()[1]['state'],'MATCHED')
        # Trigger bypass is solely a disposable fixture for aging immutable observations.
        for interval in ('-6 minutes','+1 minute','-5 minutes'):
            with self.admin() as conn:
                conn.execute('ALTER TABLE hosting.partner_secret_checks DISABLE TRIGGER partner_secret_check_immutable')
                conn.execute('UPDATE hosting.partner_secret_checks SET checked_at=clock_timestamp()+%s::interval WHERE organization_id=%s',(interval,self.org))
                conn.execute('ALTER TABLE hosting.partner_secret_checks ENABLE TRIGGER partner_secret_check_immutable')
            self.assertEqual(self.readback()[1]['state'],'CHECK_REQUIRED')

    def test_check_and_withdrawal_serialize_without_deadlock(self):
        self.imported();entered=threading.Event();finish=threading.Event();bao=FakeBao()
        def probe(*args):entered.set();self.assertTrue(finish.wait(10));return 1,{'password':'private-secret-value'}
        bao.get_partner=probe;withdrawn={**self.binding,'id':str(uuid.uuid4()),'enabled':False}
        with ThreadPoolExecutor(max_workers=2) as pool:
            checked=pool.submit(self.checked,bao);self.assertTrue(entered.wait(10));changed=pool.submit(self.imported,withdrawn)
            finish.set();self.assertEqual(checked.result(timeout=15)['state'],'AVAILABLE');self.assertTrue(changed.result(timeout=15)['current'])
        self.assertEqual(self.readback()[1]['state'],'BINDING_DISABLED')

    def test_functions_share_snapshot_and_http_is_read_only(self):
        self.imported();self.checked()
        with self.admin() as conn:
            names=('partner_secret_readback','partner_intent_evidence','partner_intent_profile_evidence_v1')
            rows=conn.execute('SELECT provolatile FROM pg_proc WHERE pronamespace=\'hosting\'::regnamespace AND proname=ANY(%s)',(list(names),)).fetchall()
            self.assertEqual(len(rows),3);self.assertTrue(all(row['provolatile']=='s' for row in rows))
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.jwks=object()
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        path=f'/v1/organizations/{self.org}/applications/{self.app}/intents/{self.intent_id}/secrets'
        def request(method='GET',identity=None):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            with patch('hosting_api.__main__.authenticate',return_value=identity or Identity(self.owner)),patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn):
                connection.request(method,path,json.dumps({'binding':self.binding}) if method=='POST' else None,{'Authorization':'Bearer fixture','Content-Type':'application/json'})
                response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
        try:
            self.assertEqual(request()[1]['state'],'MATCHED');self.assertEqual(request('POST')[0],404)
            self.assertEqual(request(identity=Identity(self.viewer))[0],404)
            self.assertEqual(request(identity=Identity(self.owner,'machine','https://issuer.example.org'))[0],404)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)
