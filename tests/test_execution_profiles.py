"""Typed reviewed profile boundary and safe observer behavior without external services."""
import copy
import json
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
sys.path.insert(0,str(ROOT/'tools'))
from hosting_api.execution_profiles import STATES,validate
from hosting_api.intent_contract import validate as digest
from hosting_api.partner_intents import evaluate
from hosting_cli import parser,request_for
from set_execution_profile import private_json
from tests.profile_fixtures import profile_fixture
from tests.intent_fixtures import intent_fixture,evidence_fixture


class ExecutionProfileTests(unittest.TestCase):
    def test_exact_contract_validity_and_no_mutation(self):
        value=profile_fixture();original=copy.deepcopy(value)
        self.assertEqual(validate(value),original)
        for patch in ({'enabled':'true'},{'organization_id':str(uuid.uuid4()).upper()},{'template_version':'latest\n'},
                      {'database_profile':'supabase-unqualified'},{'storage_profile':'s3-redundant-unqualified'},
                      {'environment_profile':'production','storage_profile':'garage-development-v1'},
                      {'resource_ceiling':{'cpu_milli':500.0,'memory_mb':1024}},
                      {'resource_ceiling':{'cpu_milli':True,'memory_mb':1024}},
                      {'resource_ceiling':{'cpu_milli':32001,'memory_mb':1024}},
                      {'node_bindings':[]},{'node_bindings':value['node_bindings']*2},
                      {'plaintext_password':'private-marker'},{'qualification_refs':{'template':'template-proof://only'}},
                      {'valid_from':'2026-10-08T24:00:00Z'},{'valid_from':'2026-10-08T00:00:00+16:00'},
                      {'valid_from':'2026-10-08T00:00:00'}, {'valid_until':value['valid_from']}):
            with self.subTest(patch=patch),self.assertRaises(ValueError):validate({**value,**patch})
        start=datetime.now(timezone.utc)
        validate({**value,'valid_from':start.isoformat(),'valid_until':(start+timedelta(days=90)).isoformat()})
        with self.assertRaises(ValueError):validate({**value,'valid_from':start.isoformat(),'valid_until':(start+timedelta(days=90,seconds=1)).isoformat()})

    def test_independent_qualification_refs_are_typed_and_no_unknown_fields(self):
        value=profile_fixture()
        for key in value:
            with self.subTest(key=key),self.assertRaises(ValueError):validate({k:v for k,v in value.items() if k!=key})
        for key in value['qualification_refs']:
            for ref in ('https://private-host/proof','private-secret',key+'-proof://proof\n','estate-proof://wrong-kind' if key!='estate' else 'template-proof://wrong-kind'):
                with self.subTest(key=key,ref=ref),self.assertRaises(ValueError):
                    validate({**value,'qualification_refs':{**value['qualification_refs'],key:ref}})

    def test_private_profile_file_bounds_and_duplicate_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'profile.json';path.write_text(json.dumps(profile_fixture()));path.chmod(0o600)
            self.assertEqual(private_json(path)['runtime_class'],'docker-http-v1')
            alias=Path(directory)/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):private_json(alias)
            path.chmod(0o640)
            with self.assertRaises(ValueError):private_json(path)
            path.chmod(0o600);path.write_text('{"id":"one","id":"two"}')
            with self.assertRaises(ValueError):private_json(path)
            path.write_text(' '*65537)
            with self.assertRaises(ValueError):private_json(path)
            fifo=Path(directory)/'fifo';os.mkfifo(fifo,0o600)
            with self.assertRaises(ValueError):private_json(fifo)

    def test_evaluator_matches_only_current_reviewed_profile_without_qualification_promotion(self):
        intent=intent_fixture();evidence=evidence_fixture(intent)
        for state in STATES:
            evidence['execution_profile']={'state':state}
            receipt=evaluate(intent,digest(intent),evidence)
            stage=receipt['stages'][2]
            self.assertEqual(stage['state'],'MATCHED' if state=='MATCHED' else 'BLOCKED')
            self.assertEqual(receipt['state'],'NOT_QUALIFIED');self.assertEqual(receipt['transformations'],[])
            self.assertFalse(receipt['resource_mutations_performed'])
            self.assertEqual(receipt['stages'][1]['state'],'BLOCKED')
            self.assertEqual(receipt['stages'][5]['state'],'BLOCKED')
            self.assertNotIn('private-profile-marker',str(receipt))
        evidence.pop('execution_profile')
        self.assertEqual(evaluate(intent,digest(intent),evidence)['stages'][2]['state'],'BLOCKED')

    def test_cli_uses_exact_scoped_profile_route(self):
        org,app,intent=(str(uuid.uuid4()) for _ in range(3))
        args=parser().parse_args(['--base-url','https://control.example:443','intent-profile',org,app,intent])
        self.assertEqual(request_for(args),(f'/v1/organizations/{org}/applications/{app}/intents/{intent}/profile',None,None))
