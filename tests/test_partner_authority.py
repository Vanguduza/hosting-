"""Contract and private-file boundary checks without external services."""
import copy
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
sys.path.insert(0,str(ROOT/'tools'))
from hosting_api.partner_authority import validate
from hosting_api.partner_intents import evaluate
from hosting_api.intent_contract import validate as intent_digest
from partner_authority_source import private_json
from hosting_cli import parser, request_for
from tests.intent_fixtures import intent_fixture,evidence_fixture


def source_fixture():
    return {'id':str(uuid.uuid4()),'organization_id':str(uuid.uuid4()),'purpose':'partner-commercial-bindings-v1',
        'name':'partner-factory','issuer':'https://issuer.example.org','client_id':'partner-factory',
        'actor_sub':'publisher-雪','enabled':True,'max_validity_seconds':600,'evidence_ref':'authority://private-proof'}


def receipt_fixture():
    return {'schema_version':'1.0','purpose':'partner-commercial-bindings-v1','id':str(uuid.uuid4()),
        'source_version_id':str(uuid.uuid4()),'intent_sha256':'a'*64,'sequence':2**63-1,'disposition':'AUTHORIZE',
        'hosting_entitlement_version_id':str(uuid.uuid4()),'admin_bindings':[{'ref':'partner-admin','actor_sub':'user-雪'}],
        'issued_at':'2026-10-08T00:00:00Z','valid_until':'2026-10-08T00:05:00Z','evidence_ref':'partner-proof://private-proof'}


class PartnerAuthorityTests(unittest.TestCase):
    def test_contract_accepts_unicode_subjects_and_exact_integer_sequence(self):
        for value,source in ((source_fixture(),True),(receipt_fixture(),False)):
            original=copy.deepcopy(value)
            self.assertEqual(validate(value,source=source),original)
        for patch in ({'sequence':True},{'sequence':1.0},{'sequence':0},{'sequence':2**63},
                      {'purpose':'release-deployer'},{'admin_bindings':[]},{'issued_at':'2026-10-08T00:00:00'},
                      {'valid_until':'2026-10-07T00:00:00Z'},{'raw_token':'private'},
                      {'admin_bindings':[{'ref':'partner-admin','actor_sub':'bad\x00subject'}]}):
            with self.subTest(patch=patch),self.assertRaises(ValueError):validate({**receipt_fixture(),**patch})
        for patch in ({'enabled':'true'},{'max_validity_seconds':30.0},{'max_validity_seconds':True},
                      {'max_validity_seconds':3601},{'issuer':'https://user:secret@issuer.example.org'},
                      {'issuer':'http://issuer.example.org'},{'actor_sub':'\ud800'}):
            with self.subTest(patch=patch),self.assertRaises(ValueError):validate({**source_fixture(),**patch},source=True)

    def test_revoke_has_no_plan_admin_bindings_or_expiry(self):
        value={**receipt_fixture(),'disposition':'REVOKE','hosting_entitlement_version_id':None,'admin_bindings':[],'valid_until':None}
        validate(value)
        for patch in ({'admin_bindings':receipt_fixture()['admin_bindings']},{'valid_until':'2026-10-08T00:05:00Z'},
                      {'hosting_entitlement_version_id':str(uuid.uuid4())}):
            with self.assertRaises(ValueError):validate({**value,**patch})
        value=receipt_fixture();value['admin_bindings']*=2
        with self.assertRaises(ValueError):validate(value)

    def test_private_files_reject_duplicates_symlinks_public_permissions_and_large_inputs(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.json';path.write_text(json.dumps(source_fixture()));path.chmod(0o600)
            self.assertEqual(private_json(path)['name'],'partner-factory')
            link=Path(directory)/'link.json';link.symlink_to(path)
            with self.assertRaises(OSError):private_json(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError):private_json(path)
            path.chmod(0o600);path.write_text('{"id":"one","id":"two"}')
            with self.assertRaises(ValueError):private_json(path)
            path.write_text(' '*65537)
            with self.assertRaises(ValueError):private_json(path)
            fifo=Path(directory)/'fifo';os.mkfifo(fifo,0o600)
            with self.assertRaises(ValueError):private_json(fifo)

    def test_reconciliation_uses_only_active_current_snapshot_authority(self):
        intent=intent_fixture();evidence=evidence_fixture(intent)
        for state in ('UNCONFIGURED','AWAITING_RECEIPT','SOURCE_DISABLED','SOURCE_CHANGED','EXPIRED','REVOKED',
                      'PLAN_CHANGED','PLAN_UNAVAILABLE','ADMIN_UNBOUND','ACTIVE'):
            evidence['partner_authority']={'state':state}
            receipt=evaluate(intent,intent_digest(intent),evidence)
            states={stage['stage']:stage['state'] for stage in receipt['stages']}
            expected='MATCHED' if state=='ACTIVE' else 'BLOCKED'
            self.assertEqual(states['commercial_authority'],expected)
            self.assertEqual(states['tenant_admin_bindings'],expected)
            self.assertEqual(receipt['state'],'NOT_QUALIFIED');self.assertFalse(receipt['resource_mutations_performed'])
            self.assertEqual(states['backups'],'BLOCKED');self.assertEqual(states['profile_qualification'],'BLOCKED')

    def test_cli_authority_readback_uses_tenant_application_and_intent(self):
        org,app,intent=(str(uuid.uuid4()) for _ in range(3))
        args=parser().parse_args(['--base-url','https://hosting.example.org:443','intent-authority',org,app,intent])
        self.assertEqual(request_for(args),(f'/v1/organizations/{org}/applications/{app}/intents/{intent}/authority',None,None))
