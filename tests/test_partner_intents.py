import copy
import sys
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'services/api'))
from hosting_api.intent_contract import validate
from hosting_api.partner_intents import evaluate, public, timestamp
from tests.intent_fixtures import intent_fixture, evidence_fixture


class IntentEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.intent = intent_fixture()
        self.evidence = evidence_fixture(self.intent)

    def receipt(self):
        return evaluate(self.intent, validate(self.intent), self.evidence)

    def states(self):
        return {row['stage']:row['state'] for row in self.receipt()['stages']}

    def test_observation_never_grants_authority_or_transforms_desired_state(self):
        before = copy.deepcopy((self.intent,self.evidence))
        receipt, states = self.receipt(), self.states()
        self.assertEqual(receipt['state'],'NOT_QUALIFIED')
        self.assertFalse(receipt['resource_mutations_performed'])
        self.assertEqual(receipt['transformations'],[])
        self.assertEqual(states['release_health'],'OBSERVED_HEALTHY')
        for stage in ('commercial_authority','profile_qualification','tenant_admin_bindings','secret_bindings','backups'):
            self.assertEqual(states[stage],'BLOCKED')
        self.assertEqual(before,(self.intent,self.evidence))
        for value in ('partner-private-marker','business-private-marker','secret://','admin-private-marker',
                      'commercial-private-marker','requester-private-marker'):
            self.assertNotIn(value,str(receipt))
        row = {'id':self.intent['request_id'],'application_id':self.evidence['application']['id'],
               'intent_sha256':receipt['intent_sha256'],'payload':self.intent,'created_at':receipt['observed_at']}
        for value in ('partner-private-marker','business-private-marker','secret://','admin-private-marker',
                      'commercial-private-marker','requester-private-marker'):
            self.assertNotIn(value,str(public(row)))

    def test_wrong_artifact_or_binding_cannot_borrow_healthy_observation(self):
        for key, patch in [('release',{'image':'registry.test/other@sha256:'+'b'*64}),
                           ('release',{'state':'RETIRED'}), ('health',{'release_id':'different-release'}),
                           ('application',{'project_id':'different-project'}),
                           ('application',{'environment':'production'}), ('application',{'traffic_state':'SUSPENDED'}),
                           ('domain',{'hostname':'different.example.org'}), ('domain',{'verified_at':None}),
                           ('node',{'enabled':False})]:
            with self.subTest(key=key, patch=patch):
                original = self.evidence[key]
                self.evidence[key] = {**original,**patch}
                self.assertEqual(self.states()['release_health'],'BLOCKED')
                self.assertEqual(self.states()['route_tls'],'BLOCKED')
                self.evidence[key] = original

    def test_stale_future_malformed_or_unbound_domain_evidence_is_blocked(self):
        now = timestamp(self.evidence['observed_at'])
        for key, field, minutes in [('health','checked_at',-4),('health','checked_at',1),
                                    ('node','observed_at',-6),('node','observed_at',1),
                                    ('domain','verified_at',1)]:
            original = self.evidence[key][field]
            for value in ((now+timedelta(minutes=minutes)).isoformat(),'invalid',None,'2026-10-07T00:00:00'):
                with self.subTest(key=key,value=value):
                    self.evidence[key][field] = value
                    self.assertEqual(self.states()['release_health'],'BLOCKED')
            self.evidence[key][field] = original

    def test_actual_allocation_and_other_tenant_app_capacity_are_counted(self):
        self.assertEqual(self.states()['resource_budget'],'MATCHED')
        self.evidence['reservations']['memory_mb'] = '1025'
        self.assertEqual(self.states()['resource_budget'],'BLOCKED')
        self.evidence['reservations']['memory_mb'] = '256'
        self.evidence['organization_reserved']['cpu_milli'] = '1751'
        self.assertEqual(self.states()['hosting_plan'],'BLOCKED')
        self.evidence['organization_reserved']['cpu_milli'] = '1750'
        self.assertEqual(self.states()['hosting_plan'],'MATCHED')
        self.evidence['quota']['cpu_milli_limit'] = '1749'
        self.assertEqual(self.states()['hosting_plan'],'BLOCKED')

    def test_missing_expired_future_or_incompatible_plan_is_blocked(self):
        original = copy.deepcopy(self.evidence['plan'])
        for patch in [None, {'features':['release']}, {'valid_until':self.evidence['observed_at']},
                      {'valid_from':'2099-01-01T00:00:00Z'}, {'valid_until':None}]:
            with self.subTest(patch=patch):
                self.evidence['plan'] = None if patch is None else {**original,**patch}
                self.assertEqual(self.states()['hosting_plan'],'BLOCKED')
        self.evidence['plan'] = original
        self.evidence['quota'] = None
        self.assertEqual(self.states()['hosting_plan'],'BLOCKED')

    def test_requested_and_unrequested_services_are_explicit(self):
        node = self.evidence['release']['node_id']
        for profile in ('postgres-private-v1','supabase-unqualified'):
            self.intent['database_profile'] = profile
            self.evidence['postgres'] = {'state':'READY','node_id':node}
            self.assertEqual(self.states()['postgres'],'MATCHED' if profile=='postgres-private-v1' else 'BLOCKED')
        self.intent['database_profile'] = 'none'
        self.assertEqual(self.states()['postgres'],'BLOCKED')
        self.evidence['postgres'] = None
        self.intent['storage_profile'] = 'garage-development-v1'
        self.evidence['storage'] = {'state':'READY','node_id':node}
        self.assertEqual(self.states()['storage'],'MATCHED')
        self.evidence['storage']['node_id'] = 'different-node'
        self.assertEqual(self.states()['storage'],'BLOCKED')
        self.evidence['storage']['node_id'] = node
        self.intent['environment_profile'] = 'production'
        self.assertEqual(self.states()['storage'],'BLOCKED')
        self.assertEqual(self.states()['hosting_plan'],'BLOCKED')
        self.intent['secret_refs'] = []
        self.assertEqual(self.states()['secret_bindings'],'NOT_REQUESTED')


if __name__ == '__main__':
    unittest.main()
