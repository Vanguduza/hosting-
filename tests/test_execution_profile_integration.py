"""Profile trust boundaries, current measured bindings and immutable history on PostgreSQL."""
import copy
import hashlib
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
from tests.profile_fixtures import profile_fixture
from hosting_api.__main__ import Handler,Identity
from hosting_api.execution_profiles import handle,validate
from hosting_api.intent_contract import validate as intent_digest
from hosting_api.openapi import document
from set_execution_profile import import_profile,node_binding


@unittest.skipUnless(os.environ.get('TEST_ADMIN_DSN'),'requires disposable PostgreSQL')
class ExecutionProfileIntegration(unittest.TestCase):
    setUpClass=classmethod(fixtures.PartnerIntentIntegration.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.PartnerIntentIntegration.tearDownClass.__func__)
    admin=fixtures.PartnerIntentIntegration.admin
    api=fixtures.PartnerIntentIntegration.api
    request=fixtures.PartnerIntentIntegration.request
    record=fixtures.PartnerIntentIntegration.record
    recheck=fixtures.PartnerIntentIntegration.recheck
    counts=fixtures.PartnerIntentIntegration.counts
    healthy=fixtures.PartnerIntentIntegration.healthy

    def setUp(self):
        fixtures.PartnerIntentIntegration.setUp(self)
        self.intent_id=uuid.UUID(self.intent['request_id'])
        self.healthy()
        with self.admin() as conn:
            address='8.'+'.'.join(str(byte) for byte in self.node.bytes[:3])
            conn.execute('UPDATE hosting.nodes SET public_ipv4=%s WHERE id=%s',(address,self.node))
            binding=node_binding(conn,str(self.node),'profile-test-operator')
        self.profile=profile_fixture(self.org,self.node,self.intent,node_bindings=[binding])
        self.record()

    def import_value(self,value=None,operator='profile-test-operator'):
        with self.admin() as conn:return import_profile(conn,value or self.profile,operator)

    def readback(self,actor=None,kind='human',org=None,app=None,intent=None):
        with self.api(actor,kind) as conn:return handle(conn,org or self.org,app or self.app,intent or self.intent_id)

    def replace(self,**patches):
        self.profile={**self.profile,'id':str(uuid.uuid4()),**patches}
        return self.import_value()

    def binding(self,node=None):
        with self.admin() as conn:return node_binding(conn,str(node or self.node),'profile-test-operator')

    def test_match_is_redacted_audited_independent_and_does_not_provision(self):
        self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED')
        before=self.counts()
        self.assertEqual(self.import_value()['current'],True)
        status,row=self.readback();self.assertEqual(status,200);self.assertEqual(row['state'],'MATCHED')
        self.assertEqual(row['intent_sha256'],intent_digest(self.intent))
        schema=document()['paths']['/v1/organizations/{organization_id}/applications/{application_id}/intents/{intent_id}/profile']['get']['responses']['200']['content']['application/json']['schema']
        Draft202012Validator(schema).validate(json.loads(json.dumps(row,default=str)))
        for private in ('private-profile-marker','qualification_refs','node_bindings','endpoint','issued_by',str(self.node)):
            self.assertNotIn(private,str(row))
        previous=self.request(method='GET',intent_id=self.intent_id)[1]['intent']['evaluation']['receipt']
        self.assertEqual(previous['stages'][2]['state'],'BLOCKED')
        evaluation=self.recheck()[1]['evaluation']['receipt']
        self.assertEqual(evaluation['stages'][2]['state'],'MATCHED')
        self.assertEqual(evaluation['stages'][1]['state'],'BLOCKED');self.assertEqual(evaluation['stages'][5]['state'],'BLOCKED')
        self.assertEqual(evaluation['state'],'NOT_QUALIFIED');self.assertFalse(evaluation['resource_mutations_performed'])
        after=self.counts()
        for table in ('releases','jobs','capacity_intervals','postgres_instances','valkey_instances','object_storage_instances'):
            self.assertEqual(before[table],after[table])
        self.assertEqual(after['audit_events']-before['audit_events'],2)
        self.assertEqual(after['event_outbox']-before['event_outbox'],2)
        expected=hashlib.sha256(json.dumps(self.profile,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(row['profile_sha256'],expected)

    def test_commercial_and_profile_matches_remain_independent_and_cannot_promote_full_qualification(self):
        from tests.test_partner_authority import source_fixture,receipt_fixture
        from partner_authority_source import register
        from hosting_api.partner_authority import handle as authority_request
        self.import_value()
        source={**source_fixture(),'organization_id':str(self.org)}
        now=datetime.now(timezone.utc)-timedelta(seconds=1)
        with self.admin() as conn:
            register(conn,source,'profile-test-operator')
            plan=conn.execute('SELECT version_id FROM hosting.organization_entitlements WHERE organization_id=%s',(self.org,)).fetchone()['version_id']
        receipt={**receipt_fixture(),'source_version_id':source['id'],'intent_sha256':intent_digest(self.intent),'sequence':1,
            'hosting_entitlement_version_id':str(plan),'issued_at':now.isoformat(),'valid_until':(now+timedelta(minutes=5)).isoformat(),
            'admin_bindings':[{'ref':ref,'actor_sub':self.admin_actor} for ref in self.intent['tenant_admin_refs']]}
        with self.api(source['actor_sub'],'service') as conn:
            conn.execute("SELECT set_config('hosting.token_issuer',%s,true)",(source['issuer'],))
            conn.execute("SELECT set_config('hosting.service_client_id',%s,true)",(source['client_id'],))
            self.assertEqual(authority_request(conn,self.org,self.app,self.intent_id,{'receipt':receipt},'POST')[0],201)
        before=self.counts()
        evaluation=self.recheck()[1]['evaluation']['receipt']
        self.assertEqual([evaluation['stages'][i]['state'] for i in (1,2,3)],['MATCHED']*3)
        self.assertEqual([evaluation['stages'][i]['state'] for i in (4,5)],['BLOCKED']*2)
        self.assertEqual(evaluation['state'],'NOT_QUALIFIED');self.assertFalse(evaluation['resource_mutations_performed'])
        after=self.counts()
        for table in ('releases','jobs','capacity_intervals','postgres_instances','valkey_instances','object_storage_instances'):
            self.assertEqual(before[table],after[table])

    def test_tenant_role_and_machine_isolation(self):
        self.import_value()
        self.assertEqual(self.readback(actor=self.admin_actor)[0],200)
        for patches in ({'actor':self.viewer},{'kind':'service','actor':self.owner},{'org':uuid.uuid4()},
                        {'app':uuid.uuid4()},{'intent':uuid.uuid4()}):
            with self.subTest(patches=patches):self.assertEqual(self.readback(**patches),(404,{'error':'not_found'}))
        with self.admin() as conn:
            conn.execute('DELETE FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s',(self.org,self.owner))
        self.assertEqual(self.readback()[0],404)

    def test_old_retries_never_reactivate_withdrawn_or_replaced_profile(self):
        self.import_value();old=copy.deepcopy(self.profile)
        before=self.counts();self.assertTrue(self.import_value()['replayed']);self.assertEqual(before,self.counts())
        self.replace(enabled=False);self.assertEqual(self.readback()[1]['state'],'DISABLED')
        result=self.import_value(old)
        self.assertTrue(result['replayed']);self.assertFalse(result['current'])
        self.assertEqual(self.readback()[1]['state'],'DISABLED')
        self.replace(enabled=True);self.assertEqual(self.readback()[1]['state'],'MATCHED')
        for patches in ({'qualification_refs':{**old['qualification_refs'],'estate':'estate-proof://changed'}},
                        {'organization_id':str(uuid.uuid4())}):
            with self.subTest(patches=patches),self.assertRaises(ValueError):self.import_value({**old,**patches})
        with self.assertRaises(ValueError):self.import_value(old,operator='other-operator')

    def test_pending_future_expired_and_latest_mismatch_have_no_fallback(self):
        self.import_value()
        now=datetime.now(timezone.utc)
        self.replace(valid_from=(now+timedelta(minutes=1)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat())
        self.assertEqual(self.readback()[1]['state'],'NOT_YET_VALID')
        self.replace(valid_from=(now-timedelta(days=2)).isoformat(),valid_until=(now-timedelta(days=1)).isoformat())
        self.assertEqual(self.readback()[1]['state'],'EXPIRED')
        self.replace(valid_from=(now-timedelta(minutes=1)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat(),database_profile='postgres-private-v1')
        self.assertEqual(self.readback()[1]['state'],'PROFILE_MISMATCH')
        self.assertEqual(self.recheck()[1]['evaluation']['receipt']['stages'][2]['state'],'BLOCKED')

    def test_template_version_environment_and_artifact_cannot_borrow_profiles(self):
        for patches in ({'template_id':'different'},{'template_version':'2.0'},{'environment_profile':'production'}):
            value={**self.profile,'id':str(uuid.uuid4()),**patches}
            self.import_value(value)
            self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED')
        self.import_value()
        new={**self.intent,'request_id':str(uuid.uuid4()),'release_artifact_ref':'registry.example.org/team/other@sha256:'+'d'*64}
        self.assertEqual(self.request({'intent':new})[0],201)
        self.assertEqual(self.readback(intent=uuid.UUID(new['request_id']))[1]['state'],'PROFILE_MISMATCH')

    def test_requested_budget_is_bounded_separately_from_hosting_quota(self):
        self.profile['resource_ceiling']={'cpu_milli':499,'memory_mb':4096};self.import_value()
        self.assertEqual(self.readback()[1]['state'],'BUDGET_EXCEEDED')
        self.replace(resource_ceiling={'cpu_milli':2000,'memory_mb':1023})
        self.assertEqual(self.readback()[1]['state'],'BUDGET_EXCEEDED')
        self.replace(resource_ceiling={'cpu_milli':500,'memory_mb':1024})
        self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_fresh_enabled_nodes_are_required_and_heartbeat_does_not_change_binding(self):
        self.import_value();original=self.binding()
        for field,expression in (('enabled','false'),('observed_at',"now()-interval '6 minutes'"),
                                 ('observed_at',"now()+interval '1 minute'")):
            with self.admin() as conn:conn.execute(f'UPDATE hosting.nodes SET {field}={expression} WHERE id=%s',(self.node,))
            self.assertEqual(self.readback()[1]['state'],'NO_ELIGIBLE_NODE')
            with self.admin() as conn:conn.execute('UPDATE hosting.nodes SET enabled=true,observed_at=now() WHERE id=%s',(self.node,))
            self.assertEqual(self.binding(),original);self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_configuration_capacity_and_lifecycle_changes_require_new_review(self):
        self.import_value()
        original=self.binding()
        for field,value in (('server_name','replacement-node.test'),('public_ipv4','9.'+'.'.join(str(v) for v in self.node.bytes[:3])),
                            ('cpu_milli',30000),('memory_mb',64000)):
            with self.admin() as conn:conn.execute(f'UPDATE hosting.nodes SET {field}=%s WHERE id=%s',(value,self.node))
            self.assertNotEqual(self.binding(),original)
            self.assertEqual(self.readback()[1]['state'],'NO_ELIGIBLE_NODE')
            self.replace(node_bindings=[self.binding()]);self.assertEqual(self.readback()[1]['state'],'MATCHED')
            original=self.binding()
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.node_state_changes(node_id,enabled,operator,reason) VALUES (%s,false,'profile-tests','disposable quarantine')",(self.node,))
            conn.execute("INSERT INTO hosting.node_state_changes(node_id,enabled,operator,reason) VALUES (%s,true,'profile-tests','disposable re-enrollment')",(self.node,))
        self.assertNotEqual(self.binding(),original);self.assertEqual(self.readback()[1]['state'],'NO_ELIGIBLE_NODE')
        self.replace(node_bindings=[self.binding()]);self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_serving_requested_artifact_must_use_one_of_the_eligible_reviewed_nodes(self):
        alternative=uuid.uuid4()
        with self.admin() as conn:
            address='11.'+'.'.join(str(v) for v in alternative.bytes[:3])
            conn.execute('INSERT INTO hosting.nodes(id,endpoint,server_name,public_ipv4,enabled,cpu_milli,memory_mb,observed_at) VALUES (%s,%s,%s,%s,true,32000,65536,now())',
                         (alternative,'https://node-'+alternative.hex+'.test:8443','node-'+alternative.hex+'.test',address))
        self.profile['node_bindings']=[self.binding(alternative)];self.import_value()
        self.assertEqual(self.readback()[1]['state'],'PLACEMENT_MISMATCH')
        self.replace(node_bindings=[self.binding(),self.binding(alternative)])
        self.assertEqual(self.readback()[1]['state'],'MATCHED')

    def test_import_requires_admission_current_node_binding_capacity_and_prerequisites(self):
        for patches in ({'release_artifact_ref':'registry.example.org/not-admitted@sha256:'+'e'*64},
                        {'node_bindings':[{'node_id':str(uuid.uuid4()),'configuration_sha256':'b'*64}]},
                        {'node_bindings':[{'node_id':str(self.node),'configuration_sha256':'b'*64}]}):
            with self.subTest(patches=patches),self.assertRaises(psycopg.errors.RaiseException):self.import_value({**self.profile,**patches})
        with self.admin() as conn:conn.execute('UPDATE hosting.nodes SET cpu_milli=1000 WHERE id=%s',(self.node,))
        self.profile['node_bindings']=[self.binding()]
        with self.assertRaises(psycopg.errors.RaiseException):self.import_value()
        # Withdrawal is always available even after underlying evidence is unavailable.
        self.profile['enabled']=False;self.import_value();self.assertEqual(self.readback()[1]['state'],'DISABLED')

    def test_admission_removed_from_an_unused_digest_blocks_current_readback(self):
        image='registry.example.org/team/unplaced@sha256:'+'c'*64
        intent={**self.intent,'request_id':str(uuid.uuid4()),'release_artifact_ref':image}
        self.request({'intent':intent})
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) VALUES (%s,%s,%s,'profile-fixture','{}')",(image,'b'*64,'c'*40))
        self.replace(release_artifact_ref=image)
        self.assertEqual(self.readback(intent=uuid.UUID(intent['request_id']))[1]['state'],'MATCHED')
        with self.admin() as conn:conn.execute('DELETE FROM hosting.artifact_admissions WHERE image=%s',(image,))
        self.assertEqual(self.readback(intent=uuid.UUID(intent['request_id']))[1]['state'],'ARTIFACT_UNADMITTED')

    def test_concurrent_duplicates_record_once_and_effective_versions_serialize(self):
        before=self.counts()
        with ThreadPoolExecutor(max_workers=4) as pool:replies=list(pool.map(lambda _:self.import_value(),range(4)))
        self.assertEqual(sum(not reply['replayed'] for reply in replies),1)
        self.assertEqual(self.counts()['audit_events']-before['audit_events'],1)
        values=[{**self.profile,'id':str(uuid.uuid4()),'enabled':enabled} for enabled in (False,True)]
        with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(self.import_value,values))
        with self.admin() as conn:
            current=conn.execute('SELECT id,payload FROM hosting.execution_profile_versions WHERE organization_id=%s ORDER BY revision DESC LIMIT 1',(self.org,)).fetchone()
        expected='MATCHED' if current['payload']['enabled'] else 'DISABLED'
        self.assertEqual(self.readback()[1]['state'],expected)
        self.assertFalse(self.import_value()['current']);self.assertEqual(self.readback()[1]['state'],expected)

    def test_private_immutable_table_restricted_helpers_and_atomic_rollback(self):
        before=self.counts()
        with self.admin() as conn:
            conn.execute('SELECT 1');import_profile(conn,self.profile,'profile-test-operator');conn.rollback()
        self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED');self.assertEqual(before,self.counts())
        self.import_value()
        with self.api() as conn,self.assertRaises(PermissionError):import_profile(conn,self.profile,'pretend-operator')
        with self.api() as conn:
            for privilege in ('SELECT','INSERT','UPDATE','DELETE'):
                self.assertFalse(conn.execute("SELECT has_table_privilege(current_user,'hosting.execution_profile_versions',%s) AS ok",(privilege,)).fetchone()['ok'])
            for function in ('hosting.execution_node_fingerprint(uuid)','hosting.execution_node_eligible(uuid,text,integer,integer,timestamp with time zone)',
                             'hosting.partner_intent_authority_evidence_v1(uuid,uuid,uuid)'):
                self.assertFalse(conn.execute('SELECT has_function_privilege(current_user,%s,\'EXECUTE\') AS ok',(function,)).fetchone()['ok'])
        for operation in ('UPDATE hosting.execution_profile_versions SET payload=payload','DELETE FROM hosting.execution_profile_versions'):
            with self.assertRaises(psycopg.errors.RaiseException),self.admin() as conn:conn.execute(operation+' WHERE id=%s',(self.profile['id'],))
        with self.admin() as conn:
            for name in ('execution_node_fingerprint','execution_node_eligible','execution_profile_readback','partner_intent_evidence'):
                self.assertEqual(conn.execute("SELECT provolatile FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='hosting' AND proname=%s",(name,)).fetchone()['provolatile'],'s')

    def test_sql_validator_canonical_hash_and_unicode_node_fingerprint(self):
        with self.admin() as conn:
            conn.execute('UPDATE hosting.nodes SET server_name=%s WHERE id=%s',('node-雪',self.node))
            node=conn.execute('SELECT id,endpoint,server_name,host(public_ipv4) AS public_ipv4,cpu_milli,memory_mb FROM hosting.nodes WHERE id=%s',(self.node,)).fetchone()
            node['id']=str(node['id']);node['state_revision']='0'
            expected=hashlib.sha256(json.dumps(node,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
            self.assertEqual(node_binding(conn,str(self.node),'profile-test-operator')['configuration_sha256'],expected)
            self.assertTrue(conn.execute('SELECT hosting.execution_profile_valid(%s) AS ok',(Jsonb(self.profile),)).fetchone()['ok'])
            for key in self.profile:
                for value in ({k:v for k,v in self.profile.items() if k!=key},{**self.profile,key:None}):
                    self.assertFalse(conn.execute('SELECT hosting.execution_profile_valid(%s) AS ok',(Jsonb(value),)).fetchone()['ok'])
            for stamp in ('2026-10-08T24:00:00Z','2026-10-08T00:00:00+16:00','2026-10-08T00:00:60Z'):
                self.assertFalse(conn.execute('SELECT hosting.execution_profile_valid(%s) AS ok',(Jsonb({**self.profile,'valid_from':stamp}),)).fetchone()['ok'])

    def test_http_profile_is_read_only_human_scoped_and_cannot_import(self):
        self.import_value()
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.jwks=None
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        path=f'/v1/organizations/{self.org}/applications/{self.app}/intents/{self.intent_id}/profile'
        def request(method='GET',identity=None):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            with patch('hosting_api.__main__.authenticate',return_value=identity or Identity(self.owner)),patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn):
                connection.request(method,path,json.dumps({'profile':self.profile}) if method=='POST' else None,{'Authorization':'Bearer fixture','Content-Type':'application/json'})
                response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
        try:
            self.assertEqual(request()[1]['state'],'MATCHED')
            self.assertEqual(request('POST')[0],404)
            self.assertEqual(request(identity=Identity(self.viewer))[0],404)
            self.assertEqual(request(identity=Identity(self.owner,'publisher','https://issuer.example.org'))[0],404)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)
