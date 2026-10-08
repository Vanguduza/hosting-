"""Immutable intent intake, RLS, authority boundaries and receipts on real PostgreSQL."""
import copy
import http.client
import json
import os
import sys
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
sys.path.insert(0,str(ROOT/'tools'))
from hosting_api.__main__ import Handler, Identity
from hosting_api.intent_contract import validate
from hosting_api.migrate import apply, verify
from hosting_api.openapi import document
from hosting_api.partner_intents import handle
from set_entitlement import FEATURES, assign
from tests.intent_fixtures import intent_fixture


@unittest.skipUnless(os.environ.get('TEST_ADMIN_DSN'),'requires disposable PostgreSQL')
class PartnerIntentIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_dsn = os.environ['TEST_ADMIN_DSN']
        if conninfo_to_dict(cls.server_dsn).get('host') not in ('localhost','127.0.0.1','::1'):
            raise RuntimeError('Intent tests require a local disposable server')
        cls.database = 'hosting_intent_ci_'+uuid.uuid4().hex
        with psycopg.connect(cls.server_dsn,autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(cls.database)))
        cls.admin_dsn = make_conninfo(cls.server_dsn,dbname=cls.database)
        cls.api_dsn = make_conninfo(os.environ['TEST_API_DSN'],dbname=cls.database)
        try:
            with psycopg.connect(cls.admin_dsn) as conn:
                apply(conn)
                verify(conn)
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        with psycopg.connect(cls.server_dsn,autocommit=True) as conn:
            conn.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(cls.database)))

    def setUp(self):
        self.org,self.project,self.app,self.node = (uuid.uuid4() for _ in range(4))
        self.owner,self.admin_actor,self.viewer = ('subject-'+uuid.uuid4().hex for _ in range(3))
        self.handler = object.__new__(Handler)
        self.intent = intent_fixture(self.project,domain_intent={'hostname':uuid.uuid4().hex+'.example.org'})
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'intent tests')",(self.org,))
            for actor,role in ((self.owner,'owner'),(self.admin_actor,'admin'),(self.viewer,'viewer')):
                conn.execute('INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,%s)',(self.org,actor,role))
            conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'intent project')",(self.project,self.org))
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) VALUES (%s,%s,%s,'development','intent app')",(self.app,self.org,self.project))

    def admin(self):
        return psycopg.connect(self.admin_dsn,row_factory=dict_row)

    @contextmanager
    def api(self,actor=None,kind='human'):
        with psycopg.connect(self.api_dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)",(actor or self.owner,))
            conn.execute("SELECT set_config('hosting.auth_kind',%s,true)",(kind,))
            yield conn

    def request(self,body=None,method='POST',intent_id=None,reconcile=False,actor=None,app=None,org=None,kind='human'):
        with self.api(actor,kind) as conn:
            return handle(self.handler,conn,org or self.org,app or self.app,actor or self.owner,
                          body if body is not None else {'intent':self.intent},method,intent_id,reconcile)

    def record(self):
        status,body = self.request()
        self.assertEqual(status,201)
        return body['intent']

    def recheck(self,key=None,**kwargs):
        return self.request({'idempotency_key':str(key or uuid.uuid4())},intent_id=uuid.UUID(self.intent['request_id']),reconcile=True,**kwargs)

    def counts(self):
        tables = ('partner_intents','partner_intent_evaluations','releases','jobs','capacity_intervals','postgres_instances',
                  'valkey_instances','object_storage_instances','audit_events','event_outbox')
        with self.admin() as conn:
            return {table:conn.execute('SELECT count(*) AS n FROM hosting.'+table+' WHERE organization_id=%s',(self.org,)).fetchone()['n'] for table in tables}

    def healthy(self):
        now = datetime.now(timezone.utc)
        plan = {'id':str(uuid.uuid4()),'organization_id':str(self.org),'plan_ref':'plan://intent-ci',
                'evidence_ref':'entitlement://private-proof','features':sorted(FEATURES),
                'cpu_milli_limit':4000,'memory_mb_limit':8192,'project_limit':3,'application_limit':4,
                'domain_limit':4,'registration_limit':2,'valid_from':(now-timedelta(minutes=1)).isoformat(),
                'valid_until':(now+timedelta(days=1)).isoformat()}
        self.release = uuid.uuid4()
        with self.admin() as conn:
            assign(conn,plan,'intent-test-operator')
            conn.execute("INSERT INTO hosting.nodes(id,endpoint,server_name,enabled,cpu_milli,memory_mb,observed_at) VALUES (%s,%s,%s,true,32000,65536,now())",
                         (self.node,'https://node-'+self.node.hex+'.test:8443','node-'+self.node.hex+'.test'))
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) VALUES (%s,%s,%s,'intent-test','{}'::jsonb) ON CONFLICT DO NOTHING",
                         (self.intent['release_artifact_ref'],'b'*64,'c'*40))
            conn.execute("INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,idempotency_key,image,port,health_path,memory_mb,cpu_milli,state) VALUES (%s,%s,%s,%s,%s,%s,%s,8080,'/health',256,250,'SERVING')",
                         (self.release,self.org,self.app,self.node,self.owner,uuid.uuid4(),self.intent['release_artifact_ref']))
            conn.execute('UPDATE hosting.applications SET active_release_id=%s WHERE id=%s',(self.release,self.app))
            conn.execute("INSERT INTO hosting.domains(organization_id,application_id,hostname,verification_token,verified_at) VALUES (%s,%s,%s,%s,now()-interval '1 minute')",
                         (self.org,self.app,self.intent['domain_intent']['hostname'],uuid.uuid4().hex+'a'*11))
            conn.execute("INSERT INTO hosting.release_health(release_id,organization_id,application_id,state,checked_at) VALUES (%s,%s,%s,'UP',now())",(self.release,self.org,self.app))

    def test_record_is_atomic_private_audited_and_does_not_provision(self):
        row = self.record()
        self.assertEqual(row['intent_sha256'],validate(self.intent))
        self.assertEqual(row['evaluation']['receipt']['state'],'NOT_QUALIFIED')
        counts = self.counts()
        self.assertEqual(counts['partner_intents'],1)
        self.assertEqual(counts['partner_intent_evaluations'],1)
        self.assertEqual(counts['audit_events'],2)
        self.assertEqual(counts['event_outbox'],2)
        for table in ('releases','jobs','capacity_intervals','postgres_instances','valkey_instances','object_storage_instances'):
            self.assertEqual(counts[table],0)
        with self.admin() as conn:
            facts = conn.execute('SELECT a.id,a.action,a.previous_hash,a.event_hash,e.audit_event_id FROM hosting.audit_events a JOIN hosting.event_outbox e ON e.audit_event_id=a.id WHERE a.organization_id=%s ORDER BY a.id',(self.org,)).fetchall()
            self.assertEqual([row['action'] for row in facts],['intent.recorded','intent.reconciled'])
            self.assertEqual(facts[1]['previous_hash'],facts[0]['event_hash'])
        for result in (row,self.request(method='GET')[1],self.request(method='GET',intent_id=uuid.UUID(self.intent['request_id']))[1]):
            for marker in ('partner-private-marker','business-private-marker','secret://','admin-private-marker','commercial-private-marker','requester-private-marker'):
                self.assertNotIn(marker,str(result))

    def test_submission_replay_conflict_and_concurrent_retries(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda _:self.request(),range(2)))
        self.assertEqual(sorted(status for status,_ in replies),[200,201])
        self.assertEqual(replies[0][1]['intent']['evaluation']['id'],replies[1][1]['intent']['evaluation']['id'])
        before = self.counts()
        self.assertEqual(self.request({'intent':{**self.intent,'template_version':'2.0'}})[0],409)
        self.assertEqual(self.request()[0],200)
        self.assertEqual(self.counts(),before)

    def test_reconciliation_replay_preserves_original_observation_and_new_key_advances(self):
        self.healthy()
        self.record()
        key = uuid.uuid4()
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda _:self.recheck(key),range(2)))
        self.assertEqual(sorted(status for status,_ in replies),[200,201])
        original = replies[0][1]['evaluation']
        self.assertEqual(original,replies[1][1]['evaluation'])
        self.assertEqual({x['stage']:x['state'] for x in original['receipt']['stages']}['release_health'],'OBSERVED_HEALTHY')
        with self.admin() as conn:
            conn.execute("UPDATE hosting.applications SET traffic_state='SUSPENDED' WHERE id=%s",(self.app,))
        self.assertEqual(self.recheck(key)[1]['evaluation'],original)
        new = self.recheck()[1]['evaluation']
        self.assertGreater(new['revision'],original['revision'])
        self.assertEqual({x['stage']:x['state'] for x in new['receipt']['stages']}['release_health'],'BLOCKED')
        self.assertEqual(new['receipt']['state'],'NOT_QUALIFIED')
        history = self.request(method='GET',intent_id=uuid.UUID(self.intent['request_id']))[1]
        self.assertEqual(len(history['evaluations']),3)
        self.assertEqual(history['intent']['evaluation']['id'],new['id'])

    def test_same_evaluation_key_for_different_intents_is_a_conflict_even_concurrently(self):
        first = uuid.UUID(self.intent['request_id'])
        self.record()
        second_intent = {**self.intent,'request_id':str(uuid.uuid4())}
        self.assertEqual(self.request({'intent':second_intent})[0],201)
        key = str(uuid.uuid4())
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda intent:self.request({'idempotency_key':key},intent_id=intent,reconcile=True),
                                    [first,uuid.UUID(second_intent['request_id'])]))
        self.assertEqual(sorted(status for status,_ in replies),[201,409])
        self.assertEqual(self.counts()['partner_intent_evaluations'],3)

    def test_readback_and_evidence_require_human_owner_or_admin_at_query_time(self):
        self.record()
        intent = uuid.UUID(self.intent['request_id'])
        self.assertEqual(self.request(method='GET',actor=self.admin_actor)[0],200)
        for actor,kind in ((self.viewer,'human'),('foreign-subject','human'),(self.owner,'service')):
            with self.subTest(actor=actor,kind=kind):
                self.assertEqual(self.request(method='GET',actor=actor,kind=kind)[0],404)
                with self.api(actor,kind) as conn:
                    self.assertEqual(conn.execute('SELECT * FROM hosting.partner_intents').fetchall(),[])
                    self.assertEqual(conn.execute('SELECT * FROM hosting.partner_intent_evaluations').fetchall(),[])
                    self.assertIsNone(conn.execute('SELECT hosting.partner_intent_evidence(%s,%s,%s) AS e',(self.org,self.app,intent)).fetchone()['e'])
        with self.admin() as conn:
            conn.execute('DELETE FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s',(self.org,self.admin_actor))
        self.assertEqual(self.request(method='GET',actor=self.admin_actor)[0],404)

    def test_tenant_application_project_environment_and_request_binding(self):
        before = self.counts()
        self.assertEqual(self.request(app=uuid.uuid4())[0],404)
        self.assertEqual(self.request(org=uuid.uuid4())[0],404)
        for change in ({'project_id':str(uuid.uuid4())},{'environment_profile':'production'}):
            with self.subTest(change=change),self.assertRaisesRegex(psycopg.errors.RaiseException,'intent_binding_conflict'):
                self.request({'intent':{**self.intent,**change}})
        self.assertEqual(self.counts(),before)
        self.record()
        self.assertEqual(self.request(method='GET',intent_id=uuid.uuid4())[0],404)
        self.assertEqual(self.recheck(app=uuid.uuid4())[0],404)

    def test_database_rejects_untyped_payload_and_actor_spoofing(self):
        for change in ({'secret_refs':['plaintext-password']},{'resource_budget':{'cpu_milli':100.0,'memory_mb':256}},
                       {'domain_intent':{'hostname':'app.internal'}},{'requested_by':None},{'requested_by':'invalid\n'},
                       {'tenant_admin_refs':[]},{'tenant_admin_refs':['same','same']},{'schema_version':None}):
            invalid = {**self.intent,**change}
            with self.subTest(change=change),self.api() as conn:
                self.assertFalse(conn.execute('SELECT hosting.intent_valid(%s) AS valid',(Jsonb(invalid),)).fetchone()['valid'])
                with self.assertRaises(psycopg.errors.CheckViolation):
                    conn.execute('INSERT INTO hosting.partner_intents(organization_id,application_id,id,payload,submitted_by) VALUES (%s,%s,%s,%s,%s)',
                                 (self.org,self.app,self.intent['request_id'],Jsonb(invalid),self.owner))
        with self.api() as conn,self.assertRaises(psycopg.errors.InsufficientPrivilege):
            conn.execute('INSERT INTO hosting.partner_intents(organization_id,application_id,id,payload,submitted_by) VALUES (%s,%s,%s,%s,%s)',
                         (self.org,self.app,self.intent['request_id'],Jsonb(self.intent),self.viewer))
        self.assertEqual(self.counts()['partner_intents'],0)

    def test_database_prevents_receipt_qualification_transformation_and_wrong_digest(self):
        recorded = self.record()
        receipt = recorded['evaluation']['receipt']
        for change in ({'state':'QUALIFIED'},{'resource_mutations_performed':True},{'transformations':['smaller-plan']},
                       {'transformations':None},{'stages':[]},{'observed_at':'invalid'}, {'commercial_approved':True}):
            with self.subTest(change=change),self.api() as conn,self.assertRaises(psycopg.errors.CheckViolation):
                conn.execute('INSERT INTO hosting.partner_intent_evaluations(organization_id,application_id,intent_id,id,receipt,evaluated_by) VALUES (%s,%s,%s,%s,%s,%s)',
                             (self.org,self.app,self.intent['request_id'],uuid.uuid4(),Jsonb({**receipt,**change}),self.owner))
        with self.api() as conn,self.assertRaisesRegex(psycopg.errors.RaiseException,'intent_binding_conflict'):
            conn.execute('INSERT INTO hosting.partner_intent_evaluations(organization_id,application_id,intent_id,id,receipt,evaluated_by) VALUES (%s,%s,%s,%s,%s,%s)',
                         (self.org,self.app,self.intent['request_id'],uuid.uuid4(),Jsonb({**receipt,'intent_sha256':'b'*64}),self.owner))
        self.assertEqual(self.counts()['partner_intent_evaluations'],1)

    def test_history_is_immutable_even_for_the_protected_operator(self):
        self.record()
        for table,column in (('partner_intents','payload'),('partner_intent_evaluations','receipt')):
            for verb in ('UPDATE','DELETE'):
                statement = (f'UPDATE hosting.{table} SET {column}={column}' if verb=='UPDATE' else f'DELETE FROM hosting.{table}')+' WHERE organization_id=%s'
                with self.admin() as conn,self.assertRaisesRegex(psycopg.errors.RaiseException,'immutable'):
                    conn.execute(statement,(self.org,))
                with self.api() as conn,self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    conn.execute(statement,(self.org,))

    def test_evaluation_failure_rolls_back_parent_audit_and_outbox(self):
        before = self.counts()
        with patch('hosting_api.partner_intents.evaluate',side_effect=RuntimeError('injected evaluation failure')):
            with self.assertRaises(RuntimeError): self.request()
        self.assertEqual(self.counts(),before)
        self.assertEqual(self.request()[0],201)

    def test_real_snapshot_counts_old_release_and_cache_reservations(self):
        self.healthy()
        first = self.record()
        self.assertEqual({s['stage']:s['state'] for s in first['evaluation']['receipt']['stages']}['resource_budget'],'MATCHED')
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,idempotency_key,image,port,health_path,memory_mb,cpu_milli,state) VALUES (%s,%s,%s,%s,%s,%s,%s,8080,'/health',512,150,'SUPERSEDED')",
                         (uuid.uuid4(),self.org,self.app,self.node,self.owner,uuid.uuid4(),self.intent['release_artifact_ref']))
        self.assertEqual({s['stage']:s['state'] for s in self.recheck()[1]['evaluation']['receipt']['stages']}['resource_budget'],'MATCHED')
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.capacity_intervals(organization_id,application_id,resource_type,resource_id,node_id,cpu_milli,memory_mb,started_at,source) VALUES (%s,%s,'valkey',%s,%s,300,800,now(),'NEW')",
                         (self.org,self.app,uuid.uuid4(),self.node))
        status,body = self.recheck()
        self.assertEqual(status,201)
        self.assertEqual({s['stage']:s['state'] for s in body['evaluation']['receipt']['stages']}['resource_budget'],'BLOCKED')

    def test_public_http_contract_body_limits_duplicates_roles_and_history(self):
        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.jwks = None
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        base = f'/v1/organizations/{self.org}/applications/{self.app}/intents'
        def exchange(method,path,body=None,actor=None,kind='human',media='application/json'):
            def identity(header,_):
                if header!='Bearer test-identity': raise PermissionError()
                return Identity(actor or self.owner,'test-client' if kind=='service' else None)
            headers = {'Authorization':'Bearer test-identity','Content-Type':media}
            encoded = body if isinstance(body,str) else json.dumps(body) if body is not None else None
            with patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn),patch('hosting_api.__main__.authenticate',side_effect=identity):
                connection = http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
                connection.request(method,path,body=encoded,headers=headers)
                response = connection.getresponse()
                status,result = response.status,json.loads(response.read())
                connection.close()
                return status,result
        try:
            self.assertEqual(exchange('POST',base,{'intent':self.intent},media='text/plain')[0],415)
            duplicate = '{"intent":'+json.dumps(self.intent)+',"intent":'+json.dumps(self.intent)+'}'
            self.assertEqual(exchange('POST',base,duplicate)[0],400)
            self.assertEqual(exchange('POST',base,' '*65537)[0],413)
            self.assertEqual(exchange('POST',base,{'intent':self.intent},actor=self.viewer)[0],404)
            self.assertEqual(exchange('POST',base,{'intent':self.intent},kind='service')[0],404)
            self.assertEqual(exchange('POST',base,{'intent':{**self.intent,'environment_profile':'production'}})[0],409)
            paths = document()['paths']
            template = '/v1/organizations/{organization_id}/applications/{application_id}/intents'
            def valid(template,method,status,payload):
                wire = json.loads(json.dumps(payload,default=str))
                Draft202012Validator(paths[template][method]['responses'][str(status)]['content']['application/json']['schema']).validate(wire)
            status,body = exchange('POST',base,{'intent':self.intent})
            self.assertEqual(status,201); valid(template,'post',status,body)
            large = {**self.intent,'request_id':str(uuid.uuid4()),'secret_refs':['secret://'+('a'*120)+str(i)+'/key#1' for i in range(64)]}
            self.assertGreater(len(json.dumps({'intent':large})),8192)
            self.assertEqual(exchange('POST',base,{'intent':large})[0],201)
            status,body = exchange('GET',base)
            self.assertEqual(status,200); valid(template,'get',status,body)
            detail = base+'/'+self.intent['request_id']
            status,body = exchange('GET',detail)
            self.assertEqual(status,200); valid(template+'/{intent_id}','get',status,body)
            status,body = exchange('POST',detail+'/reconcile',{'idempotency_key':str(uuid.uuid4())})
            self.assertEqual(status,201); valid(template+'/{intent_id}/reconcile','post',status,body)
            self.assertEqual(exchange('GET',base,actor=self.viewer)[0],404)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
