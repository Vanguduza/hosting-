"""Real PostgreSQL publisher isolation, immutable decisions and live validity checks."""
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
from hosting_api.__main__ import Handler,Identity
from hosting_api.intent_contract import validate as intent_digest
from hosting_api.partner_authority import handle,validate
from hosting_api.openapi import document
from partner_authority_source import register
from set_entitlement import FEATURES,assign


@unittest.skipUnless(os.environ.get('TEST_ADMIN_DSN'),'requires disposable PostgreSQL')
class PartnerAuthorityIntegration(unittest.TestCase):
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
        self.intent_id=uuid.UUID(self.intent['request_id'])
        now=datetime.now(timezone.utc)
        self.plan={'id':str(uuid.uuid4()),'organization_id':str(self.org),'plan_ref':'plan://authority-fixture',
            'evidence_ref':'entitlement://private-marker','features':sorted(FEATURES),'cpu_milli_limit':4000,
            'memory_mb_limit':8192,'project_limit':3,'application_limit':4,'domain_limit':4,'registration_limit':2,
            'valid_from':(now-timedelta(minutes=1)).isoformat(),'valid_until':(now+timedelta(days=1)).isoformat()}
        with self.admin() as conn: assign(conn,self.plan,'authority-test-operator')
        self.record()
        self.source={'id':str(uuid.uuid4()),'organization_id':str(self.org),'purpose':'partner-commercial-bindings-v1',
            'name':'fixture-publisher','issuer':'https://issuer.example.org','client_id':'partner-factory',
            'actor_sub':'publisher-subject','enabled':True,'max_validity_seconds':600,'evidence_ref':'authority://private-marker'}
        self.assertEqual(self.readback()[1]['state'],'UNCONFIGURED')
        self.install()
        self.receipt=self.decision()

    def install(self,source=None):
        with self.admin() as conn: return register(conn,source or self.source,'authority-test-operator')

    def decision(self,**patches):
        now=datetime.now(timezone.utc)-timedelta(seconds=1)
        return {'schema_version':'1.0','purpose':'partner-commercial-bindings-v1','id':str(uuid.uuid4()),
            'source_version_id':self.source['id'],'intent_sha256':intent_digest(self.intent),'sequence':1,
            'disposition':'AUTHORIZE','hosting_entitlement_version_id':self.plan['id'],
            'admin_bindings':[{'ref':ref,'actor_sub':self.admin_actor} for ref in self.intent['tenant_admin_refs']],
            'issued_at':now.isoformat(),'valid_until':(now+timedelta(minutes=5)).isoformat(),
            'evidence_ref':'partner-proof://private-marker',**patches}

    def publish(self,receipt=None,actor=None,client=None,issuer=None,kind='service',org=None,app=None,intent=None):
        with self.api(actor or self.source['actor_sub'],kind) as conn:
            conn.execute("SELECT set_config('hosting.service_client_id',%s,true)",(client or self.source['client_id'],))
            conn.execute("SELECT set_config('hosting.token_issuer',%s,true)",(issuer or self.source['issuer'],))
            return handle(conn,org or self.org,app or self.app,intent or self.intent_id,{'receipt':receipt or self.receipt},'POST')

    def readback(self,actor=None,kind='human',org=None,app=None,intent=None):
        with self.api(actor,kind) as conn: return handle(conn,org or self.org,app or self.app,intent or self.intent_id,{},'GET')

    def alter_source(self,**patches):
        previous=copy.deepcopy(self.source)
        self.source={**self.source,'id':str(uuid.uuid4()),**patches}
        self.install()
        return previous

    def test_registered_publisher_exact_bindings_redaction_and_no_provisioning(self):
        before=self.counts()
        self.assertEqual(self.readback()[1]['state'],'AWAITING_RECEIPT')
        status,ack=self.publish()
        self.assertEqual(status,201)
        self.assertEqual(ack,{'id':self.receipt['id'],'state':'RECORDED','sequence':'1','replayed':False})
        status,readback=self.readback()
        self.assertEqual(status,200);self.assertEqual(readback['state'],'ACTIVE')
        schema=document()['paths']['/v1/organizations/{organization_id}/applications/{application_id}/intents/{intent_id}/authority']['get']['responses']['200']['content']['application/json']['schema']
        Draft202012Validator(schema).validate(json.loads(json.dumps(readback,default=str)))
        for private in ('private-marker','publisher-subject','partner-factory',self.admin_actor,*self.intent['tenant_admin_refs']):
            self.assertNotIn(private,str(readback))
        # Historic observations are unchanged until a new explicit observation.
        original=self.request(method='GET',intent_id=self.intent_id)[1]['intent']['evaluation']['receipt']
        self.assertEqual(original['stages'][1]['state'],'BLOCKED')
        status,row=self.recheck()
        states={stage['stage']:stage['state'] for stage in row['evaluation']['receipt']['stages']}
        self.assertEqual((states['commercial_authority'],states['tenant_admin_bindings']),('MATCHED','MATCHED'))
        self.assertEqual(states['profile_qualification'],'BLOCKED');self.assertEqual(states['backups'],'BLOCKED')
        self.assertEqual(row['evaluation']['receipt']['state'],'NOT_QUALIFIED')
        self.assertFalse(row['evaluation']['receipt']['resource_mutations_performed'])
        after=self.counts()
        for table in ('releases','jobs','capacity_intervals','postgres_instances','valkey_instances','object_storage_instances'):
            self.assertEqual(before[table],after[table])
        self.assertEqual(after['audit_events']-before['audit_events'],2)
        self.assertEqual(after['event_outbox']-before['event_outbox'],2)

    def test_publisher_machine_purpose_and_tenant_isolation(self):
        for patches in ({'kind':'human','actor':self.owner},{'client':'release-bot'},{'actor':'other-publisher'},
                        {'issuer':'https://other.example.org'},{'org':uuid.uuid4()},{'app':uuid.uuid4()},{'intent':uuid.uuid4()}):
            with self.subTest(patches=patches):self.assertEqual(self.publish(**patches),(404,{'error':'not_found'}))
        self.publish()
        for patches in ({'actor':self.viewer},{'kind':'service','actor':self.source['actor_sub']},
                        {'org':uuid.uuid4()},{'app':uuid.uuid4()},{'intent':uuid.uuid4()}):
            with self.subTest(patches=patches):self.assertEqual(self.readback(**patches),(404,{'error':'not_found'}))

    def test_wrong_intent_plan_source_refs_and_non_admin_membership_rejected(self):
        for patches in ({'intent_sha256':'b'*64},{'source_version_id':str(uuid.uuid4())},
                        {'hosting_entitlement_version_id':str(uuid.uuid4())},
                        {'admin_bindings':[{'ref':'wrong-admin','actor_sub':self.admin_actor}]},
                        {'admin_bindings':[{'ref':self.intent['tenant_admin_refs'][0],'actor_sub':self.viewer}]},
                        {'admin_bindings':[{'ref':self.intent['tenant_admin_refs'][0],'actor_sub':'nonmember'}]}):
            with self.subTest(patches=patches),self.assertRaises(psycopg.errors.RaiseException):
                self.publish({**self.receipt,**patches})
        self.assertEqual(self.readback()[1]['state'],'AWAITING_RECEIPT')

    def test_idempotency_and_monotonic_decisions_with_persistent_revocation(self):
        self.publish()
        self.assertEqual(self.publish()[0],200)
        with self.assertRaises(psycopg.errors.RaiseException):self.publish({**self.receipt,'evidence_ref':'partner-proof://changed'})
        with self.assertRaises(psycopg.errors.RaiseException):self.publish(self.decision())
        revoked=self.decision(sequence=2,disposition='REVOKE',hosting_entitlement_version_id=None,admin_bindings=[],valid_until=None)
        self.publish(revoked);self.assertEqual(self.readback()[1]['state'],'REVOKED')
        self.publish();self.assertEqual(self.readback()[1]['state'],'REVOKED')
        self.publish(self.decision(sequence=3));self.assertEqual(self.readback()[1]['state'],'ACTIVE')

    def test_concurrent_duplicate_and_sequence_races_record_once(self):
        before=self.counts()
        with ThreadPoolExecutor(max_workers=4) as pool: replies=list(pool.map(lambda _:self.publish(),range(4)))
        self.assertEqual(sorted(reply[0] for reply in replies),[200,200,200,201])
        self.assertEqual(self.counts()['audit_events']-before['audit_events'],1)
        def race(receipt):
            try:return self.publish(receipt)[0]
            except psycopg.errors.RaiseException:return 409
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies=list(pool.map(race,[self.decision(sequence=2),self.decision(sequence=2)]))
        self.assertEqual(sorted(replies),[201,409])

    def test_source_replace_disable_reenable_and_old_replay_never_reactivate(self):
        self.publish();old=self.alter_source(name='reconfigured-publisher')
        self.assertEqual(self.readback()[1]['state'],'SOURCE_CHANGED')
        self.assertEqual(self.publish()[0],200)
        self.assertEqual(self.readback()[1]['state'],'SOURCE_CHANGED')
        self.assertFalse(self.install(old)['current'])
        self.alter_source(enabled=False)
        self.assertEqual(self.readback()[1]['state'],'SOURCE_DISABLED')
        self.assertEqual(self.publish()[0],404)
        self.alter_source(enabled=True)
        self.assertEqual(self.readback()[1]['state'],'SOURCE_CHANGED')
        self.publish(self.decision(sequence=2));self.assertEqual(self.readback()[1]['state'],'ACTIVE')
        self.alter_source(actor_sub='replacement-subject')
        with self.assertRaises(psycopg.errors.RaiseException):self.publish()
        self.assertEqual(self.publish(actor=old['actor_sub'])[0],404)

    def test_removing_or_downgrading_admin_invalidates_approval_without_grant(self):
        self.publish()
        with self.admin() as conn:conn.execute("UPDATE hosting.memberships SET role='viewer' WHERE organization_id=%s AND actor_sub=%s",(self.org,self.admin_actor))
        self.assertEqual(self.readback()[1]['state'],'ADMIN_UNBOUND')
        self.assertEqual(self.recheck()[1]['evaluation']['receipt']['stages'][3]['state'],'BLOCKED')
        with self.admin() as conn:conn.execute('DELETE FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s',(self.org,self.admin_actor))
        self.assertEqual(self.readback()[1]['state'],'ADMIN_UNBOUND')

    def test_plan_reassignment_requires_new_receipt(self):
        self.publish()
        self.plan={**self.plan,'id':str(uuid.uuid4())}
        with self.admin() as conn:assign(conn,self.plan,'authority-test-operator')
        self.assertEqual(self.readback()[1]['state'],'PLAN_CHANGED')
        self.publish();self.assertEqual(self.readback()[1]['state'],'PLAN_CHANGED')
        self.publish(self.decision(sequence=2));self.assertEqual(self.readback()[1]['state'],'ACTIVE')

    def test_expired_future_and_overlong_decisions_fail_closed(self):
        now=datetime.now(timezone.utc)
        for patches in ({'issued_at':(now+timedelta(seconds=30)).isoformat()},
                        {'issued_at':(now-timedelta(hours=1)).isoformat(),'valid_until':(now+timedelta(minutes=1)).isoformat()},
                        {'valid_until':(now+timedelta(hours=1)).isoformat()},
                        {'issued_at':(now-timedelta(minutes=1)).isoformat(),'valid_until':(now-timedelta(seconds=1)).isoformat()}):
            with self.subTest(patches=patches),self.assertRaises(psycopg.errors.RaiseException):self.publish({**self.receipt,**patches})
        # Short receipt expires without changing its immutable history.
        self.receipt=self.decision(valid_until=(now+timedelta(seconds=1)).isoformat())
        self.publish()
        with self.api() as conn:
            conn.execute('SELECT pg_sleep(1.1)')
            status,row=handle(conn,self.org,self.app,self.intent_id,{},'GET')
            self.assertEqual(row['state'],'EXPIRED')
        self.assertEqual(self.publish()[0],200)
        self.assertEqual(self.readback()[1]['state'],'EXPIRED')
        self.publish(self.decision(sequence=2));self.assertEqual(self.readback()[1]['state'],'ACTIVE')

    def test_db_tables_are_private_immutable_and_audits_rollback_atomically(self):
        self.publish()
        for table in ('partner_authority_sources','partner_authority_receipts'):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.api() as conn:conn.execute('SELECT * FROM hosting.'+table)
            for operation in ('UPDATE '+table+' SET payload=payload','DELETE FROM '+table):
                query=operation.replace('UPDATE ','UPDATE hosting.').replace('DELETE FROM ','DELETE FROM hosting.')+' WHERE organization_id=%s'
                with self.assertRaises(psycopg.errors.RaiseException),self.admin() as conn:conn.execute(query,(self.org,))
        with self.api() as conn,self.assertRaises(PermissionError):register(conn,self.source,'pretend-operator')
        before=self.counts()
        with self.admin() as conn:
            conn.execute("SELECT set_config('hosting.entitlement_operator','authority-test-operator',true)")
            new={**self.source,'id':str(uuid.uuid4())}
            conn.execute('INSERT INTO hosting.partner_authority_sources(id,organization_id,payload,issued_by) VALUES (%s,%s,%s,%s)',
                         (new['id'],self.org,Jsonb(new),'authority-test-operator'))
            conn.rollback()
        self.assertEqual(before,self.counts())
        with self.admin() as conn:
            for function in ('partner_intent_evidence','partner_intent_base_evidence_v1','partner_authority_readback','authority_admin_bound'):
                self.assertEqual(conn.execute('SELECT provolatile FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=\'hosting\' AND proname=%s',(function,)).fetchone()['provolatile'],'s')

    def test_plan_expiry_invalidates_an_unexpired_partner_receipt(self):
        now=datetime.now(timezone.utc)
        self.plan={**self.plan,'id':str(uuid.uuid4()),'valid_until':(now+timedelta(seconds=2)).isoformat()}
        with self.admin() as conn:assign(conn,self.plan,'authority-test-operator')
        self.receipt=self.decision()
        self.publish();self.assertEqual(self.readback()[1]['state'],'ACTIVE')
        with self.api() as conn:
            conn.execute('SELECT pg_sleep(2.1)')
            self.assertEqual(handle(conn,self.org,self.app,self.intent_id,{},'GET')[1]['state'],'PLAN_UNAVAILABLE')

    def test_pending_disable_serializes_with_publication_and_transaction_rollback(self):
        self.publish();before=self.counts()
        with self.api(self.source['actor_sub'],'service') as conn:
            conn.execute("SELECT set_config('hosting.service_client_id',%s,true)",(self.source['client_id'],))
            conn.execute("SELECT set_config('hosting.token_issuer',%s,true)",(self.source['issuer'],))
            handle(conn,self.org,self.app,self.intent_id,{'receipt':self.decision(sequence=2)},'POST')
            conn.rollback()
        self.assertEqual(self.counts(),before)
        disabled={**self.source,'id':str(uuid.uuid4()),'enabled':False}
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.admin() as conn:
                # Keep the source change pending in an outer transaction.
                conn.execute('SELECT 1')
                register(conn,disabled,'authority-test-operator')
                started=threading.Event()
                def publish_pending():
                    started.set()
                    return self.publish(self.decision(sequence=2))
                future=pool.submit(publish_pending)
                self.assertTrue(started.wait(5))
                self.assertFalse(future.done())
            self.assertEqual(future.result(timeout=5)[0],404)
        self.assertEqual(self.readback()[1]['state'],'SOURCE_DISABLED')
        self.assertEqual(self.counts()['audit_events']-before['audit_events'],1)

    def test_unicode_subject_canonical_hash_and_sql_contract_agree(self):
        self.alter_source(actor_sub='partner-雪')
        receipt=self.decision(admin_bindings=[{'ref':ref,'actor_sub':self.owner} for ref in self.intent['tenant_admin_refs']])
        self.publish(receipt)
        import hashlib
        with self.admin() as conn:
            row=conn.execute('SELECT payload_sha256 FROM hosting.partner_authority_sources WHERE id=%s',(self.source['id'],)).fetchone()
            expected=hashlib.sha256(json.dumps(self.source,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
            self.assertEqual(row['payload_sha256'],expected)
            for value,is_source in ((self.source,True),(receipt,False)):
                self.assertTrue(conn.execute('SELECT hosting.authority_valid(%s,%s) AS ok',(Jsonb(value),is_source)).fetchone()['ok'])
                for key in value:
                    bad={k:v for k,v in value.items() if k!=key}
                    self.assertFalse(conn.execute('SELECT hosting.authority_valid(%s,%s) AS ok',(Jsonb(bad),is_source)).fetchone()['ok'])
                    bad={**value,key:None}
                    self.assertFalse(conn.execute('SELECT hosting.authority_valid(%s,%s) AS ok',(Jsonb(bad),is_source)).fetchone()['ok'])

    def test_signed_machine_token_carries_verified_issuer_into_publisher_boundary(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from tests.test_auth import FakeJWKS
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.jwks=FakeJWKS(key.public_key())
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        path=f'/v1/organizations/{self.org}/applications/{self.app}/intents/{self.intent_id}/authority'
        now=int(datetime.now(timezone.utc).timestamp())
        claims={'iss':self.source['issuer'],'aud':'hosting-machine','sub':self.source['actor_sub'],
                'client_id':self.source['client_id'],'iat':now,'exp':now+300}
        def request(patches=None):
            signed=jwt.encode({**claims,**(patches or {})},key,algorithm='RS256',headers={'kid':'fixture'})
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            connection.request('POST',path,json.dumps({'receipt':self.receipt}),
                               {'Authorization':'Bearer '+signed,'Content-Type':'application/json'})
            response=connection.getresponse();status=response.status;response.read();connection.close();return status
        try:
            with patch.dict(os.environ,{'OIDC_ISSUER':self.source['issuer'],'OIDC_AUDIENCE':'hosting-human','OIDC_SERVICE_AUDIENCE':'hosting-machine'}),patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn):
                self.assertEqual(request(),201)
                self.assertEqual(request({'iss':'https://forged.example.org'}),401)
                self.assertEqual(request({'aud':['hosting-machine','hosting-human']}),401)
                self.assertEqual(request({'client_id':'release-bot'}),404)
                self.assertEqual(request({'sub':'different-publisher'}),404)
                self.assertEqual(request({'aud':'hosting-human','sub':self.owner}),404)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_http_machine_only_post_human_only_get_body_strictness(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.jwks=None
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        path=f'/v1/organizations/{self.org}/applications/{self.app}/intents/{self.intent_id}/authority'
        identity=Identity(self.source['actor_sub'],self.source['client_id'],self.source['issuer'])
        def request(method='POST',body=None,route=path,who=identity,headers=None):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            with patch('hosting_api.__main__.authenticate',return_value=who),patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn):
                connection.request(method,route,body=body if body is not None else json.dumps({'receipt':self.receipt}) if method=='POST' else None,
                    headers=headers or {'Authorization':'Bearer fixture','Content-Type':'application/json'})
                response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
        try:
            self.assertEqual(request()[0],201)
            self.assertEqual(request()[0],200)
            self.assertEqual(request(method='GET')[0],404)
            self.assertEqual(request(method='GET',who=Identity(self.owner))[1]['state'],'ACTIVE')
            self.assertEqual(request(who=Identity(self.owner))[0],404)
            self.assertEqual(request(route=path.removesuffix('/authority'))[0],404)
            self.assertEqual(request(body='{"receipt":{},"receipt":{}}')[0],400)
            self.assertEqual(request(body='x'*65537)[0],413)
            self.assertEqual(request(headers={'Content-Type':'text/plain'})[0],415)
            self.assertEqual(request(body=json.dumps({'receipt':{**self.receipt,'sequence':True}}))[0],400)
        finally:server.shutdown();server.server_close();thread.join(timeout=5)
