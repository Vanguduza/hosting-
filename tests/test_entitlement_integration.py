"""Plan admission, operator authority and queued execution on disposable PostgreSQL."""
import http.client
import json
import os
import sys
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/api'))
sys.path.insert(0, str(ROOT / 'tools'))
from hosting_api.__main__ import Handler
from hosting_api.migrate import apply, verify
from hosting_api.openapi import document
from hosting_api.worker import claim as release_claim
from hosting_api.postgres_jobs import claim as postgres_claim
from hosting_api.valkey_jobs import claim as valkey_claim
from hosting_api.storage_jobs import claim as storage_claim
from hosting_api.registration import handle as registration
from github_build_worker import claim as build_claim
from set_entitlement import FEATURES, assign, enable
from set_quota import set_quota
from entitlement_health import inspect as inspect_entitlements
from registration_operator import quote, start


@unittest.skipUnless(os.environ.get('TEST_ADMIN_DSN'), 'requires disposable PostgreSQL')
class EntitlementIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_dsn = os.environ['TEST_ADMIN_DSN']
        params = conninfo_to_dict(cls.server_dsn)
        if params.get('host') not in ('localhost', '127.0.0.1', '::1'):
            raise RuntimeError('Entitlement tests require a local disposable server')
        cls.database = 'hosting_entitlement_ci_' + uuid.uuid4().hex
        with psycopg.connect(cls.server_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(cls.database)))
        cls.admin_dsn = make_conninfo(cls.server_dsn, dbname=cls.database)
        cls.api_dsn = make_conninfo(os.environ['TEST_API_DSN'], dbname=cls.database)
        cls.worker_dsn = make_conninfo(os.environ['TEST_WORKER_DSN'], dbname=cls.database)
        cls.build_dsn = make_conninfo(os.environ['TEST_BUILDWORKER_DSN'], dbname=cls.database)
        with psycopg.connect(cls.admin_dsn) as conn:
            apply(conn)
            verify(conn)

    @classmethod
    def tearDownClass(cls):
        with psycopg.connect(cls.server_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(cls.database)))

    def setUp(self):
        self.org, self.project, self.app, self.node = (uuid.uuid4() for _ in range(4))
        self.owner = 'owner-' + uuid.uuid4().hex
        self.handler = object.__new__(Handler)
        self.image = 'registry.example.test/entitlements/web@sha256:' + 'a'*64
        with self.admin() as conn:
            conn.execute('UPDATE hosting.nodes SET enabled=false,public_ipv4=NULL')
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'entitlement tests')", (self.org,))
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,'owner')", (self.org, self.owner))
            conn.execute("INSERT INTO hosting.nodes(id,endpoint,server_name,enabled,cpu_milli,memory_mb,observed_at,public_ipv4) "
                         "VALUES (%s,%s,%s,true,32000,65536,now(),'8.8.8.8')", (self.node, 'https://node-'+self.node.hex+'.test:8443', 'node-'+self.node.hex+'.test'))
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                         "VALUES (%s,%s,%s,'test-policy','{}'::jsonb) ON CONFLICT DO NOTHING", (self.image, 'b'*64, 'c'*40))
        self.current = self.plan()
        with self.admin() as conn:
            assign(conn, self.current, 'test-operator')
            conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'first project')", (self.project, self.org))
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) "
                         "VALUES (%s,%s,%s,'production','first app')", (self.app, self.org, self.project))
            conn.execute("INSERT INTO hosting.domains(organization_id,application_id,hostname,verification_token,verified_at) "
                         "VALUES (%s,%s,%s,%s,now())", (self.org, self.app, uuid.uuid4().hex + '.com', 'a'*43))

    def tearDown(self):
        # Keep other test tenants/history, but prevent their queues from claiming.
        with self.admin() as conn:
            for table in ('jobs','postgres_jobs','valkey_jobs','object_storage_jobs'):
                conn.execute('UPDATE hosting.' + table + " SET state='FAILED',lease_until=NULL WHERE organization_id=%s AND state IN ('PENDING','RUNNING')", (self.org,))
            conn.execute("UPDATE hosting.github_builds SET state='FAILED',lease_until=NULL WHERE source_id IN "
                         '(SELECT id FROM hosting.git_sources WHERE organization_id=%s)', (self.org,))

    def admin(self):
        return psycopg.connect(self.admin_dsn, row_factory=dict_row)

    @contextmanager
    def api(self, actor=None, kind='human'):
        with psycopg.connect(self.api_dsn, row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (actor or self.owner,))
            conn.execute("SELECT set_config('hosting.auth_kind',%s,true)", (kind,))
            yield conn

    def plan(self, **changes):
        now = datetime.now(timezone.utc)
        return {'id': str(uuid.uuid4()), 'organization_id': str(self.org), 'plan_ref': 'plan://hosting-ci',
                'evidence_ref': 'entitlement://private-assignment', 'features': sorted(FEATURES),
                'cpu_milli_limit': 4000, 'memory_mb_limit': 8192, 'project_limit': 2, 'application_limit': 3,
                'domain_limit': 3, 'registration_limit': 2, 'valid_from': (now-timedelta(minutes=1)).isoformat(),
                'valid_until': (now+timedelta(days=1)).isoformat(), **changes}

    def replace(self, **changes):
        self.current = self.plan(**changes)
        with self.admin() as conn:
            return assign(conn, self.current, 'test-operator')

    def queue(self, kind, body=None):
        body = body or {'idempotency_key': str(uuid.uuid4()), 'memory_mb': 512, 'cpu_milli': 100}
        if kind == 'releases':
            body = {**body, 'image': self.image, 'port': 8080, 'health_path': '/health'}
        with self.api() as conn:
            return getattr(self.handler, kind)(conn, self.org, self.app, self.owner, body, 'POST', uuid.uuid4())

    def readback(self, actor=None, kind='human'):
        with self.api(actor, kind) as conn:
            return conn.execute('SELECT hosting.entitlement_readback(%s) AS result', (self.org,)).fetchone()['result']

    def test_assignment_history_idempotency_and_transactional_audit(self):
        with self.admin() as conn:
            before = conn.execute('SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s', (self.org,)).fetchone()['n']
            self.assertTrue(assign(conn, self.current, 'test-operator')['replayed'])
            with self.assertRaisesRegex(ValueError, 'idempotency conflict'):
                assign(conn, {**self.current, 'cpu_milli_limit': 5000}, 'test-operator')
            self.assertEqual(conn.execute('SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s', (self.org,)).fetchone()['n'], before)
        old = self.current
        self.replace(plan_ref='plan://hosting-upgraded')
        with self.admin() as conn:
            self.assertFalse(assign(conn, old, 'test-operator')['current'])
            self.assertEqual(conn.execute('SELECT version_id FROM hosting.organization_entitlements WHERE organization_id=%s', (self.org,)).fetchone()['version_id'], uuid.UUID(self.current['id']))
            for statement in ("UPDATE hosting.entitlement_versions SET plan_ref='plan://forged' WHERE organization_id=%s",
                              'DELETE FROM hosting.organization_entitlements WHERE organization_id=%s'):
                with conn.transaction():
                    with self.assertRaises(psycopg.errors.RaiseException):
                        with conn.transaction():
                            conn.execute(statement, (self.org,))
            events = conn.execute('SELECT a.id,a.previous_hash,a.event_hash,e.audit_event_id FROM hosting.audit_events a '
                                  'JOIN hosting.event_outbox e ON e.audit_event_id=a.id WHERE a.organization_id=%s ORDER BY a.id', (self.org,)).fetchall()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]['previous_hash'], events[0]['event_hash'])
            conn.execute("SELECT set_config('hosting.entitlement_operator','test-operator',true)")
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'revision must advance'):
                conn.execute('UPDATE hosting.organization_entitlements SET version_id=%s WHERE organization_id=%s', (old['id'], self.org))

    def test_plan_changes_cannot_remove_reserved_capacity_or_lower_existing_counts(self):
        self.assertEqual(self.queue('postgres')[0], 202)
        for changes in ({'memory_mb_limit': 256}, {'cpu_milli_limit': 50}, {'project_limit': 0}, {'application_limit': 0}, {'domain_limit': 0}):
            candidate = self.plan(**changes)
            with self.admin() as conn:
                with self.assertRaises(psycopg.errors.RaiseException):
                    assign(conn, candidate, 'test-operator')
            with self.admin() as conn:
                self.assertIsNone(conn.execute('SELECT id FROM hosting.entitlement_versions WHERE id=%s', (candidate['id'],)).fetchone())
                self.assertEqual(conn.execute('SELECT version_id FROM hosting.organization_entitlements WHERE organization_id=%s', (self.org,)).fetchone()['version_id'], uuid.UUID(self.current['id']))

    def test_database_tenant_authority_and_public_contract(self):
        data = self.readback()
        schema = document()['paths']['/v1/organizations/{organization_id}/entitlements']['get']['responses']['200']['content']['application/json']['schema']
        Draft202012Validator(schema).validate(data)
        self.assertEqual(data['status'], 'ACTIVE')
        self.assertNotIn('evidence_ref', json.dumps(data))
        self.assertIsNone(self.readback('foreign-owner'))
        self.assertIsNone(self.readback(kind='service'))
        with self.admin() as conn:
            for role in ('admin','viewer'):
                conn.execute('INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,%s)', (self.org, role, role))
        for role in ('admin','viewer'):
            self.assertEqual(self.readback(role)['version']['id'], self.current['id'])
        for dsn in (self.api_dsn, self.worker_dsn, self.build_dsn):
            with psycopg.connect(dsn, row_factory=dict_row) as conn:
                with self.assertRaises(PermissionError):
                    assign(conn, self.current, 'forged')
                with self.assertRaises(PermissionError):
                    inspect_entitlements(conn)
            with psycopg.connect(dsn) as conn:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    conn.execute('SELECT * FROM hosting.entitlement_versions')
            with psycopg.connect(dsn) as conn:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    conn.execute('UPDATE hosting.entitlement_policy SET require_assigned=false')

    def test_feature_denial_and_capacity_failure_roll_back_node_jobs_and_audit(self):
        self.replace(features=['domain'])
        with self.admin() as conn:
            before = conn.execute('SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s', (self.node,)).fetchone()
        for kind in ('releases','postgres','valkey','storage'):
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'entitlement_unavailable'):
                self.queue(kind)
        self.replace(cpu_milli_limit=100, memory_mb_limit=512)
        self.assertEqual(self.queue('postgres')[0], 202)
        # Independently prove CPU and memory denial after enlarging the quota.
        for cpu,memory in ((100,2048),(200,512)):
            self.replace(cpu_milli_limit=cpu,memory_mb_limit=memory)
            with self.admin() as conn:
                set_quota(conn, self.org, 10000, 20000, 'quota-operator', 'Capacity check independent of the plan')
                audit_before = conn.execute('SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s', (self.org,)).fetchone()['n']
                node_before = conn.execute('SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s', (self.node,)).fetchone()
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'entitlement_limit_exceeded'):
                self.queue('valkey')
            with self.admin() as conn:
                self.assertEqual(conn.execute('SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s', (self.node,)).fetchone(), node_before)
                self.assertEqual(conn.execute('SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s', (self.org,)).fetchone()['n'], audit_before)
                self.assertEqual(conn.execute('SELECT count(*) AS n FROM hosting.valkey_jobs WHERE organization_id=%s', (self.org,)).fetchone()['n'], 0)
                self.assertEqual(conn.execute('SELECT count(*) AS n FROM hosting.capacity_intervals WHERE organization_id=%s', (self.org,)).fetchone()['n'], 1)
        self.assertEqual(before['reserved_cpu_milli'], 0)

    def test_project_admission_race_counts_exactly_one_remaining_slot(self):
        barrier = threading.Barrier(2)
        def insert():
            try:
                with self.api() as conn:
                    barrier.wait(timeout=5)
                    conn.execute('INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,%s)', (uuid.uuid4(), self.org, uuid.uuid4().hex))
                return 'admitted'
            except psycopg.errors.RaiseException as error:
                return error.diag.message_primary
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: insert(), range(2)))
        self.assertCountEqual(results, ['admitted', 'entitlement_limit_exceeded'])
        self.assertEqual(self.readback()['usage']['projects'], 2)

    def test_plan_change_serializes_with_an_admission_waiting_on_the_tenant(self):
        with self.admin() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,7))',(str(self.org),))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(self.queue,'postgres')
                waiting=False
                for _ in range(200):
                    waiting=conn.execute("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted) AS waiting").fetchone()['waiting']
                    if waiting: break
                    time.sleep(0.01)
                if not waiting:
                    conn.rollback()
                    self.fail('Admission did not wait for the tenant policy lock')
                try:
                    assign(conn,self.plan(features=['domain']),'test-operator')
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
                with self.assertRaisesRegex(psycopg.errors.RaiseException,'entitlement_unavailable'):
                    future.result(timeout=5)
        with self.admin() as conn:
            self.assertEqual(conn.execute('SELECT count(*) AS n FROM hosting.postgres_instances WHERE organization_id=%s',(self.org,)).fetchone()['n'],0)
            self.assertEqual(conn.execute('SELECT reserved_cpu_milli FROM hosting.nodes WHERE id=%s',(self.node,)).fetchone()['reserved_cpu_milli'],0)

    def test_application_domain_and_registration_count_limits(self):
        self.replace(application_limit=1,domain_limit=1,registration_limit=0)
        with self.api() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException,'entitlement_limit_exceeded'):
                conn.execute("INSERT INTO hosting.applications(organization_id,project_id,environment,name) VALUES (%s,%s,'staging','blocked')",(self.org,self.project))
        with self.api() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException,'entitlement_limit_exceeded'):
                registration(self.handler,conn,self.org,self.owner,{'idempotency_key':str(uuid.uuid4()),
                    'hostname':uuid.uuid4().hex+'.com','term_years':1,'registrant_ref':'registrant://ci'},'POST')
        self.replace(application_limit=2,domain_limit=1)
        other_app=uuid.uuid4()
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) VALUES (%s,%s,%s,'staging','second')",(other_app,self.org,self.project))
        with self.api() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException,'entitlement_limit_exceeded'):
                conn.execute('INSERT INTO hosting.domains(organization_id,application_id,hostname,verification_token) VALUES (%s,%s,%s,%s)',(self.org,other_app,uuid.uuid4().hex+'.com','a'*43))

    def test_capacity_readback_preserves_full_integer_precision(self):
        self.replace(cpu_milli_limit=2**63-1,memory_mb_limit=2**63-1)
        data=self.readback()
        self.assertEqual(data['version']['cpu_milli_limit'],str(2**63-1))
        self.assertEqual(data['version']['memory_mb_limit'],str(2**63-1))

    def test_expiry_blocks_new_admission_but_keeps_idempotent_readback(self):
        body = {'idempotency_key': str(uuid.uuid4()), 'memory_mb': 512, 'cpu_milli': 100}
        _, created = self.queue('postgres', body)
        # PostgreSQL transaction time is fixed; waiting inside a transaction
        # would expose implementations incorrectly using now() for expiry.
        self.replace(valid_until=(datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat())
        with self.admin() as conn:
            conn.execute('SELECT pg_sleep(1.1)')
            self.assertFalse(conn.execute("SELECT hosting.entitlement_permits(%s,'valkey') AS ok", (self.org,)).fetchone()['ok'])
            self.assertIn(str(self.org),inspect_entitlements(conn)['expired'])
        self.assertEqual(self.readback()['status'], 'EXPIRED')
        status, replay = self.queue('postgres', body)
        self.assertEqual((status, replay['id'], replay['replayed']), (200, created['id'], True))
        with self.assertRaisesRegex(psycopg.errors.RaiseException, 'entitlement_unavailable'):
            self.queue('valkey')

    def test_all_resource_workers_hold_without_attempts_and_resume_after_renewal(self):
        jobs = []
        for kind, table, claim in (('releases','jobs',release_claim), ('postgres','postgres_jobs',postgres_claim),
                                  ('valkey','valkey_jobs',valkey_claim), ('storage','object_storage_jobs',storage_claim)):
            status, receipt = self.queue(kind)
            self.assertEqual(status, 202)
            jobs.append((table, claim, receipt['job_id']))
        self.replace(features=['domain'])
        for table, claim, job in jobs:
            with psycopg.connect(self.worker_dsn, row_factory=dict_row) as conn:
                self.assertIsNone(claim(conn))
            with self.admin() as conn:
                held = conn.execute('SELECT state,attempts,last_error,next_attempt_at>now() AS delayed FROM hosting.' + table + ' WHERE id=%s', (job,)).fetchone()
                self.assertEqual((held['state'], held['attempts'], held['last_error'], held['delayed']), ('PENDING', 0, 'entitlement_unavailable', True))
        self.replace()
        for table, claim, job in jobs:
            with self.admin() as conn:
                conn.execute('UPDATE hosting.' + table + ' SET next_attempt_at=now() WHERE id=%s', (job,))
            with psycopg.connect(self.worker_dsn, row_factory=dict_row) as conn:
                claimed = claim(conn)
                self.assertEqual(claimed[0]['id'], job)
                self.assertEqual(claimed[-1], 1)

    def test_builder_rechecks_plan_and_preserves_delivery_identity(self):
        source, delivery = uuid.uuid4(), uuid.uuid4()
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.git_sources(id,organization_id,application_id,repository_id,full_name,branch,image_repository,builder,policy_revision) "
                         "VALUES (%s,%s,%s,123,'ci/entitlements','main','registry.example.test/ci/web','ci-builder','ci-policy')", (source, self.org, self.app))
            conn.execute('INSERT INTO hosting.github_builds(delivery_id,source_id,source_commit) VALUES (%s,%s,%s)', (delivery, source, 'a'*40))
        self.replace(features=['domain'])
        with psycopg.connect(self.build_dsn, row_factory=dict_row) as conn:
            self.assertIsNone(build_claim(conn))
        with self.admin() as conn:
            self.assertEqual(conn.execute('SELECT attempts FROM hosting.github_builds WHERE delivery_id=%s', (delivery,)).fetchone()['attempts'], 0)
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'entitlement_unavailable'):
                conn.execute('INSERT INTO hosting.github_builds(delivery_id,source_id,source_commit) VALUES (%s,%s,%s)', (uuid.uuid4(), source, 'b'*40))
        self.replace()
        with self.admin() as conn:
            conn.execute('UPDATE hosting.github_builds SET next_attempt_at=now() WHERE delivery_id=%s', (delivery,))
        with psycopg.connect(self.build_dsn, row_factory=dict_row) as conn:
            self.assertEqual(build_claim(conn)[0]['delivery_id'], delivery)

    def test_expired_running_lease_holds_and_reclaims_the_same_operation(self):
        _, queued = self.queue('postgres')
        with psycopg.connect(self.worker_dsn,row_factory=dict_row) as conn:
            first = postgres_claim(conn)
            self.assertEqual(first[-1],1)
        self.replace(features=['domain'])
        with self.admin() as conn:
            conn.execute("UPDATE hosting.postgres_jobs SET lease_until=now()-interval '1 second' WHERE id=%s",(queued['job_id'],))
        with psycopg.connect(self.worker_dsn,row_factory=dict_row) as conn:
            self.assertIsNone(postgres_claim(conn))
        with self.admin() as conn:
            row=conn.execute('SELECT attempts,state FROM hosting.postgres_jobs WHERE id=%s',(queued['job_id'],)).fetchone()
            self.assertEqual((row['attempts'],row['state']),(1,'PENDING'))
        self.replace()
        with self.admin() as conn:
            conn.execute('UPDATE hosting.postgres_jobs SET next_attempt_at=now() WHERE id=%s',(queued['job_id'],))
        with psycopg.connect(self.worker_dsn,row_factory=dict_row) as conn:
            resumed=postgres_claim(conn)
            self.assertEqual((resumed[1]['id'],resumed[-1]),(first[1]['id'],2))
            self.assertIsNone(conn.execute('SELECT last_error FROM hosting.postgres_jobs WHERE id=%s',(queued['job_id'],)).fetchone()['last_error'])

    def test_registration_purchase_start_rechecks_feature_without_consuming_consent(self):
        with self.api() as conn:
            _, requested = registration(self.handler, conn, self.org, self.owner,
                {'idempotency_key':str(uuid.uuid4()), 'hostname':uuid.uuid4().hex+'.com', 'term_years':1,
                 'registrant_ref':'registrant://ci-customer'}, 'POST')
        with self.admin() as conn:
            quoted = quote(conn, self.org, requested['id'], uuid.uuid4(), 'test-operator', registrar='Test registrar',
                amount_minor=2000, renewal_minor=2000, currency='USD', expires_at=datetime.now(timezone.utc)+timedelta(hours=1),
                terms_text='One-year registration with separate renewal consent.', provider_quote_ref='quote://ci')
        with self.api() as conn:
            self.assertEqual(registration(self.handler, conn, self.org, self.owner,
                {'quote_id':str(quoted['id']), 'quote_sha256':quoted['sha256'], 'confirm':'approve_registration_quote'},
                'POST','approve',requested['id'])[1]['state'], 'APPROVED')
        operation = uuid.uuid4()
        self.replace(features=['domain'])
        with self.admin() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'entitlement_unavailable'):
                start(conn, self.org, requested['id'], quoted['id'], operation, 'test-operator', 'payment://ci')
        with self.admin() as conn:
            self.assertEqual(conn.execute('SELECT state FROM hosting.domain_registration_requests WHERE id=%s', (requested['id'],)).fetchone()['state'], 'APPROVED')
        self.replace()
        with self.admin() as conn:
            self.assertEqual(start(conn, self.org, requested['id'], quoted['id'], operation, 'test-operator', 'payment://ci')['state'], 'PROCESSING')

    def test_http_maps_plan_denial_to_conflict_and_scopes_readback(self):
        self.replace(features=['domain'])
        server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        server.jwks = object()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        identity = SimpleNamespace(sub=self.owner, client_id=None, issuer=None)
        path = '/v1/organizations/' + str(self.org)
        def request(method, suffix, body=None):
            conn = http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            try:
                conn.request(method, path+suffix, body=json.dumps(body) if body else None,
                             headers={'Authorization':'Bearer fixture', 'Content-Type':'application/json'})
                response = conn.getresponse()
                return response.status, json.loads(response.read())
            finally:
                conn.close()
        try:
            with patch('hosting_api.__main__.database_dsn',return_value=self.api_dsn), patch('hosting_api.__main__.authenticate',return_value=identity):
                self.assertEqual(request('GET','/entitlements')[0],200)
                self.assertEqual(request('POST','/applications/'+str(self.app)+'/postgres',
                    {'idempotency_key':str(uuid.uuid4()),'memory_mb':512,'cpu_milli':100}), (409,{'error':'entitlement_unavailable'}))
                identity.client_id = 'machine'
                self.assertEqual(request('GET','/entitlements'),(404,{'error':'not_found'}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_zz_one_way_required_mode_rejects_missing_assignment(self):
        unassigned = uuid.uuid4()
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'unassigned')", (unassigned,))
        with self.admin() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'All tenants require'):
                enable(conn,'test-operator','entitlement://production-enforcement')
        with self.admin() as conn:
            organizations = conn.execute('SELECT id FROM hosting.organizations').fetchall()
            for org in organizations:
                assign(conn,self.plan(organization_id=str(org['id']),cpu_milli_limit=32000,memory_mb_limit=65536,
                                     project_limit=100,application_limit=100,domain_limit=100,registration_limit=100),'test-operator')
            self.assertFalse(enable(conn,'test-operator','entitlement://production-enforcement')['replayed'])
            self.assertTrue(enable(conn,'test-operator','entitlement://production-enforcement')['replayed'])
            self.assertEqual(inspect_entitlements(conn)['state'],'ENFORCED')
        new_org = uuid.uuid4()
        with self.admin() as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'after enforcement')", (new_org,))
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,'owner')", (new_org,self.owner))
            self.assertIn(str(new_org),inspect_entitlements(conn)['unassigned'])
        with self.api() as conn:
            data = conn.execute('SELECT hosting.entitlement_readback(%s) AS result',(new_org,)).fetchone()['result']
            self.assertEqual((data['status'],data['requires_assignment']),('UNCONFIGURED',True))
            with self.assertRaisesRegex(psycopg.errors.RaiseException,'entitlement_unavailable'):
                conn.execute("INSERT INTO hosting.projects(organization_id,name) VALUES (%s,'blocked')",(new_org,))
        with self.admin() as conn:
            with self.assertRaisesRegex(psycopg.errors.RaiseException,'enabled once'):
                conn.execute('UPDATE hosting.entitlement_policy SET require_assigned=false')
