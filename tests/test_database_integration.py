"""Runs against disposable PostgreSQL in CI; skipped without TEST_ADMIN_DSN."""
import os
import shutil
import hashlib
import hmac
import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
sys.path.insert(0, str(ROOT / "tools"))
from hosting_api.__main__ import Handler, record, audit_after, capacity_window
from hosting_api.worker import claim, finalize, sweep_retirements, sweep_failed, process_traffic_once
from hosting_api.postgres_jobs import claim as claim_postgres, finalize as finalize_postgres
from hosting_api.valkey_jobs import claim as claim_valkey, finalize as finalize_valkey
from hosting_api.storage_jobs import claim as claim_storage, finalize as finalize_storage
from hosting_api.github_webhook import Handler as HookHandler
from hosting_api.github_webhook import enqueue, parse_push, verify
from http.server import ThreadingHTTPServer
from github_build_worker import claim as claim_build, finalize as finalize_build
from hosting_api.migrate import apply as apply_migrations, verify as verify_migrations
import admit_image
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("TEST_ADMIN_DSN"), "requires disposable PostgreSQL")
class DatabaseIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ["TEST_ADMIN_DSN"]
        cls.api = os.environ["TEST_API_DSN"]
        cls.worker = os.environ["TEST_WORKER_DSN"]
        with psycopg.connect(cls.admin) as conn:
            assert apply_migrations(conn) == len(list((ROOT / "services/api/schema").glob("*.sql")))
            assert apply_migrations(conn) == 0
            verify_migrations(conn)
            cls.org_a, cls.org_b = uuid.uuid4(), uuid.uuid4()
            cls.project_a, cls.project_b = uuid.uuid4(), uuid.uuid4()
            cls.node = uuid.uuid4()
            cls.image = "registry.example.test/team/app@sha256:" + "a" * 64
            for org, project, actor in ((cls.org_a, cls.project_a, "alice"), (cls.org_b, cls.project_b, "bob")):
                conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,%s)", (org, actor))
                conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,'owner')", (org, actor))
                conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,%s)", (project, org, actor))
            conn.execute("INSERT INTO hosting.nodes(id,endpoint,server_name,enabled,cpu_milli,memory_mb,observed_at) "
                         "VALUES (%s,'https://10.0.0.2:8443','10.0.0.2',true,2000,4096,now())", (cls.node,))
            conn.execute("UPDATE hosting.nodes SET public_ipv4='8.8.8.8' WHERE id=%s", (cls.node,))
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                         "VALUES (%s,%s,%s,'test-policy','{}'::jsonb)", (cls.image, "b" * 64, "c" * 40))

    def test_schema_migration_history_detects_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "schema"
            shutil.copytree(ROOT / "services/api/schema", destination)
            target = destination / "011_build_release_ownership.sql"
            target.write_text(target.read_text() + "\n-- drift\n")
            with psycopg.connect(self.admin, autocommit=True) as conn:
                with self.assertRaisesRegex(RuntimeError, "history differs"):
                    apply_migrations(conn, destination)
                with self.assertRaisesRegex(RuntimeError, "differs from service image"):
                    verify_migrations(conn, destination)
                self.assertEqual(conn.execute("SELECT count(*) FROM hosting.schema_migrations").fetchone()[0],
                                 len(list(destination.glob("*.sql"))))

        for dsn in (self.api, self.worker, os.environ["TEST_HOOK_DSN"],
                    os.environ["TEST_BUILDWORKER_DSN"]):
            with psycopg.connect(dsn) as conn:
                verify_migrations(conn)
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    conn.execute("DELETE FROM hosting.schema_migrations")

    def test_failed_migration_rolls_back_schema_and_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "schema"
            shutil.copytree(ROOT / "services/api/schema", destination)
            (destination / "018_rollback_probe.sql").write_text(
                "CREATE TABLE hosting.rollback_probe(id integer);\n"
                "SELECT 1 / 0;\n", encoding="utf-8")
            with psycopg.connect(self.admin, autocommit=True) as conn:
                with self.assertRaises(psycopg.errors.DivisionByZero):
                    apply_migrations(conn, destination)
                self.assertIsNone(conn.execute("SELECT to_regclass('hosting.rollback_probe')").fetchone()[0])
                self.assertEqual(conn.execute("SELECT count(*) FROM hosting.schema_migrations").fetchone()[0], 17)
                verify_migrations(conn)

    def test_capacity_reservation_intervals_are_tenant_scoped_and_close_once(self):
        org, project, app, release, database = (uuid.uuid4() for _ in range(5))
        actor, viewer = "meter-owner-" + org.hex, "meter-viewer-" + org.hex
        start = datetime.now(timezone.utc)
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'meter-test')", (org,))
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) "
                         "VALUES (%s,%s,'owner'),(%s,%s,'viewer')", (org, actor, org, viewer))
            conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'meter')", (project, org))
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) "
                         "VALUES (%s,%s,%s,'production','meter')", (app, org, project))
            conn.execute("INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,"
                         "idempotency_key,image,port,health_path,memory_mb,cpu_milli) "
                         "VALUES (%s,%s,%s,%s,%s,%s,%s,8080,'/health',128,250)",
                         (release, org, app, self.node, actor, uuid.uuid4(), self.image))
            conn.execute("INSERT INTO hosting.postgres_instances(id,organization_id,application_id,node_id,"
                         "requested_by,idempotency_key,memory_mb,cpu_milli) "
                         "VALUES (%s,%s,%s,%s,%s,%s,512,500)",
                         (database, org, app, self.node, actor, uuid.uuid4()))
        time.sleep(.02)
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (actor,))
                conn.execute("SELECT set_config('hosting.auth_kind','human',true)")
                code, result = handler.capacity(conn, org, actor, (start, datetime.now(timezone.utc)))
                self.assertEqual(code, 200)
                amounts = {row["resource_type"]: row for row in result["allocations"]}
                self.assertEqual(set(amounts), {"release", "postgres"})
                self.assertEqual(amounts["release"]["reservations"], 1)
                self.assertGreater(amounts["release"]["reserved_cpu_milli_ms"], 0)
                self.assertGreater(amounts["postgres"]["reserved_memory_mb_ms"], 0)
                self.assertEqual(handler.capacity(conn, self.org_b, actor,
                                 (start, datetime.now(timezone.utc)))[0], 404)
                epoch = conn.execute("SELECT started_at FROM hosting.capacity_metering_epoch").fetchone()["started_at"]
                self.assertEqual(handler.capacity(conn, org, actor,
                                 (epoch - timedelta(seconds=1), epoch))[0], 409)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (viewer,))
                conn.execute("SELECT set_config('hosting.auth_kind','human',true)")
                self.assertEqual(handler.capacity(conn, org, viewer,
                                 (start, datetime.now(timezone.utc)))[0], 200)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (actor,))
                conn.execute("SELECT set_config('hosting.auth_kind','service',true)")
                self.assertEqual(conn.execute("SELECT count(*) FROM hosting.capacity_intervals").fetchone()["count"], 0)
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.releases SET state='FAILED',cleanup_at=now() WHERE id=%s", (release,))
            end = conn.execute("SELECT ended_at FROM hosting.capacity_intervals "
                               "WHERE resource_type='release' AND resource_id=%s", (release,)).fetchone()[0]
            self.assertIsNotNone(end)
            conn.execute("UPDATE hosting.releases SET cleanup_at=now() WHERE id=%s", (release,))
            self.assertEqual(conn.execute("SELECT ended_at FROM hosting.capacity_intervals "
                                          "WHERE resource_type='release' AND resource_id=%s",
                                          (release,)).fetchone()[0], end)
        with self.assertRaises(ValueError):
            capacity_window("from=2026-09-24T00:00:00Z&to=2026-09-23T00:00:00Z")

    def test_tenant_audit_readback_cursor_and_chain(self):
        org, resource = uuid.uuid4(), uuid.uuid4()
        owner, viewer = "audit-owner-" + org.hex, "audit-viewer-" + org.hex
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'audit-readback')", (org,))
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) "
                         "VALUES (%s,%s,'owner'),(%s,%s,'viewer')", (org, owner, org, viewer))
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (owner,))
                record(conn, org, owner, "audit.first", resource, uuid.uuid4())
                record(conn, org, owner, "audit.second", resource, uuid.uuid4())
                code, result = handler.audit(conn, org, owner, audit_after(""))
                self.assertEqual(code, 200)
                self.assertEqual([row["action"] for row in result["events"]],
                                 ["audit.first", "audit.second"])
                self.assertEqual(result["events"][0]["previous_hash"], "")
                first_id = result["events"][0]["id"]
                self.assertEqual([row["action"] for row in handler.audit(conn, org, owner, first_id)[1]["events"]],
                                 ["audit.second"])
                self.assertEqual(handler.audit(conn, self.org_b, owner, 0)[0], 404)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (viewer,))
                self.assertEqual(handler.audit(conn, org, viewer, 0)[0], 200)
        for invalid in ("after=-1", "after=01", "after=1&after=2", "other=3", "after=9223372036854775808"):
            with self.subTest(cursor=invalid), self.assertRaises(ValueError):
                audit_after(invalid)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            conn.execute("UPDATE hosting.audit_events SET event_hash=%s WHERE organization_id=%s AND id=%s",
                         ("0" * 64, org, first_id))
            with self.assertRaisesRegex(RuntimeError, "integrity"):
                handler.audit(conn, org, owner, 0)
            conn.rollback()

    def test_service_account_application_scope_and_revoke(self):
        app, other_app = uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(self.admin) as conn:
            for app_id in (app, other_app):
                conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) "
                             "VALUES (%s,%s,%s,'production',%s)",
                             (app_id, self.org_a, self.project_a, "service-" + app_id.hex[:12]))
                conn.execute("INSERT INTO hosting.domains(organization_id,application_id,hostname,"
                             "verification_token,verified_at) VALUES (%s,%s,%s,%s,now())",
                             (self.org_a, app_id, "svc-" + app_id.hex[:12] + ".example.org", "A" * 43))
        handler = Handler.__new__(Handler)
        client_id = "deploy-client-" + app.hex[:12]
        grant = {"application_id": str(app), "client_id": client_id, "actor_sub": "alice"}
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                conn.execute("SELECT set_config('hosting.auth_kind','human',true)")
                code, created = handler.service_accounts(conn, self.org_a, "alice", grant, "POST", uuid.uuid4())
                self.assertEqual(code, 201)
                account_id = created["id"]
                self.assertEqual(handler.service_accounts(conn, self.org_a, "alice", {}, "GET", uuid.uuid4())[0], 200)
        request = {"idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                   "health_path": "/health", "memory_mb": 128, "cpu_milli": 100}
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                conn.execute("SELECT set_config('hosting.auth_kind','service',true)")
                conn.execute("SELECT set_config('hosting.service_client_id',%s,true)", (client_id,))
                self.assertIsNone(handler.membership(conn, self.org_a, "alice"))
                self.assertEqual(conn.execute("SELECT count(*) FROM hosting.projects").fetchone()["count"], 0)
                self.assertEqual(handler.service_accounts(conn, self.org_a, "alice", {}, "GET", uuid.uuid4())[0], 404)
                self.assertEqual(handler.releases(conn, self.org_a, other_app, "alice", request,
                                                  "POST", uuid.uuid4())[0], 404)
                self.assertEqual(handler.releases(conn, self.org_b, app, "alice", request,
                                                  "POST", uuid.uuid4())[0], 404)
                self.assertEqual(handler.releases(conn, self.org_a, app, "alice", request,
                                                  "POST", uuid.uuid4())[0], 202)
                self.assertEqual(handler.releases(conn, self.org_a, app, "alice", request,
                                                  "POST", uuid.uuid4())[1]["replayed"], True)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                conn.execute("SELECT set_config('hosting.auth_kind','human',true)")
                self.assertEqual(handler.service_accounts(conn, self.org_a, "alice",
                                  {"id": str(account_id), "confirm": "revoke_service_account"},
                                  "POST", uuid.uuid4(), revoke=True)[0], 200)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                conn.execute("SELECT set_config('hosting.auth_kind','service',true)")
                conn.execute("SELECT set_config('hosting.service_client_id',%s,true)", (client_id,))
                self.assertEqual(handler.releases(conn, self.org_a, app, "alice", request,
                                                  "GET", uuid.uuid4())[0], 404)

    def test_application_suspension_and_verified_resume(self):
        org, project, app, release = (uuid.uuid4() for _ in range(4))
        owner, viewer = "traffic-owner-" + str(app), "traffic-viewer-" + str(app)
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'traffic-test')", (org,))
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) "
                         "VALUES (%s,%s,'owner'),(%s,%s,'viewer')", (org, owner, org, viewer))
            conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'traffic')", (project, org))
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name,active_release_id) "
                         "VALUES (%s,%s,%s,'production','traffic',%s)", (app, org, project, release))
            conn.execute("INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,"
                         "idempotency_key,image,port,health_path,memory_mb,cpu_milli,state) "
                         "VALUES (%s,%s,%s,%s,%s,%s,%s,8080,'/health',128,100,'SERVING')",
                         (release, org, app, self.node, owner, uuid.uuid4(), self.image))
            conn.execute("INSERT INTO hosting.domains(organization_id,application_id,hostname,"
                         "verification_token,verified_at) VALUES (%s,%s,%s,%s,now())",
                         (org, app, "traffic-" + app.hex[:12] + ".example.org", "A" * 43))
        handler = Handler.__new__(Handler)
        suspend = {"action": "suspend", "reason": "Owner abuse investigation 123",
                   "confirm": "suspend_application"}
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (viewer,))
                self.assertEqual(handler.traffic(conn, org, app, viewer, {}, "GET", uuid.uuid4())[0], 200)
                self.assertEqual(handler.traffic(conn, org, app, viewer, suspend, "POST", uuid.uuid4())[0], 404)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                self.assertEqual(handler.traffic(conn, org, app, "alice", {}, "GET", uuid.uuid4())[0], 404)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (owner,))
                self.assertEqual(handler.traffic(conn, org, app, owner, suspend, "POST", uuid.uuid4())[0], 202)
                self.assertEqual(handler.traffic(conn, org, app, owner, suspend, "POST", uuid.uuid4())[1],
                                 {"state": "SUSPENDING", "replayed": True})
                release_body = {"idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                                "health_path": "/health", "memory_mb": 128, "cpu_milli": 100}
                self.assertEqual(handler.releases(conn, org, app, owner, release_body, "POST", uuid.uuid4())[1],
                                 {"error": "application_traffic_not_active"})
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            with patch("hosting_api.worker.route_request", side_effect=RuntimeError("node unavailable")) as remove, \
                    patch("hosting_api.worker.node_application_state") as lifecycle:
                self.assertTrue(process_traffic_once(conn, {}))
                remove.assert_called_once()
                lifecycle.assert_not_called()
            with psycopg.connect(self.admin, row_factory=dict_row) as admin:
                state = admin.execute("SELECT traffic_state,traffic_last_error FROM hosting.applications WHERE id=%s",
                                      (app,)).fetchone()
                self.assertEqual((state["traffic_state"], state["traffic_last_error"]),
                                 ("SUSPENDING", "RuntimeError"))
                admin.execute("UPDATE hosting.applications SET traffic_next_attempt_at=now() WHERE id=%s", (app,))
            with patch("hosting_api.worker.route_request", return_value={"state": "UNROUTED"}) as remove, \
                    patch("hosting_api.worker.node_application_state", return_value={"state": "PAUSED"}) as lifecycle:
                self.assertTrue(process_traffic_once(conn, {}))
                self.assertTrue(remove.call_args.kwargs["remove"])
                self.assertEqual(lifecycle.call_args.args[3], "pause")
            self.assertFalse(process_traffic_once(conn, {}))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            state = conn.execute("SELECT active_release_id,traffic_state FROM hosting.applications WHERE id=%s",
                                 (app,)).fetchone()
            self.assertEqual((state["active_release_id"], state["traffic_state"]), (release, "SUSPENDED"))
            self.assertEqual(conn.execute("SELECT count(*) FROM hosting.application_traffic_events "
                                          "WHERE application_id=%s", (app,)).fetchone()["count"], 1)
            conn.execute("UPDATE hosting.applications SET traffic_next_attempt_at=now() WHERE id=%s", (app,))
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            with patch("hosting_api.worker.route_request", return_value={"state": "UNROUTED"}) as remove, \
                    patch("hosting_api.worker.node_application_state", return_value={"state": "PAUSED"}) as lifecycle:
                self.assertTrue(process_traffic_once(conn, {}))
                self.assertTrue(remove.call_args.kwargs["remove"])
                self.assertEqual(lifecycle.call_args.args[3], "pause")
            self.assertFalse(process_traffic_once(conn, {}))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM hosting.audit_events "
                                          "WHERE organization_id=%s AND action='application.suspended'",
                                          (org,)).fetchone()["count"], 1)
            failed = uuid.uuid4()
            conn.execute("INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,"
                         "idempotency_key,image,port,health_path,memory_mb,cpu_milli,state,previous_release_id) "
                         "VALUES (%s,%s,%s,%s,%s,%s,%s,8080,'/health',128,100,'FAILED',%s)",
                         (failed, org, app, self.node, owner, uuid.uuid4(), self.image, release))
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            with patch("hosting_api.worker.restore_route") as restore, patch("hosting_api.worker.node_abort") as abort:
                sweep_failed(conn, {})
                restore.assert_not_called()
                abort.assert_not_called()
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.releases SET cleanup_at=now() WHERE id=%s", (failed,))
        resume = {"action": "resume", "reason": "Owner completed review",
                  "confirm": "resume_application"}
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.applications SET traffic_lease_token=%s,"
                         "traffic_lease_until=now()+interval '1 minute' WHERE id=%s",
                         (uuid.uuid4(), app))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (owner,))
                self.assertEqual(handler.traffic(conn, org, app, owner, resume, "POST", uuid.uuid4())[1],
                                 {"error": "traffic_reconciliation_in_progress"})
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.applications SET traffic_lease_token=NULL,traffic_lease_until=NULL "
                         "WHERE id=%s", (app,))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (owner,))
                self.assertEqual(handler.traffic(conn, org, app, owner, resume, "POST", uuid.uuid4())[0], 202)
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            with patch("hosting_api.worker.publish", side_effect=RuntimeError("proof failed")), \
                    patch("hosting_api.worker.route_request", return_value={"state": "UNROUTED"}) as remove, \
                    patch("hosting_api.worker.node_application_state") as lifecycle:
                self.assertTrue(process_traffic_once(conn, {}))
                self.assertEqual([call.args[3] for call in lifecycle.call_args_list], ["resume", "pause"])
                remove.assert_called_once()
            with psycopg.connect(self.admin, row_factory=dict_row) as admin:
                self.assertEqual(admin.execute("SELECT traffic_state FROM hosting.applications WHERE id=%s",
                                               (app,)).fetchone()["traffic_state"], "RESUMING")
                admin.execute("UPDATE hosting.applications SET traffic_next_attempt_at=now() WHERE id=%s", (app,))
            with patch("hosting_api.worker.publish", return_value={"state": "SERVING"}) as proof, \
                    patch("hosting_api.worker.node_application_state") as lifecycle:
                self.assertTrue(process_traffic_once(conn, {}))
                self.assertEqual(proof.call_args.args[1]["id"], release)
                self.assertIsNone(proof.call_args.args[1]["previous_release_id"])
                self.assertEqual(lifecycle.call_args.args[3], "resume")
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            state = conn.execute("SELECT traffic_state,traffic_last_error FROM hosting.applications WHERE id=%s",
                                 (app,)).fetchone()
            self.assertEqual((state["traffic_state"], state["traffic_last_error"]), ("ACTIVE", None))
            self.assertEqual(conn.execute("SELECT count(*) FROM hosting.application_traffic_events "
                                          "WHERE application_id=%s", (app,)).fetchone()["count"], 2)

    def test_rls_and_durable_release(self):
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                visible = conn.execute("SELECT id FROM hosting.projects ORDER BY id").fetchall()
                self.assertEqual([row["id"] for row in visible], [self.project_a])
                self.assertEqual(handler.applications(conn, self.org_b, self.project_b, "alice", {}, "GET", uuid.uuid4())[0], 404)
                status, app = handler.applications(conn, self.org_a, self.project_a, "alice",
                                                    {"name": "web", "environment": "production"}, "POST", uuid.uuid4())
                self.assertEqual(status, 201)
                app_id = app["id"]
                status, domain = handler.domains(conn, self.org_a, app_id, "alice",
                                                 {"hostname": "web.example.org"}, "POST", uuid.uuid4())
                self.assertEqual(status, 201)
                self.assertEqual(handler.domains(conn, self.org_b, app_id, "alice", {}, "GET", uuid.uuid4())[0], 404)
                with patch("hosting_api.__main__.txt_proves", return_value=True):
                    self.assertEqual(handler.domains(conn, self.org_a, app_id, "alice", {},
                                                     "POST", uuid.uuid4(), verify=True)[0], 200)
                body = {"idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                        "health_path": "/health", "cpu_milli": 100, "memory_mb": 128}
                status, release = handler.releases(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())[0], 200)
                mismatch = {**body, "memory_mb": 256}
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", mismatch, "POST", uuid.uuid4())[1]["error"], "idempotency_conflict")
                other = {**body, "idempotency_key": str(uuid.uuid4())}
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", other, "POST", uuid.uuid4())[0], 409)
                self.assertEqual(handler.releases(conn, self.org_b, app_id, "alice", body, "GET", uuid.uuid4())[0], 404)
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, selected_release, node, attempt = claim(conn)
            self.assertEqual(selected_release["id"], release["id"])
            self.assertEqual(node["id"], self.node)
            self.assertTrue(finalize(conn, job, selected_release, attempt,
                                     receipt={"operation_id": str(job["id"]),
                                              "release_id": str(release["id"]), "state": "HEALTHY_PRIVATE",
                                              "public": {"release_id": str(release["id"]), "state": "SERVING"}}))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            active = conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()
            self.assertEqual(active["active_release_id"], release["id"])
            row = conn.execute("SELECT state FROM hosting.releases WHERE id=%s", (release["id"],)).fetchone()
            self.assertEqual(row["state"], "SERVING")
            self.assertEqual(conn.execute("SELECT count(*) FROM hosting.audit_events WHERE organization_id=%s",
                                          (self.org_a,)).fetchone()["count"], 5)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                retry_body = {**body, "idempotency_key": str(uuid.uuid4())}
                status, retry = handler.releases(conn, self.org_a, app_id, "alice", retry_body, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
        for attempt_number in (1, 2, 3):
            with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
                job, attempted_release, node, attempt = claim(conn)
                self.assertEqual(attempt, attempt_number)
                self.assertEqual(attempted_release["id"], retry["id"])
                self.assertTrue(finalize(conn, job, attempted_release, attempt, failure="private probe failed"))
            if attempt_number < 3:
                with psycopg.connect(self.admin) as conn:
                    conn.execute("UPDATE hosting.jobs SET next_attempt_at=now() WHERE id=%s", (job["id"],))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT state FROM hosting.releases WHERE id=%s", (retry["id"],)).fetchone()["state"], "FAILED")
            self.assertEqual(conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()["active_release_id"], release["id"])
            reservations = conn.execute("SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s", (self.node,)).fetchone()
            self.assertEqual((reservations["reserved_cpu_milli"], reservations["reserved_memory_mb"]), (200, 256))
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            with patch("hosting_api.worker.node_abort") as abort, patch("hosting_api.worker.restore_route") as restore:
                sweep_failed(conn, {})
                abort.assert_called_once()
                restore.assert_called_once()
                sweep_failed(conn, {})
                abort.assert_called_once()
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            reservations = conn.execute("SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s", (self.node,)).fetchone()
            self.assertEqual((reservations["reserved_cpu_milli"], reservations["reserved_memory_mb"]), (100, 128))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                next_body = {**body, "idempotency_key": str(uuid.uuid4())}
                status, promoted = handler.releases(conn, self.org_a, app_id, "alice", next_body, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, selected, node, attempt = claim(conn)
            self.assertEqual(selected["id"], promoted["id"])
            self.assertTrue(finalize(conn, job, selected, attempt,
                                     receipt={"operation_id": str(job["id"]), "release_id": str(promoted["id"]),
                                              "state": "HEALTHY_PRIVATE", "public": {"release_id": str(promoted["id"]), "state": "SERVING"}}))
            with patch("hosting_api.worker.node_retire") as retirement:
                sweep_retirements(conn, {})
                retirement.assert_called_once()
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT state FROM hosting.releases WHERE id=%s", (release["id"],)).fetchone()["state"], "RETIRED")
            self.assertEqual(conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()["active_release_id"], promoted["id"])
            reservations = conn.execute("SELECT reserved_cpu_milli,reserved_memory_mb FROM hosting.nodes WHERE id=%s", (self.node,)).fetchone()
            self.assertEqual((reservations["reserved_cpu_milli"], reservations["reserved_memory_mb"]), (100, 128))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                status, rollback = handler.rollback(conn, self.org_a, app_id, "alice",
                                                    {"target_release_id": str(release["id"]),
                                                     "idempotency_key": str(uuid.uuid4())}, uuid.uuid4())
                self.assertEqual(status, 202)
                self.assertEqual(rollback["rollback_of_release_id"], release["id"])
                self.assertNotEqual(rollback["id"], release["id"])
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, selected, node, attempt = claim(conn)
            self.assertEqual(selected["id"], rollback["id"])
            self.assertEqual(selected["image"], self.image)
            self.assertEqual(selected["rollback_of_release_id"], release["id"])
            self.assertTrue(finalize(conn, job, selected, attempt,
                                     receipt={"operation_id": str(job["id"]),
                                              "release_id": str(rollback["id"]), "state": "HEALTHY_PRIVATE",
                                              "public": {"release_id": str(rollback["id"]), "state": "SERVING"}}))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()["active_release_id"], rollback["id"])
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(conn.execute("SELECT id FROM hosting.applications WHERE organization_id=%s",
                                              (self.org_a,)).fetchall(), [])
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'forged')",
                                     (uuid.uuid4(), self.org_a))

    def test_z_postgres_tenant_reservation_and_job(self):
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                _, app = handler.applications(conn, self.org_a, self.project_a, "alice",
                                               {"name": "database-client", "environment": "production"},
                                               "POST", uuid.uuid4())
                app_id = app["id"]
                body = {"idempotency_key": str(uuid.uuid4()), "memory_mb": 256, "cpu_milli": 200}
                self.assertEqual(handler.postgres(conn, self.org_b, app_id, "alice", body, "POST", uuid.uuid4())[0], 404)
                code, result = handler.postgres(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(code, 202)
                self.assertEqual(handler.postgres(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())[0], 200)
                self.assertEqual(handler.postgres(conn, self.org_a, app_id, "alice", {**body, "memory_mb": 512},
                                                  "POST", uuid.uuid4())[0], 409)
                self.assertEqual(handler.postgres(conn, self.org_a, app_id, "alice", {}, "GET", uuid.uuid4())[1]
                                 ["postgres"]["state"], "QUEUED")
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, instance, node, attempt = claim_postgres(conn)
            self.assertEqual(instance["id"], result["id"])
            self.assertEqual(node["id"], self.node)
            self.assertTrue(finalize_postgres(conn, job, instance, attempt, receipt={
                "instance_id": str(instance["id"]), "state": "READY_PRIVATE", "secret_version": 1,
                "host": "dial-pg-" + str(instance["id"])}))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                status, data = handler.postgres(conn, self.org_a, app_id, "alice", {}, "GET", uuid.uuid4())
                self.assertEqual((status, data["postgres"]["state"], data["postgres"]["secret_version"]),
                                 (200, "READY", 1))
                # The database's node is the only eligible release placement.
                domain = handler.domains(conn, self.org_a, app_id, "alice",
                                         {"hostname": "dbclient.example.org"}, "POST", uuid.uuid4())[1]
                with patch("hosting_api.__main__.txt_proves", return_value=True):
                    handler.domains(conn, self.org_a, app_id, "alice", {}, "POST", uuid.uuid4(), verify=True)
                status, release = handler.releases(conn, self.org_a, app_id, "alice", {
                    "idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                    "health_path": "/health", "cpu_milli": 100, "memory_mb": 128}, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
                self.assertEqual(conn.execute("SELECT node_id FROM hosting.releases WHERE id=%s",
                                              (release["id"],)).fetchone()["node_id"], self.node)

        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(conn.execute("SELECT id FROM hosting.postgres_instances WHERE id=%s",
                                              (result["id"],)).fetchall(), [])

    def test_zz_valkey_tenant_reservation_and_job(self):
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                _, app = handler.applications(conn, self.org_a, self.project_a, "alice",
                                               {"name": "cache-client", "environment": "production"},
                                               "POST", uuid.uuid4())
                app_id = app["id"]
                body = {"idempotency_key": str(uuid.uuid4()), "memory_mb": 128, "cpu_milli": 200}
                self.assertEqual(handler.valkey(conn, self.org_b, app_id, "alice", body, "POST", uuid.uuid4())[0], 404)
                code, queued = handler.valkey(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(code, 202)
                self.assertEqual(handler.valkey(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())[0], 200)
                self.assertEqual(handler.valkey(conn, self.org_a, app_id, "alice", {**body, "memory_mb": 256},
                                                "POST", uuid.uuid4())[0], 409)
                self.assertEqual(handler.valkey(conn, self.org_a, app_id, "alice", {}, "GET", uuid.uuid4())[1]
                                 ["valkey"]["state"], "QUEUED")
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, instance, node, attempt = claim_valkey(conn)
            self.assertEqual(instance["id"], queued["id"])
            self.assertEqual(node["id"], self.node)
            self.assertTrue(finalize_valkey(conn, job, instance, attempt, receipt={
                "instance_id": str(instance["id"]), "state": "READY_PRIVATE", "secret_version": 1,
                "host": "dial-vk-" + str(instance["id"])}))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                self.assertEqual(handler.valkey(conn, self.org_a, app_id, "alice", {}, "GET", uuid.uuid4())[1]
                                 ["valkey"]["state"], "READY")
                self.assertEqual(conn.execute("SELECT id FROM hosting.valkey_instances WHERE organization_id=%s",
                                              (self.org_b,)).fetchall(), [])
                handler.domains(conn, self.org_a, app_id, "alice",
                                {"hostname": "cacheclient.example.org"}, "POST", uuid.uuid4())
                with patch("hosting_api.__main__.txt_proves", return_value=True):
                    handler.domains(conn, self.org_a, app_id, "alice", {}, "POST", uuid.uuid4(), verify=True)
                status, release = handler.releases(conn, self.org_a, app_id, "alice", {
                    "idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                    "health_path": "/health", "cpu_milli": 100, "memory_mb": 128}, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
                self.assertEqual(conn.execute("SELECT node_id FROM hosting.releases WHERE id=%s",
                                              (release["id"],)).fetchone()["node_id"], self.node)

    def test_zzz_object_storage_tenant_bucket_and_release_placement(self):
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                _, app = handler.applications(conn, self.org_a, self.project_a, "alice",
                                               {"name": "storage-client", "environment": "production"},
                                               "POST", uuid.uuid4())
                app_id = app["id"]
                body = {"idempotency_key": str(uuid.uuid4()), "memory_mb": 256, "cpu_milli": 200}
                self.assertEqual(handler.storage(conn, self.org_b, app_id, "alice", body,
                                                 "POST", uuid.uuid4())[0], 404)
                code, queued = handler.storage(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(code, 202)
                self.assertEqual(handler.storage(conn, self.org_a, app_id, "alice", body,
                                                 "POST", uuid.uuid4())[1]["replayed"], True)
                self.assertEqual(handler.storage(conn, self.org_a, app_id, "alice",
                                                 {**body, "memory_mb": 512}, "POST", uuid.uuid4())[0], 409)
                handler.domains(conn, self.org_a, app_id, "alice",
                                {"hostname": "storageclient.example.org"}, "POST", uuid.uuid4())
                with patch("hosting_api.__main__.txt_proves", return_value=True):
                    handler.domains(conn, self.org_a, app_id, "alice", {}, "POST", uuid.uuid4(), verify=True)
                release_body = {"idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                                "health_path": "/health", "cpu_milli": 100, "memory_mb": 128}
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", release_body,
                                                  "POST", uuid.uuid4())[1], {"error": "storage_not_ready"})
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, instance, node, attempt = claim_storage(conn)
            self.assertEqual((instance["id"], node["id"]), (queued["id"], self.node))
            self.assertTrue(finalize_storage(conn, job, instance, attempt, receipt={
                "instance_id": str(instance["id"]), "state": "READY_PRIVATE", "secret_version": 1,
                "bucket": "dial-" + str(instance["id"]), "host": "dial-s3-" + str(instance["id"])}))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                self.assertEqual(handler.storage(conn, self.org_a, app_id, "alice", {}, "GET", uuid.uuid4())[1]
                                 ["storage"]["state"], "READY")
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", release_body,
                                                  "POST", uuid.uuid4())[0], 202)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(conn.execute("SELECT id FROM hosting.object_storage_instances "
                                              "WHERE id=%s", (queued["id"],)).fetchall(), [])

    def test_team_invitation_single_use_tenant_scope_and_owner_guard(self):
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                body = {"idempotency_key": str(uuid.uuid4()), "role": "admin", "expires_hours": 2,
                        "confirm": "invite_admin"}
                self.assertEqual(handler.team(conn, self.org_a, "alice", {**body, "confirm": ""},
                                              "POST", uuid.uuid4())[0], 400)
                code, invite = handler.team(conn, self.org_a, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(code, 201)
                self.assertEqual(len(invite["token"]), 43)
                self.assertEqual(handler.team(conn, self.org_a, "alice", body, "POST", uuid.uuid4())[1]
                                 ["replayed"], True)
                self.assertEqual(handler.team(conn, self.org_a, "alice", {**body, "role": "viewer",
                                                                          "confirm": "invite_viewer"},
                                              "POST", uuid.uuid4())[0], 409)
                rows = handler.team(conn, self.org_a, "alice", {}, "GET", uuid.uuid4())[1]["invitations"]
                self.assertEqual(rows[0]["id"], invite["id"])
                self.assertNotIn("token_hash", rows[0])
                self.assertEqual(handler.team(conn, self.org_a, "alice", {}, "GET", uuid.uuid4(),
                                              action="members")[1]["members"][0]["actor_sub"], "alice")
                self.assertEqual(handler.team(conn, self.org_a, "alice",
                                              {"actor_sub": "alice", "confirm": "remove_member"},
                                              "POST", uuid.uuid4(), action="remove")[0], 409)
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) "
                                     "VALUES (%s,'forged','owner')", (self.org_a,))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(handler.team(conn, self.org_a, "bob", {}, "GET", uuid.uuid4())[0], 404)
                self.assertEqual(conn.execute("SELECT id FROM hosting.team_invitations WHERE organization_id=%s",
                                              (self.org_a,)).fetchall(), [])
                joined = handler.accept_invitation(conn, "bob", {"token": invite["token"]}, uuid.uuid4())
                self.assertEqual((joined[0], joined[1]["role"]), (200, "admin"))
                self.assertEqual(handler.accept_invitation(conn, "bob", {"token": invite["token"]},
                                                           uuid.uuid4())[1]["replayed"], True)
                self.assertEqual(handler.team(conn, self.org_a, "bob", {}, "GET", uuid.uuid4())[0], 404)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','carol',true)")
                self.assertEqual(handler.accept_invitation(conn, "carol", {"token": invite["token"]},
                                                           uuid.uuid4())[0], 409)
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                members = handler.team(conn, self.org_a, "alice", {}, "GET", uuid.uuid4(),
                                       action="members")[1]["members"]
                self.assertIn({"actor_sub": "bob", "role": "admin"}, members)
                second = handler.team(conn, self.org_a, "alice",
                                      {"idempotency_key": str(uuid.uuid4()), "role": "viewer",
                                       "expires_hours": 1, "confirm": "invite_viewer"},
                                      "POST", uuid.uuid4())[1]
                expired = handler.team(conn, self.org_a, "alice",
                                       {"idempotency_key": str(uuid.uuid4()), "role": "viewer",
                                        "expires_hours": 1, "confirm": "invite_viewer"},
                                       "POST", uuid.uuid4())[1]
                self.assertEqual(handler.team(conn, self.org_a, "alice", {"invitation_id": str(second["id"])},
                                              "POST", uuid.uuid4(), action="revoke")[0], 200)
                self.assertEqual(handler.team(conn, self.org_a, "alice",
                                              {"actor_sub": "bob", "confirm": "remove_member"},
                                              "POST", uuid.uuid4(), action="remove")[0], 200)
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.team_invitations SET created_at=now()-interval '2 hours',"
                         "expires_at=now()-interval '1 hour' WHERE id=%s", (expired["id"],))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(handler.accept_invitation(conn, "bob", {"token": invite["token"]},
                                                           uuid.uuid4())[0], 409)
                self.assertEqual(handler.accept_invitation(conn, "bob", {"token": second["token"]},
                                                           uuid.uuid4())[0], 409)
                self.assertEqual(handler.accept_invitation(conn, "bob", {"token": expired["token"]},
                                                           uuid.uuid4())[0], 409)
                self.assertEqual(conn.execute("SELECT role FROM hosting.memberships WHERE organization_id=%s",
                                              (self.org_a,)).fetchall(), [])

    def test_restricted_image_admission_identity(self):
        image = "registry.example.test/team/verified@sha256:" + "d" * 64
        with psycopg.connect(os.environ["TEST_ADMITTER_DSN"], row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("INSERT INTO hosting.artifact_admissions "
                             "(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                             "VALUES (%s,%s,%s,'ci','{}'::jsonb)",
                             (image, "e" * 64, "f" * 40))
                for statement in ("SELECT id FROM hosting.organizations",
                                  "DELETE FROM hosting.artifact_admissions WHERE image=%s",
                                  "INSERT INTO hosting.organizations(id,name) VALUES (%s,'forged')"):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        with conn.transaction():
                            value = image if "%s" in statement and "DELETE" in statement else uuid.uuid4()
                            conn.execute(statement, (value,) if "%s" in statement else ())
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT policy_revision FROM hosting.artifact_admissions WHERE image=%s",
                                          (image,)).fetchone()["policy_revision"], "ci")

    def test_admission_receipt_replay_after_completed_write(self):
        image = "registry.example.test/team/replay@sha256:" + "1" * 64
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            key = Path(temp) / "cosign.pub"
            key.write_text("disposable-ci-key")
            args = ["admit_image.py", "--image", image, "--source-commit", "2" * 40,
                    "--policy-revision", "ci-replay", "--cosign-public-key", str(key),
                    "--evidence-dir", str(evidence)]
            fake = [json.dumps([{"critical": {"image": {"docker-manifest-digest": "sha256:" + "1" * 64}}}]),
                    json.dumps({"Results": []}), json.dumps({"bomFormat": "CycloneDX"})]
            with patch.dict(os.environ, {"HOSTING_ADMISSION_DSN": os.environ["TEST_ADMITTER_DSN"]}), \
                    patch.object(sys, "argv", args), patch("admit_image.run", side_effect=fake) as subprocess_run:
                admit_image.main()
                self.assertEqual(subprocess_run.call_count, 3)
                admit_image.main()
                self.assertEqual(subprocess_run.call_count, 3)  # Exact replay uses recorded proof.
            with psycopg.connect(self.admin) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM hosting.artifact_admissions WHERE image=%s",
                                              (image,)).fetchone()[0], 1)
            artifact = hashlib.sha256(image.encode()).hexdigest()
            (evidence / f"{artifact}.sbom.json").write_text("tampered")
            with patch.dict(os.environ, {"HOSTING_ADMISSION_DSN": os.environ["TEST_ADMITTER_DSN"]}), \
                    patch.object(sys, "argv", args), self.assertRaises(RuntimeError):
                admit_image.main()

    def test_signed_push_durable_build_queue_and_restricted_roles(self):
        app, source, delivery = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        repo_id = uuid.uuid4().int % (2**31) + 1
        commit = "3" * 40
        image = "registry.example.test/team/gitweb@sha256:" + "4" * 64
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) "
                         "VALUES (%s,%s,%s,'ci','gitweb')", (app, self.org_a, self.project_a))
            conn.execute("INSERT INTO hosting.git_sources "
                         "(id,organization_id,application_id,repository_id,full_name,branch,"
                         "image_repository,builder,policy_revision) "
                         "VALUES (%s,%s,%s,%s,'Vanguduza/hosting-','main',"
                         "'registry.example.test/team/gitweb','ci_builder','ci_policy')",
                         (source, self.org_a, app, repo_id))
        secret = b"github-ci-hmac-secret-32-bytes-minimum"
        server = ThreadingHTTPServer(("127.0.0.1", 0), HookHandler)
        server.secret, server.dsn = secret, os.environ["TEST_HOOK_DSN"]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = json.dumps({"repository": {"id": repo_id, "full_name": "Vanguduza/hosting-"},
                           "ref": "refs/heads/main", "after": commit, "deleted": False}).encode()
        headers = {"Content-Type": "application/json", "X-GitHub-Event": "push",
                   "X-GitHub-Delivery": str(delivery),
                   "X-Hub-Signature-256": "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()}
        def request(payload, metadata):
            client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                client.request("POST", "/v1/github/push", payload, metadata)
                result = client.getresponse()
                return result.status, json.loads(result.read())
            finally:
                client.close()
        try:
            self.assertTrue(verify(secret, body, headers["X-Hub-Signature-256"]))
            self.assertEqual(parse_push(json.loads(body))[0], repo_id)
            self.assertEqual(request(body, {**headers, "X-Hub-Signature-256": "sha256=" + "0" * 64})[0], 401)
            self.assertEqual(request(body, headers)[1]["state"], "QUEUED")
            self.assertEqual(request(body, headers)[1]["state"], "REPLAYED")
            changed = json.dumps({**json.loads(body), "after": "5" * 40}).encode()
            changed_headers = {**headers, "X-Hub-Signature-256": "sha256=" +
                               hmac.new(secret, changed, hashlib.sha256).hexdigest()}
            self.assertEqual(request(changed, changed_headers)[0], 400)
            wrong_branch = json.dumps({**json.loads(body), "ref": "refs/heads/untrusted"}).encode()
            wrong_headers = {**headers, "X-GitHub-Delivery": str(uuid.uuid4()),
                             "X-Hub-Signature-256": "sha256=" +
                             hmac.new(secret, wrong_branch, hashlib.sha256).hexdigest()}
            self.assertEqual(request(wrong_branch, wrong_headers)[1]["state"], "IGNORED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        with psycopg.connect(os.environ["TEST_HOOK_DSN"]) as conn:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("UPDATE hosting.github_builds SET state='ADMITTED' WHERE delivery_id=%s", (delivery,))
        handler = Handler.__new__(Handler)
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) "
                         "VALUES (%s,'charlie','viewer')", (self.org_a,))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                status, listing = handler.builds(conn, self.org_a, app, "alice", "GET")
                self.assertEqual((status, listing["builds"][0]["state"]), (200, "QUEUED"))
                self.assertEqual(handler.builds(conn, self.org_b, app, "alice", "GET")[0], 404)
                self.assertEqual(handler.builds(conn, self.org_a, app, "alice", "POST")[0], 404)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(conn.execute("SELECT delivery_id FROM hosting.github_builds").fetchall(), [])
                self.assertEqual(handler.builds(conn, self.org_a, app, "bob", "GET")[0], 404)
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','charlie',true)")
                self.assertEqual(handler.builds(conn, self.org_a, app, "charlie", "GET")[0], 200)
        with psycopg.connect(os.environ["TEST_BUILDWORKER_DSN"], row_factory=dict_row,
                             autocommit=True) as conn:
            job, registered, attempt = claim_build(conn)
            self.assertEqual((job["delivery_id"], registered["id"], attempt), (delivery, source, 1))
            self.assertTrue(finalize_build(conn, job, registered, attempt, failure="RuntimeError"))
        with psycopg.connect(self.admin) as conn:
            conn.execute("UPDATE hosting.github_builds SET next_attempt_at=now() WHERE delivery_id=%s", (delivery,))
            receipt = {"image": image, "source_commit": commit, "policy_revision": "ci_policy"}
            conn.execute("INSERT INTO hosting.artifact_admissions "
                         "(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                         "VALUES (%s,%s,%s,'ci_policy',%s::jsonb)",
                         (image, "6" * 64, commit, json.dumps(receipt)))
        with psycopg.connect(os.environ["TEST_BUILDWORKER_DSN"], row_factory=dict_row,
                             autocommit=True) as conn:
            job, registered, attempt = claim_build(conn)
            self.assertEqual(attempt, 2)
            self.assertTrue(finalize_build(conn, job, registered, attempt, receipt=receipt))
            self.assertIsNone(claim_build(conn))
        with psycopg.connect(self.admin) as conn:
            self.assertEqual(conn.execute("SELECT state,image FROM hosting.github_builds WHERE delivery_id=%s",
                                          (delivery,)).fetchone(), ("ADMITTED", image))
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                status, listing = handler.builds(conn, self.org_a, app, "alice", "GET")
                self.assertEqual((status, listing["builds"][0]["image"]), (200, image))
        other_app = uuid.uuid4()
        with psycopg.connect(self.admin) as conn:
            conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,environment,name) "
                         "VALUES (%s,%s,%s,'ci','foreign-build')", (other_app, self.org_b, self.project_b))
            for org, target, hostname in ((self.org_a, app, "gitweb.example.org"),
                                          (self.org_b, other_app, "foreign-build.example.org")):
                conn.execute("INSERT INTO hosting.domains(organization_id,application_id,hostname,"
                             "verification_token,verified_at) VALUES (%s,%s,%s,%s,now())",
                             (org, target, hostname, "z" * 43))
        body = {"idempotency_key": str(uuid.uuid4()), "image": image, "port": 8080,
                "health_path": "/health", "memory_mb": 128, "cpu_milli": 100}
        with psycopg.connect(self.api, row_factory=dict_row) as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(handler.releases(conn, self.org_b, other_app, "bob", body,
                                                  "POST", uuid.uuid4()),
                                 (409, {"error": "artifact_not_admitted"}))
                self.assertFalse(conn.execute("SELECT hosting.release_image_admitted(%s,%s,%s) AS admitted",
                                              (image, self.org_b, other_app)).fetchone()["admitted"])
            with conn.transaction():
                conn.execute("SELECT set_config('hosting.actor_sub','alice',true)")
                self.assertTrue(conn.execute("SELECT hosting.release_image_admitted(%s,%s,%s) AS admitted",
                                             (image, self.org_a, app)).fetchone()["admitted"])
                self.assertTrue(conn.execute("SELECT hosting.release_image_admitted(%s,%s,%s) AS admitted",
                                             (self.image, self.org_a, app)).fetchone()["admitted"])
                self.assertEqual(handler.releases(conn, self.org_a, app, "alice", body,
                                                  "POST", uuid.uuid4())[0], 202)


if __name__ == "__main__":
    unittest.main()
