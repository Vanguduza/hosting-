"""Runs against disposable PostgreSQL in CI; skipped without TEST_ADMIN_DSN."""
import os
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_api.__main__ import Handler
from hosting_api.worker import claim, finalize, sweep_retirements
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("TEST_ADMIN_DSN"), "requires disposable PostgreSQL")
class DatabaseIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ["TEST_ADMIN_DSN"]
        cls.api = os.environ["TEST_API_DSN"]
        cls.worker = os.environ["TEST_WORKER_DSN"]
        with psycopg.connect(cls.admin) as conn:
            for migration in sorted((ROOT / "services/api/schema").glob("*.sql")):
                conn.execute(migration.read_text())
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
            conn.execute("INSERT INTO hosting.artifact_admissions(image,sbom_sha256,source_commit,policy_revision,verification_receipt) "
                         "VALUES (%s,%s,%s,'test-policy','{}'::jsonb)", (cls.image, "b" * 64, "c" * 40))

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
                body = {"idempotency_key": str(uuid.uuid4()), "image": self.image, "port": 8080,
                        "health_path": "/health", "cpu_milli": 100, "memory_mb": 128}
                status, release = handler.releases(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())
                self.assertEqual(status, 202)
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", body, "POST", uuid.uuid4())[0], 200)
                other = {**body, "idempotency_key": str(uuid.uuid4())}
                self.assertEqual(handler.releases(conn, self.org_a, app_id, "alice", other, "POST", uuid.uuid4())[0], 409)
                self.assertEqual(handler.releases(conn, self.org_b, app_id, "alice", body, "GET", uuid.uuid4())[0], 404)
        with psycopg.connect(self.worker, row_factory=dict_row, autocommit=True) as conn:
            job, selected_release, node, attempt = claim(conn)
            self.assertEqual(selected_release["id"], release["id"])
            self.assertEqual(node["id"], self.node)
            self.assertTrue(finalize(conn, job, selected_release, attempt,
                                     receipt={"operation_id": str(job["id"]),
                                              "release_id": str(release["id"]), "state": "HEALTHY_PRIVATE"}))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            active = conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()
            self.assertEqual(active["active_release_id"], release["id"])
            row = conn.execute("SELECT state FROM hosting.releases WHERE id=%s", (release["id"],)).fetchone()
            self.assertEqual(row["state"], "HEALTHY_PRIVATE")
            self.assertEqual(conn.execute("SELECT count(*) FROM hosting.audit_events WHERE organization_id=%s",
                                          (self.org_a,)).fetchone()["count"], 3)
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
                                     receipt={"operation_id": str(job["id"]), "release_id": str(promoted["id"]), "state": "HEALTHY_PRIVATE"}))
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
                conn.execute("SELECT set_config('hosting.actor_sub','bob',true)")
                self.assertEqual(conn.execute("SELECT id FROM hosting.applications WHERE organization_id=%s",
                                              (self.org_a,)).fetchall(), [])
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():
                        conn.execute("INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,'forged')",
                                     (uuid.uuid4(), self.org_a))


if __name__ == "__main__":
    unittest.main()
