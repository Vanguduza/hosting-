"""Disposable Docker proof: SCRAM login, private network, persistent restart."""
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError
from node_agent.postgres import names, provision
from node_agent.valkey import names as cache_names, provision as cache_provision
sys.path.insert(0, str(ROOT / "tools"))
from postgres_backup import backup, restore_drill, backup_all, configuration, run
from postgres_physical_backup import backup as physical_backup, verify as physical_verify
from postgres_wal import evidence as wal_evidence, identity as wal_identity, members as wal_members
from postgres_wal import postgres as wal_postgres, ship as wal_ship
from control_wal import pitr as wal_pitr, recover_evidence as wal_recover_evidence


@unittest.skipUnless(os.environ.get("POSTGRES_RUNTIME_IMAGE"), "requires disposable Docker PostgreSQL image")
class PostgresRuntime(unittest.TestCase):
    def test_private_persistent_instance_and_non_superuser(self):
        with tempfile.TemporaryDirectory() as temp:
            node = Node(Path(temp) / "state.sqlite3")
            instance, app = str(uuid.uuid4()), str(uuid.uuid4())
            cache = str(uuid.uuid4())
            password = "A" * 48
            node.deliver_secrets({"resource_id": instance, "version": 1,
                                  "values": {"postgres_password": "B" * 48, "app_password": password}})
            node.deliver_secrets({"resource_id": cache, "version": 1,
                                  "values": {"app_password": "C" * 48}})
            payload = {"instance_id": instance, "application_id": app,
                       "memory_mb": 256, "cpu_milli": 250, "secret_version": 1}
            container, network, volume = names(instance)
            cache_container, cache_network, cache_volume = cache_names(cache)
            release = str(uuid.uuid4())
            previous = os.environ.get("NODE_POSTGRES_IMAGE")
            previous_cache = os.environ.get("NODE_VALKEY_IMAGE")
            os.environ["NODE_POSTGRES_IMAGE"] = os.environ["POSTGRES_RUNTIME_IMAGE"]
            os.environ["NODE_VALKEY_IMAGE"] = os.environ["VALKEY_RUNTIME_IMAGE"]
            try:
                receipt = provision(node, payload)
                self.assertEqual(cache_provision(node, {"instance_id": cache, "application_id": app,
                                                        "memory_mb": 128, "cpu_milli": 100,
                                                        "secret_version": 1})["state"], "READY_PRIVATE")
                self.assertEqual(receipt["state"], "READY_PRIVATE")
                inspect = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
                self.assertEqual(inspect["HostConfig"]["PortBindings"], {})
                self.assertTrue(json.loads(subprocess.check_output(["docker", "network", "inspect", network]))[0]["Internal"])
                ip = inspect["NetworkSettings"]["Networks"][network]["IPAddress"]
                with psycopg.connect(host=ip, port=5432, user="dial_app", password=password, dbname="appdb",
                                     connect_timeout=5) as conn:
                    self.assertEqual(conn.execute("SELECT current_user").fetchone()[0], "dial_app")
                    self.assertFalse(conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname=current_user").fetchone()[0])
                    conn.execute("CREATE TABLE durable_test (value integer)")
                    conn.execute("INSERT INTO durable_test VALUES (42)")
                app_receipt = node.deploy({"operation_id": str(uuid.uuid4()), "application_id": app,
                                           "release_id": release, "image": os.environ["POSTGRES_RUNTIME_WEB_IMAGE"],
                                           "port": 8080, "health_path": "/health", "memory_mb": 128,
                                           "cpu_milli": 100, "postgres_id": instance, "postgres_version": 1,
                                           "valkey_id": cache, "valkey_version": 1})
                self.assertEqual(app_receipt["state"], "HEALTHY_PRIVATE")
                workload = json.loads(subprocess.check_output(["docker", "inspect", node.container(release)]))[0]
                self.assertIn(network, workload["NetworkSettings"]["Networks"])
                self.assertIn(cache_network, workload["NetworkSettings"]["Networks"])
                self.assertIn(node.application_network(app), workload["NetworkSettings"]["Networks"])
                self.assertNotIn("dial-runtime", workload["NetworkSettings"]["Networks"])
                self.assertEqual(workload["Config"]["Env"].count("DATABASE_PASSWORD_FILE=/run/secrets/postgres_password"), 1)
                self.assertIn("CACHE_PASSWORD_FILE=/run/secrets/valkey_password", workload["Config"]["Env"])
                if os.environ.get("POSTGRES_RUNTIME_BACKUP"):
                    backup_env = {key: os.environ.get(key) for key in
                                  ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "BACKUP_EVIDENCE_DIR",
                                   "BACKUP_PROBE_DIR", "POSTGRES_WAL_EVIDENCE_ROOT")}
                    try:
                        repository = Path(temp) / "restic"
                        evidence = Path(temp) / "evidence"
                        restic_password = Path(temp) / "restic-password"
                        restic_password.write_text("disposable-only-credential-" + uuid.uuid4().hex)
                        os.chmod(restic_password, 0o600)
                        probes = Path(temp) / "probes"
                        probes.mkdir(mode=0o700)
                        probe = probes / (instance + ".json")
                        probe.write_text(json.dumps({"name": "durable_canary", "sql":
                            "SELECT count(*) FROM durable_test WHERE value=42", "expected": "1"}))
                        os.chmod(probe, 0o600)
                        os.environ.update(RESTIC_REPOSITORY=str(repository),
                                          RESTIC_PASSWORD_FILE=str(restic_password),
                                          BACKUP_EVIDENCE_DIR=str(evidence), BACKUP_PROBE_DIR=str(probes))
                        run(["restic", "init"], 120)
                        directory, image = configuration(offhost=False)
                        snapshot = backup(instance, directory)
                        self.assertEqual(snapshot["state"], "BACKUP_CREATED")
                        probe.write_text(json.dumps({"name": "durable_canary", "sql":
                            "SELECT count(*) FROM durable_test WHERE value=42", "expected": "2"}))
                        with self.assertRaisesRegex(RuntimeError, "semantic probe failed"):
                            restore_drill(instance, snapshot["snapshot_id"], directory, image)
                        self.assertEqual(json.loads((directory / (snapshot["snapshot_id"] + ".json")).read_text())["state"],
                                         "BACKUP_CREATED")
                        probe.write_text(json.dumps({"name": "durable_canary", "sql":
                            "SELECT count(*) FROM durable_test WHERE value=42", "expected": "1"}))
                        verified = restore_drill(instance, snapshot["snapshot_id"], directory, image)
                        self.assertEqual(verified["state"], "RESTORE_VERIFIED")
                        self.assertEqual(verified["semantic_probe"], "durable_canary")
                        self.assertGreaterEqual(verified["restored_table_count"], 1)
                        physical_evidence = Path(temp) / "physical-evidence"
                        physical_evidence.mkdir(mode=0o700)
                        wal_root = Path(temp) / "wal-evidence"
                        wal_root.mkdir(mode=0o700)
                        os.environ["POSTGRES_WAL_EVIDENCE_ROOT"] = str(wal_root)
                        wal_postgres(container, ["mkdir", "-p", "/var/lib/postgresql/data/wal-spool"])
                        wal_postgres(container, ["pg_receivewal", "--create-slot", "--if-not-exists",
                                                 "--slot", "dial_client_wal", "--no-password"])
                        receiver = subprocess.Popen(["docker", "exec", "-u", "postgres", container,
                            "pg_receivewal", "-D", "/var/lib/postgresql/data/wal-spool", "-S",
                            "dial_client_wal", "--synchronous", "--no-password"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                        try:
                            physical = physical_backup(instance, physical_evidence)
                            self.assertEqual(physical["state"], "BACKUP_CREATED")
                            physical_result = physical_verify(instance, physical["snapshot_id"],
                                                              physical_evidence, image)
                            self.assertEqual(physical_result["state"], "RESTORE_VERIFIED")
                            self.assertEqual(physical_result["semantic_probe"], "durable_canary")
                            wal_postgres(container, ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-U",
                                                     "postgres", "-d", "appdb", "-c",
                                                     "INSERT INTO durable_test VALUES (43)"])
                            target = wal_postgres(container, ["psql", "-X", "-At", "-U", "postgres",
                                                              "-d", "appdb", "-c", "SELECT clock_timestamp()"])
                            time.sleep(1)
                            wal_postgres(container, ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-U",
                                                     "postgres", "-d", "appdb", "-c",
                                                     "INSERT INTO durable_test VALUES (44)", "-c",
                                                     "SELECT pg_switch_wal()"])
                            deadline = time.monotonic() + 40
                            while not any(re.fullmatch(r"[0-9A-F]{24}", n) for n in wal_members(container)):
                                if receiver.poll() is not None or time.monotonic() > deadline:
                                    raise RuntimeError("Managed WAL stream did not close a segment")
                                time.sleep(0.5)
                        finally:
                            receiver.send_signal(signal.SIGTERM)
                            receiver.communicate(timeout=20)
                        self.assertGreaterEqual(len(wal_ship(instance, wal_root)), 1)
                        system = wal_identity(container)
                        wal_postgres(container, ["rm", "-rf", "/var/lib/postgresql/data/wal-spool"])
                        self.assertEqual(wal_pitr(wal_evidence(wal_root, instance), system,
                            physical_evidence, physical["snapshot_id"], image, target,
                            {"sql": "SELECT string_agg(value::text, ',' ORDER BY value) "
                                    "FROM durable_test", "expected": "42,43"},
                            archive_name="base.tar", database="appdb", instance_id=instance)["state"],
                            "PITR_VERIFIED")
                        from control_wal import publish_evidence as wal_publish_evidence
                        source_receipts = wal_evidence(wal_root, instance)
                        evidence_snapshot = wal_publish_evidence(source_receipts, system,
                                                                 "dial-client-postgres-wal-evidence")
                        source_receipts.rename(wal_root / "source-receipts-unavailable")
                        recovered = wal_evidence(wal_root, instance, create=True)
                        self.assertEqual(wal_recover_evidence(recovered, system,
                            "dial-client-postgres-wal-evidence")["snapshot_id"], evidence_snapshot)
                        self.assertEqual(wal_pitr(recovered, system, physical_evidence,
                            physical["snapshot_id"], image, target,
                            {"sql": "SELECT string_agg(value::text, ',' ORDER BY value) "
                                    "FROM durable_test", "expected": "42,43"},
                            archive_name="base.tar", database="appdb", instance_id=instance)["state"],
                            "PITR_VERIFIED")
                        fleet = backup_all(directory, image)
                        self.assertEqual(fleet["state"], "FLEET_BACKUP_VERIFIED")
                        self.assertEqual(fleet["instances"], 1)
                        self.assertEqual(fleet["receipts"][0]["instance_id"], instance)
                    finally:
                        for key, value in backup_env.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
                self.assertEqual(provision(node, payload), receipt)
                self.assertEqual(node.deliver_secrets({"resource_id": instance, "version": 1,
                                                       "values": {"postgres_password": "B" * 48,
                                                                  "app_password": password}})["state"], "STORED")
                subprocess.run(["docker", "restart", container], check=True, capture_output=True)
                self.assertEqual(provision(node, payload), receipt)
                with psycopg.connect(host=ip, port=5432, user="dial_app", password=password, dbname="appdb",
                                     connect_timeout=5) as conn:
                    self.assertEqual(conn.execute("SELECT value FROM durable_test").fetchone()[0], 42)
                with self.assertRaises(OperationError):
                    provision(node, {**payload, "application_id": str(uuid.uuid4())})
                node.deliver_secrets({"resource_id": instance, "version": 2,
                                      "values": {"postgres_password": "D" * 48,
                                                 "app_password": "E" * 48}})
                with self.assertRaisesRegex(ValueError, "unsupported credential revision"):
                    provision(node, {**payload, "secret_version": 2})
                subprocess.run(["docker", "network", "disconnect", network, container],
                               check=True, capture_output=True)
                with self.assertRaises(OperationError):
                    provision(node, payload)
            finally:
                subprocess.run(["docker", "rm", "-f", node.container(release)], capture_output=True)
                subprocess.run(["docker", "rm", "-f", cache_container], capture_output=True)
                subprocess.run(["docker", "volume", "rm", cache_volume], capture_output=True)
                subprocess.run(["docker", "network", "rm", cache_network], capture_output=True)
                subprocess.run(["docker", "rm", "-f", container], capture_output=True)
                subprocess.run(["docker", "volume", "rm", volume], capture_output=True)
                subprocess.run(["docker", "network", "rm", network], capture_output=True)
                subprocess.run(["docker", "network", "rm", node.application_network(app)], capture_output=True)
                if previous is None:
                    os.environ.pop("NODE_POSTGRES_IMAGE", None)
                else:
                    os.environ["NODE_POSTGRES_IMAGE"] = previous
                if previous_cache is None:
                    os.environ.pop("NODE_VALKEY_IMAGE", None)
                else:
                    os.environ["NODE_VALKEY_IMAGE"] = previous_cache
