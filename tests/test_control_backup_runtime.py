"""Disposable PostgreSQL and Restic proof for the control backup operator."""
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from backup_health import evaluate
from control_backup import backup, environment, verify
from control_physical_backup import backup as physical_backup, verify as physical_verify
from control_wal import archive as wal_archive, materialize as wal_materialize, pitr, system_id
from control_wal import publish_evidence, recover_evidence
from recovery_catalog import load_config, publish, inspect, inspect_latest


@unittest.skipUnless(os.environ.get("TEST_ADMIN_DSN") and os.environ.get("CONTROL_RUNTIME_BACKUP"),
                     "requires disposable migrated PostgreSQL and Restic")
class ControlBackupRuntime(unittest.TestCase):
    def test_offhost_wal_and_selected_point_in_time_after_source_loss(self):
        dsn = urlparse(os.environ["TEST_ADMIN_DSN"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = root / "password"
            secret.write_text("disposable-pitr-restic-password")
            secret.chmod(0o600)
            pgpass = root / "pgpass"
            pgpass.write_text(f"127.0.0.1:{dsn.port}:*:{dsn.username}:{dsn.password}\n")
            pgpass.chmod(0o600)
            spool = root / "wal-spool"
            wal_evidence = root / "wal-evidence"
            physical_evidence = root / "control-physical-evidence"
            for directory in (spool, wal_evidence, physical_evidence):
                directory.mkdir(mode=0o700)
            env = {"RESTIC_REPOSITORY": str(root / "repository"), "RESTIC_PASSWORD_FILE": str(secret),
                   "CONTROL_WAL_ALLOW_LOCAL_TEST": "1", "CONTROL_WAL_SPOOL": str(spool),
                   "CONTROL_WAL_EVIDENCE": str(wal_evidence), "PGHOST": "127.0.0.1",
                   "PGPORT": str(dsn.port), "PGUSER": dsn.username,
                   "PGDATABASE": dsn.path.lstrip("/"), "PGPASSFILE": str(pgpass)}
            with patch.dict(os.environ, env):
                from control_backup import run
                run(["restic", "init"])
                identity = system_id()
                run(["pg_receivewal", "--create-slot", "--if-not-exists", "--slot", "dial_control_wal",
                     "--no-password"])
                receiver = subprocess.Popen(["pg_receivewal", "-D", str(spool), "-S", "dial_control_wal",
                                             "--synchronous", "--no-password"], env=os.environ.copy(),
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    base = physical_backup(physical_evidence)
                    physical_verify(physical_evidence, base["snapshot_id"],
                                    os.environ["CONTROL_POSTGRES_IMAGE"])
                    run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c",
                         "CREATE TABLE public.pitr_canary(marker text PRIMARY KEY)", "-c",
                         "INSERT INTO public.pitr_canary VALUES ('before')"])
                    target = run(["psql", "-X", "-Atc", "SELECT clock_timestamp()"] ).strip()
                    time.sleep(1)
                    run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c",
                         "INSERT INTO public.pitr_canary VALUES ('after')", "-c", "SELECT pg_switch_wal()"])
                    deadline = time.monotonic() + 40
                    while not any(re.fullmatch(r"[0-9A-F]{24}", p.name) for p in spool.iterdir()):
                        if receiver.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Streaming WAL did not close a segment")
                        time.sleep(0.5)
                finally:
                    receiver.send_signal(signal.SIGTERM)
                    receiver.communicate(timeout=20)
                receipts = wal_archive(spool, wal_evidence, identity)
                self.assertGreaterEqual(len(receipts), 1)
                spool.rename(root / "source-wal-unavailable")
                destination = root / "restored-wal"
                destination.mkdir(mode=0o700)
                self.assertEqual(len(wal_materialize(wal_evidence, identity, destination)), len(receipts))
                self.assertEqual(pitr(wal_evidence, identity, physical_evidence, base["snapshot_id"],
                                      os.environ["CONTROL_POSTGRES_IMAGE"], target,
                                      {"sql": "SELECT string_agg(marker, ',' ORDER BY marker) "
                                              "FROM public.pitr_canary", "expected": "before"})["state"],
                                 "PITR_VERIFIED")
                receipt_snapshot = publish_evidence(wal_evidence, identity, "dial-control-wal-evidence")
                wal_evidence.rename(root / "source-receipts-unavailable")
                recovered = root / "recovered-wal-evidence"
                recovered.mkdir(mode=0o700)
                self.assertEqual(recover_evidence(recovered, identity,
                    "dial-control-wal-evidence")["snapshot_id"], receipt_snapshot)
                self.assertEqual(pitr(recovered, identity, physical_evidence, base["snapshot_id"],
                                      os.environ["CONTROL_POSTGRES_IMAGE"], target,
                                      {"sql": "SELECT string_agg(marker, ',' ORDER BY marker) "
                                              "FROM public.pitr_canary", "expected": "before"})["state"],
                                 "PITR_VERIFIED")

    def test_backup_and_isolated_restore(self):
        dsn = urlparse(os.environ["TEST_ADMIN_DSN"])
        api_dsn = urlparse(os.environ["TEST_API_DSN"])
        self.assertEqual(dsn.hostname, "127.0.0.1")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = root / "password"
            secret.write_text("disposable-control-restic-password")
            os.chmod(secret, 0o600)
            pgpass = root / "pgpass"
            pgpass.write_text(f"127.0.0.1:{dsn.port}:*:{dsn.username}:{dsn.password}\n"
                              f"127.0.0.1:{dsn.port}:*:{api_dsn.username}:{api_dsn.password}\n")
            os.chmod(pgpass, 0o600)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            env = {"RESTIC_REPOSITORY": str(root / "repository"), "RESTIC_PASSWORD_FILE": str(secret),
                   "BACKUP_EVIDENCE_DIR": str(evidence), "PGHOST": "127.0.0.1", "PGPORT": str(dsn.port),
                   "PGUSER": dsn.username, "PGDATABASE": dsn.path.lstrip("/"), "PGPASSFILE": str(pgpass)}
            with patch.dict(os.environ, env):
                from control_backup import run
                run(["restic", "init"])
                verified = verify(environment(offhost=False), backup(evidence)["snapshot_id"])
                self.assertEqual(verified["state"], "RESTORE_VERIFIED")
                self.assertGreaterEqual(verified["semantic_counts"]["organizations"], 2)
                self.assertEqual(evaluate("control", evidence, check_remote=True)["state"], "BACKUP_HEALTHY")
                self.assertEqual(json.loads((evidence / (verified["snapshot_id"] + ".json")).read_text())[
                    "state"], "RESTORE_VERIFIED")
                physical_evidence = root / "control-physical-evidence"
                physical_evidence.mkdir(mode=0o700)
                physical = physical_backup(physical_evidence)
                self.assertEqual(physical["state"], "BACKUP_CREATED")
                restored = physical_verify(physical_evidence, physical["snapshot_id"],
                                            os.environ["CONTROL_POSTGRES_IMAGE"])
                self.assertEqual(restored["state"], "RESTORE_VERIFIED")
                self.assertGreaterEqual(restored["semantic_counts"]["organizations"], 2)
                catalog_repository = root / "catalog-repository"
                with patch.dict(os.environ, {"RESTIC_REPOSITORY": str(catalog_repository)}):
                    run(["restic", "init"])
                catalog_dir = root / "catalog"
                catalog_dir.mkdir(mode=0o700)
                config_file = root / "catalog-config.json"
                config_file.write_text(json.dumps({
                    "version": 1, "catalog_id": "ci-control", "host_id": "ci-database",
                    "failure_domain": "ci-primary", "recovery_failure_domain": "ci-recovery",
                    "catalog_repository": str(catalog_repository), "catalog_password_file": str(secret),
                    "classes": [{"kind": kind, "evidence_dir": str(directory),
                                 "repository": str(root / "repository"), "password_file": str(secret),
                                 "max_age_hours": 36, "required_instances": []}
                                for kind, directory in (("control", evidence),
                                                        ("control-physical", physical_evidence))]}))
                os.chmod(config_file, 0o600)
                catalog = load_config(config_file, allow_local=True)
                published = publish(catalog, catalog_dir)
                self.assertEqual(published["state"], "CATALOG_PUBLISHED")
                inspected = inspect(catalog, published["snapshot_id"])
                self.assertEqual(inspected["state"], "CATALOG_INSPECTED")
                self.assertEqual(inspected["entries"], 2)
                self.assertEqual(inspected["sha256"], published["sha256"])
                evidence.rename(root / "source-evidence-unavailable")
                physical_evidence.rename(root / "source-physical-evidence-unavailable")
                self.assertEqual(inspect_latest(catalog)["sha256"], published["sha256"])
                wrong_repo = {**catalog, "classes": [{**catalog["classes"][0],
                    "repository": str(root / "missing-repository")}, catalog["classes"][1]]}
                with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
                    inspect(wrong_repo, published["snapshot_id"])
                with patch.dict(os.environ, {"PGUSER": api_dsn.username, "PGPASSFILE": str(pgpass)}):
                    with self.assertRaisesRegex(RuntimeError, "cannot see every tenant"):
                        backup(evidence)
