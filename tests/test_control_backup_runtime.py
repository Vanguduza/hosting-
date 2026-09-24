"""Disposable PostgreSQL and Restic proof for the control backup operator."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from backup_health import evaluate
from control_backup import backup, environment, verify
from control_physical_backup import backup as physical_backup, verify as physical_verify
from recovery_catalog import load_config, publish, inspect


@unittest.skipUnless(os.environ.get("TEST_ADMIN_DSN") and os.environ.get("CONTROL_RUNTIME_BACKUP"),
                     "requires disposable migrated PostgreSQL and Restic")
class ControlBackupRuntime(unittest.TestCase):
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
                wrong_repo = {**catalog, "classes": [{**catalog["classes"][0],
                    "repository": str(root / "missing-repository")}, catalog["classes"][1]]}
                with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
                    inspect(wrong_repo, published["snapshot_id"])
                with patch.dict(os.environ, {"PGUSER": api_dsn.username, "PGPASSFILE": str(pgpass)}):
                    with self.assertRaisesRegex(RuntimeError, "cannot see every tenant"):
                        backup(evidence)
