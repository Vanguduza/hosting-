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
                with patch.dict(os.environ, {"PGUSER": api_dsn.username, "PGPASSFILE": str(pgpass)}):
                    with self.assertRaisesRegex(RuntimeError, "cannot see every tenant"):
                        backup(evidence)
