"""Encrypted Restic recovery of a live receiver SQLite database."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from alert_receiver import accept, connect
from alert_receiver_backup import backup, configuration, health, restore


@unittest.skipUnless(os.environ.get("ALERT_RECEIVER_RUNTIME") and shutil.which("restic"),
                     "requires disposable Restic repository")
class AlertReceiverRecoveryTests(unittest.TestCase):
    def test_restored_queue_matches_live_alert_and_survives_source_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database, repo, password, evidence, temp, config_path = (
                root / name for name in ("receiver.sqlite3", "restic", "password",
                                         "evidence", "tmp", "backup.json"))
            evidence.mkdir(mode=0o700)
            temp.mkdir(mode=0o700)
            password.write_text("disposable-receiver-recovery-password")
            password.chmod(0o600)
            with closing(connect(database)) as db:
                alert = {"id": str(uuid.uuid4()), "check": "node", "sequence": 1,
                         "state": "DOWN", "created_at": 1780000000}
                accept(db, alert, json.dumps(alert).encode())
            config_path.write_text(json.dumps({"database": str(database), "repository": str(repo),
                                               "password_file": str(password),
                                               "evidence_dir": str(evidence), "tmp_dir": str(temp)}))
            config_path.chmod(0o600)
            subprocess.run(["restic", "init"], check=True, capture_output=True,
                           env={**os.environ, "RESTIC_REPOSITORY": str(repo),
                                "RESTIC_PASSWORD_FILE": str(password)})
            config = configuration(config_path, allow_local=True)
            receipt = backup(config)
            self.assertEqual(receipt["semantic"]["alerts"], 1)
            database.rename(root / "source-unavailable.sqlite3")
            recovery = configuration(config_path, allow_local=True, require_source=False)
            restored = restore(recovery, receipt["snapshot_id"])
            self.assertEqual(restored["state"], "RESTORE_VERIFIED")
            self.assertEqual(health(recovery)["snapshot_id"], receipt["snapshot_id"])
            self.assertEqual(restore(recovery, receipt["snapshot_id"])["semantic"], receipt["semantic"])
            with self.assertRaisesRegex(RuntimeError, "missing from encrypted repository"):
                with patch("alert_receiver_backup.restic", return_value="[]"):
                    health(recovery)


if __name__ == "__main__":
    unittest.main()
