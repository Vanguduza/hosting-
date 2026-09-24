import sys
import unittest
import json
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from control_backup import snapshot_id
from postgres_backup import restore_probe


class ReceiptTests(unittest.TestCase):
    def test_requires_one_full_snapshot_id(self):
        snapshot = "a" * 64
        output = '{"message_type":"status","percent_done":1}\n' + \
                 '{"message_type":"summary","snapshot_id":"' + snapshot + '"}\n'
        self.assertEqual(snapshot_id(output), snapshot)
        for bad in ('{}', '{"message_type":"summary","snapshot_id":"short"}', output + output):
            with self.subTest(output=bad), self.assertRaises(RuntimeError):
                snapshot_id(bad)

    def test_restore_requires_protected_semantic_contract(self):
        instance = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "probes"
            root.mkdir(mode=0o700)
            path = root / (instance + ".json")
            with patch.dict(os.environ, {"BACKUP_PROBE_DIR": str(root)}):
                with self.assertRaisesRegex(RuntimeError, "owner-only regular file"):
                    restore_probe(instance)
                path.write_text(json.dumps({"name": "canary_row", "sql": "SELECT count(*) FROM canary",
                                            "expected": "1"}))
                os.chmod(path, 0o600)
                self.assertEqual(restore_probe(instance)["expected"], "1")
                path.write_text(json.dumps({"name": "canary_row", "sql": "DELETE FROM canary",
                                            "expected": "1"}))
                with self.assertRaisesRegex(RuntimeError, "Invalid instance restore probe"):
                    restore_probe(instance)
