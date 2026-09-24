"""Catalog fails closed on missing inventory and unsafe recovery configuration."""
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from recovery_catalog import backup_entries, load_config, repository


class RecoveryCatalogContracts(unittest.TestCase):
    def test_offhost_and_protected_config(self):
        with self.assertRaisesRegex(ValueError, "remote"):
            repository("/var/local/restic")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "config.json"
            path.write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "owner-only"):
                load_config(path)
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(ValueError, "configuration"):
                load_config(path)

    def test_live_node_inventory_must_match_required_set(self):
        instance = str(uuid.uuid4())
        item = {"kind": "postgres", "required_instances": [instance], "repository": "sftp:backup:/db",
                "password_file": "/unused", "evidence_dir": "/unused", "max_age_hours": 36}
        with patch("recovery_catalog.inventory", return_value=set()):
            with self.assertRaisesRegex(RuntimeError, "Live inventory differs"):
                backup_entries({"classes": [item]})


if __name__ == "__main__":
    unittest.main()
