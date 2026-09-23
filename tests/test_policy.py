import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
sys.path.insert(0, str(ROOT / "tools"))
from hosting_api.policy import allowed, valid_name
from packcheck import check


class PolicyTests(unittest.TestCase):
    def test_viewer_cannot_create(self):
        self.assertTrue(allowed("viewer", "project:read"))
        self.assertFalse(allowed("viewer", "project:create"))
        self.assertFalse(allowed("unknown", "project:read"))

    def test_reject_bad_project_names(self):
        for value in ("", "../x", "-bad", "x" * 81, None, 10, "hello\nworld"):
            with self.subTest(value=value):
                self.assertFalse(valid_name(value))
        self.assertTrue(valid_name("Dial Groceries"))

    def test_pack_status_cannot_claim_unverified_production(self):
        self.assertEqual(check(ROOT), [])
        manifest = json.loads((ROOT / "development-pack/PACK_MANIFEST.json").read_text())
        self.assertFalse(manifest["production_qualified"])
        self.assertFalse(manifest["build_ready"])


if __name__ == "__main__":
    unittest.main()
