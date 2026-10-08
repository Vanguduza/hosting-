import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
sys.path.insert(0, str(ROOT / "tools"))
from hosting_api.policy import allowed, valid_name
from hosting_api.worker import private_endpoint
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

    def test_node_endpoint_is_private_and_literal(self):
        self.assertEqual(private_endpoint({"endpoint": "https://100.75.0.2:8443",
                                           "server_name": "100.75.0.2"}).hostname, "100.75.0.2")
        for endpoint, name in (("https://1.1.1.1:8443", "1.1.1.1"),
                               ("https://node.example:8443", "node.example"),
                               ("https://10.0.0.2:8443/path", "10.0.0.2"),
                               ("http://10.0.0.2:8443", "10.0.0.2")):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                private_endpoint({"endpoint": endpoint, "server_name": name})


if __name__ == "__main__":
    unittest.main()
