import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_api.domains import valid_hostname, txt_proves, address_proves
from hosting_api.worker import publish


class DomainsTests(unittest.TestCase):
    def test_hostname_and_txt_proof(self):
        for host in ("evil.example.org`) || Host(`x.org", "EXAMPLE.org", "foo..org", "foo.local", "-a.org"):
            self.assertFalse(valid_hostname(host))
        self.assertTrue(valid_hostname("app.example.org"))
        class Resolver:
            lifetime = None
            def resolve(self, name, kind, search):
                self.values = (name, kind, search)
                return [type("TXT", (), {"strings": [b"dial-hosting=secret"]})()]
        resolver = Resolver()
        self.assertTrue(txt_proves("app.example.org", "secret", resolver))
        self.assertEqual(resolver.values, ("_dial-verify.app.example.org", "TXT", False))
        self.assertFalse(txt_proves("app.example.org", "wrong", resolver))

    def test_dns_and_public_probe_gate_route(self):
        node = {"public_ipv4": "8.8.8.8"}
        release = {"id": "00000000-0000-0000-0000-000000000001",
                   "application_id": "00000000-0000-0000-0000-000000000002",
                   "previous_release_id": None, "port": 8080, "health_path": "/health"}
        domain = {"hostname": "app.example.org", "verification_token": "secret", "verified_at": "now"}
        with patch("hosting_api.worker.txt_proves", return_value=True), \
                patch("hosting_api.worker.address_proves", return_value=True), \
                patch("hosting_api.worker.route_request") as route, \
                patch("hosting_api.worker.public_probe", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Public HTTPS"):
                publish(node, release, domain, {}, probe_seconds=0)
            self.assertEqual(route.call_count, 2)
            self.assertTrue(route.call_args.kwargs["remove"])
        with patch("hosting_api.worker.txt_proves", return_value=True), \
                patch("hosting_api.worker.address_proves", return_value=True), \
                patch("hosting_api.worker.route_request") as route, \
                patch("hosting_api.worker.public_probe", return_value=True):
            self.assertEqual(publish(node, release, domain, {})["state"], "SERVING")
            route.assert_called_once()


if __name__ == "__main__":
    unittest.main()
