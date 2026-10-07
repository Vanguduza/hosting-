import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
sys.path.insert(0, str(ROOT / "tools"))
from hosting_api.registration import registration_name, canonical_uuid
from hosting_api.__main__ import service_route_allowed
from hosting_cli import parser, request_for


class RegistrationContracts(unittest.TestCase):
    def test_registration_is_limited_to_root_names_in_supported_namespaces(self):
        for name in ("shop.com", "shop.co.zw", "a.co.zw", "shop-1.com"):
            self.assertTrue(registration_name(name))
        for name in ("app.shop.com", "shop.org", "shop.co.zw\n", "Shop.com", "-shop.com", "shop-.com", "a" * 64 + ".com", None):
            self.assertFalse(registration_name(name))
        self.assertIsNone(canonical_uuid(True))

    def test_operator_client_keeps_stable_request_and_quote_identifiers(self):
        org = "11111111-1111-4111-8111-111111111111"
        quote = "22222222-2222-4222-8222-222222222222"
        args = parser().parse_args(["--base-url", "https://control.example:443", "registration-request", org,
                                    "shop.co.zw", "1", "registrant://customer-1", "--idempotency-key", quote])
        path, body, key = request_for(args)
        self.assertEqual(key, quote)
        self.assertEqual(body["term_years"], 1)
        self.assertFalse(service_route_allowed(path, "GET"))
        self.assertFalse(service_route_allowed(path, "POST"))
        args = parser().parse_args(["--base-url", "https://control.example:443", "registration-approve", org, org, quote, "a" * 64])
        path, body, key = request_for(args)
        self.assertTrue(path.endswith("/approve"))
        self.assertEqual(body["confirm"], "approve_registration_quote")


if __name__ == "__main__":
    unittest.main()
