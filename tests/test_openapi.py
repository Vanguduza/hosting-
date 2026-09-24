"""The published API contract must be reachable without an OIDC token."""
import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_api.__main__ import Handler
from hosting_api.openapi import document
from openapi_spec_validator import validate


class ApiContractTests(unittest.TestCase):
    def test_public_contract_is_served_and_describes_real_auth_boundary(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/openapi.json")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            contract = json.loads(response.read())
            self.assertEqual(contract, document())
            validate(contract)
            self.assertEqual(contract["openapi"], "3.1.0")
            self.assertEqual(contract["security"], [{"bearerAuth": []}])
            self.assertEqual(contract["paths"]["/live"]["get"]["security"], [])
            self.assertEqual(contract["paths"]["/openapi.json"]["get"]["security"], [])
            self.assertNotIn("security", contract["paths"]["/ready"]["get"])
            for path, item in contract["paths"].items():
                variables = {part[1:-1] for part in path.split("/") if part.startswith("{")}
                self.assertEqual(variables, {p["name"] for p in item.get("parameters", [])})
                for method, operation in item.items():
                    if method in ("get", "post"):
                        self.assertIn("responses", operation)
                        self.assertIn("default", operation["responses"])
                        self.assertEqual("requestBody" in operation, method == "post")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_only_implemented_operations_are_advertised(self):
        paths = document()["paths"]
        self.assertEqual(len(paths), 21)
        self.assertEqual(sum(method in ("get", "post") for item in paths.values()
                             for method in item), 30)
        self.assertNotIn("/v1/supabase", paths)
        self.assertEqual(paths["/v1/organizations/{organization_id}/team/invitations/revoke"]
                         ["post"]["requestBody"]["content"]["application/json"]["schema"]["required"],
                         ["invitation_id"])
