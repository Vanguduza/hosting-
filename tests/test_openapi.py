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
    def test_portal_assets_are_served_without_identity_but_do_not_bypass_api_auth(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            for path in ("/portal", "/portal/portal.mjs", "/portal/portal.css"):
                connection.request("GET", path)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))
                self.assertTrue(response.read())
            # No JWKS client is needed for static assets. Unauthorized API reads
            # still enter authenticate, independently of the portal's browser UI.
            server.jwks = None
            connection.request("GET", "/v1/organizations")
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(json.loads(response.read()), {"error": "unauthorized"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

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
        self.assertEqual(len(paths), 33)
        self.assertEqual(sum(method in ("get", "post") for item in paths.values()
                             for method in item), 44)
        self.assertIn("/v1/organizations/{organization_id}/applications/{application_id}/health", paths)
        self.assertIn("/v1/organizations/{organization_id}/applications/{application_id}/health/incidents", paths)
        self.assertIn("/v1/organizations/{organization_id}/quotas", paths)
        self.assertNotIn("/v1/supabase", paths)
        self.assertEqual(paths["/v1/organizations/{organization_id}/team/invitations/revoke"]
                         ["post"]["requestBody"]["content"]["application/json"]["schema"]["required"],
                         ["invitation_id"])
