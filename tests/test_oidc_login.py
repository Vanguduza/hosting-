"""Real signed-token and HTTP boundaries for public-client OIDC login."""
import http.client
import base64
import hashlib
import io
import json
import os
import sys
import threading
import time
import unittest
from contextlib import redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import Handler
from hosting_api.oidc_login import configuration, public_configuration, receipt, token_request, NoRedirect, MAX_RESPONSE, LOGIN_VARS

CONFIG = {"OIDC_ISSUER": "https://iam.example.test", "OIDC_AUDIENCE": "control-api", "OIDC_SERVICE_AUDIENCE": "control-machine",
    "OIDC_LOGIN_CLIENT_ID": "portal-client", "OIDC_AUTHORIZATION_URL": "https://iam.example.test/oauth/v2/authorize",
    "OIDC_TOKEN_URL": "https://iam.example.test/oauth/v2/token", "OIDC_LOGIN_REDIRECT_URI": "https://control.example.test:443/portal",
    "OIDC_LOGIN_SCOPES": "openid profile offline_access"}
NONCE = "n" * 43


class LoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=cls.key.public_key()))

    def setUp(self):
        self.config = patch.dict(os.environ, CONFIG)
        self.config.start()
        self.addCleanup(self.config.stop)

    def token(self, audience, **overrides):
        now = int(time.time())
        claims = {"iss": CONFIG["OIDC_ISSUER"], "aud": audience, "sub": "human-1", "iat": now, "exp": now + 3600}
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test"})

    def payload(self, *, access=None, identity=None):
        return {"token_type": "Bearer", "access_token": access or self.token("control-api"),
            "id_token": identity or self.token("portal-client", nonce=NONCE), "expires_in": 3600, "refresh_token": "private-refresh"}

    def test_disabled_config_and_partial_or_cross_origin_config_fail_closed(self):
        with patch.dict(os.environ, {**{name: "" for name in LOGIN_VARS}, "OIDC_LOGIN_SCOPES": ""}):
            self.assertEqual(public_configuration(), {"enabled": False})
        for changes in ({"OIDC_TOKEN_URL": ""}, {"OIDC_TOKEN_URL": "https://other.example.test/token"},
                        {"OIDC_AUTHORIZATION_URL": "http://iam.example.test/auth"},
                        {"OIDC_TOKEN_URL": "https://user:secret@iam.example.test/token"},
                        {"OIDC_LOGIN_REDIRECT_URI": "https://control.example.test/elsewhere"},
                        {"OIDC_LOGIN_REDIRECT_URI": "https://control.example.test/portal?redirect=bad"},
                        {"OIDC_LOGIN_SCOPES": "profile"}, {"OIDC_LOGIN_SCOPES": "openid openid"}):
            with self.subTest(changes=changes), patch.dict(os.environ, changes), self.assertRaises(RuntimeError):
                configuration()
        self.assertNotIn("token_url", public_configuration())

    def test_signed_identity_nonce_subject_issuer_and_human_audience_are_bound(self):
        accepted = receipt(self.payload(), self.jwks, configuration(), NONCE)
        self.assertEqual(accepted["subject"], "human-1")
        self.assertNotIn("id_token", accepted)
        self.assertEqual(receipt(self.payload(access=self.token(["control-api", "portal-client"])),
                                 self.jwks, configuration(), NONCE)["subject"], "human-1")
        for payload in (self.payload(identity=self.token("portal-client", nonce="x" * 43)),
                        self.payload(identity=self.token("another-client", nonce=NONCE)),
                        self.payload(identity=self.token("portal-client", nonce=NONCE, sub="other")),
                        self.payload(identity=self.token(["portal-client", "other"], nonce=NONCE)),
                        self.payload(access=self.token("control-machine", client_id="machine")),
                        self.payload(access=self.token(["control-api", "control-machine"])),
                        self.payload(access=self.token("control-api", iss="https://other.example.test")),
                        self.payload(access=self.token("control-api", exp=int(time.time()) - 10))):
            with self.subTest(payload=payload.keys()), self.assertRaises(PermissionError):
                receipt(payload, self.jwks, configuration(), NONCE)

    def test_unsigned_tokens_and_omitted_identity_are_rejected(self):
        payload = self.payload()
        payload["access_token"] = jwt.encode({"sub": "human-1"}, key="", algorithm="none")
        with self.assertRaises(PermissionError):
            receipt(payload, self.jwks, configuration(), NONCE)
        payload = self.payload()
        del payload["id_token"]
        with self.assertRaises(PermissionError):
            receipt(payload, self.jwks, configuration(), NONCE)

    def test_access_token_hash_is_verified_when_issuer_supplies_it(self):
        access = self.token("control-api")
        access_hash = base64.urlsafe_b64encode(hashlib.sha256(access.encode()).digest()[:16]).rstrip(b"=").decode()
        accepted = self.payload(access=access, identity=self.token("portal-client", nonce=NONCE, at_hash=access_hash))
        self.assertEqual(receipt(accepted, self.jwks, configuration(), NONCE)["subject"], "human-1")
        with self.assertRaises(PermissionError):
            receipt(self.payload(access=access, identity=self.token("portal-client", nonce=NONCE, at_hash="incorrect")),
                    self.jwks, configuration(), NONCE)

    def test_refresh_accepts_optional_identity_and_rotates_only_same_subject(self):
        payload = self.payload()
        del payload["id_token"]
        payload["refresh_token"] = "rotated-refresh"
        self.assertEqual(receipt(payload, self.jwks, configuration(), NONCE, subject="human-1",
                                 refresh_token="old-refresh")["refresh_token"], "rotated-refresh")
        del payload["refresh_token"]
        self.assertEqual(receipt(payload, self.jwks, configuration(), NONCE, subject="human-1",
                                 refresh_token="old-refresh")["refresh_token"], "old-refresh")
        with self.assertRaises(PermissionError):
            receipt(payload, self.jwks, configuration(), NONCE, subject="other-human")
        with self.assertRaises(PermissionError):
            receipt(self.payload(identity=self.token("portal-client", nonce="bad")), self.jwks,
                    configuration(), NONCE, subject="human-1")

    def test_expiry_and_refresh_response_types_are_strict(self):
        for changes in ({"expires_in": True}, {"expires_in": 0}, {"expires_in": 86401}, {"refresh_token": "token\n"}):
            with self.subTest(changes=changes), self.assertRaises((PermissionError, ValueError)):
                receipt({**self.payload(), **changes}, self.jwks, configuration(), NONCE)

    def test_provider_transport_is_bounded_fixed_and_refuses_redirects(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        response.read.return_value = json.dumps(self.payload()).encode()
        fields = {"grant_type": "authorization_code", "code": "private-code", "code_verifier": "v" * 43,
                  "client_id": "portal-client", "redirect_uri": CONFIG["OIDC_LOGIN_REDIRECT_URI"]}
        token_request(configuration(), fields, opener)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, CONFIG["OIDC_TOKEN_URL"])
        self.assertEqual(parse_qs(request.data.decode()), {key: [value] for key, value in fields.items()})
        response.read.assert_called_once_with(MAX_RESPONSE + 1)
        for raw in (b"x" * (MAX_RESPONSE + 1), b'{"token_type":"Bearer","token_type":"Bearer"}'):
            response.read.return_value = raw
            with self.assertRaises(ValueError):
                token_request(configuration(), fields, opener)
        with self.assertRaises(PermissionError):
            NoRedirect().redirect_request(None, None, 302, None, {}, "https://other.example.test")

    def test_http_origin_code_exchange_refresh_and_sanitized_errors(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.jwks = self.jwks
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        def request(path, body=None, origin="https://control.example.test"):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                conn.request("POST" if body is not None else "GET", path, body=json.dumps(body) if body is not None else None,
                    headers={"Content-Type": "application/json", "Origin": origin})
                response = conn.getresponse()
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertIsNone(response.getheader("Set-Cookie"))
                return response.status, json.loads(response.read())
            finally:
                conn.close()
        try:
            body = {"code": "private-code", "code_verifier": "v" * 43, "nonce": NONCE}
            with patch("hosting_api.oidc_login.token_request", return_value=self.payload()) as exchange:
                self.assertTrue(request("/v1/auth/config")[1]["enabled"])
                self.assertEqual(request("/v1/auth/exchange", body, "https://attacker.example.test")[0], 403)
                exchange.assert_not_called()
                self.assertEqual(request("/v1/auth/exchange", {**body, "code_verifier": "short"})[0], 400)
                exchange.assert_not_called()
                status, signed_in = request("/v1/auth/exchange", body)
                self.assertEqual((status, signed_in["subject"]), (200, "human-1"))
                self.assertEqual(exchange.call_args.args[1]["redirect_uri"], CONFIG["OIDC_LOGIN_REDIRECT_URI"])
                status, renewed = request("/v1/auth/refresh", {"refresh_token": "private-refresh", "nonce": NONCE, "subject": "human-1"})
                self.assertEqual((status, renewed["subject"]), (200, "human-1"))
                self.assertEqual(request("/v1/auth/refresh", {"refresh_token": "private-refresh", "nonce": NONCE, "subject": "other"})[0], 401)
            with patch("hosting_api.oidc_login.token_request", side_effect=RuntimeError("private provider diagnostic")):
                self.assertEqual(request("/v1/auth/exchange", body), (503, {"error": "login_unavailable"}))
            self.assertEqual(request("/v1/organizations"), (401, {"error": "unauthorized"}))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_callback_code_and_state_are_absent_from_server_logs(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            output = io.StringIO()
            with redirect_stderr(output):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/portal?code=private-authorization-code&state=private-state")
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                conn.close()
            self.assertIn("/portal", output.getvalue())
            self.assertNotIn("private-authorization-code", output.getvalue())
            self.assertNotIn("private-state", output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
