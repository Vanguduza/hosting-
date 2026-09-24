import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import authenticate, service_route_allowed


class FakeJWKS:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=self.key)


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()

    def token(self, **overrides):
        payload = {"iss": "https://iam.example.test", "aud": "dial-control",
                   "sub": "user-123", "iat": 1700000000, "exp": 4102444800}
        payload.update(overrides)
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": "test-key"})

    def test_valid_signature_and_audience(self):
        with patch.dict(os.environ, {"OIDC_ISSUER": "https://iam.example.test", "OIDC_AUDIENCE": "dial-control",
                                  "OIDC_SERVICE_AUDIENCE": "dial-machine"}):
            identity = authenticate("Bearer " + self.token(), FakeJWKS(self.public_key))
            self.assertEqual((identity.sub, identity.client_id), ("user-123", None))

    def test_cross_audience_token_denied(self):
        with patch.dict(os.environ, {"OIDC_ISSUER": "https://iam.example.test", "OIDC_AUDIENCE": "dial-control",
                                  "OIDC_SERVICE_AUDIENCE": "dial-machine"}):
            with self.assertRaises(PermissionError):
                authenticate("Bearer " + self.token(aud="hosted-app"), FakeJWKS(self.public_key))

    def test_unsigned_and_missing_claims_denied(self):
        with patch.dict(os.environ, {"OIDC_ISSUER": "https://iam.example.test", "OIDC_AUDIENCE": "dial-control",
                                  "OIDC_SERVICE_AUDIENCE": "dial-machine"}):
            with self.assertRaises(PermissionError):
                authenticate("Bearer " + jwt.encode({"sub": "user-123"}, key="", algorithm="none"),
                             FakeJWKS(self.public_key))
            with self.assertRaises(PermissionError):
                authenticate(None, FakeJWKS(self.public_key))

    def test_machine_audience_is_separate_and_requires_client_id(self):
        with patch.dict(os.environ, {"OIDC_ISSUER": "https://iam.example.test", "OIDC_AUDIENCE": "dial-control",
                                  "OIDC_SERVICE_AUDIENCE": "dial-machine"}):
            identity = authenticate("Bearer " + self.token(aud="dial-machine", client_id="ci-deployer"),
                                    FakeJWKS(self.public_key))
            self.assertEqual((identity.sub, identity.client_id), ("user-123", "ci-deployer"))
            for claims in ({"aud": "dial-machine"}, {"aud": ["dial-control", "dial-machine"],
                           "client_id": "ci-deployer"}, {"aud": "another-app", "client_id": "ci-deployer"}):
                with self.assertRaises(PermissionError):
                    authenticate("Bearer " + self.token(**claims), FakeJWKS(self.public_key))

    def test_machine_routes_exclude_membership_and_privileged_mutations(self):
        release = "/v1/organizations/" + "a" * 36 + "/applications/" + "b" * 36 + "/releases"
        for method in ("GET", "POST"):
            self.assertTrue(service_route_allowed(release, method))
        for path, method in (("/v1/team/invitations/accept", "POST"),
                             ("/v1/organizations/" + "a" * 36 + "/service-accounts", "POST"),
                             (release.removesuffix("/releases") + "/rollback", "POST"),
                             (release.removesuffix("/releases") + "/traffic", "POST"),
                             ("/v1/organizations", "GET"), (release, "DELETE")):
            self.assertFalse(service_route_allowed(path, method))
