"""Runs only in disposable CI against a TLS OpenBao dev instance."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_api.secrets import OpenBao, SecretError


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("Disposable OpenBao container failed: " + " ".join(args[:3]) + ": " + result.stderr[-500:])
    return result.stdout


@unittest.skipUnless(os.environ.get("OPENBAO_TEST_IMAGE"), "requires disposable OpenBao TLS container")
class OpenBaoIntegration(unittest.TestCase):
    def test_approle_cas_version_and_no_secret_receipt(self):
        name = "dial-ci-bao-" + uuid.uuid4().hex[:8]
        with tempfile.TemporaryDirectory(prefix="dial-bao-ci-") as directory:
            root = Path(directory)
            try:
                docker("run", "-d", "--name", name, "-p", "127.0.0.1:18200:8200",
                       os.environ["OPENBAO_TEST_IMAGE"], "server", "-dev-tls",
                       "-dev-listen-address=0.0.0.0:8200", "-dev-root-token-id=disposable-ci-root",
                       "-dev-tls-cert-dir=/tmp/dial-ci-certs")
                deadline = time.monotonic() + 60
                while True:
                    try:
                        docker("cp", name + ":/tmp/dial-ci-certs", str(root / "certs"))
                        break
                    except RuntimeError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(1)
                candidates = [path for path in (root / "certs").rglob("*") if path.is_file()
                              and b"BEGIN CERTIFICATE" in path.read_bytes() and "ca" in path.name.lower()]
                self.assertTrue(candidates, "OpenBao did not produce a development CA")
                import ssl
                context = ssl.create_default_context(cafile=str(candidates[0]))
                address = "https://127.0.0.1:18200"
                def root_request(method, path, data=None):
                    request = urllib.request.Request(address + "/v1/" + path,
                        data=json.dumps(data).encode() if data is not None else None,
                        headers={"X-Vault-Token": "disposable-ci-root", "Content-Type": "application/json"},
                        method=method)
                    with urllib.request.urlopen(request, context=context, timeout=3) as response:
                        return json.load(response) if response.status != 204 else {}
                while True:
                    try:
                        root_request("GET", "sys/health")
                        break
                    except (urllib.error.URLError, TimeoutError):
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(1)
                root_request("POST", "sys/mounts/dial", {"type": "kv", "options": {"version": "2"}})
                root_request("POST", "sys/auth/approle", {"type": "approle"})
                root_request("PUT", "sys/policies/acl/dial-worker", {"policy":
                    'path "dial/data/resources/*" { capabilities = ["create", "read", "update"] }'})
                root_request("POST", "auth/approle/role/worker", {"policies": ["dial-worker"],
                                                                "token_ttl": "5m", "token_max_ttl": "15m"})
                role = root_request("GET", "auth/approle/role/worker/role-id")["data"]["role_id"]
                secret_id = root_request("POST", "auth/approle/role/worker/secret-id", {})["data"]["secret_id"]
                for filename, value in (("role", role), ("secret-id", secret_id)):
                    path = root / filename
                    path.write_text(value)
                    os.chmod(path, 0o600)
                bao = OpenBao(address, str(candidates[0]), str(root / "role"), str(root / "secret-id"))
                resource = uuid.uuid4()
                self.assertEqual(bao.put(resource, {"postgres_password": "ci-revision-one"}, 0), 1)
                with self.assertRaises(SecretError):
                    bao.put(resource, {"postgres_password": "duplicate-create"}, 0)
                self.assertEqual(bao.put(resource, {"postgres_password": "ci-revision-two"}, 1), 2)
                self.assertEqual(bao.get(resource, version=1), (1, {"postgres_password": "ci-revision-one"}))
                self.assertEqual(bao.get(resource, version=2), (2, {"postgres_password": "ci-revision-two"}))
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    unittest.main()
