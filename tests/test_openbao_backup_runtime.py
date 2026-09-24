"""Real Raft snapshot, encrypted Restic round trip, independent-cluster recovery."""
import hashlib
import json
import os
import secrets
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
sys.path.insert(0, str(ROOT / "tools"))
from openbao_backup import backup, confirm, verify


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("Disposable OpenBao Docker operation failed: " + result.stderr[-600:])
    return result.stdout.strip()


@unittest.skipUnless(os.getenv("OPENBAO_TEST_IMAGE"), "requires disposable OpenBao Raft containers")
class RaftRecovery(unittest.TestCase):
    def test_offhost_snapshot_and_independent_restore(self):
        import ssl
        names = ["dial-raft-ci-" + uuid.uuid4().hex[:9] for _ in range(2)]
        with tempfile.TemporaryDirectory(prefix="dial-raft-test-") as directory:
            root = Path(directory)
            # The disposable server's non-root UID must traverse TLS and HCL
            # mounts; the production backup credentials below stay owner-only.
            os.chmod(root, 0o711)
            certificate, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                            "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True)
            os.chmod(certificate, 0o600)
            os.chmod(key, 0o644)
            context = ssl.create_default_context(cafile=str(certificate))

            def request(port, method, path, token=None, payload=None):
                body = json.dumps(payload).encode() if payload is not None else None
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["X-Vault-Token"] = token
                req = urllib.request.Request(f"https://127.0.0.1:{port}/v1/{path}",
                                             data=body, headers=headers, method=method)
                with urllib.request.urlopen(req, context=context, timeout=15) as response:
                    raw = response.read()
                return json.loads(raw) if raw else {}

            def server(name, port):
                config = root / (name + ".hcl")
                config.write_text('ui = false\ndisable_mlock = true\n'
                                  'api_addr = "https://127.0.0.1:8200"\n'
                                  'cluster_addr = "https://127.0.0.1:8201"\n'
                                  'storage "raft" { path = "/data" node_id = "' + name + '" }\n'
                                  'listener "tcp" { address = "0.0.0.0:8200" '
                                  'tls_cert_file = "/tls/cert.pem" tls_key_file = "/tls/key.pem" }\n')
                os.chmod(config, 0o644)
                docker("volume", "create", name)
                docker("run", "--rm", "--user", "0:0", "--entrypoint", "chown", "-v", f"{name}:/data",
                       os.environ["OPENBAO_TEST_IMAGE"], "-R", "openbao:openbao", "/data")
                docker("run", "-d", "--name", name, "--user", "0:0", "-p", f"127.0.0.1:{port}:8200",
                       "-v", f"{name}:/data", "-v", f"{config}:/etc/openbao/server.hcl:ro",
                       "-v", f"{root}:/tls:ro", os.environ["OPENBAO_TEST_IMAGE"],
                       "server", "-config=/etc/openbao/server.hcl")
                deadline = time.monotonic() + 90
                while True:
                    try:
                        request(port, "GET", "sys/init")
                        break
                    except (urllib.error.URLError, TimeoutError):
                        if time.monotonic() > deadline:
                            raise RuntimeError("Raft server did not start: " + docker("logs", name)[-700:])
                        time.sleep(.5)
                init = request(port, "PUT", "sys/init", payload={"secret_shares": 1, "secret_threshold": 1})
                request(port, "PUT", "sys/unseal", payload={"key": init["keys"][0]})
                return init

            try:
                source = server(names[0], 18210)
                target = server(names[1], 18211)
                source_token, target_token = root / "source-token", root / "target-token"
                source_token.write_text(source["root_token"])
                target_token.write_text(target["root_token"])
                os.chmod(source_token, 0o600)
                os.chmod(target_token, 0o600)
                request(18210, "POST", "sys/mounts/dial", source["root_token"],
                        {"type": "kv", "options": {"version": "2"}})
                path = "dial/data/resources/" + str(uuid.uuid4())
                data = {"recovery_canary": secrets.token_hex(24)}
                request(18210, "POST", path, source["root_token"], {"data": data})
                probe = {"path": path, "sha256": hashlib.sha256(json.dumps(data, sort_keys=True,
                          separators=(",", ":")).encode()).hexdigest()}
                marker = secrets.token_hex(32)
                request(18211, "POST", "identity/entity", target["root_token"],
                        {"name": "dial-disposable-restore", "metadata": {"nonce": marker}})
                repo = root / "offsite-repository"
                restic_password = root / "restic-password"
                restic_password.write_text(secrets.token_hex(32))
                os.chmod(restic_password, 0o600)
                os.environ.update(RESTIC_REPOSITORY=str(repo), RESTIC_PASSWORD_FILE=str(restic_password),
                                  BAO_ADDR="https://127.0.0.1:18210", BAO_CA_FILE=str(certificate),
                                  BAO_BACKUP_TOKEN_FILE=str(source_token))
                subprocess.run(["restic", "init"], check=True, capture_output=True)
                evidence = root / "evidence"
                evidence.mkdir(mode=0o700)
                receipt = backup(evidence, probe)
                self.assertEqual(receipt["state"], "BACKUP_CREATED")
                with self.assertRaises(RuntimeError):
                    verify(evidence, probe, receipt["snapshot_id"], os.environ["BAO_ADDR"],
                           str(certificate), str(target_token), marker)
                restored = verify(evidence, probe, receipt["snapshot_id"], "https://127.0.0.1:18211",
                                  str(certificate), str(target_token), marker)
                self.assertEqual(restored["state"], "RESTORE_PENDING_UNSEAL")
                # The restored state has the source's barrier key and root token.
                deadline = time.monotonic() + 45
                while True:
                    try:
                        status = request(18211, "GET", "sys/seal-status")
                        if status["sealed"]:
                            request(18211, "PUT", "sys/unseal", payload={"key": source["keys"][0]})
                        result = confirm(evidence, probe, receipt["snapshot_id"],
                                         "https://127.0.0.1:18211", str(certificate))
                        break
                    except (RuntimeError, urllib.error.URLError, urllib.error.HTTPError):
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(1)
                self.assertEqual(result["state"], "RESTORE_VERIFIED")
                self.assertNotEqual(receipt["cluster_id"], restored["restore_target_cluster_id"])
            finally:
                for name in names:
                    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
                    subprocess.run(["docker", "volume", "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    unittest.main()
