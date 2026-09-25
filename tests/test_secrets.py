import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
sys.path.insert(0, str(ROOT / "services/api"))
from node_agent.core import Node, OperationError
from hosting_api.secrets import OpenBao, SecretError, private_file


class SecretsTests(unittest.TestCase):
    def test_node_delivery_replay_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3")
            data = {"resource_id": str(uuid.uuid4()), "version": 1,
                    "values": {"postgres_password": "hardened-example-value"}}
            self.assertEqual(node.deliver_secrets(data)["state"], "STORED")
            stored = node.secrets_dir / data["resource_id"] / "1" / "postgres_password"
            self.assertEqual(stored.read_text(), data["values"]["postgres_password"])
            self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
            self.assertEqual(node.deliver_secrets(data)["state"], "STORED")
            with self.assertRaises(OperationError):
                node.deliver_secrets({**data, "values": {"postgres_password": "changed"}})
            with self.assertRaises(ValueError):
                node.deliver_secrets({**data, "version": True})
            with self.assertRaises(ValueError):
                node.deliver_secrets({**data, "values": {"../bad": "value"}})

    def test_openbao_cas_and_pinned_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in (("role", "role-1"), ("secret-id", "id-1")):
                file = root / name
                file.write_text(content)
                os.chmod(file, 0o600)
            with patch("hosting_api.secrets.ssl.create_default_context", return_value=object()):
                bao = OpenBao("https://bao.example.org", "ca.pem", root / "role", root / "secret-id")
            calls = []
            resource = uuid.uuid4()
            def fake_request(method, path, payload=None, token=None):
                calls.append((method, path, payload, token))
                if path == "auth/approle/login":
                    self.assertEqual(payload, {"role_id": "role-1", "secret_id": "id-1"})
                    return {"auth": {"client_token": "limited-token"}}
                self.assertEqual(token, "limited-token")
                if method == "POST":
                    return {"data": {"version": payload["options"]["cas"] + 1}}
                return {"data": {"metadata": {"version": 1}, "data": {"postgres_password": "secret"}}}
            bao.request = fake_request
            self.assertEqual(bao.put(resource, {"postgres_password": "secret"}, 0), 1)
            self.assertEqual(bao.get(resource, version=1), (1, {"postgres_password": "secret"}))
            self.assertEqual(calls[1][1], "dial/data/resources/" + str(resource))
            self.assertEqual(calls[1][2]["options"], {"cas": 0})
            self.assertTrue(calls[3][1].endswith("?version=1"))
            os.chmod(root / "role", 0o644)
            with self.assertRaises(SecretError):
                private_file(root / "role")


if __name__ == "__main__":
    unittest.main()
