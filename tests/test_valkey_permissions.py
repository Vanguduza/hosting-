import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError
from node_agent.valkey import acl_mount, provision


class ValkeyPermissionsTests(unittest.TestCase):
    def test_retry_repairs_old_umask_permissions_and_rejects_changed_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            node = Node(Path(temporary) / "state.sqlite3")
            instance = str(uuid.uuid4())
            path = acl_mount(node, instance, "A" * 48)
            path.chmod(0o600)
            self.assertEqual(acl_mount(node, instance, "A" * 48).stat().st_mode & 0o777, 0o444)
            with self.assertRaisesRegex(OperationError, "immutable secret"):
                acl_mount(node, instance, "B" * 48)
            path.unlink()
            foreign = Path(temporary) / "foreign"
            foreign.write_text("do not change")
            path.symlink_to(foreign)
            with self.assertRaises(OSError):
                acl_mount(node, instance, "A" * 48)
            self.assertEqual(foreign.read_text(), "do not change")

    def test_private_umask_still_allows_container_uid_to_read_acl(self):
        instance, app = str(uuid.uuid4()), str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as temporary:
            def runner(args, timeout):
                if args[1] == "pull":
                    acl = node.secrets_dir / "vk-acl" / (instance + ".acl")
                    self.assertEqual(acl.stat().st_mode & 0o777, 0o444)
                    self.assertEqual(acl.parent.stat().st_mode & 0o777, 0o700)
                    self.assertIn("user default off", acl.read_text())
                    raise OperationError("stop before Docker")
                raise OperationError("fixture absent")

            node = Node(Path(temporary) / "state.sqlite3", runner=runner)
            node.deliver_secrets({"resource_id": instance, "version": 1, "values": {"app_password": "A" * 48}})
            old = os.umask(0o077)
            try:
                with patch.dict(os.environ, {"NODE_VALKEY_IMAGE": "valkey/valkey:9@sha256:" + "a" * 64}):
                    with self.assertRaisesRegex(OperationError, "stop before Docker"):
                        provision(node, {"instance_id": instance, "application_id": app,
                                         "memory_mb": 128, "cpu_milli": 100, "secret_version": 1})
            finally:
                os.umask(old)


if __name__ == "__main__":
    unittest.main()
