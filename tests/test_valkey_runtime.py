"""Disposable Valkey service proof: authenticated RESP, persistence, and isolation."""
import json
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError
from node_agent.valkey import names, probe, provision


def wire(ip, *args):
    with socket.create_connection((ip, 6379), timeout=3) as conn:
        conn.settimeout(3)
        result = b""
        for command in args:
            data = b"*" + str(len(command)).encode() + b"\r\n"
            for value in command:
                value = value.encode()
                data += b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"
            conn.sendall(data)
            result = conn.recv(512)
        return result


@unittest.skipUnless(os.environ.get("VALKEY_RUNTIME_IMAGE"), "requires disposable Docker Valkey image")
class ValkeyRuntime(unittest.TestCase):
    def test_persistent_private_authenticated_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            node = Node(Path(temp) / "state.sqlite3")
            instance, app, release = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
            foreign_app, foreign_release = str(uuid.uuid4()), str(uuid.uuid4())
            password = "A" * 48
            node.deliver_secrets({"resource_id": instance, "version": 1,
                                  "values": {"app_password": password}})
            payload = {"instance_id": instance, "application_id": app,
                       "memory_mb": 128, "cpu_milli": 250, "secret_version": 1}
            container, network, volume = names(instance)
            previous = os.environ.get("NODE_VALKEY_IMAGE")
            os.environ["NODE_VALKEY_IMAGE"] = os.environ["VALKEY_RUNTIME_IMAGE"]
            try:
                ready = provision(node, payload)
                self.assertEqual(ready["state"], "READY_PRIVATE")
                obj = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
                self.assertEqual(obj["HostConfig"]["PortBindings"], {})
                self.assertTrue(json.loads(subprocess.check_output(["docker", "network", "inspect", network]))[0]["Internal"])
                ip = obj["NetworkSettings"]["Networks"][network]["IPAddress"]
                probe(ip, password)
                self.assertTrue(wire(ip, ["PING"]).startswith(b"-NOAUTH"))
                self.assertTrue(wire(ip, ["AUTH", "dial_app", "wrong"]).startswith(b"-WRONGPASS"))
                self.assertEqual(wire(ip, ["AUTH", "dial_app", password], ["SET", "key", "durable"]), b"+OK\r\n")
                self.assertTrue(wire(ip, ["AUTH", "dial_app", password], ["FLUSHALL"]).startswith(b"-NOPERM"))
                self.assertEqual(wire(ip, ["AUTH", "dial_app", password], ["GET", "key"]), b"$7\r\ndurable\r\n")
                app_receipt = node.deploy({"operation_id": str(uuid.uuid4()), "application_id": app,
                                           "release_id": release, "image": os.environ["VALKEY_RUNTIME_WEB_IMAGE"],
                                           "port": 8080, "health_path": "/health", "memory_mb": 128,
                                           "cpu_milli": 100, "valkey_id": instance, "valkey_version": 1})
                self.assertEqual(app_receipt["state"], "HEALTHY_PRIVATE")
                workload = json.loads(subprocess.check_output(["docker", "inspect", node.container(release)]))[0]
                self.assertIn(network, workload["NetworkSettings"]["Networks"])
                self.assertIn(node.application_network(app), workload["NetworkSettings"]["Networks"])
                self.assertIn("CACHE_PASSWORD_FILE=/run/secrets/valkey_password", workload["Config"]["Env"])
                client_script = (
                    "import os,socket; "
                    "p=open(os.environ['CACHE_PASSWORD_FILE']).read().encode(); "
                    "s=socket.create_connection((os.environ['CACHE_HOST'],6379),3); "
                    "s.sendall(b'*3\\r\\n$4\\r\\nAUTH\\r\\n$8\\r\\ndial_app\\r\\n$'+"
                    "str(len(p)).encode()+b'\\r\\n'+p+b'\\r\\n'); "
                    "assert s.recv(128)==b'+OK\\r\\n'; "
                    "s.sendall(b'*1\\r\\n$4\\r\\nPING\\r\\n'); "
                    "assert s.recv(128)==b'+PONG\\r\\n'")
                subprocess.run(["docker", "exec", node.container(release), "python", "-c", client_script],
                               check=True, capture_output=True)
                node.deploy({"operation_id": str(uuid.uuid4()), "application_id": foreign_app,
                             "release_id": foreign_release, "image": os.environ["VALKEY_RUNTIME_WEB_IMAGE"],
                             "port": 8080, "health_path": "/health", "memory_mb": 128, "cpu_milli": 100})
                foreign = json.loads(subprocess.check_output(["docker", "inspect", node.container(foreign_release)]))[0]
                self.assertNotIn(network, foreign["NetworkSettings"]["Networks"])
                lookup = subprocess.run(["docker", "exec", node.container(foreign_release), "python", "-c",
                                         "import socket; socket.getaddrinfo('" + container + "',6379)"],
                                        capture_output=True)
                self.assertNotEqual(lookup.returncode, 0)
                self.assertEqual(provision(node, payload), ready)
                time.sleep(2)  # Let appendfsync everysec persist the acknowledged write.
                subprocess.run(["docker", "restart", container], check=True, capture_output=True)
                self.assertEqual(provision(node, payload), ready)
                self.assertEqual(wire(ip, ["AUTH", "dial_app", password], ["GET", "key"]), b"$7\r\ndurable\r\n")
                if os.environ.get("VALKEY_RUNTIME_BACKUP"):
                    sys.path.insert(0, str(ROOT / "tools"))
                    from valkey_backup import backup_all, configuration, restore_drill
                    from backup_health import evaluate
                    folders = {key: Path(temp) / folder for key, folder in (
                        ("BACKUP_EVIDENCE_DIR", "evidence"), ("BACKUP_TMP_DIR", "backup-tmp"),
                        ("BACKUP_PROBE_DIR", "probes"))}
                    for folder in folders.values():
                        folder.mkdir(mode=0o700)
                    password_file = Path(temp) / "restic-password"
                    password_file.write_text("disposable-valkey-backup-test-password")
                    os.chmod(password_file, 0o600)
                    probe_file = folders["BACKUP_PROBE_DIR"] / (instance + ".json")
                    probe_file.write_text(json.dumps({"key": "key", "sha256": hashlib.sha256(b"durable").hexdigest(),
                                                      "size_bytes": 7}))
                    os.chmod(probe_file, 0o600)
                    setting = {"RESTIC_REPOSITORY": str(Path(temp) / "repository"),
                               "RESTIC_PASSWORD_FILE": str(password_file),
                               "NODE_STATE_FILE": str(Path(temp) / "state.sqlite3"),
                               "NODE_SECRETS_DIR": str(node.secrets_dir),
                               "NODE_STORAGE_SHELL_IMAGE": os.environ["VALKEY_BACKUP_SHELL_IMAGE"],
                               **{key: str(path) for key, path in folders.items()}}
                    previous_backup = {key: os.environ.get(key) for key in setting}
                    os.environ.update(setting)
                    try:
                        subprocess.run(["restic", "init"], check=True, capture_output=True)
                        evidence, backup_node, helper = configuration(offhost=False)
                        result = backup_all(evidence, backup_node, helper)
                        self.assertEqual((result["state"], result["instances"]), ("FLEET_BACKUP_VERIFIED", 1))
                        snapshot = result["receipts"][0]["snapshot_id"]
                        self.assertEqual(json.loads((evidence / (snapshot + ".json")).read_text())["state"],
                                         "RESTORE_VERIFIED")
                        self.assertEqual(evaluate("valkey", evidence, check_remote=True)["state"], "BACKUP_HEALTHY")
                        contract = json.loads(probe_file.read_text())
                        contract["sha256"] = "0" * 64
                        probe_file.write_text(json.dumps(contract))
                        with self.assertRaisesRegex(RuntimeError, "probe changed"):
                            restore_drill(instance, snapshot, evidence, backup_node, helper)
                    finally:
                        for key, value in previous_backup.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
                with self.assertRaises(OperationError):
                    provision(node, {**payload, "application_id": str(uuid.uuid4())})
                subprocess.run(["docker", "network", "disconnect", network, container],
                               check=True, capture_output=True)
                with self.assertRaises(OperationError):
                    provision(node, payload)
            finally:
                subprocess.run(["docker", "rm", "-f", node.container(release)], capture_output=True)
                subprocess.run(["docker", "rm", "-f", node.container(foreign_release)], capture_output=True)
                subprocess.run(["docker", "rm", "-f", container], capture_output=True)
                subprocess.run(["docker", "volume", "rm", volume], capture_output=True)
                subprocess.run(["docker", "network", "rm", network], capture_output=True)
                subprocess.run(["docker", "network", "rm", node.application_network(app)], capture_output=True)
                subprocess.run(["docker", "network", "rm", node.application_network(foreign_app)], capture_output=True)
                if previous is None:
                    os.environ.pop("NODE_VALKEY_IMAGE", None)
                else:
                    os.environ["NODE_VALKEY_IMAGE"] = previous
