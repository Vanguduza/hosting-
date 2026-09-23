"""Disposable Valkey service proof: authenticated RESP, persistence, and isolation."""
import json
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
                with self.assertRaises(OperationError):
                    provision(node, {**payload, "application_id": str(uuid.uuid4())})
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
