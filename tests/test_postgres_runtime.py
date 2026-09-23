"""Disposable Docker proof: SCRAM login, private network, persistent restart."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError
from node_agent.postgres import names, provision


@unittest.skipUnless(os.environ.get("POSTGRES_RUNTIME_IMAGE"), "requires disposable Docker PostgreSQL image")
class PostgresRuntime(unittest.TestCase):
    def test_private_persistent_instance_and_non_superuser(self):
        with tempfile.TemporaryDirectory() as temp:
            node = Node(Path(temp) / "state.sqlite3")
            instance, app = str(uuid.uuid4()), str(uuid.uuid4())
            password = "A" * 48
            node.deliver_secrets({"resource_id": instance, "version": 1,
                                  "values": {"postgres_password": "B" * 48, "app_password": password}})
            payload = {"instance_id": instance, "application_id": app,
                       "memory_mb": 256, "cpu_milli": 250, "secret_version": 1}
            container, network, volume = names(instance)
            previous = os.environ.get("NODE_POSTGRES_IMAGE")
            os.environ["NODE_POSTGRES_IMAGE"] = os.environ["POSTGRES_RUNTIME_IMAGE"]
            try:
                receipt = provision(node, payload)
                self.assertEqual(receipt["state"], "READY_PRIVATE")
                inspect = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
                self.assertEqual(inspect["HostConfig"]["PortBindings"], {})
                self.assertTrue(json.loads(subprocess.check_output(["docker", "network", "inspect", network]))[0]["Internal"])
                ip = inspect["NetworkSettings"]["Networks"][network]["IPAddress"]
                with psycopg.connect(host=ip, port=5432, user="dial_app", password=password, dbname="appdb",
                                     connect_timeout=5) as conn:
                    self.assertEqual(conn.execute("SELECT current_user").fetchone()[0], "dial_app")
                    self.assertFalse(conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname=current_user").fetchone()[0])
                    conn.execute("CREATE TABLE durable_test (value integer)")
                    conn.execute("INSERT INTO durable_test VALUES (42)")
                self.assertEqual(provision(node, payload), receipt)
                subprocess.run(["docker", "restart", container], check=True, capture_output=True)
                self.assertEqual(provision(node, payload), receipt)
                with psycopg.connect(host=ip, port=5432, user="dial_app", password=password, dbname="appdb",
                                     connect_timeout=5) as conn:
                    self.assertEqual(conn.execute("SELECT value FROM durable_test").fetchone()[0], 42)
                with self.assertRaises(OperationError):
                    provision(node, {**payload, "application_id": str(uuid.uuid4())})
            finally:
                subprocess.run(["docker", "rm", "-f", container], capture_output=True)
                subprocess.run(["docker", "volume", "rm", volume], capture_output=True)
                subprocess.run(["docker", "network", "rm", network], capture_output=True)
                if previous is None:
                    os.environ.pop("NODE_POSTGRES_IMAGE", None)
                else:
                    os.environ["NODE_POSTGRES_IMAGE"] = previous
