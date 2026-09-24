"""Real Garage S3 proof: private network, signed object I/O and durable restart."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError
from node_agent.storage import names, bucket_name, provision


def s3(ip, key, secret):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=f"http://{ip}:3900", region_name="garage",
                        aws_access_key_id=key, aws_secret_access_key=secret,
                        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
                        use_ssl=False)


@unittest.skipUnless(os.environ.get("STORAGE_RUNTIME_IMAGE"), "requires disposable Docker Garage image")
class StorageRuntime(unittest.TestCase):
    def test_private_bucket_credentials_persistence_and_isolation(self):
        from botocore.exceptions import ClientError
        with tempfile.TemporaryDirectory() as temp:
            node = Node(Path(temp) / "state.sqlite3")
            first, second = str(uuid.uuid4()), str(uuid.uuid4())
            app, foreign_app, release, foreign_release = (str(uuid.uuid4()) for _ in range(4))
            secret = {"access_key": "GK" + "a" * 32, "secret_key": "b" * 64,
                      "rpc_secret": "c" * 64, "admin_token": "d" * 64}
            other_secret = {"access_key": "GK" + "e" * 32, "secret_key": "f" * 64,
                            "rpc_secret": "1" * 64, "admin_token": "2" * 64}
            for instance, values in ((first, secret), (second, other_secret)):
                node.deliver_secrets({"resource_id": instance, "version": 1, "values": values})
            previous = os.environ.get("NODE_GARAGE_IMAGE")
            os.environ["NODE_GARAGE_IMAGE"] = os.environ["STORAGE_RUNTIME_IMAGE"]
            containers = [names(first)[0], names(second)[0], node.container(release), node.container(foreign_release)]
            volumes = [names(first)[2], names(second)[2]]
            networks = [names(first)[1], names(second)[1], node.application_network(app),
                        node.application_network(foreign_app)]
            try:
                payload = {"instance_id": first, "application_id": app, "memory_mb": 256,
                           "cpu_milli": 250, "secret_version": 1}
                receipt = provision(node, payload)
                self.assertEqual((receipt["state"], receipt["bucket"]), ("READY_PRIVATE", bucket_name(first)))
                provision(node, {**payload, "instance_id": second, "application_id": foreign_app})
                item = json.loads(subprocess.check_output(["docker", "inspect", names(first)[0]]))[0]
                self.assertEqual(item["HostConfig"]["PortBindings"], {})
                self.assertTrue(json.loads(subprocess.check_output(["docker", "network", "inspect",
                                                                    names(first)[1]]))[0]["Internal"])
                self.assertFalse(any("SECRET" in value or secret["secret_key"] in value
                                     for value in item["Config"]["Env"]))
                ip = item["NetworkSettings"]["Networks"][names(first)[1]]["IPAddress"]
                first_client = s3(ip, secret["access_key"], secret["secret_key"])
                first_client.put_object(Bucket=bucket_name(first), Key="durable.txt", Body=b"safe-data")
                self.assertEqual(first_client.get_object(Bucket=bucket_name(first), Key="durable.txt")["Body"].read(),
                                 b"safe-data")
                with self.assertRaises(ClientError):
                    s3(ip, other_secret["access_key"], other_secret["secret_key"]).get_object(
                        Bucket=bucket_name(first), Key="durable.txt")
                with self.assertRaises(ClientError):
                    first_client.get_object(Bucket=bucket_name(second), Key="durable.txt")
                self.assertEqual(provision(node, payload), receipt)
                subprocess.run(["docker", "restart", names(first)[0]], check=True, capture_output=True)
                self.assertEqual(provision(node, payload), receipt)
                self.assertEqual(first_client.get_object(Bucket=bucket_name(first), Key="durable.txt")["Body"].read(),
                                 b"safe-data")
                with self.assertRaises(OperationError):
                    provision(node, {**payload, "application_id": foreign_app})
                web = os.environ["STORAGE_RUNTIME_WEB_IMAGE"]
                node.deploy({"operation_id": str(uuid.uuid4()), "application_id": app, "release_id": release,
                             "image": web, "port": 8080, "health_path": "/health", "memory_mb": 128,
                             "cpu_milli": 100, "storage_id": first, "storage_version": 1})
                workload = json.loads(subprocess.check_output(["docker", "inspect", node.container(release)]))[0]
                self.assertIn(names(first)[1], workload["NetworkSettings"]["Networks"])
                self.assertIn("S3_SECRET_KEY_FILE=/run/secrets/s3_secret_key", workload["Config"]["Env"])
                self.assertNotIn(secret["secret_key"], str(workload["Config"]["Env"]))
                node.deploy({"operation_id": str(uuid.uuid4()), "application_id": foreign_app,
                             "release_id": foreign_release, "image": web, "port": 8080,
                             "health_path": "/health", "memory_mb": 128, "cpu_milli": 100,
                             "storage_id": second, "storage_version": 1})
                foreign = json.loads(subprocess.check_output(["docker", "inspect", node.container(foreign_release)]))[0]
                self.assertNotIn(names(first)[1], foreign["NetworkSettings"]["Networks"])
                self.assertIn(names(second)[1], foreign["NetworkSettings"]["Networks"])
                subprocess.run(["docker", "network", "disconnect", names(first)[1], names(first)[0]],
                               check=True, capture_output=True)
                with self.assertRaises(OperationError):
                    provision(node, payload)
            finally:
                for container in containers:
                    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
                for volume in volumes:
                    subprocess.run(["docker", "volume", "rm", volume], capture_output=True)
                for network in networks:
                    subprocess.run(["docker", "network", "rm", network], capture_output=True)
                if previous is None:
                    os.environ.pop("NODE_GARAGE_IMAGE", None)
                else:
                    os.environ["NODE_GARAGE_IMAGE"] = previous
