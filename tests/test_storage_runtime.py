"""Real Garage S3 proof: private network, signed object I/O and durable restart."""
import json
import hashlib
import http.client
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
            previous_shell = os.environ.get("NODE_STORAGE_SHELL_IMAGE")
            os.environ["NODE_GARAGE_IMAGE"] = os.environ["STORAGE_RUNTIME_IMAGE"]
            os.environ["NODE_STORAGE_SHELL_IMAGE"] = os.environ["STORAGE_SHELL_IMAGE"]
            containers = [names(first)[0], names(second)[0], node.container(release), node.container(foreign_release)]
            volumes = [names(first)[2], names(second)[2]]
            networks = [names(first)[1], names(second)[1], node.application_network(app),
                        node.application_network(foreign_app)]
            try:
                payload = {"instance_id": first, "application_id": app, "memory_mb": 256,
                           "cpu_milli": 250, "secret_version": 1}
                try:
                    receipt = provision(node, payload)
                except OperationError:
                    failed = subprocess.run(["docker", "inspect", names(first)[0]], capture_output=True, text=True)
                    if failed.returncode == 0:
                        item = json.loads(failed.stdout)[0]
                        state = item["State"]
                        print("Garage state:", {key: state.get(key) for key in ("Status", "ExitCode", "Error")},
                              file=sys.stderr)
                        ip = item.get("NetworkSettings", {}).get("Networks", {}).get(names(first)[1], {}).get("IPAddress")
                        if ip and state.get("Running"):
                            try:
                                connection = http.client.HTTPConnection(ip, 3900, timeout=3)
                                connection.request("GET", "/" + bucket_name(first), headers={"Host": "localhost"})
                                print("Garage unsigned HTTP:", connection.getresponse().status, file=sys.stderr)
                                connection.close()
                            except OSError as exc:
                                print("Garage HTTP failure:", type(exc).__name__, file=sys.stderr)
                            info = subprocess.run(["docker", "exec", names(first)[0], "/garage", "bucket", "info",
                                                   bucket_name(first)], capture_output=True, text=True)
                            print("Garage bucket info exit:", info.returncode, file=sys.stderr)
                        log = subprocess.run(["docker", "logs", "--tail", "30", names(first)[0]],
                                             capture_output=True, text=True).stderr[-4000:]
                        for value in secret.values():
                            log = log.replace(value, "[redacted]")
                        print("Garage logs:", log, file=sys.stderr)
                    raise
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
                if os.environ.get("STORAGE_RUNTIME_BACKUP"):
                    sys.path.insert(0, str(ROOT / "tools"))
                    from storage_backup import backup_all, configuration, restore_drill
                    secret_file = Path(temp) / "restic-password"
                    secret_file.write_text("disposable-storage-backup-test-password")
                    os.chmod(secret_file, 0o600)
                    directories = {key: Path(temp) / value for key, value in (
                        ("BACKUP_EVIDENCE_DIR", "evidence"), ("BACKUP_TMP_DIR", "backup-tmp"),
                        ("BACKUP_PROBE_DIR", "probes"))}
                    for directory in directories.values():
                        directory.mkdir(mode=0o700)
                    for resource, content, values in ((first, b"safe-data", secret),
                                                     (second, b"foreign-data", other_secret)):
                        address = json.loads(subprocess.check_output(["docker", "inspect", names(resource)[0]]))[0][
                            "NetworkSettings"]["Networks"][names(resource)[1]]["IPAddress"]
                        s3(address, values["access_key"], values["secret_key"]).put_object(
                            Bucket=bucket_name(resource), Key="durable.txt", Body=content)
                        probe_file = directories["BACKUP_PROBE_DIR"] / (resource + ".json")
                        probe_file.write_text(json.dumps({"key": "durable.txt", "sha256": hashlib.sha256(content).hexdigest(),
                                                          "size_bytes": len(content)}))
                        os.chmod(probe_file, 0o600)
                    setting = {"RESTIC_REPOSITORY": str(Path(temp) / "repository"),
                               "RESTIC_PASSWORD_FILE": str(secret_file),
                               "NODE_STATE_FILE": str(Path(temp) / "state.sqlite3"),
                               "NODE_SECRETS_DIR": str(node.secrets_dir),
                               **{key: str(value) for key, value in directories.items()}}
                    previous_backup = {key: os.environ.get(key) for key in setting}
                    os.environ.update(setting)
                    try:
                        subprocess.run(["restic", "init"], check=True, capture_output=True)
                        evidence, backed_node, helper = configuration(offhost=False)
                        result = backup_all(evidence, backed_node, helper)
                        self.assertEqual(result["state"], "FLEET_BACKUP_VERIFIED")
                        self.assertEqual(result["instances"], 2)
                        receipts = {entry["instance_id"]: entry["snapshot_id"] for entry in result["receipts"]}
                        for resource in (first, second):
                            self.assertEqual(json.loads((evidence / (receipts[resource] + ".json")).read_text())[
                                "state"], "RESTORE_VERIFIED")
                        probe_file = directories["BACKUP_PROBE_DIR"] / (first + ".json")
                        probe = json.loads(probe_file.read_text())
                        probe["sha256"] = "0" * 64
                        probe_file.write_text(json.dumps(probe))
                        with self.assertRaisesRegex(RuntimeError, "probe changed"):
                            restore_drill(first, receipts[first], evidence, backed_node, helper)
                    finally:
                        for key, value in previous_backup.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
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
                if previous_shell is None:
                    os.environ.pop("NODE_STORAGE_SHELL_IMAGE", None)
                else:
                    os.environ["NODE_STORAGE_SHELL_IMAGE"] = previous_shell
