"""Disposable real Docker/registry test; only enabled in a CI Docker job."""
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents/node-agent"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from node_agent.core import Node
from node_agent.__main__ import Handler as NodeHandler
from hosting_api.worker import node_application_state


def node_tls(directory):
    root = Path(directory)
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=DialCI", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"))
    for label, subject, extension in (("server", "127.0.0.1", "serverAuth"),
                                      ("client", "ci-worker", "clientAuth")):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + subject,
                "-keyout", str(root / (label + ".key")), "-out", str(root / (label + ".csr")))
        (root / (label + ".ext")).write_text(
            "basicConstraints=CA:FALSE\n" +
            ("subjectAltName=IP:127.0.0.1\n" if label == "server" else "") +
            "extendedKeyUsage=" + extension + "\n")
        openssl("x509", "-req", "-in", str(root / (label + ".csr")),
                "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
                "-days", "1", "-extfile", str(root / (label + ".ext")),
                "-out", str(root / (label + ".crt")))
    return {"ca": str(root / "ca.crt"), "cert": str(root / "client.crt"),
            "key": str(root / "client.key")}


@unittest.skipUnless(os.environ.get("NODE_RUNTIME_TEST_IMAGE"), "requires disposable Docker runtime")
class DockerRuntime(unittest.TestCase):
    def test_digest_deploy_replay_and_retire(self):
        image = os.environ["NODE_RUNTIME_TEST_IMAGE"]
        app = str(uuid.uuid4())
        first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as temp:
            node = Node(Path(temp) / "agent.sqlite3")
            def request(release):
                return {"operation_id": str(uuid.uuid4()), "application_id": app,
                        "release_id": release, "image": image, "port": 8080,
                        "health_path": "/health", "memory_mb": 128, "cpu_milli": 100}
            first, second = request(first_id), request(second_id)
            try:
                self.assertEqual(node.deploy(first)["state"], "HEALTHY_PRIVATE")
                self.assertEqual(node.deploy(first)["state"], "HEALTHY_PRIVATE")
                self.assertEqual(node.observed(app)["release_id"], first_id)
                lifecycle = {"application_id": app, "release_id": first_id, "port": 8080,
                             "health_path": "/health", "action": "pause"}
                cert = node_tls(temp)
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(cafile=cert["ca"])
                context.load_cert_chain(str(Path(temp) / "server.crt"), str(Path(temp) / "server.key"))
                server = ThreadingHTTPServer(("127.0.0.1", 0), NodeHandler)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                server.node, server.client_cn = node, "ci-worker"
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    endpoint = {"endpoint": f"https://127.0.0.1:{server.server_port}",
                                "server_name": "127.0.0.1"}
                    self.assertEqual(node_application_state(endpoint, {**lifecycle, "id": first_id},
                                                            cert, "pause")["state"], "PAUSED")
                    self.assertEqual(node.application_state(lifecycle)["state"], "PAUSED")
                    self.assertEqual(node.observed(app)["state"], "UNREACHABLE")
                    self.assertEqual(node_application_state(endpoint, {**lifecycle, "id": first_id},
                                                            cert, "resume")["state"], "RESUMED")
                    self.assertEqual(node.observed(app)["state"], "RUNNING_PRIVATE")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                self.assertEqual(node.deploy(second)["state"], "HEALTHY_PRIVATE")
                self.assertEqual(node.retire(app, first_id)["state"], "RETIRED")
                self.assertEqual(node.observed(app)["release_id"], second_id)
            finally:
                for release in (first_id, second_id):
                    try:
                        node.runner(["docker", "rm", "-f", node.container(release)], 30)
                    except Exception:
                        pass
