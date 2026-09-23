"""Traefik file-provider and TLS routing against disposable Docker containers."""
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.routing import route_document


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Docker failed: " + " ".join(args[:3]) + ": " + result.stderr[-1000:])
    return result.stdout


@unittest.skipUnless(os.environ.get("INGRESS_TEST_IMAGE") and os.environ.get("NODE_RUNTIME_TEST_IMAGE"),
                     "requires disposable Docker ingress and app image")
class IngressRuntime(unittest.TestCase):
    def test_release_header_over_trusted_tls_and_host_route(self):
        app, release = str(uuid.uuid4()), str(uuid.uuid4())
        app_container = "dial-" + release
        ingress_container = "dial-ingress-test-" + uuid.uuid4().hex[:8]
        host = "app.example.org"
        with tempfile.TemporaryDirectory(prefix="dial-ingress-test-") as directory:
            root = Path(directory)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=" + host,
                            "-addext", "subjectAltName=DNS:" + host,
                            "-keyout", str(root / "tls.key"), "-out", str(root / "tls.crt")],
                           check=True, capture_output=True, timeout=30)
            (root / "app.json").write_text(json.dumps(route_document(app, release, host, app_container, 8080)))
            (root / "cert.json").write_text(json.dumps({"tls": {"certificates": [{
                "certFile": "/routes/tls.crt", "keyFile": "/routes/tls.key"}]}}))
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            try:
                if subprocess.run(["docker", "network", "inspect", "dial-runtime"], capture_output=True).returncode:
                    docker("network", "create", "dial-runtime")
                docker("run", "-d", "--name", app_container, "--network", "dial-runtime",
                       "--label", "dial.application=" + app, "--label", "dial.release=" + release,
                       os.environ["NODE_RUNTIME_TEST_IMAGE"])
                docker("run", "-d", "--name", ingress_container, "--network", "dial-runtime",
                       "-p", f"127.0.0.1:{port}:443", "-v", str(root) + ":/routes:ro",
                       os.environ["INGRESS_TEST_IMAGE"],
                       "--providers.file.directory=/routes", "--providers.file.watch=true",
                       "--entrypoints.web.address=:80", "--entrypoints.websecure.address=:443",
                       "--certificatesresolvers.acme.acme.email=ci@example.org",
                       "--certificatesresolvers.acme.acme.storage=/tmp/acme.json",
                       "--certificatesresolvers.acme.acme.httpchallenge.entrypoint=web")
                context = ssl.create_default_context(cafile=str(root / "tls.crt"))
                deadline = time.monotonic() + 40
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                            with context.wrap_socket(raw, server_hostname=host) as tls:
                                tls.settimeout(2)
                                tls.sendall(f"GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                                response = http.client.HTTPResponse(tls)
                                response.begin()
                                response.read(1024)
                                self.assertEqual(response.status, 200)
                                self.assertEqual(response.getheader("X-Dial-Release"), release)
                                return
                    except (OSError, ssl.SSLError, http.client.HTTPException):
                        if time.monotonic() >= deadline:
                            self.fail("Traefik TLS route did not become available:\n" +
                                      docker("logs", ingress_container)[-3000:])
                        time.sleep(1)
            finally:
                subprocess.run(["docker", "rm", "-f", ingress_container, app_container], capture_output=True)


if __name__ == "__main__":
    unittest.main()
