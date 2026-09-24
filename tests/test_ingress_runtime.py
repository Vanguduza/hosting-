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
from node_agent.routing import route_toml


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Docker failed: " + " ".join(args[:3]) + ": " + result.stderr[-1000:])
    return result.stdout + result.stderr if args[0] == "logs" else result.stdout


@unittest.skipUnless(os.environ.get("INGRESS_TEST_IMAGE") and os.environ.get("NODE_RUNTIME_TEST_IMAGE"),
                     "requires disposable Docker ingress and app image")
class IngressRuntime(unittest.TestCase):
    def test_release_header_over_trusted_tls_and_host_route(self):
        app, release = str(uuid.uuid4()), str(uuid.uuid4())
        app_container = "dial-" + release
        app_network = "dial-app-net-" + app
        other_network = "dial-app-net-" + str(uuid.uuid4())
        other_container = "dial-isolation-test-" + uuid.uuid4().hex[:8]
        ingress_container = "dial-ingress-test-" + uuid.uuid4().hex[:8]
        host = "app.example.org"
        with tempfile.TemporaryDirectory(prefix="dial-ingress-test-") as directory:
            root = Path(directory)
            (root / "routes").mkdir()
            (root / "certs").mkdir()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=" + host,
                            "-addext", "subjectAltName=DNS:" + host,
                            "-keyout", str(root / "certs/tls.key"), "-out", str(root / "certs/tls.crt")],
                           check=True, capture_output=True, timeout=30)
            (root / "routes/app.toml").write_text(route_toml(app, release, host, app_container, 8080,
                                                               average=1, burst=2, period="60s"))
            (root / "routes/cert.toml").write_text('[[tls.certificates]]\ncertFile = "/certs/tls.crt"\nkeyFile = "/certs/tls.key"\n')
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            try:
                if subprocess.run(["docker", "network", "inspect", "dial-runtime"], capture_output=True).returncode:
                    docker("network", "create", "dial-runtime")
                docker("network", "create", app_network)
                docker("network", "create", other_network)
                docker("run", "-d", "--name", app_container, "--network", app_network,
                       "--label", "dial.application=" + app, "--label", "dial.release=" + release,
                       os.environ["NODE_RUNTIME_TEST_IMAGE"])
                docker("run", "-d", "--name", other_container, "--network", other_network,
                       os.environ["NODE_RUNTIME_TEST_IMAGE"])
                isolated = subprocess.run(["docker", "exec", other_container, "python", "-c",
                                           "import socket; socket.getaddrinfo('" + app_container + "',8080)"],
                                          capture_output=True, timeout=10)
                self.assertNotEqual(isolated.returncode, 0, "Separate application network resolved another tenant")
                docker("run", "-d", "--name", ingress_container, "--network", "dial-runtime",
                       "-p", f"127.0.0.1:{port}:443", "-v", str(root / "routes") + ":/routes:ro",
                       "-v", str(root / "certs") + ":/certs:ro",
                       os.environ["INGRESS_TEST_IMAGE"],
                       "--providers.file.directory=/routes", "--providers.file.watch=true",
                       "--log.level=DEBUG",
                       "--entrypoints.web.address=:80", "--entrypoints.websecure.address=:443",
                       "--certificatesresolvers.acme.acme.email=ci@example.org",
                       "--certificatesresolvers.acme.acme.storage=/tmp/acme.json",
                       "--certificatesresolvers.acme.acme.httpchallenge.entrypoint=web")
                docker("network", "connect", app_network, ingress_container)
                context = ssl.create_default_context(cafile=str(root / "certs/tls.crt"))
                deadline = time.monotonic() + 12
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
                                statuses = []
                                for _ in range(8):
                                    with socket.create_connection(("127.0.0.1", port), timeout=2) as peer:
                                        with context.wrap_socket(peer, server_hostname=host) as next_tls:
                                            next_tls.settimeout(2)
                                            next_tls.sendall(f"GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                                            next_response = http.client.HTTPResponse(next_tls)
                                            next_response.begin()
                                            next_response.read(1024)
                                            statuses.append(next_response.status)
                                self.assertIn(429, statuses, "Traefik did not enforce the per-client rate limit")
                                return
                    except (OSError, ssl.SSLError, http.client.HTTPException):
                        if time.monotonic() >= deadline:
                            self.fail("Traefik TLS route did not become available:\n" +
                                      docker("logs", ingress_container)[-12000:])
                        time.sleep(1)
            finally:
                subprocess.run(["docker", "rm", "-f", ingress_container, app_container, other_container], capture_output=True)
                subprocess.run(["docker", "network", "rm", app_network, other_network], capture_output=True)


if __name__ == "__main__":
    unittest.main()
