import json
import tomllib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents/node-agent"))
from node_agent.core import Node, OperationError, valid


def request(**updates):
    data = {"operation_id": str(uuid.uuid4()), "application_id": str(uuid.uuid4()),
            "release_id": str(uuid.uuid4()), "image": "registry.example.test/team/app@sha256:" + "a" * 64,
            "port": 8080, "health_path": "/health", "memory_mb": 128, "cpu_milli": 100}
    data.update(updates)
    return data


class DockerFixture:
    def __init__(self):
        self.containers = {}
        self.container_networks = {}
        self.networks = {}
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append(args)
        if args[1:3] == ["network", "inspect"]:
            if args[3] not in self.networks:
                raise OperationError("network absent")
            return json.dumps([self.networks[args[3]]])
        if args[1:3] == ["network", "create"]:
            label = args[args.index("--label") + 1]
            self.networks[args[-1]] = {"Driver": "bridge", "Labels": dict([label.split("=", 1)])}
        if args[1:3] == ["network", "connect"]:
            self.container_networks[args[4]].add(args[3])
        if args[1] == "inspect":
            if args[2] not in self.containers:
                raise OperationError("absent")
            return json.dumps([{"State": {"Running": True}, "NetworkSettings": {"Networks": {
                network: {"IPAddress": "172.22.0.2"} for network in self.container_networks[args[2]]}},
                "Config": {"Labels": self.containers[args[2]]}}])
        if args[1] == "run":
            labels = [args[index + 1] for index, value in enumerate(args) if value == "--label"]
            name = args[args.index("--name") + 1]
            self.containers[name] = dict(label.split("=", 1) for label in labels)
            self.container_networks[name] = {args[args.index("--network") + 1]}
        if args[1:3] == ["rm", "-f"]:
            self.containers.pop(args[3], None)
            self.container_networks.pop(args[3], None)
        return "ok"


class NodeTests(unittest.TestCase):
    def test_existing_foreign_application_network_is_rejected(self):
        fixture = DockerFixture()
        command = request()
        fixture.networks[Node.application_network(command["application_id"])] = {
            "Driver": "bridge", "Labels": {"dial.application": str(uuid.uuid4())}}
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            with self.assertRaisesRegex(OperationError, "network ownership mismatch"):
                node.deploy(command)
            self.assertNotIn(Node.container(command["release_id"]), fixture.containers)

    def test_reject_mutable_or_privileged_input(self):
        for change in ({"image": "registry.example.test/app:latest"},
                       {"port": True}, {"health_path": "//evil.example"},
                       {"privileged": True}, {"memory_mb": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                valid(request(**change))

    def test_replay_and_failed_update_preserve_active(self):
        fixture = DockerFixture()
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            first = request()
            receipt = node.deploy(first)
            self.assertEqual(receipt["state"], "HEALTHY_PRIVATE")
            before = len(fixture.calls)
            self.assertEqual(node.deploy(first), receipt)
            self.assertEqual(fixture.calls[before:], [["docker", "inspect", Node.container(first["release_id"])]])
            with self.assertRaises(OperationError):
                node.deploy({**first, "image": first["image"].replace("a" * 64, "b" * 64)})
            self.assertEqual(node.observed(first["application_id"])["release_id"], first["release_id"])

    def test_old_container_retained_until_explicit_retirement(self):
        fixture = DockerFixture()
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            first = request()
            node.deploy(first)
            with self.assertRaises(OperationError):
                node.retire(first["application_id"], first["release_id"])
            second = request(application_id=first["application_id"])
            node.deploy(second)
            promoted = second["release_id"]
            self.assertIn(Node.container(first["release_id"]), fixture.containers)
            self.assertEqual(node.retire(first["application_id"], first["release_id"])["state"], "RETIRED")
            self.assertNotIn(Node.container(first["release_id"]), fixture.containers)
            self.assertEqual(node.retire(first["application_id"], first["release_id"])["state"], "RETIRED")
            node.health_probe = lambda ip, port, path: False
            second = request(application_id=first["application_id"])
            # Avoid a 90-second timeout while asserting the current release survives.
            import unittest.mock as mock
            with mock.patch("node_agent.core.time.monotonic", side_effect=[0, 91]):
                with self.assertRaises(OperationError):
                    node.deploy(second)
            self.assertEqual(node.observed(first["application_id"])["release_id"], promoted)

    def test_stale_success_receipt_is_rechecked(self):
        fixture = DockerFixture()
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            first = request()
            node.deploy(first)
            fixture.containers.pop(Node.container(first["release_id"]))
            previous_pulls = len([call for call in fixture.calls if call[1] == "pull"])
            self.assertEqual(node.deploy(first)["state"], "HEALTHY_PRIVATE")
            self.assertEqual(len([call for call in fixture.calls if call[1] == "pull"]), previous_pulls + 1)

    def test_public_route_is_atomic_and_retirement_guarded(self):
        fixture = DockerFixture()
        fixture.containers["dial-ingress"] = {}
        fixture.container_networks["dial-ingress"] = {"dial-runtime"}
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            first = request()
            node.deploy(first)
            route = {"application_id": first["application_id"], "release_id": first["release_id"],
                     "hostname": "app.example.org", "port": 8080, "health_path": "/health"}
            self.assertEqual(node.route(route)["state"], "ROUTED")
            route_file = node.routes_dir / (first["application_id"] + ".toml")
            document = tomllib.loads(route_file.read_text())
            name = "app-" + first["application_id"]
            self.assertEqual(document["http"]["routers"][name]["middlewares"],
                             [name + "-rate", name + "-receipt"])
            self.assertEqual(document["http"]["middlewares"][name + "-rate"]["rateLimit"],
                             {"average": 20, "burst": 40, "period": "1s"})
            self.assertEqual(document["http"]["middlewares"]["app-" + first["application_id"] + "-receipt"]
                             ["headers"]["customResponseHeaders"]["X-Dial-Release"], first["release_id"])
            before = route_file.read_bytes()
            with self.assertRaises(ValueError):
                node.route({**route, "hostname": "evil.example.org`) || Host(`attacker.example.org"})
            self.assertEqual(route_file.read_bytes(), before)
            second = request(application_id=first["application_id"])
            node.deploy(second)
            with self.assertRaises(OperationError):
                node.retire(first["application_id"], first["release_id"])
            node.route({**route, "release_id": second["release_id"]})
            self.assertEqual(node.retire(first["application_id"], first["release_id"])["state"], "RETIRED")
            self.assertEqual(node.unroute(second["application_id"], second["release_id"])["state"], "UNROUTED")
            self.assertFalse(route_file.exists())

    def test_failed_release_compensation_retains_previous_container(self):
        fixture = DockerFixture()
        fixture.containers["dial-ingress"] = {}
        fixture.container_networks["dial-ingress"] = {"dial-runtime"}
        with tempfile.TemporaryDirectory() as directory:
            node = Node(Path(directory) / "agent.sqlite3", runner=fixture,
                        health_probe=lambda ip, port, path: True)
            first = request()
            node.deploy(first)
            route = {"application_id": first["application_id"], "release_id": first["release_id"],
                     "hostname": "app.example.org", "port": 8080, "health_path": "/health"}
            node.route(route)
            second = request(application_id=first["application_id"])
            node.deploy(second)
            node.route({**route, "release_id": second["release_id"]})
            with self.assertRaises(OperationError):
                node.abort(first["application_id"], second["release_id"], first["release_id"])
            node.route(route)
            self.assertEqual(node.abort(first["application_id"], second["release_id"], first["release_id"])["state"], "ABORTED")
            self.assertEqual(node.observed(first["application_id"])["release_id"], first["release_id"])
            self.assertNotIn(Node.container(second["release_id"]), fixture.containers)
            self.assertEqual(node.abort(first["application_id"], second["release_id"], first["release_id"])["state"], "ABORTED")


if __name__ == "__main__":
    unittest.main()
