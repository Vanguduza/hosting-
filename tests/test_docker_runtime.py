"""Disposable real Docker/registry test; only enabled in a CI Docker job."""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents/node-agent"))
from node_agent.core import Node


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
                self.assertEqual(node.application_state(lifecycle)["state"], "PAUSED")
                self.assertEqual(node.application_state(lifecycle)["state"], "PAUSED")
                self.assertEqual(node.observed(app)["state"], "UNREACHABLE")
                self.assertEqual(node.application_state({**lifecycle, "action": "resume"})["state"], "RESUMED")
                self.assertEqual(node.observed(app)["state"], "RUNNING_PRIVATE")
                self.assertEqual(node.deploy(second)["state"], "HEALTHY_PRIVATE")
                self.assertEqual(node.retire(app, first_id)["state"], "RETIRED")
                self.assertEqual(node.observed(app)["release_id"], second_id)
            finally:
                for release in (first_id, second_id):
                    try:
                        node.runner(["docker", "rm", "-f", node.container(release)], 30)
                    except Exception:
                        pass
