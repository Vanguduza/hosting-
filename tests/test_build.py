import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_release import image_digest
from github_build_worker import checkout, run, source_auth


class BuildTests(unittest.TestCase):
    def test_git_checkout_uses_only_repository_scoped_deploy_key(self):
        source = {"full_name": "Dial/private", "repository_id": 42, "branch": "main"}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "keys"
            root.mkdir(mode=0o700)
            key = root / "42.key"
            key.write_text("disposable-private-key")
            os.chmod(key, 0o600)
            hosts = Path(temp) / "known_hosts"
            hosts.write_text("github.com ssh-ed25519 disposable-host-key\n")
            os.chmod(hosts, 0o600)
            env = {"GITHUB_DEPLOY_KEYS_DIR": str(root), "GITHUB_KNOWN_HOSTS_FILE": str(hosts)}
            with patch.dict(os.environ, env):
                url, auth = source_auth(source)
                self.assertEqual(url, "ssh://git@github.com/Dial/private.git")
                self.assertEqual(auth["GIT_ALLOW_PROTOCOL"], "ssh")
                self.assertIn("StrictHostKeyChecking=yes", auth["GIT_SSH_COMMAND"])
                calls = []
                def mock_run(args, **kwargs):
                    calls.append((args, kwargs))
                    return "a" * 40 if args[1:] == ["rev-parse", "HEAD"] else ""
                with patch("github_build_worker.run", side_effect=mock_run):
                    checkout(source, "a" * 40, Path(temp) / "source")
                self.assertEqual(len(calls), 5)
                self.assertTrue(all(row[1]["git_env"]["GIT_ALLOW_PROTOCOL"] == "ssh" for row in calls))
                self.assertTrue(all(row[1]["git_env"]["HOME"] == str(Path(temp) / "git-home") for row in calls))
                self.assertIn(url, calls[0][0])
                key.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, "owner-only"):
                    source_auth(source)
                key.unlink()
                self.assertEqual(source_auth(source)[1], {"GIT_ALLOW_PROTOCOL": "https"})

    def test_git_run_ignores_ambient_credentials(self):
        result = type("Result", (), {"returncode": 0, "stdout": "ok"})()
        with patch.dict(os.environ, {"GIT_SSH_COMMAND": "ssh -i /wrong/key",
                                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                                    "GIT_CONFIG_VALUE_0": "secret"}), \
                patch("github_build_worker.subprocess.run", return_value=result) as process:
            self.assertEqual(run(["git", "status"]), "ok")
            child = process.call_args.kwargs["env"]
            self.assertNotIn("GIT_SSH_COMMAND", child)
            self.assertNotIn("GIT_CONFIG_COUNT", child)
            self.assertNotIn("GIT_CONFIG_VALUE_0", child)
            self.assertEqual(child["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_metadata_must_contain_sha256_digest(self):
        name = "registry.example.test/team/app"
        self.assertEqual(image_digest({"containerimage.digest": "sha256:" + "a" * 64}, name),
                         name + "@sha256:" + "a" * 64)
        for invalid in ({}, {"containerimage.digest": "latest"}, {"containerimage.digest": "sha256:too-short"}):
            with self.assertRaises(RuntimeError):
                image_digest(invalid, name)
