import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_release import image_digest


class BuildTests(unittest.TestCase):
    def test_metadata_must_contain_sha256_digest(self):
        name = "registry.example.test/team/app"
        self.assertEqual(image_digest({"containerimage.digest": "sha256:" + "a" * 64}, name),
                         name + "@sha256:" + "a" * 64)
        for invalid in ({}, {"containerimage.digest": "latest"}, {"containerimage.digest": "sha256:too-short"}):
            with self.assertRaises(RuntimeError):
                image_digest(invalid, name)
