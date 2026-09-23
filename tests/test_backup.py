import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from control_backup import snapshot_id


class ReceiptTests(unittest.TestCase):
    def test_requires_one_full_snapshot_id(self):
        snapshot = "a" * 64
        output = '{"message_type":"status","percent_done":1}\n' + \
                 '{"message_type":"summary","snapshot_id":"' + snapshot + '"}\n'
        self.assertEqual(snapshot_id(output), snapshot)
        for bad in ('{}', '{"message_type":"summary","snapshot_id":"short"}', output + output):
            with self.subTest(output=bad), self.assertRaises(RuntimeError):
                snapshot_id(bad)
