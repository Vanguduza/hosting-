"""Protected assignment-file boundaries and strict policy import types."""
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from set_entitlement import assignment, private_json


class EntitlementImportTests(unittest.TestCase):
    def value(self):
        return {'id':str(uuid.uuid4()), 'organization_id':str(uuid.uuid4()), 'plan_ref':'plan://hosting-start',
                'evidence_ref':'entitlement://private-agreement', 'features':['release','domain'],
                'cpu_milli_limit':2000,'memory_mb_limit':4096,'project_limit':2,'application_limit':4,
                'domain_limit':2,'registration_limit':0,'valid_from':'2026-01-01T00:00:00Z','valid_until':'2027-01-01T00:00:00Z'}

    def test_rejects_ambiguous_policy_values(self):
        value=self.value()
        for change in ({'features':['release','release']},{'features':['paid']},{'features':[True]},
                       {'cpu_milli_limit':True},{'project_limit':1.5},{'domain_limit':-1},
                       {'plan_ref':'https://billing.test/plan'}, {'evidence_ref':'entitlement://secret\n'},
                       {'valid_from':'2026-01-01T00:00:00'}, {'valid_until':'2025-01-01T00:00:00Z'},
                       {'id':'not-a-uuid'}, {'commercial_price':9}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                assignment({**value, **change})

    def test_private_file_rejects_duplicate_keys_world_readable_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'assignment.json'
            value=self.value()
            path.write_text(json.dumps(value));path.chmod(0o600)
            self.assertEqual(private_json(path),value)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'owner-only'):
                private_json(path)
            path.chmod(0o600)
            linked=Path(directory)/'linked.json';linked.symlink_to(path)
            with self.assertRaises(OSError):
                private_json(linked)
            path.write_text(json.dumps(value)[:-1]+',"project_limit":10}')
            with self.assertRaisesRegex(ValueError,'Duplicate'):
                private_json(path)

    def test_named_pipe_is_rejected_without_waiting_for_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'pipe';os.mkfifo(path,0o600)
            with self.assertRaisesRegex(ValueError,'regular file'):
                private_json(path)
