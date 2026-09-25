"""Operator-side checks must fail closed on public routing and release identity."""
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from external_public_health import probe, status


class Inventory:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, statement):
        assert "traffic_state='ACTIVE'" in statement
        return self

    def fetchall(self):
        return self.rows


class ExternalPublicHealthTests(unittest.TestCase):
    def test_real_public_proof_is_required_for_each_serving_application(self):
        row = {"application_id": uuid.uuid4(), "release_id": uuid.uuid4(),
               "hostname": "app.example.org", "verified_at": object(),
               "public_ipv4": "8.8.8.8", "health_path": "/health"}
        inventory = Inventory([row])
        with patch("external_public_health.address_proves", return_value=True), \
                patch("external_public_health.public_probe", return_value=True) as https:
            self.assertTrue(status(inventory)["healthy"])
            https.assert_called_once_with("app.example.org", "8.8.8.8",
                                          row["release_id"], "/health")
        with patch("external_public_health.address_proves", return_value=False), \
                patch("external_public_health.public_probe") as https:
            result = status(inventory)
            self.assertEqual(result["failed"], [{"application_id": str(row["application_id"]),
                                                  "reason": "dns"}])
            https.assert_not_called()
        with patch("external_public_health.address_proves", return_value=True), \
                patch("external_public_health.public_probe", return_value=False):
            self.assertEqual(status(inventory)["failed"][0]["reason"], "https")
        self.assertEqual(probe({**row, "verified_at": None}), "configuration")
        self.assertFalse(status(Inventory([]))["healthy"])
