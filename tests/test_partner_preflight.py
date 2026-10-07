import copy
import json
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from partner_preflight import SCHEMA, VALIDATOR, preflight, unique_object, validate


class PartnerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.org, self.project, self.app, self.release = (str(uuid.uuid4()) for _ in range(4))
        self.now = datetime.now(timezone.utc)
        self.intent = {
            "schema_version": "1.0", "partner_id": "partner-1", "dial_business_account_id": "business-1",
            "project_id": self.project, "template_id": "supplier", "template_version": "1.0",
            "environment_profile": "development", "runtime_class": "docker-http-v1",
            "domain_intent": {"hostname": "supplier.example.org"}, "database_profile": "none",
            "storage_profile": "none", "backup_profile": "encrypted-offhost-v1",
            "observability_profile": "release-health-v1", "resource_budget": {"cpu_milli": 100, "memory_mb": 128},
            "release_artifact_ref": "registry.example.org/team/app@sha256:" + "a" * 64,
            "secret_refs": [], "tenant_admin_refs": ["issuer-subject-1"],
            "commercial_entitlement_ref": "entitlement-1", "requested_by": "factory-1", "request_id": str(uuid.uuid4()),
        }
        self.responses = {
            "applications": {"applications": [{"id": self.app, "environment": "development"}]},
            "releases": {"releases": [{"id": self.release, "image": self.intent["release_artifact_ref"], "state": "SERVING"}]},
            "health": {"state": "UP", "release_id": self.release, "checked_at": self.now.isoformat()},
            "domain": {"domain": {"hostname": "supplier.example.org", "verified_at": self.now.isoformat()}},
            "postgres": {"postgres": None}, "storage": {"storage": None},
        }
        self.calls = []

    def read(self, path):
        self.calls.append(path)
        self.assertTrue(path.startswith("/v1/organizations/" + self.org + "/"))
        return 200, self.responses[path.rsplit("/", 1)[-1]]

    def report(self):
        return preflight(self.intent, self.org, self.app, self.read, self.now)

    def states(self):
        return {row["stage"]: row["state"] for row in self.report()["stages"]}

    def test_contract_and_stable_content_identity(self):
        VALIDATOR.check_schema(SCHEMA)
        reversed_intent = dict(reversed(list(self.intent.items())))
        self.assertEqual(validate(self.intent), validate(reversed_intent))
        changed = {**self.intent, "template_version": "2.0"}
        self.assertNotEqual(validate(self.intent), validate(changed))

    def test_reject_ambiguous_or_untyped_desired_state(self):
        changes = ({"schema_version": "2.0"}, {"runtime_class": "privileged"},
                   {"project_id": self.project.upper()}, {"release_artifact_ref": "app:latest"},
                   {"resource_budget": {"cpu_milli": True, "memory_mb": 128}},
                   {"resource_budget": {"cpu_milli": 100.0, "memory_mb": 128}},
                   {"resource_budget": {"cpu_milli": 100, "memory_mb": 0}},
                   {"domain_intent": {"hostname": "app.example.org", "verified": True}},
                   {"domain_intent": {"hostname": "app.internal"}},
                   {"secret_refs": ["plaintext-password"]}, {"secret_refs": ["secret://app/password#0"]},
                   {"tenant_admin_refs": []}, {"secret_refs": ["secret://app/password#1"] * 2},
                   {"commercial_consent": True})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate({**self.intent, **change})
        missing = copy.deepcopy(self.intent)
        del missing["commercial_entitlement_ref"]
        with self.assertRaises(ValueError):
            validate(missing)
        with self.assertRaises(ValueError):
            json.loads('{"schema_version":"1.0","schema_version":"2.0"}', object_pairs_hook=unique_object)

    def test_healthy_readback_cannot_grant_commercial_authority_or_qualification(self):
        before = copy.deepcopy(self.intent)
        report = self.report()
        states = {row["stage"]: row["state"] for row in report["stages"]}
        self.assertEqual(states["release_health"], "OBSERVED_HEALTHY")
        self.assertEqual(states["commercial_authority"], "BLOCKED")
        self.assertEqual(states["backups"], "BLOCKED")
        self.assertEqual(report["state"], "NOT_QUALIFIED")
        self.assertFalse(report["mutations_performed"])
        self.assertEqual(report["transformations"], [])
        self.assertEqual(before, self.intent)
        self.assertEqual(len(self.calls), 6)

    def test_environment_mismatch_stops_application_readback(self):
        self.responses["applications"]["applications"][0]["environment"] = "production"
        self.assertEqual(self.states()["tenant_project_environment"], "BLOCKED")
        self.assertEqual(len(self.calls), 1)

    def test_wrong_artifact_or_release_cannot_borrow_health(self):
        for key, value in (("image", "registry.example.org/app@sha256:" + "b" * 64), ("id", str(uuid.uuid4())), ("state", "SUPERSEDED")):
            with self.subTest(key=key):
                original = self.responses["releases"]["releases"][0][key]
                self.responses["releases"]["releases"][0][key] = value
                self.assertEqual(self.states()["release_health"], "BLOCKED")
                self.responses["releases"]["releases"][0][key] = original

    def test_stale_future_naive_or_invalid_observation_is_blocked(self):
        for checked in ((self.now - timedelta(minutes=4)).isoformat(), (self.now + timedelta(seconds=1)).isoformat(),
                        self.now.replace(tzinfo=None).isoformat(), "invalid", None):
            with self.subTest(checked=checked):
                self.responses["health"]["checked_at"] = checked
                self.assertEqual(self.states()["release_health"], "BLOCKED")

    def test_missing_resource_field_is_not_absence_proof(self):
        self.responses["postgres"] = {}
        with self.assertRaises(ValueError):
            self.report()

    def test_unrequested_resources_and_wrong_domain_are_blocked(self):
        self.responses["postgres"] = {"postgres": {"state": "READY"}}
        self.responses["domain"]["domain"]["hostname"] = "different.example.org"
        states = self.states()
        self.assertEqual(states["postgres"], "BLOCKED")
        self.assertEqual(states["domain_ownership"], "BLOCKED")

    def test_unqualified_profiles_and_secret_bindings_are_visible(self):
        self.intent.update(environment_profile="production", storage_profile="garage-development-v1",
                           database_profile="supabase-unqualified", secret_refs=["secret://app/password#1"])
        report = preflight(self.intent, self.org, self.app)
        states = {row["stage"]: row["state"] for row in report["stages"]}
        self.assertEqual(states["storage_profile"], "BLOCKED")
        self.assertEqual(states["database_profile"], "BLOCKED")
        self.assertEqual(states["secret_bindings"], "BLOCKED")
        self.assertNotIn("secret://", json.dumps(report))
        self.assertEqual(states["live_readback"], "NOT_OBSERVED")

    def test_authentication_failure_is_not_a_green_receipt(self):
        with self.assertRaises(ValueError):
            preflight(self.intent, self.org, self.app, lambda path: (404, {}))


if __name__ == "__main__":
    unittest.main()
