"""Registrar request authority and consent against disposable PostgreSQL."""
import os
import http.client
import json
import sys
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
from jsonschema import Draft202012Validator

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
sys.path.insert(0, str(ROOT / "tools"))
from hosting_api.__main__ import Handler
from hosting_api.registration import handle
from hosting_api.migrate import apply, verify
from hosting_api.openapi import document
from registration_operator import quote, start, complete, fail


@unittest.skipUnless(os.environ.get("TEST_ADMIN_DSN"), "requires disposable PostgreSQL")
class RegistrationIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ["TEST_ADMIN_DSN"]
        cls.api_dsn = os.environ["TEST_API_DSN"]
        with psycopg.connect(cls.admin) as conn:
            apply(conn)
            verify(conn)

    def setUp(self):
        self.org, self.other = uuid.uuid4(), uuid.uuid4()
        suffix = uuid.uuid4().hex
        self.owner, self.admin_actor, self.viewer, self.other_owner = (role + suffix for role in ("owner", "admin", "viewer", "other"))
        self.hostname = "shop-" + suffix + ".co.zw"
        self.handler = object.__new__(Handler)
        self.expires = datetime.now(timezone.utc) + timedelta(hours=1)
        with psycopg.connect(self.admin) as conn:
            for org in (self.org, self.other):
                conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,'registration tests')", (org,))
            for org, actor, role in ((self.org, self.owner, "owner"), (self.org, self.admin_actor, "admin"),
                                     (self.org, self.viewer, "viewer"), (self.other, self.other_owner, "owner")):
                conn.execute("INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,%s)", (org, actor, role))

    @contextmanager
    def api(self, actor=None, kind="human"):
        with psycopg.connect(self.api_dsn, row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (actor or self.owner,))
            conn.execute("SELECT set_config('hosting.auth_kind',%s,true)", (kind,))
            yield conn

    def request(self, body=None, actor=None, org=None):
        body = body or {"idempotency_key": str(uuid.uuid4()), "hostname": self.hostname,
                        "term_years": 1, "registrant_ref": "registrant://customer-1"}
        with self.api(actor) as conn:
            return handle(self.handler, conn, org or self.org, actor or self.owner, body, "POST")

    def issue(self, request, *, quote_id=None, amount=2000, expires=None):
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            return quote(conn, self.org, request, quote_id or uuid.uuid4(), "test-operator", registrar="Test ZISPA member",
                         amount_minor=amount, renewal_minor=1500, currency="USD", expires_at=expires or self.expires,
                         terms_text="Register for one year. Renewal requires separate consent.", provider_quote_ref="quote://verified-provider-quote")

    def consent(self, request, quoted=None, cancel=False, actor=None):
        body = {"confirm": "cancel_registration"} if cancel else {"confirm": "approve_registration_quote",
                "quote_id": str(quoted["id"]), "quote_sha256": quoted["sha256"]}
        with self.api(actor) as conn:
            return handle(self.handler, conn, self.org, actor or self.owner, body, "POST", "cancel" if cancel else "approve", request)

    def test_owner_scope_initial_state_and_direct_database_permissions(self):
        for actor in (self.admin_actor, self.viewer, self.other_owner):
            self.assertEqual(self.request(actor=actor)[0], 404)
        status, created = self.request()
        self.assertEqual((status, created["state"]), (201, "REQUESTED"))
        with self.api(self.other_owner) as conn:
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_requests").fetchone()["n"], 0)
            self.assertIsNone(conn.execute("SELECT hosting.registration_consent(%s,%s,NULL,NULL,true) AS result",
                                         (self.org, created["id"])).fetchone()["result"])
        with self.api(kind="service") as conn:
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_requests").fetchone()["n"], 0)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute("INSERT INTO hosting.domain_registration_requests (id,organization_id,idempotency_key,hostname,"
                             "term_years,registrant_ref,requested_by) VALUES (%s,%s,%s,%s,1,'registrant://customer-1',%s)",
                             (uuid.uuid4(), self.org, uuid.uuid4(), "another-" + self.hostname, self.owner))
        with self.api() as conn:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute("UPDATE hosting.domain_registration_requests SET state='APPROVED' WHERE id=%s", (created["id"],))
        with self.api() as conn:
            with self.assertRaises(PermissionError):
                quote(conn, self.org, created["id"], uuid.uuid4(), "forged", registrar="member", amount_minor=2000,
                      renewal_minor=1000, currency="USD", expires_at=self.expires, terms_text="Terms accepted by customer.",
                      provider_quote_ref="quote://private")

    def test_request_replay_conflict_and_invalid_parameters(self):
        body = {"idempotency_key": str(uuid.uuid4()), "hostname": self.hostname, "term_years": 1, "registrant_ref": "registrant://customer-1"}
        status, first = self.request(body)
        status, again = self.request(body)
        self.assertEqual((status, again["id"], again["replayed"]), (200, first["id"], True))
        self.assertEqual(self.request({**body, "registrant_ref": "registrant://customer-2"})[0], 409)
        for change in ({"term_years": True}, {"term_years": 2}, {"registrant_ref": "customer@example.org"},
                       {"hostname": "app.shop.com"}, {"hostname": self.hostname + "\n"}, {"paid": True}):
            self.assertEqual(self.request({**body, **change})[0], 400)

    def test_quote_hash_expiry_requote_and_immutable_consent(self):
        _, created = self.request()
        request = created["id"]
        first = self.issue(request)
        self.assertEqual(self.consent(request, {**first, "sha256": "0" * 64})[0], 409)
        self.assertEqual(self.consent(request, first)[1]["state"], "APPROVED")
        self.assertTrue(self.consent(request, first)[1]["replayed"])
        second = self.issue(request, amount=2500)
        self.assertEqual(self.consent(request, first)[0], 409)
        self.assertEqual(self.consent(request, second)[1]["state"], "APPROVED")
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_consents WHERE registration_id=%s",
                                          (request,)).fetchone()["n"], 2)
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
                conn.execute("UPDATE hosting.domain_registration_quotes SET payload='{}' WHERE id=%s", (first["id"],))
        with self.api() as conn:
            rows = handle(self.handler, conn, self.org, self.owner, {}, "GET")[1]["registrations"]
            self.assertEqual(rows[0]["quote"]["sha256"], second["sha256"])
        _, new = self.request({"idempotency_key": str(uuid.uuid4()), "hostname": "expiry-" + self.hostname,
                               "term_years": 1, "registrant_ref": "registrant://customer-1"})
        expired = self.issue(new["id"], expires=datetime.now(timezone.utc) + timedelta(seconds=2))
        self.assertEqual(self.consent(new["id"], expired)[0], 200)
        import time
        time.sleep(2.1)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            with self.assertRaisesRegex(ValueError, "Unexpired owner consent"):
                start(conn, self.org, new["id"], expired["id"], uuid.uuid4(), "test-operator", "payment://verified")
        renewed = self.issue(new["id"], expires=datetime.now(timezone.utc) + timedelta(seconds=2))
        time.sleep(2.1)
        self.assertEqual(self.consent(new["id"], renewed)[0], 409)

    def test_same_hostname_cannot_be_approved_by_two_tenants(self):
        _, first = self.request()
        first_quote = self.issue(first["id"])
        _, second = self.request(actor=self.other_owner, org=self.other)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            second_quote = quote(conn, self.other, second["id"], uuid.uuid4(), "test-operator", registrar="Test member",
                amount_minor=2000, renewal_minor=1500, currency="USD", expires_at=self.expires,
                terms_text="Registration terms. No automatic renewal.", provider_quote_ref="quote://verified")
        self.assertEqual(self.consent(first["id"], first_quote)[0], 200)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            with self.api(self.other_owner) as conn:
                handle(self.handler, conn, self.other, self.other_owner,
                    {"confirm": "approve_registration_quote", "quote_id": str(second_quote["id"]),
                     "quote_sha256": second_quote["sha256"]}, "POST", "approve", second["id"])
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_consents WHERE registration_id=%s",
                                          (second["id"],)).fetchone()["n"], 0)
        self.assertEqual(self.consent(first["id"], cancel=True)[0], 200)
        with self.api(self.other_owner) as conn:
            self.assertEqual(handle(self.handler, conn, self.other, self.other_owner,
                {"confirm": "approve_registration_quote", "quote_id": str(second_quote["id"]),
                 "quote_sha256": second_quote["sha256"]}, "POST", "approve", second["id"])[0], 200)

    def test_start_and_cancel_race_never_processes_a_cancelled_request(self):
        _, created = self.request()
        quoted = self.issue(created["id"])
        self.consent(created["id"], quoted)
        def process():
            try:
                with psycopg.connect(self.admin, row_factory=dict_row) as conn:
                    return start(conn, self.org, created["id"], quoted["id"], uuid.uuid4(), "test-operator", "payment://verified")
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as workers:
            processing = workers.submit(process)
            cancelling = workers.submit(self.consent, created["id"], None, True)
            result, cancelled = processing.result(), cancelling.result()
        with self.api() as conn:
            state = conn.execute("SELECT state FROM hosting.domain_registration_requests WHERE id=%s", (created["id"],)).fetchone()["state"]
        if result:
            self.assertEqual((state, cancelled[0]), ("PROCESSING", 409))
        else:
            self.assertEqual((state, cancelled[0]), ("CANCELLED", 200))

    def test_http_routes_commit_owner_consent_and_exclude_service_identity(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.jwks = None
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        identity = SimpleNamespace(sub=self.owner, client_id=None, issuer=None)
        path = f"/v1/organizations/{self.org}/domain-registrations"
        def request(method, route, body=None):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                connection.request(method, route, body=json.dumps(body) if body else None,
                                   headers={"Authorization": "Bearer test-only", "Content-Type": "application/json"})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()
        try:
            with patch("hosting_api.__main__.database_dsn", return_value=self.api_dsn), \
                 patch("hosting_api.__main__.authenticate", return_value=identity):
                status, created = request("POST", path, {"idempotency_key": str(uuid.uuid4()),
                    "hostname": self.hostname, "term_years": 1, "registrant_ref": "registrant://customer-1"})
                self.assertEqual(status, 201)
                quoted = self.issue(created["id"])
                status, readback = request("GET", path)
                self.assertEqual(status, 200)
                schema = document()["paths"]["/v1/organizations/{organization_id}/domain-registrations"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                Draft202012Validator(schema).validate(readback)
                body = {"quote_id": str(quoted["id"]), "quote_sha256": quoted["sha256"], "confirm": "approve_registration_quote"}
                route = path + f"/{created['id']}/approve"
                self.assertEqual(request("POST", route, body)[1]["state"], "APPROVED")
                identity.client_id = "machine"
                self.assertEqual(request("GET", path), (404, {"error": "not_found"}))
                self.assertEqual(request("POST", route, body), (404, {"error": "not_found"}))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_manual_fulfillment_retry_cancellation_boundary_and_transactional_audit(self):
        _, created = self.request()
        request = created["id"]
        quoted = self.issue(request)
        self.consent(request, quoted)
        operation = uuid.uuid4()
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            result = start(conn, self.org, request, quoted["id"], operation, "test-operator", "payment://verified-payment")
            self.assertEqual(result["state"], "PROCESSING")
            self.assertTrue(start(conn, self.org, request, quoted["id"], operation, "test-operator", "payment://verified-payment")["replayed"])
            with self.assertRaises(ValueError):
                start(conn, self.org, request, quoted["id"], uuid.uuid4(), "test-operator", "payment://verified-payment")
        self.assertEqual(self.consent(request, cancel=True)[0], 409)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            with self.assertRaises(ValueError):
                complete(conn, self.org, request, uuid.uuid4(), "test-operator", "order://confirmed", "a" * 64)
            result = complete(conn, self.org, request, operation, "test-operator", "order://confirmed", "a" * 64)
            self.assertEqual(result["state"], "FULFILLMENT_RECORDED")
            self.assertTrue(complete(conn, self.org, request, operation, "test-operator", "order://confirmed", "a" * 64)["replayed"])
            with self.assertRaises(ValueError):
                complete(conn, self.org, request, operation, "test-operator", "order://different", "b" * 64)
            audit = conn.execute("SELECT a.id,a.action,e.audit_event_id FROM hosting.audit_events a "
                                 "JOIN hosting.event_outbox e ON e.audit_event_id=a.id WHERE a.organization_id=%s ORDER BY a.id", (self.org,)).fetchall()
            self.assertEqual([row["action"] for row in audit], ["registration.requested", "registration.quote", "registration.quoted",
                "registration.approved", "registration.processing", "registration.fulfillment_recorded"])
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_consents WHERE registration_id=%s",
                                          (request,)).fetchone()["n"], 1)

    def test_concurrent_approval_and_cancel_have_single_legal_order(self):
        _, created = self.request()
        quoted = self.issue(created["id"])
        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(lambda cancel: self.consent(created["id"], quoted, cancel), (False, True)))
        self.assertIn(outcomes[0][0], (200, 409))
        self.assertEqual(outcomes[1][0], 200)
        with self.api() as conn:
            self.assertEqual(conn.execute("SELECT state FROM hosting.domain_registration_requests WHERE id=%s", (created["id"],)).fetchone()["state"], "CANCELLED")
        self.assertEqual(self.consent(created["id"], quoted)[0], 409)

    def test_rollbacks_leave_no_request_audit_or_quote_and_cancel_replays(self):
        with self.assertRaises(RuntimeError):
            with self.api() as conn:
                status, created = handle(self.handler, conn, self.org, self.owner,
                    {"idempotency_key": str(uuid.uuid4()), "hostname": self.hostname, "term_years": 1, "registrant_ref": "registrant://customer-1"}, "POST")
                self.assertEqual(status, 201)
                raise RuntimeError("rollback")
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s", (self.org,)).fetchone()["n"], 0)
        _, created = self.request()
        self.assertEqual(self.consent(created["id"], cancel=True)[1]["state"], "CANCELLED")
        self.assertTrue(self.consent(created["id"], cancel=True)[1]["replayed"])

    def test_start_requires_current_consent_payment_evidence_and_owner_membership(self):
        _, created = self.request()
        quoted = self.issue(created["id"])
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            with self.assertRaises(ValueError):
                start(conn, self.org, created["id"], quoted["id"], uuid.uuid4(), "test-operator", "payment://verified")
        self.consent(created["id"], quoted)
        replaced = self.issue(created["id"], amount=3000)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            with self.assertRaises(ValueError):
                start(conn, self.org, created["id"], quoted["id"], uuid.uuid4(), "test-operator", "payment://verified")
            with self.assertRaises(ValueError):
                start(conn, self.org, created["id"], replaced["id"], uuid.uuid4(), "test-operator", "payment://verified")
        self.consent(created["id"], replaced)
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            conn.execute("DELETE FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s", (self.org, self.owner))
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            with self.assertRaises(ValueError):
                start(conn, self.org, created["id"], replaced["id"], uuid.uuid4(), "test-operator", "payment://verified")

    def test_timeout_remains_processing_and_only_definitive_failure_releases_request(self):
        _, created = self.request()
        quoted = self.issue(created["id"])
        self.consent(created["id"], quoted)
        operation = uuid.uuid4()
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            start(conn, self.org, created["id"], quoted["id"], operation, "test-operator", "payment://verified")
        # A crashed operator has no lease timeout that silently permits another
        # purchase. Its stable operation remains pending reconciliation.
        with psycopg.connect(self.admin, row_factory=dict_row) as conn:
            self.assertEqual(conn.execute("SELECT state FROM hosting.domain_registration_requests WHERE id=%s", (created["id"],)).fetchone()["state"], "PROCESSING")
            with self.assertRaises(ValueError):
                fail(conn, self.org, created["id"], uuid.uuid4(), "test-operator", "failure://no-purchase")
            self.assertEqual(fail(conn, self.org, created["id"], operation, "test-operator", "failure://no-purchase")["state"], "FAILED")
            self.assertTrue(fail(conn, self.org, created["id"], operation, "test-operator", "failure://no-purchase")["replayed"])
        self.assertEqual(self.request()[0], 201)

    def test_quote_retry_cannot_reactivate_old_consent_or_cross_registration_binding(self):
        _, created = self.request()
        quote_id = uuid.uuid4()
        original = self.issue(created["id"], quote_id=quote_id)
        self.assertTrue(self.issue(created["id"], quote_id=quote_id)["replayed"])
        self.consent(created["id"], original)
        latest = self.issue(created["id"], amount=3000)
        self.assertTrue(self.issue(created["id"], quote_id=quote_id)["replayed"])
        with self.api() as conn:
            row = conn.execute("SELECT state,current_quote_id FROM hosting.domain_registration_requests WHERE id=%s", (created["id"],)).fetchone()
            self.assertEqual((row["state"], row["current_quote_id"]), ("QUOTED", latest["id"]))
        with self.assertRaises(ValueError):
            self.issue(created["id"], quote_id=quote_id, amount=5000)

    def test_quote_operator_rollback_removes_receipt_and_audit_atomically(self):
        _, created = self.request()
        with self.assertRaises(RuntimeError):
            with psycopg.connect(self.admin, row_factory=dict_row) as conn:
                self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.audit_events WHERE organization_id=%s", (self.org,)).fetchone()["n"], 1)
                quote(conn, self.org, created["id"], uuid.uuid4(), "test-operator", registrar="Test member",
                      amount_minor=2000, renewal_minor=1500, currency="USD", expires_at=self.expires,
                      terms_text="Registration terms. No automatic renewal.", provider_quote_ref="quote://verified")
                raise RuntimeError("rollback")
        with self.api() as conn:
            self.assertEqual(conn.execute("SELECT state FROM hosting.domain_registration_requests WHERE id=%s", (created["id"],)).fetchone()["state"], "REQUESTED")
            self.assertEqual(conn.execute("SELECT count(*) AS n FROM hosting.domain_registration_quotes WHERE registration_id=%s", (created["id"],)).fetchone()["n"], 0)


if __name__ == "__main__":
    unittest.main()
