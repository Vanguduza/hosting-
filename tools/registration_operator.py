#!/usr/bin/env python3
"""Audited manual registrar fulfillment. Does not contact a registrar or charge funds."""
import argparse
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify


def reference(value, kind):
    if not isinstance(value, str) or not re.fullmatch(kind + r"://[a-zA-Z0-9/_-]{1,120}", value):
        raise ValueError("Invalid evidence reference")
    return value


def identity(operator):
    if not isinstance(operator, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}", operator):
        raise ValueError("Invalid operator identity")


def protected(conn, operator):
    identity(operator)
    if conn.execute("SELECT current_user AS role").fetchone()["role"] in SERVICE_ROLES:
        raise PermissionError("Protected operator credentials required")
    conn.execute("SELECT set_config('hosting.registration_operator',%s,true)", (operator,))


def request_row(conn, org, request):
    row = conn.execute("SELECT * FROM hosting.domain_registration_requests WHERE organization_id=%s AND id=%s FOR UPDATE",
                       (org, request)).fetchone()
    if not row:
        raise ValueError("Registration request unavailable")
    return row


def quote(conn, org, request, quote_id, operator, *, registrar, amount_minor, renewal_minor,
          currency, expires_at, terms_text, provider_quote_ref):
    identity(operator)
    if not isinstance(registrar, str) or not 1 <= len(registrar) <= 128 or any(ord(c) < 32 for c in registrar) or \
            type(amount_minor) is not int or not 1 <= amount_minor <= 2147483647 or \
            type(renewal_minor) is not int or not 0 <= renewal_minor <= 2147483647 or \
            currency not in ("USD", "ZAR", "ZWG") or not isinstance(terms_text, str) or \
            not 10 <= len(terms_text) <= 4000 or any(ord(c) < 32 and c not in "\n\t" for c in terms_text) or \
            len(terms_text.encode("utf-8")) > 4000 or \
            not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        raise ValueError("Invalid registration quote")
    reference(provider_quote_ref, "quote")
    with conn.transaction():
        protected(conn, operator)
        row = request_row(conn, org, request)
        payload = {"quote_id": str(quote_id), "hostname": row["hostname"], "term_years": row["term_years"],
                   "registrant_ref": row["registrant_ref"], "registrar": registrar,
                   "provider": "ZISPA_MEMBER" if row["hostname"].endswith(".co.zw") else "OPENSRS",
                   "initial_amount_minor": amount_minor, "renewal_amount_minor": renewal_minor,
                   "renewal_term_years": 1,
                   "currency": currency, "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
                   "terms_text": terms_text, "provider_quote_ref": provider_quote_ref, "fulfillment_mode": "MANUAL"}
        existing = conn.execute("SELECT id,organization_id,registration_id,payload,quote_sha256 FROM hosting.domain_registration_quotes WHERE id=%s",
                                (quote_id,)).fetchone()
        if existing:
            if existing["organization_id"] != org or existing["registration_id"] != request or existing["payload"] != payload:
                raise ValueError("Quote idempotency conflict")
            return {"id": quote_id, "sha256": existing["quote_sha256"], "replayed": True}
        now = datetime.now(timezone.utc)
        if row["state"] not in ("REQUESTED", "QUOTED", "APPROVED") or not now < expires_at <= now + timedelta(days=7):
            raise ValueError("Registration quote transition unavailable")
        result = conn.execute("INSERT INTO hosting.domain_registration_quotes "
                              "(id,organization_id,registration_id,payload,expires_at,issued_by) VALUES (%s,%s,%s,%s,%s,%s) "
                              "RETURNING id,quote_sha256", (quote_id, org, request, Jsonb(payload), expires_at, operator)).fetchone()
        # Requoting invalidates previous consent. The old immutable quote and its
        # audit fact remain; a different price always requires a new approval.
        conn.execute("UPDATE hosting.domain_registration_requests SET state='QUOTED',current_quote_id=%s,"
                     "approved_by=NULL,approved_at=NULL,updated_at=clock_timestamp() WHERE id=%s", (quote_id, request))
        return {"id": result["id"], "sha256": result["quote_sha256"], "replayed": False}


def start(conn, org, request, quote_id, operation_id, operator, payment_ref):
    reference(payment_ref, "payment")
    with conn.transaction():
        protected(conn, operator)
        row = request_row(conn, org, request)
        if row["current_quote_id"] != quote_id:
            raise ValueError("Registration quote changed")
        if row["state"] in ("PROCESSING", "FULFILLMENT_RECORDED"):
            if row["operation_id"] != operation_id or row["payment_evidence_ref"] != payment_ref:
                raise ValueError("Registration operation idempotency conflict")
            return {"id": request, "state": row["state"], "operation_id": operation_id, "replayed": True}
        valid = conn.execute("SELECT 1 FROM hosting.domain_registration_quotes q JOIN hosting.memberships m "
                             "ON m.organization_id=q.organization_id AND m.actor_sub=%s AND m.role='owner' "
                             "WHERE q.id=%s AND q.expires_at>clock_timestamp()", (row["approved_by"], quote_id)).fetchone()
        if row["state"] != "APPROVED" or not valid:
            raise ValueError("Unexpired owner consent required")
        conn.execute("UPDATE hosting.domain_registration_requests SET state='PROCESSING',operation_id=%s,"
                     "payment_evidence_ref=%s,updated_at=clock_timestamp() WHERE id=%s", (operation_id, payment_ref, request))
        return {"id": request, "state": "PROCESSING", "operation_id": operation_id, "replayed": False}


def complete(conn, org, request, operation_id, operator, provider_order_ref, receipt_sha256):
    reference(provider_order_ref, "order")
    if not isinstance(receipt_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", receipt_sha256):
        raise ValueError("Registrar receipt hash required")
    with conn.transaction():
        protected(conn, operator)
        row = request_row(conn, org, request)
        if row["operation_id"] != operation_id:
            raise ValueError("Registration operation differs")
        if row["state"] == "FULFILLMENT_RECORDED":
            if row["provider_order_ref"] != provider_order_ref or row["receipt_sha256"] != receipt_sha256:
                raise ValueError("Registrar receipt idempotency conflict")
            return {"id": request, "state": row["state"], "replayed": True}
        if row["state"] != "PROCESSING":
            raise ValueError("Processing registration required")
        conn.execute("UPDATE hosting.domain_registration_requests SET state='FULFILLMENT_RECORDED',provider_order_ref=%s,"
                     "receipt_sha256=%s,fulfilled_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=%s",
                     (provider_order_ref, receipt_sha256, request))
        return {"id": request, "state": "FULFILLMENT_RECORDED", "receipt_sha256": receipt_sha256, "replayed": False}


def fail(conn, org, request, operation_id, operator, evidence_ref):
    reference(evidence_ref, "failure")
    with conn.transaction():
        protected(conn, operator)
        row = request_row(conn, org, request)
        if row["operation_id"] != operation_id or row["state"] not in ("PROCESSING", "FAILED"):
            raise ValueError("Registration failure transition unavailable")
        if row["state"] == "FAILED":
            if row["failure_evidence_ref"] != evidence_ref:
                raise ValueError("Registration failure idempotency conflict")
            return {"id": request, "state": "FAILED", "replayed": True}
        conn.execute("UPDATE hosting.domain_registration_requests SET state='FAILED',failure_evidence_ref=%s,"
                     "updated_at=clock_timestamp() WHERE id=%s", (evidence_ref, request))
        return {"id": request, "state": "FAILED", "replayed": False}


def terms_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, encoding="utf-8") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 16000:
            raise ValueError("Terms require an owner-only regular file")
        return file.read(4001)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("organization", type=uuid.UUID)
    parser.add_argument("registration", type=uuid.UUID)
    parser.add_argument("--operator", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    q = commands.add_parser("quote")
    q.add_argument("--quote-id", type=uuid.UUID, required=True)
    q.add_argument("--registrar", required=True)
    q.add_argument("--amount-minor", type=int, required=True)
    q.add_argument("--renewal-minor", type=int, required=True)
    q.add_argument("--currency", choices=["USD", "ZAR", "ZWG"], required=True)
    q.add_argument("--expires-at", type=datetime.fromisoformat, required=True)
    q.add_argument("--terms-file", required=True)
    q.add_argument("--provider-quote-ref", required=True)
    s = commands.add_parser("start")
    s.add_argument("--quote-id", type=uuid.UUID, required=True)
    s.add_argument("--payment-ref", required=True)
    s.add_argument("--operation-id", type=uuid.UUID, required=True)
    c = commands.add_parser("complete")
    c.add_argument("--operation-id", type=uuid.UUID, required=True)
    c.add_argument("--provider-order-ref", required=True)
    c.add_argument("--receipt-sha256", required=True)
    f = commands.add_parser("fail")
    f.add_argument("--operation-id", type=uuid.UUID, required=True)
    f.add_argument("--evidence-ref", required=True)
    f.add_argument("--confirm", choices=["registrar_failed_without_purchase"], required=True)
    args = parser.parse_args(argv)
    try:
        with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
            verify(conn)
            base = (conn, args.organization, args.registration)
            if args.command == "quote":
                result = quote(*base, args.quote_id, args.operator, registrar=args.registrar, amount_minor=args.amount_minor,
                               renewal_minor=args.renewal_minor, currency=args.currency, expires_at=args.expires_at,
                               terms_text=terms_file(args.terms_file), provider_quote_ref=args.provider_quote_ref)
            elif args.command == "start":
                result = start(*base, args.quote_id, args.operation_id, args.operator, args.payment_ref)
            elif args.command == "complete":
                result = complete(*base, args.operation_id, args.operator, args.provider_order_ref, args.receipt_sha256)
            else:
                result = fail(*base, args.operation_id, args.operator, args.evidence_ref)
        print(json.dumps(result, default=str, sort_keys=True))
        return 0
    except (ValueError, PermissionError, OSError, psycopg.Error):
        print(json.dumps({"error": "registration_operator_failed"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
