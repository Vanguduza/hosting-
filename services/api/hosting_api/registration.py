"""Owner registrar requests and consent; no external purchase occurs here."""
import re
import uuid


def canonical_uuid(value):
    try:
        result = uuid.UUID(value)
        return result if str(result) == value else None
    except (ValueError, TypeError, AttributeError):
        return None


def registration_name(value):
    return isinstance(value, str) and bool(re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|co\.zw)", value))


def handle(handler, conn, org, actor, body, method, action=None, registration_id=None):
    if handler.membership(conn, org, actor) != "owner":
        return 404, {"error": "not_found"}
    if action:
        if method != "POST":
            return 404, {"error": "not_found"}
        cancel = action == "cancel"
        fields = {"confirm"} if cancel else {"confirm", "quote_id", "quote_sha256"}
        if set(body) != fields or body["confirm"] != ("cancel_registration" if cancel else "approve_registration_quote"):
            return 400, {"error": "invalid_registration_consent"}
        quote = None if cancel else canonical_uuid(body["quote_id"])
        digest = None if cancel else body["quote_sha256"]
        if not cancel and (not quote or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            return 400, {"error": "invalid_registration_consent"}
        row = conn.execute("SELECT hosting.registration_consent(%s,%s,%s,%s,%s) AS receipt",
                           (org, registration_id, quote, digest, cancel)).fetchone()
        return (200, row["receipt"]) if row["receipt"] else (409, {"error": "registration_transition_unavailable"})
    if method == "GET":
        rows = conn.execute(
            "SELECT r.id,r.hostname,r.term_years,r.registrant_ref,r.state,r.created_at,r.updated_at,"
            "r.approved_at,r.fulfilled_at,r.receipt_sha256,"
            "CASE WHEN q.id IS NULL THEN NULL ELSE jsonb_build_object('id',q.id,'sha256',q.quote_sha256,"
            "'payload',q.payload) END AS quote FROM hosting.domain_registration_requests r "
            "LEFT JOIN hosting.domain_registration_quotes q ON q.organization_id=r.organization_id "
            "AND q.registration_id=r.id AND q.id=r.current_quote_id WHERE r.organization_id=%s "
            "ORDER BY r.created_at DESC,r.id DESC LIMIT 25", (org,)).fetchall()
        return 200, {"registrations": rows, "fulfillment_mode": "MANUAL"}
    if method != "POST":
        return 404, {"error": "not_found"}
    if set(body) != {"idempotency_key", "hostname", "term_years", "registrant_ref"} or \
            not registration_name(body["hostname"]) or type(body["term_years"]) is not int or \
            not 1 <= body["term_years"] <= 5 or (body["hostname"].endswith(".co.zw") and body["term_years"] != 1) or \
            not isinstance(body["registrant_ref"], str) or not re.fullmatch(r"registrant://[a-z0-9/_-]{1,120}", body["registrant_ref"]):
        return 400, {"error": "invalid_registration_request"}
    key = canonical_uuid(body["idempotency_key"])
    if not key:
        return 400, {"error": "invalid_registration_request"}
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,6))", (str(org),))
    existing = conn.execute("SELECT id,hostname,term_years,registrant_ref,state FROM hosting.domain_registration_requests "
                            "WHERE organization_id=%s AND idempotency_key=%s", (org, key)).fetchone()
    if existing:
        if any(existing[field] != body[field] for field in ("hostname", "term_years", "registrant_ref")):
            return 409, {"error": "idempotency_conflict"}
        return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
    if conn.execute("SELECT 1 FROM hosting.domain_registration_requests WHERE organization_id=%s AND hostname=%s "
                    "AND state NOT IN ('CANCELLED','FAILED')", (org, body["hostname"])).fetchone():
        return 409, {"error": "registration_already_requested"}
    request = uuid.uuid4()
    conn.execute("INSERT INTO hosting.domain_registration_requests "
                 "(id,organization_id,idempotency_key,hostname,term_years,registrant_ref,requested_by) "
                 "VALUES (%s,%s,%s,%s,%s,%s,%s)", (request, org, key, body["hostname"], body["term_years"], body["registrant_ref"], actor))
    return 201, {"id": request, "state": "REQUESTED", "fulfillment_mode": "MANUAL"}
