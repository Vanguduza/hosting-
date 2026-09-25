import json
import hashlib
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import jwt
import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from .policy import allowed, valid_name, valid_release
from .domains import new_token, txt_proves, valid_hostname


def environment():
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD_FILE", "OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_SERVICE_AUDIENCE", "OIDC_JWKS_URL")
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise RuntimeError("Missing configuration: " + ", ".join(missing))
    issuer = os.environ["OIDC_ISSUER"]
    jwks = os.environ["OIDC_JWKS_URL"]
    if not issuer.startswith("https://") or not jwks.startswith("https://"):
        raise RuntimeError("OIDC issuer and JWKS URL must use HTTPS")
    if os.environ["OIDC_AUDIENCE"] == os.environ["OIDC_SERVICE_AUDIENCE"]:
        raise RuntimeError("Human and service token audiences must differ")
    if not os.path.isfile(os.environ["DB_PASSWORD_FILE"]):
        raise RuntimeError("DB password file unavailable")
    return jwt.PyJWKClient(jwks, cache_jwk_set=True, lifespan=300)


def database_dsn():
    with open(os.environ["DB_PASSWORD_FILE"], encoding="utf-8") as file:
        password = file.read().strip()
    if not password:
        raise RuntimeError("DB password is empty")
    return make_conninfo(host=os.environ["DB_HOST"], dbname=os.environ["DB_NAME"],
                         user=os.environ["DB_USER"], password=password)


@dataclass(frozen=True)
class Identity:
    sub: str
    client_id: str | None = None


def authenticate(header, client):
    if not header or not header.startswith("Bearer "):
        raise PermissionError("Bearer token required")
    token = header[7:]
    if len(token) > 16384:
        raise PermissionError("Token too long")
    try:
        key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, key.key, algorithms=["RS256", "ES256"],
            issuer=os.environ["OIDC_ISSUER"],
            audience=[os.environ["OIDC_AUDIENCE"], os.environ["OIDC_SERVICE_AUDIENCE"]],
            options={"require": ["exp", "iat", "sub", "iss", "aud"]}, leeway=30,
        )
        if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 255:
            raise PermissionError("Invalid subject")
        audience = claims["aud"]
        if audience == os.environ["OIDC_AUDIENCE"]:
            return Identity(claims["sub"])
        if audience != os.environ["OIDC_SERVICE_AUDIENCE"]:
            raise PermissionError("Ambiguous audience")
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not 1 <= len(client_id) <= 128:
            raise PermissionError("Invalid client")
        return Identity(claims["sub"], client_id)
    except (jwt.PyJWTError, ValueError) as exc:
        raise PermissionError("Invalid bearer token") from exc


def service_route_allowed(path, method):
    return (path == "/ready" and method == "GET") or bool(
        method in ("GET", "POST") and re.fullmatch(
            r"/v1/organizations/[0-9a-f-]{36}/applications/[0-9a-f-]{36}/releases", path))


def record(conn, org_id, actor, action, resource, request_id):
    # Serialize each organization's hash chain; update is in the same transaction as intent.
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(org_id),))
    previous = conn.execute(
        "SELECT event_hash FROM hosting.audit_events WHERE organization_id=%s ORDER BY id DESC LIMIT 1",
        (org_id,),
    ).fetchone()
    conn.execute(
        "INSERT INTO hosting.audit_events(organization_id, actor_sub, action, resource_id, request_id, previous_hash, event_hash) "
        "VALUES (%s,%s,%s,%s,%s,COALESCE(%s,''), encode(public.digest(COALESCE(%s,'') || %s || %s || %s || %s,'sha256'),'hex'))",
        (org_id, actor, action, resource, request_id, previous["event_hash"] if previous else "",
         previous["event_hash"] if previous else "", actor, action, str(resource), str(request_id)),
    )


def audit_after(query):
    if not query:
        return 0
    if not re.fullmatch(r"after=(0|[1-9][0-9]{0,18})", query):
        raise ValueError("Invalid audit cursor")
    value = int(query[6:])
    if value > 9223372036854775807:
        raise ValueError("Invalid audit cursor")
    return value


def capacity_window(query):
    match = re.fullmatch(r"from=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)&"
                         r"to=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", query)
    if not match:
        raise ValueError("Invalid capacity window")
    try:
        start, end = (datetime.fromisoformat(value.replace("Z", "+00:00")) for value in match.groups())
    except ValueError as exc:
        raise ValueError("Invalid capacity window") from exc
    now = datetime.now(timezone.utc)
    if not start < end <= now + timedelta(days=1) or end - start > timedelta(days=31) or start >= now:
        raise ValueError("Invalid capacity window")
    return start, min(end, now)


class Handler(BaseHTTPRequestHandler):
    server_version = "DialHosting/0.1"

    def reply(self, code, payload):
        body = json.dumps(payload, default=str, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def audit(self, conn, org_id, actor, after):
        if not allowed(self.membership(conn, org_id, actor), "audit:read"):
            return 404, {"error": "not_found"}
        predecessor = conn.execute(
            "SELECT event_hash FROM hosting.audit_events WHERE organization_id=%s AND id<=%s "
            "ORDER BY id DESC LIMIT 1", (org_id, after)).fetchone()
        previous = predecessor["event_hash"] if predecessor else ""
        rows = conn.execute(
            "SELECT id,actor_sub,action,resource_id,request_id,previous_hash,event_hash,created_at "
            "FROM hosting.audit_events WHERE organization_id=%s AND id>%s ORDER BY id LIMIT 101",
            (org_id, after)).fetchall()
        for row in rows:
            calculated = hashlib.sha256((previous + row["actor_sub"] + row["action"] +
                                         str(row["resource_id"]) + str(row["request_id"])).encode()).hexdigest()
            if row["previous_hash"] != previous or row["event_hash"] != calculated:
                raise RuntimeError("Tenant audit chain integrity check failed")
            previous = row["event_hash"]
        page = rows[:100]
        return 200, {"events": page, "next_after": page[-1]["id"] if page else after,
                     "has_more": len(rows) > 100}

    def capacity(self, conn, org_id, actor, window):
        if not allowed(self.membership(conn, org_id, actor), "capacity:read"):
            return 404, {"error": "not_found"}
        start, end = window
        epoch = conn.execute("SELECT started_at FROM hosting.capacity_metering_epoch WHERE singleton=true").fetchone()
        if not epoch or start < epoch["started_at"]:
            return 409, {"error": "capacity_coverage_unavailable"}
        rows = conn.execute(
            "SELECT resource_type,count(*) AS reservations,"
            "SUM(cpu_milli::numeric * floor(extract(epoch from ("
            "least(coalesce(ended_at,%s),%s)-greatest(started_at,%s)))*1000))::bigint "
            "AS reserved_cpu_milli_ms,"
            "SUM(memory_mb::numeric * floor(extract(epoch from ("
            "least(coalesce(ended_at,%s),%s)-greatest(started_at,%s)))*1000))::bigint "
            "AS reserved_memory_mb_ms "
            "FROM hosting.capacity_intervals WHERE organization_id=%s AND started_at<%s "
            "AND (ended_at IS NULL OR ended_at>%s) GROUP BY resource_type ORDER BY resource_type",
            (end, end, start, end, end, start, org_id, end, start)).fetchall()
        return 200, {"from": start.isoformat(), "to": end.isoformat(),
                     "coverage_start": epoch["started_at"].isoformat(), "allocations": rows}

    def quotas(self, conn, org_id, actor):
        if not allowed(self.membership(conn, org_id, actor), "capacity:read"):
            return 404, {"error": "not_found"}
        quota = conn.execute(
            "SELECT cpu_milli_limit,memory_mb_limit,updated_at FROM hosting.organization_quotas "
            "WHERE organization_id=%s", (org_id,)).fetchone()
        reserved = conn.execute(
            "SELECT coalesce(sum(cpu_milli),0) AS cpu_milli,"
            "coalesce(sum(memory_mb),0) AS memory_mb "
            "FROM hosting.capacity_intervals WHERE organization_id=%s AND ended_at IS NULL",
            (org_id,)).fetchone()
        return 200, {"quota": quota, "reserved": reserved,
                     "mode": "OPERATOR_SET" if quota else "UNBOUNDED"}

    def membership(self, conn, org_id, actor):
        row = conn.execute(
            "SELECT role FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s",
            (org_id, actor),
        ).fetchone()
        return row["role"] if row else None

    def service_accounts(self, conn, org_id, actor, body, method, request_id, revoke=False):
        if self.membership(conn, org_id, actor) != "owner":
            return 404, {"error": "not_found"}
        if revoke:
            if method != "POST" or set(body) != {"id", "confirm"} or body["confirm"] != "revoke_service_account":
                return 400, {"error": "invalid_service_revoke"}
            try:
                account_id = uuid.UUID(body["id"])
                if str(account_id) != body["id"]:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                return 400, {"error": "invalid_service_revoke"}
            # A release queue holds this lock through commit, so revocation and
            # admission have a single deterministic order.
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,3))", (str(account_id),))
            row = conn.execute("UPDATE hosting.service_accounts SET revoked_at=now() "
                               "WHERE organization_id=%s AND id=%s AND revoked_at IS NULL RETURNING id",
                               (org_id, account_id)).fetchone()
            if not row:
                return 409, {"error": "service_account_unavailable"}
            record(conn, org_id, actor, "service_account.revoke", account_id, request_id)
            return 200, {"state": "REVOKED", "request_id": request_id}
        if method == "GET":
            rows = conn.execute("SELECT id,application_id,client_id,actor_sub,created_by,created_at,revoked_at "
                                "FROM hosting.service_accounts WHERE organization_id=%s "
                                "ORDER BY created_at DESC,id DESC LIMIT 100", (org_id,)).fetchall()
            return 200, {"service_accounts": rows}
        if method != "POST" or set(body) != {"application_id", "client_id", "actor_sub"} or \
                not isinstance(body["client_id"], str) or not 1 <= len(body["client_id"]) <= 128 or \
                not isinstance(body["actor_sub"], str) or not 1 <= len(body["actor_sub"]) <= 255:
            return 400, {"error": "invalid_service_account"}
        try:
            app_id = uuid.UUID(body["application_id"])
            if str(app_id) != body["application_id"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_service_account"}
        if not conn.execute("SELECT 1 FROM hosting.applications WHERE organization_id=%s AND id=%s",
                            (org_id, app_id)).fetchone():
            return 404, {"error": "not_found"}
        account_id = uuid.uuid4()
        conn.execute("INSERT INTO hosting.service_accounts(id,organization_id,application_id,client_id,actor_sub,created_by) "
                     "VALUES (%s,%s,%s,%s,%s,%s)",
                     (account_id, org_id, app_id, body["client_id"], body["actor_sub"], actor))
        record(conn, org_id, actor, "service_account.create", account_id, request_id)
        return 201, {"id": account_id, "application_id": app_id, "request_id": request_id}

    def team(self, conn, org_id, actor, body, method, request_id, action="invitations"):
        if self.membership(conn, org_id, actor) != "owner":
            return 404, {"error": "not_found"}
        if action == "members":
            if method != "GET":
                return 404, {"error": "not_found"}
            rows = conn.execute("SELECT actor_sub,role FROM hosting.team_members(%s)", (org_id,)).fetchall()
            return 200, {"members": rows}
        if action == "remove":
            target = body.get("actor_sub")
            if method != "POST" or set(body) != {"actor_sub", "confirm"} or \
                    not isinstance(target, str) or not 1 <= len(target) <= 255 or \
                    body["confirm"] != "remove_member":
                return 400, {"error": "invalid_member_removal"}
            removed = conn.execute("SELECT hosting.remove_team_member(%s,%s)", (org_id, target)).fetchone()
            if not removed or not removed["remove_team_member"]:
                return 409, {"error": "member_removal_blocked"}
            resource = uuid.uuid5(uuid.NAMESPACE_URL, "member/" + str(org_id) + "/" + target)
            record(conn, org_id, actor, "team.member_removed", resource, request_id)
            return 200, {"state": "REMOVED", "request_id": request_id}
        if action == "revoke":
            if method != "POST" or set(body) != {"invitation_id"}:
                return 400, {"error": "invalid_invitation_revoke"}
            try:
                invitation_id = uuid.UUID(body["invitation_id"])
                if str(invitation_id) != body["invitation_id"]:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                return 400, {"error": "invalid_invitation_revoke"}
            row = conn.execute("UPDATE hosting.team_invitations SET revoked_at=now() "
                               "WHERE organization_id=%s AND id=%s AND accepted_at IS NULL AND revoked_at IS NULL "
                               "RETURNING id", (org_id, invitation_id)).fetchone()
            if not row:
                return 409, {"error": "invitation_unavailable"}
            record(conn, org_id, actor, "team.invitation_revoked", invitation_id, request_id)
            return 200, {"state": "REVOKED", "request_id": request_id}
        if action != "invitations":
            return 404, {"error": "not_found"}
        if method == "GET":
            rows = conn.execute("SELECT id,role,issued_by,expires_at,created_at,accepted_by,accepted_at,revoked_at "
                                "FROM hosting.team_invitations WHERE organization_id=%s "
                                "ORDER BY created_at DESC LIMIT 100", (org_id,)).fetchall()
            return 200, {"invitations": rows}
        if method != "POST" or set(body) != {"idempotency_key", "role", "expires_hours", "confirm"} or \
                body["role"] not in ("admin", "viewer") or \
                body["confirm"] != "invite_" + body["role"] or \
                type(body["expires_hours"]) is not int or not 1 <= body["expires_hours"] <= 72:
            return 400, {"error": "invalid_team_invitation"}
        try:
            key = uuid.UUID(body["idempotency_key"])
            if str(key) != body["idempotency_key"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_team_invitation"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,2))",
                     (str(org_id) + "/" + str(key),))
        existing = conn.execute("SELECT id,role,duration_hours,expires_at,accepted_at,revoked_at "
                                "FROM hosting.team_invitations WHERE organization_id=%s AND idempotency_key=%s",
                                (org_id, key)).fetchone()
        if existing:
            if (existing["role"], existing["duration_hours"]) != (body["role"], body["expires_hours"]):
                return 409, {"error": "idempotency_conflict"}
            # Never return a token again; its plaintext is not stored.
            return 200, {"id": existing["id"], "expires_at": existing["expires_at"], "replayed": True}
        token = secrets.token_urlsafe(32)
        invitation_id = uuid.uuid4()
        expires = conn.execute("INSERT INTO hosting.team_invitations "
                               "(id,organization_id,token_hash,idempotency_key,role,duration_hours,issued_by,expires_at) "
                               "VALUES (%s,%s,%s,%s,%s,%s,%s,now()+(%s * interval '1 hour')) "
                               "RETURNING expires_at",
                               (invitation_id, org_id, hashlib.sha256(token.encode()).digest(), key,
                                body["role"], body["expires_hours"], actor, body["expires_hours"])).fetchone()
        record(conn, org_id, actor, "team.invitation_created", invitation_id, request_id)
        return 201, {"id": invitation_id, "token": token, "expires_at": expires["expires_at"],
                     "role": body["role"], "request_id": request_id}

    def accept_invitation(self, conn, actor, body, request_id):
        token = body.get("token")
        if set(body) != {"token"} or not isinstance(token, str) or \
                not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return 400, {"error": "invalid_invitation"}
        digest = hashlib.sha256(token.encode()).digest()
        row = conn.execute("SELECT * FROM hosting.accept_team_invitation(%s)", (digest,)).fetchone()
        if not row:
            return 409, {"error": "invitation_unavailable"}
        if not row["replayed"]:
            record(conn, row["organization_id"], actor, "team.invitation_accepted",
                   row["invitation_id"], request_id)
        return 200, {"organization_id": row["organization_id"], "role": row["assigned_role"],
                     "state": "JOINED", "replayed": row["replayed"], "request_id": request_id}

    def domains(self, conn, org_id, app_id, actor, body, method, request_id, verify=False):
        if verify and method != "POST":
            return 404, {"error": "not_found"}
        action = "domain:verify" if verify else ("domain:read" if method == "GET" else "domain:create")
        if not allowed(self.membership(conn, org_id, actor), action):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        current = conn.execute("SELECT id,hostname,verification_token,verified_at,challenge_expires_at "
                               "FROM hosting.domains WHERE organization_id=%s AND application_id=%s",
                               (org_id, app_id)).fetchone()
        if method == "GET":
            if not current:
                return 200, {"domain": None}
            result = {key: current[key] for key in ("id", "hostname", "verified_at", "challenge_expires_at")}
            if allowed(self.membership(conn, org_id, actor), "domain:verify") and not current["verified_at"]:
                result["txt_name"] = "_dial-verify." + current["hostname"]
                result["txt_value"] = "dial-hosting=" + current["verification_token"]
            return 200, {"domain": result}
        if verify:
            if body or not current:
                return 400, {"error": "invalid_domain_verification"}
            if current["verified_at"]:
                return 200, {"id": current["id"], "verified_at": current["verified_at"]}
            if not conn.execute("SELECT 1 WHERE %s > now()", (current["challenge_expires_at"],)).fetchone():
                return 409, {"error": "domain_challenge_expired"}
            if not txt_proves(current["hostname"], current["verification_token"]):
                return 409, {"error": "domain_dns_proof_missing"}
            verified = conn.execute("UPDATE hosting.domains SET verified_at=now() WHERE id=%s RETURNING verified_at",
                                    (current["id"],)).fetchone()
            record(conn, org_id, actor, "domain.verify", current["id"], request_id)
            return 200, {"id": current["id"], "verified_at": verified["verified_at"]}
        if set(body) != {"hostname"} or not valid_hostname(body["hostname"]):
            return 400, {"error": "invalid_hostname"}
        if current:
            return 409, {"error": "domain_already_registered"}
        domain_id, token = uuid.uuid4(), new_token()
        conn.execute("INSERT INTO hosting.domains(id,organization_id,application_id,hostname,verification_token) "
                     "VALUES (%s,%s,%s,%s,%s)", (domain_id, org_id, app_id, body["hostname"], token))
        record(conn, org_id, actor, "domain.register", domain_id, request_id)
        return 201, {"id": domain_id, "hostname": body["hostname"],
                     "txt_name": "_dial-verify." + body["hostname"], "txt_value": "dial-hosting=" + token,
                     "request_id": request_id}

    def applications(self, conn, org_id, project_id, actor, body, method, request_id):
        role = self.membership(conn, org_id, actor)
        if not allowed(role, "application:read" if method == "GET" else "application:create"):
            return 404, {"error": "not_found"}
        project = conn.execute("SELECT id FROM hosting.projects WHERE organization_id=%s AND id=%s",
                               (org_id, project_id)).fetchone()
        if not project:
            return 404, {"error": "not_found"}
        if method == "GET":
            rows = conn.execute(
                "SELECT id,name,environment,active_release_id,traffic_state,created_at FROM hosting.applications "
                "WHERE organization_id=%s AND project_id=%s ORDER BY created_at DESC LIMIT 100",
                (org_id, project_id),
            ).fetchall()
            return 200, {"applications": rows}
        if set(body) != {"name", "environment"} or not valid_name(body["name"]) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", str(body["environment"])):
            return 400, {"error": "invalid_application"}
        app_id = uuid.uuid4()
        conn.execute("INSERT INTO hosting.applications(id,organization_id,project_id,name,environment) VALUES (%s,%s,%s,%s,%s)",
                     (app_id, org_id, project_id, body["name"], body["environment"]))
        record(conn, org_id, actor, "application.create", app_id, request_id)
        return 201, {"id": app_id, "request_id": request_id}

    def traffic(self, conn, org_id, app_id, actor, body, method, request_id):
        role = self.membership(conn, org_id, actor)
        if not allowed(role, "application:read" if method == "GET" else "application:traffic"):
            return 404, {"error": "not_found"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(app_id),))
        app = conn.execute("SELECT traffic_state,traffic_reason,traffic_requested_by,traffic_updated_at,"
                           "traffic_last_error FROM hosting.applications WHERE organization_id=%s AND id=%s" +
                           (" FOR UPDATE" if method == "POST" else ""),
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        if method == "GET":
            return 200, {"traffic": app}
        action, reason = body.get("action"), body.get("reason")
        if (set(body) != {"action", "reason", "confirm"} or action not in ("suspend", "resume") or
                body["confirm"] != action + "_application" or not isinstance(reason, str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,:;_()/-]{2,239}", reason)):
            return 400, {"error": "invalid_traffic_request"}
        state = app["traffic_state"]
        target = "SUSPENDING" if action == "suspend" else "RESUMING"
        if state == target or state == ("SUSPENDED" if action == "suspend" else "ACTIVE"):
            return 200, {"state": state, "replayed": True}
        if state != ("ACTIVE" if action == "suspend" else "SUSPENDED"):
            return 409, {"error": "traffic_transition_in_progress"}
        if action == "resume" and conn.execute(
                "SELECT 1 FROM hosting.applications WHERE id=%s AND traffic_lease_until>now()",
                (app_id,)).fetchone():
            return 409, {"error": "traffic_reconciliation_in_progress"}
        if action == "suspend" and conn.execute(
                "SELECT 1 FROM hosting.releases WHERE application_id=%s AND state IN ('QUEUED','DEPLOYING')",
                (app_id,)).fetchone():
            return 409, {"error": "release_in_progress"}
        conn.execute("UPDATE hosting.applications SET traffic_state=%s,traffic_reason=%s,traffic_requested_by=%s,"
                     "traffic_updated_at=now(),traffic_next_attempt_at=now(),traffic_last_error=NULL WHERE id=%s",
                     (target, reason, actor, app_id))
        conn.execute("INSERT INTO hosting.application_traffic_events "
                     "(organization_id,application_id,actor_sub,action,reason,request_id) "
                     "VALUES (%s,%s,%s,%s,%s,%s)", (org_id, app_id, actor, action, reason, request_id))
        record(conn, org_id, actor, "application.traffic_" + action, app_id, request_id)
        return 202, {"state": target, "request_id": request_id}

    def builds(self, conn, org_id, app_id, actor, method):
        if method != "GET" or not allowed(self.membership(conn, org_id, actor), "release:read"):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        rows = conn.execute(
            "SELECT b.delivery_id,b.source_commit,b.state,b.attempts,b.image,b.last_error,b.created_at,"
            "s.id AS source_id,s.full_name,s.branch FROM hosting.github_builds b "
            "JOIN hosting.git_sources s ON s.id=b.source_id "
            "WHERE s.organization_id=%s AND s.application_id=%s "
            "ORDER BY b.created_at DESC,b.delivery_id DESC LIMIT 100", (org_id, app_id),
        ).fetchall()
        return 200, {"builds": rows}

    def health(self, conn, org_id, app_id, actor, method):
        if method != "GET" or not allowed(self.membership(conn, org_id, actor), "release:read"):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT a.active_release_id,a.traffic_state,r.state AS release_state "
                           "FROM hosting.applications a LEFT JOIN hosting.releases r "
                           "ON r.id=a.active_release_id WHERE a.organization_id=%s AND a.id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        if not app["active_release_id"]:
            return 200, {"state": "NOT_DEPLOYED", "release_id": None, "checked_at": None,
                         "consecutive_failures": 0}
        if app["traffic_state"] != "ACTIVE":
            return 200, {"state": app["traffic_state"], "release_id": app["active_release_id"],
                         "checked_at": None, "consecutive_failures": 0}
        if app["release_state"] != "SERVING":
            return 200, {"state": "UNKNOWN", "release_id": app["active_release_id"],
                         "checked_at": None, "consecutive_failures": 0}
        health = conn.execute("SELECT state,consecutive_failures,checked_at,"
                              "(checked_at IS NULL OR checked_at<now()-interval '3 minutes') AS stale "
                              "FROM hosting.release_health WHERE organization_id=%s AND application_id=%s "
                              "AND release_id=%s", (org_id, app_id, app["active_release_id"])).fetchone()
        return 200, {"state": "UNKNOWN" if not health or health["stale"] else health["state"],
                     "release_id": app["active_release_id"],
                     "checked_at": health["checked_at"] if health else None,
                     "consecutive_failures": health["consecutive_failures"] if health else 0}

    def health_incidents(self, conn, org_id, app_id, actor, method):
        if method != "GET" or not allowed(self.membership(conn, org_id, actor), "release:read"):
            return 404, {"error": "not_found"}
        if not conn.execute("SELECT 1 FROM hosting.applications WHERE organization_id=%s AND id=%s",
                            (org_id, app_id)).fetchone():
            return 404, {"error": "not_found"}
        rows = conn.execute("SELECT id,release_id,opened_at,closed_at,resolution "
                            "FROM hosting.release_health_incidents WHERE organization_id=%s "
                            "AND application_id=%s ORDER BY opened_at DESC,id DESC LIMIT 100",
                            (org_id, app_id)).fetchall()
        return 200, {"incidents": rows}

    def releases(self, conn, org_id, app_id, actor, body, method, request_id, rollback_of=None):
        role = self.membership(conn, org_id, actor)
        service_client = conn.execute("SELECT current_setting('hosting.service_client_id',true) AS client_id").fetchone()["client_id"]
        if service_client:
            account = conn.execute("SELECT id FROM hosting.service_accounts WHERE organization_id=%s "
                                   "AND application_id=%s AND actor_sub=%s AND client_id=%s AND revoked_at IS NULL",
                                   (org_id, app_id, actor, service_client)).fetchone()
            if not account:
                return 404, {"error": "not_found"}
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,3))", (str(account["id"]),))
            if not conn.execute("SELECT 1 FROM hosting.service_accounts WHERE id=%s AND revoked_at IS NULL",
                                (account["id"],)).fetchone():
                return 404, {"error": "not_found"}
        elif not allowed(role, "release:read" if method == "GET" else "release:create"):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT id,active_release_id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        if method == "GET":
            rows = conn.execute(
                "SELECT id,image,state,node_id,previous_release_id,rollback_of_release_id,created_at FROM hosting.releases "
                "WHERE organization_id=%s AND application_id=%s ORDER BY created_at DESC LIMIT 100",
                (org_id, app_id),
            ).fetchall()
            return 200, {"releases": rows}
        if not valid_release(body):
            return 400, {"error": "invalid_release"}
        domain = conn.execute("SELECT id FROM hosting.domains WHERE organization_id=%s AND application_id=%s "
                              "AND verified_at IS NOT NULL", (org_id, app_id)).fetchone()
        if not domain:
            return 409, {"error": "verified_domain_required"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 1))", (str(app_id),))
        app = conn.execute("SELECT active_release_id,traffic_state FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()
        if app["traffic_state"] != "ACTIVE":
            return 409, {"error": "application_traffic_not_active"}
        existing = conn.execute(
            "SELECT id,state,image,port,health_path,memory_mb,cpu_milli,rollback_of_release_id FROM hosting.releases "
            "WHERE organization_id=%s AND application_id=%s AND idempotency_key=%s",
            (org_id, app_id, body["idempotency_key"]),
        ).fetchone()
        if existing:
            if (any(existing[key] != body[key] for key in ("image", "port", "health_path", "memory_mb", "cpu_milli")) or
                    existing["rollback_of_release_id"] != rollback_of):
                return 409, {"error": "idempotency_conflict"}
            return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
        pending = conn.execute("SELECT 1 FROM hosting.releases WHERE application_id=%s AND state IN ('QUEUED','DEPLOYING')",
                               (app_id,)).fetchone()
        if pending:
            return 409, {"error": "release_in_progress"}
        admitted = conn.execute("SELECT hosting.release_image_admitted(%s,%s,%s) AS allowed",
                                (body["image"], org_id, app_id)).fetchone()
        if not admitted["allowed"]:
            return 409, {"error": "artifact_not_admitted"}
        previous_node = None
        if app["active_release_id"]:
            previous = conn.execute("SELECT node_id FROM hosting.releases WHERE id=%s",
                                    (app["active_release_id"],)).fetchone()
            previous_node = previous["node_id"]
        database = conn.execute("SELECT node_id,state FROM hosting.postgres_instances WHERE application_id=%s "
                                "AND state IN ('QUEUED','PROVISIONING','READY')", (app_id,)).fetchone()
        if database:
            if database["state"] != "READY":
                return 409, {"error": "database_not_ready"}
            if previous_node and previous_node != database["node_id"]:
                return 409, {"error": "database_placement_conflict"}
            previous_node = database["node_id"]
        cache = conn.execute("SELECT node_id,state FROM hosting.valkey_instances WHERE application_id=%s", (app_id,)).fetchone()
        if cache:
            if cache["state"] != "READY":
                return 409, {"error": "cache_not_ready"}
            if previous_node and previous_node != cache["node_id"]:
                return 409, {"error": "cache_placement_conflict"}
            previous_node = cache["node_id"]
        storage = conn.execute("SELECT node_id,state FROM hosting.object_storage_instances WHERE application_id=%s",
                               (app_id,)).fetchone()
        if storage:
            if storage["state"] != "READY":
                return 409, {"error": "storage_not_ready"}
            if previous_node and previous_node != storage["node_id"]:
                return 409, {"error": "storage_placement_conflict"}
            previous_node = storage["node_id"]
        node = conn.execute(
            "SELECT id FROM hosting.nodes WHERE enabled AND public_ipv4 IS NOT NULL "
            "AND observed_at > now() - interval '5 minutes' "
            "AND cpu_milli-reserved_cpu_milli >= %s AND memory_mb-reserved_memory_mb >= %s "
            "AND (%s::uuid IS NULL OR id=%s::uuid) "
            "ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1",
            (body["cpu_milli"], body["memory_mb"], previous_node, previous_node),
        ).fetchone()
        if not node:
            return 409, {"error": "capacity_unavailable"}
        conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli+%s, "
                     "reserved_memory_mb=reserved_memory_mb+%s WHERE id=%s",
                     (body["cpu_milli"], body["memory_mb"], node["id"]))
        release_id, job_id = uuid.uuid4(), uuid.uuid4()
        conn.execute(
            "INSERT INTO hosting.releases(id,organization_id,application_id,node_id,requested_by,idempotency_key,"
            "image,port,health_path,memory_mb,cpu_milli,previous_release_id,rollback_of_release_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (release_id, org_id, app_id, node["id"], actor, body["idempotency_key"], body["image"],
             body["port"], body["health_path"], body["memory_mb"], body["cpu_milli"], app["active_release_id"], rollback_of),
        )
        conn.execute("INSERT INTO hosting.jobs(id,organization_id,release_id) VALUES (%s,%s,%s)",
                     (job_id, org_id, release_id))
        record(conn, org_id, actor, "release.rollback_queue" if rollback_of else "release.queue", release_id, request_id)
        return 202, {"id": release_id, "job_id": job_id, "state": "QUEUED", "request_id": request_id,
                     "rollback_of_release_id": rollback_of}

    def rollback(self, conn, org_id, app_id, actor, body, request_id):
        if not allowed(self.membership(conn, org_id, actor), "release:rollback"):
            return 404, {"error": "not_found"}
        if set(body) != {"target_release_id", "idempotency_key"}:
            return 400, {"error": "invalid_rollback"}
        try:
            target_id = uuid.UUID(body["target_release_id"])
            if str(target_id) != body["target_release_id"]:
                raise ValueError()
            if str(uuid.UUID(body["idempotency_key"])) != body["idempotency_key"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_rollback"}
        target = conn.execute("SELECT id,image,port,health_path,memory_mb,cpu_milli,state "
                              "FROM hosting.releases WHERE organization_id=%s AND application_id=%s AND id=%s",
                              (org_id, app_id, target_id)).fetchone()
        if not target or target["state"] not in ("SERVING", "SUPERSEDED", "RETIRED"):
            return 409, {"error": "rollback_target_unavailable"}
        active = conn.execute("SELECT active_release_id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                              (org_id, app_id)).fetchone()
        if active and active["active_release_id"] == target_id:
            return 409, {"error": "target_already_active"}
        request = {"idempotency_key": body["idempotency_key"], "image": target["image"], "port": target["port"],
                   "health_path": target["health_path"], "memory_mb": target["memory_mb"], "cpu_milli": target["cpu_milli"]}
        return self.releases(conn, org_id, app_id, actor, request, "POST", request_id, rollback_of=target_id)

    def postgres(self, conn, org_id, app_id, actor, body, method, request_id):
        if not allowed(self.membership(conn, org_id, actor), "postgres:read" if method == "GET" else "postgres:create"):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,secret_version,idempotency_key "
                                "FROM hosting.postgres_instances WHERE organization_id=%s AND application_id=%s",
                                (org_id, app_id)).fetchone()
        if method == "GET":
            if not existing:
                return 200, {"postgres": None}
            return 200, {"postgres": {key: existing[key] for key in
                                      ("id", "node_id", "memory_mb", "cpu_milli", "state", "secret_version")}}
        if set(body) != {"idempotency_key", "memory_mb", "cpu_milli"} or \
                type(body["memory_mb"]) is not int or not 256 <= body["memory_mb"] <= 32768 or \
                type(body["cpu_milli"]) is not int or not 100 <= body["cpu_milli"] <= 32000:
            return 400, {"error": "invalid_postgres_request"}
        try:
            key = uuid.UUID(body["idempotency_key"])
            if str(key) != body["idempotency_key"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_postgres_request"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(app_id),))
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,secret_version,idempotency_key "
                                "FROM hosting.postgres_instances WHERE application_id=%s", (app_id,)).fetchone()
        if existing:
            if (existing["idempotency_key"], existing["memory_mb"], existing["cpu_milli"]) != \
                    (key, body["memory_mb"], body["cpu_milli"]):
                return 409, {"error": "postgres_already_exists"}
            return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
        prior = conn.execute("SELECT node_id FROM hosting.valkey_instances WHERE application_id=%s", (app_id,)).fetchone()
        storage_placement = conn.execute("SELECT node_id FROM hosting.object_storage_instances WHERE application_id=%s",
                                         (app_id,)).fetchone()
        previous = conn.execute("SELECT node_id FROM hosting.releases WHERE application_id=%s "
                             "AND state IN ('SERVING','QUEUED','DEPLOYING') ORDER BY created_at DESC LIMIT 1", (app_id,)).fetchone()
        if len({row["node_id"] for row in (prior, previous, storage_placement) if row}) > 1:
            return 409, {"error": "resource_placement_conflict"}
        prior = prior or previous or storage_placement
        node = conn.execute(
            "SELECT id FROM hosting.nodes WHERE enabled AND observed_at > now()-interval '5 minutes' "
            "AND cpu_milli-reserved_cpu_milli >= %s AND memory_mb-reserved_memory_mb >= %s "
            "AND (%s::uuid IS NULL OR id=%s::uuid) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1",
            (body["cpu_milli"], body["memory_mb"], prior["node_id"] if prior else None,
             prior["node_id"] if prior else None)).fetchone()
        if not node:
            return 409, {"error": "capacity_unavailable"}
        conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli+%s, "
                     "reserved_memory_mb=reserved_memory_mb+%s WHERE id=%s",
                     (body["cpu_milli"], body["memory_mb"], node["id"]))
        instance_id, job_id = uuid.uuid4(), uuid.uuid4()
        conn.execute("INSERT INTO hosting.postgres_instances(id,organization_id,application_id,node_id,requested_by,"
                     "idempotency_key,memory_mb,cpu_milli) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                     (instance_id, org_id, app_id, node["id"], actor, key, body["memory_mb"], body["cpu_milli"]))
        conn.execute("INSERT INTO hosting.postgres_jobs(id,organization_id,instance_id) VALUES (%s,%s,%s)",
                     (job_id, org_id, instance_id))
        record(conn, org_id, actor, "postgres.queue", instance_id, request_id)
        return 202, {"id": instance_id, "job_id": job_id, "state": "QUEUED", "request_id": request_id}

    def valkey(self, conn, org_id, app_id, actor, body, method, request_id):
        if not allowed(self.membership(conn, org_id, actor), "valkey:read" if method == "GET" else "valkey:create"):
            return 404, {"error": "not_found"}
        if not conn.execute("SELECT 1 FROM hosting.applications WHERE organization_id=%s AND id=%s",
                            (org_id, app_id)).fetchone():
            return 404, {"error": "not_found"}
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,secret_version,idempotency_key "
                                "FROM hosting.valkey_instances WHERE organization_id=%s AND application_id=%s",
                                (org_id, app_id)).fetchone()
        if method == "GET":
            return 200, {"valkey": ({key: existing[key] for key in
                                     ("id", "node_id", "memory_mb", "cpu_milli", "state", "secret_version")}
                                    if existing else None)}
        if (set(body) != {"idempotency_key", "memory_mb", "cpu_milli"} or
                type(body["memory_mb"]) is not int or not 128 <= body["memory_mb"] <= 16384 or
                type(body["cpu_milli"]) is not int or not 100 <= body["cpu_milli"] <= 16000):
            return 400, {"error": "invalid_valkey_request"}
        try:
            key = uuid.UUID(body["idempotency_key"])
            if str(key) != body["idempotency_key"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_valkey_request"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(app_id),))
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,idempotency_key FROM hosting.valkey_instances "
                                "WHERE application_id=%s", (app_id,)).fetchone()
        if existing:
            if (existing["idempotency_key"], existing["memory_mb"], existing["cpu_milli"]) != \
                    (key, body["memory_mb"], body["cpu_milli"]):
                return 409, {"error": "valkey_already_exists"}
            return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
        prior = conn.execute("SELECT node_id FROM hosting.postgres_instances WHERE application_id=%s", (app_id,)).fetchone()
        storage_placement = conn.execute("SELECT node_id FROM hosting.object_storage_instances WHERE application_id=%s",
                                         (app_id,)).fetchone()
        previous = conn.execute("SELECT node_id FROM hosting.releases WHERE application_id=%s "
                             "AND state IN ('SERVING','QUEUED','DEPLOYING') "
                             "ORDER BY created_at DESC LIMIT 1", (app_id,)).fetchone()
        if len({row["node_id"] for row in (prior, previous, storage_placement) if row}) > 1:
            return 409, {"error": "resource_placement_conflict"}
        prior = prior or previous or storage_placement
        node = conn.execute("SELECT id FROM hosting.nodes WHERE enabled AND observed_at>now()-interval '5 minutes' "
                            "AND cpu_milli-reserved_cpu_milli >= %s AND memory_mb-reserved_memory_mb >= %s "
                            "AND (%s::uuid IS NULL OR id=%s::uuid) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1",
                            (body["cpu_milli"], body["memory_mb"], prior["node_id"] if prior else None,
                             prior["node_id"] if prior else None)).fetchone()
        if not node:
            return 409, {"error": "capacity_unavailable"}
        conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli+%s, "
                     "reserved_memory_mb=reserved_memory_mb+%s WHERE id=%s",
                     (body["cpu_milli"], body["memory_mb"], node["id"]))
        instance_id, job_id = uuid.uuid4(), uuid.uuid4()
        conn.execute("INSERT INTO hosting.valkey_instances(id,organization_id,application_id,node_id,requested_by,"
                     "idempotency_key,memory_mb,cpu_milli) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                     (instance_id, org_id, app_id, node["id"], actor, key, body["memory_mb"], body["cpu_milli"]))
        conn.execute("INSERT INTO hosting.valkey_jobs(id,organization_id,instance_id) VALUES (%s,%s,%s)",
                     (job_id, org_id, instance_id))
        record(conn, org_id, actor, "valkey.queue", instance_id, request_id)
        return 202, {"id": instance_id, "job_id": job_id, "state": "QUEUED", "request_id": request_id}

    def storage(self, conn, org_id, app_id, actor, body, method, request_id):
        if not allowed(self.membership(conn, org_id, actor), "storage:read" if method == "GET" else "storage:create"):
            return 404, {"error": "not_found"}
        if not conn.execute("SELECT 1 FROM hosting.applications WHERE organization_id=%s AND id=%s",
                            (org_id, app_id)).fetchone():
            return 404, {"error": "not_found"}
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,secret_version,idempotency_key "
                                "FROM hosting.object_storage_instances WHERE organization_id=%s AND application_id=%s",
                                (org_id, app_id)).fetchone()
        if method == "GET":
            return 200, {"storage": ({key: existing[key] for key in
                                      ("id", "node_id", "memory_mb", "cpu_milli", "state", "secret_version")}
                                     if existing else None)}
        if (set(body) != {"idempotency_key", "memory_mb", "cpu_milli"} or
                type(body["memory_mb"]) is not int or not 256 <= body["memory_mb"] <= 16384 or
                type(body["cpu_milli"]) is not int or not 100 <= body["cpu_milli"] <= 16000):
            return 400, {"error": "invalid_storage_request"}
        try:
            key = uuid.UUID(body["idempotency_key"])
            if str(key) != body["idempotency_key"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return 400, {"error": "invalid_storage_request"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(app_id),))
        existing = conn.execute("SELECT id,node_id,memory_mb,cpu_milli,state,idempotency_key "
                                "FROM hosting.object_storage_instances WHERE application_id=%s", (app_id,)).fetchone()
        if existing:
            if (existing["idempotency_key"], existing["memory_mb"], existing["cpu_milli"]) != \
                    (key, body["memory_mb"], body["cpu_milli"]):
                return 409, {"error": "storage_already_exists"}
            return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
        placements = [row["node_id"] for table in ("postgres_instances", "valkey_instances")
                      if (row := conn.execute("SELECT node_id FROM hosting." + table + " WHERE application_id=%s",
                                              (app_id,)).fetchone())]
        previous = conn.execute("SELECT node_id FROM hosting.releases WHERE application_id=%s "
                                "AND state IN ('SERVING','QUEUED','DEPLOYING') "
                                "ORDER BY created_at DESC LIMIT 1", (app_id,)).fetchone()
        if previous:
            placements.append(previous["node_id"])
        if len(set(placements)) > 1:
            return 409, {"error": "resource_placement_conflict"}
        pinned = placements[0] if placements else None
        node = conn.execute("SELECT id FROM hosting.nodes WHERE enabled AND observed_at>now()-interval '5 minutes' "
                            "AND cpu_milli-reserved_cpu_milli >= %s AND memory_mb-reserved_memory_mb >= %s "
                            "AND (%s::uuid IS NULL OR id=%s::uuid) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1",
                            (body["cpu_milli"], body["memory_mb"], pinned, pinned)).fetchone()
        if not node:
            return 409, {"error": "capacity_unavailable"}
        conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli+%s, "
                     "reserved_memory_mb=reserved_memory_mb+%s WHERE id=%s",
                     (body["cpu_milli"], body["memory_mb"], node["id"]))
        instance_id, job_id = uuid.uuid4(), uuid.uuid4()
        conn.execute("INSERT INTO hosting.object_storage_instances(id,organization_id,application_id,node_id,"
                     "requested_by,idempotency_key,memory_mb,cpu_milli) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                     (instance_id, org_id, app_id, node["id"], actor, key, body["memory_mb"], body["cpu_milli"]))
        conn.execute("INSERT INTO hosting.object_storage_jobs(id,organization_id,instance_id) VALUES (%s,%s,%s)",
                     (job_id, org_id, instance_id))
        record(conn, org_id, actor, "storage.queue", instance_id, request_id)
        return 202, {"id": instance_id, "job_id": job_id, "state": "QUEUED", "request_id": request_id}

    def handle_request(self, method):
        parsed_url = urlsplit(self.path)
        path = parsed_url.path
        if path == "/live" and method == "GET":
            return self.reply(200, {"status": "process_alive"})
        if path == "/openapi.json" and method == "GET":
            from .openapi import document
            return self.reply(200, document())
        try:
            identity = authenticate(self.headers.get("Authorization"), self.server.jwks)
            actor = identity.sub
            if identity.client_id and not service_route_allowed(path, method):
                return self.reply(404, {"error": "not_found"})
            if method == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 8192:
                    return self.reply(413, {"error": "body_size"})
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    return self.reply(400, {"error": "invalid_body"})
            else:
                body = {}
            request_id = uuid.uuid4()
            with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
                with conn.transaction():
                    conn.execute("SET LOCAL search_path = hosting, pg_catalog")
                    conn.execute("SELECT set_config('hosting.actor_sub', %s, true)", (actor,))
                    conn.execute("SELECT set_config('hosting.auth_kind', %s, true)",
                                 ("service" if identity.client_id else "human",))
                    if identity.client_id:
                        conn.execute("SELECT set_config('hosting.service_client_id', %s, true)", (identity.client_id,))
                    if path == "/ready" and method == "GET":
                        conn.execute("SELECT 1")
                        result = (200, {"status": "database_reachable"})
                    elif path == "/v1/organizations" and method == "GET":
                        rows = conn.execute(
                            "SELECT o.id, o.name, m.role FROM hosting.organizations o JOIN hosting.memberships m "
                            "ON m.organization_id=o.id WHERE m.actor_sub=%s ORDER BY o.name LIMIT 100",
                            (actor,),
                        ).fetchall()
                        result = (200, {"organizations": rows})
                    elif method == "GET" and (match := re.fullmatch(
                            r"/v1/organizations/([0-9a-f-]{36})/audit", path)):
                        result = self.audit(conn, uuid.UUID(match.group(1)), actor,
                                            audit_after(parsed_url.query))
                    elif method == "GET" and (match := re.fullmatch(
                            r"/v1/organizations/([0-9a-f-]{36})/capacity", path)):
                        result = self.capacity(conn, uuid.UUID(match.group(1)), actor,
                                               capacity_window(parsed_url.query))
                    elif method == "GET" and (match := re.fullmatch(
                            r"/v1/organizations/([0-9a-f-]{36})/quotas", path)):
                        result = self.quotas(conn, uuid.UUID(match.group(1)), actor)
                    elif path == "/v1/team/invitations/accept" and method == "POST":
                        result = self.accept_invitation(conn, actor, body, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/service-accounts(/revoke)?", path):
                        result = self.service_accounts(conn, uuid.UUID(match.group(1)), actor, body, method,
                                                       request_id, revoke=bool(match.group(2)))
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/team/(invitations|invitations/revoke|members|members/remove)", path):
                        action = {"invitations": "invitations", "invitations/revoke": "revoke",
                                  "members": "members", "members/remove": "remove"}[match.group(2)]
                        result = self.team(conn, uuid.UUID(match.group(1)), actor, body, method, request_id, action)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/projects", path):
                        org_id = uuid.UUID(match.group(1))
                        role = conn.execute(
                            "SELECT role FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s",
                            (org_id, actor),
                        ).fetchone()
                        if not role or not allowed(role["role"], "project:" + ("read" if method == "GET" else "create")):
                            result = (404, {"error": "not_found"})
                        elif method == "GET":
                            rows = conn.execute(
                                "SELECT id, name, created_at FROM hosting.projects WHERE organization_id=%s ORDER BY created_at DESC LIMIT 100",
                                (org_id,),
                            ).fetchall()
                            result = (200, {"projects": rows})
                        elif method == "POST":
                            name = body.get("name")
                            if not valid_name(name):
                                result = (400, {"error": "invalid_name"})
                            else:
                                project_id = uuid.uuid4()
                                conn.execute(
                                    "INSERT INTO hosting.projects(id,organization_id,name) VALUES (%s,%s,%s)",
                                    (project_id, org_id, name),
                                )
                                record(conn, org_id, actor, "project.create", project_id, request_id)
                                result = (201, {"id": project_id, "name": name, "request_id": request_id})
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/projects/([0-9a-f-]{36})/applications", path):
                        result = self.applications(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                                   actor, body, method, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/traffic", path):
                        result = self.traffic(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                              actor, body, method, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/domain(/verify)?", path):
                        result = self.domains(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                              actor, body, method, request_id, verify=bool(match.group(3)))
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/postgres", path):
                        result = self.postgres(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                               actor, body, method, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/valkey", path):
                        result = self.valkey(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                             actor, body, method, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/storage", path):
                        result = self.storage(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                              actor, body, method, request_id)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/builds", path):
                        result = self.builds(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                             actor, method)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/health", path):
                        result = self.health(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                             actor, method)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/health/incidents", path):
                        result = self.health_incidents(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                                       actor, method)
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/releases", path):
                        result = self.releases(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                               actor, body, method, request_id)
                    elif method == "POST" and (match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/rollback", path)):
                        result = self.rollback(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                               actor, body, request_id)
                    else:
                        result = (404, {"error": "not_found"})
            return self.reply(*result)
        except PermissionError:
            return self.reply(401, {"error": "unauthorized"})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_request"})
        except psycopg.errors.UniqueViolation:
            return self.reply(409, {"error": "conflict"})
        except psycopg.errors.RaiseException as exc:
            if exc.diag.message_primary == "quota_exceeded":
                return self.reply(409, {"error": "quota_exceeded"})
            return self.reply(503, {"error": "unavailable"})
        except Exception:
            # No SQL, token or configuration detail in a public response.
            return self.reply(503, {"error": "unavailable"})


def main():
    jwks = environment()
    from .migrate import verify
    with psycopg.connect(database_dsn(), connect_timeout=5) as conn:
        verify(conn)
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.jwks = jwks
    server.serve_forever()


if __name__ == "__main__":
    main()
