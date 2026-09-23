import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import jwt
import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from .policy import allowed, valid_name, valid_release


def environment():
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD_FILE", "OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_JWKS_URL")
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise RuntimeError("Missing configuration: " + ", ".join(missing))
    issuer = os.environ["OIDC_ISSUER"]
    jwks = os.environ["OIDC_JWKS_URL"]
    if not issuer.startswith("https://") or not jwks.startswith("https://"):
        raise RuntimeError("OIDC issuer and JWKS URL must use HTTPS")
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
            issuer=os.environ["OIDC_ISSUER"], audience=os.environ["OIDC_AUDIENCE"],
            options={"require": ["exp", "iat", "sub", "iss", "aud"]}, leeway=30,
        )
        if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 255:
            raise PermissionError("Invalid subject")
        return claims["sub"]
    except (jwt.PyJWTError, ValueError) as exc:
        raise PermissionError("Invalid bearer token") from exc


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

    def membership(self, conn, org_id, actor):
        row = conn.execute(
            "SELECT role FROM hosting.memberships WHERE organization_id=%s AND actor_sub=%s",
            (org_id, actor),
        ).fetchone()
        return row["role"] if row else None

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
                "SELECT id,name,environment,active_release_id,created_at FROM hosting.applications "
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

    def releases(self, conn, org_id, app_id, actor, body, method, request_id):
        role = self.membership(conn, org_id, actor)
        if not allowed(role, "release:read" if method == "GET" else "release:create"):
            return 404, {"error": "not_found"}
        app = conn.execute("SELECT id,active_release_id FROM hosting.applications WHERE organization_id=%s AND id=%s",
                           (org_id, app_id)).fetchone()
        if not app:
            return 404, {"error": "not_found"}
        if method == "GET":
            rows = conn.execute(
                "SELECT id,image,state,node_id,created_at FROM hosting.releases "
                "WHERE organization_id=%s AND application_id=%s ORDER BY created_at DESC LIMIT 100",
                (org_id, app_id),
            ).fetchall()
            return 200, {"releases": rows}
        if not valid_release(body):
            return 400, {"error": "invalid_release"}
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 1))", (str(app_id),))
        app = conn.execute("SELECT active_release_id FROM hosting.applications WHERE id=%s", (app_id,)).fetchone()
        existing = conn.execute(
            "SELECT id,state FROM hosting.releases WHERE organization_id=%s AND application_id=%s AND idempotency_key=%s",
            (org_id, app_id, body["idempotency_key"]),
        ).fetchone()
        if existing:
            return 200, {"id": existing["id"], "state": existing["state"], "replayed": True}
        pending = conn.execute("SELECT 1 FROM hosting.releases WHERE application_id=%s AND state IN ('QUEUED','DEPLOYING')",
                               (app_id,)).fetchone()
        if pending:
            return 409, {"error": "release_in_progress"}
        admitted = conn.execute("SELECT 1 FROM hosting.artifact_admissions WHERE image=%s", (body["image"],)).fetchone()
        if not admitted:
            return 409, {"error": "artifact_not_admitted"}
        previous_node = None
        if app["active_release_id"]:
            previous = conn.execute("SELECT node_id FROM hosting.releases WHERE id=%s",
                                    (app["active_release_id"],)).fetchone()
            previous_node = previous["node_id"]
        node = conn.execute(
            "SELECT id FROM hosting.nodes WHERE enabled AND observed_at > now() - interval '5 minutes' "
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
            "image,port,health_path,memory_mb,cpu_milli,previous_release_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (release_id, org_id, app_id, node["id"], actor, body["idempotency_key"], body["image"],
             body["port"], body["health_path"], body["memory_mb"], body["cpu_milli"], app["active_release_id"]),
        )
        conn.execute("INSERT INTO hosting.jobs(id,organization_id,release_id) VALUES (%s,%s,%s)",
                     (job_id, org_id, release_id))
        record(conn, org_id, actor, "release.queue", release_id, request_id)
        return 202, {"id": release_id, "job_id": job_id, "state": "QUEUED", "request_id": request_id}

    def handle_request(self, method):
        path = urlsplit(self.path).path
        if path == "/live" and method == "GET":
            return self.reply(200, {"status": "process_alive"})
        try:
            actor = authenticate(self.headers.get("Authorization"), self.server.jwks)
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
                    elif match := re.fullmatch(r"/v1/organizations/([0-9a-f-]{36})/applications/([0-9a-f-]{36})/releases", path):
                        result = self.releases(conn, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)),
                                               actor, body, method, request_id)
                    else:
                        result = (404, {"error": "not_found"})
            return self.reply(*result)
        except PermissionError:
            return self.reply(401, {"error": "unauthorized"})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_request"})
        except psycopg.errors.UniqueViolation:
            return self.reply(409, {"error": "conflict"})
        except Exception:
            # No SQL, token or configuration detail in a public response.
            return self.reply(503, {"error": "unavailable"})


def main():
    jwks = environment()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.jwks = jwks
    server.serve_forever()


if __name__ == "__main__":
    main()
