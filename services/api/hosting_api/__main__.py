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

from .policy import allowed, valid_name


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
