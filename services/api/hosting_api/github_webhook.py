"""Signed GitHub push receiver. It only records jobs for operator-registered sources."""
import hashlib
import hmac
import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .__main__ import database_dsn


def verify(secret, body, signature):
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[a-f0-9]{64}", signature):
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_push(payload):
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    repo = payload.get("repository")
    if not isinstance(repo, dict) or type(repo.get("id")) is not int or repo["id"] <= 0 or \
            not isinstance(repo.get("full_name"), str) or not isinstance(payload.get("ref"), str) or \
            not re.fullmatch(r"[a-f0-9]{40}", payload.get("after", "")) or \
            payload.get("deleted") is not False:
        raise ValueError("Push fields invalid")
    return repo["id"], repo["full_name"], payload["ref"], payload["after"]


def enqueue(conn, delivery, repo_id, full_name, ref, commit):
    source = conn.execute("SELECT id FROM hosting.git_sources WHERE repository_id=%s "
                          "AND full_name=%s AND 'refs/heads/'||branch=%s AND enabled",
                          (repo_id, full_name, ref)).fetchone()
    if not source:
        return "IGNORED"
    inserted = conn.execute("INSERT INTO hosting.github_builds(delivery_id,source_id,source_commit) "
                            "VALUES (%s,%s,%s) ON CONFLICT(delivery_id) DO NOTHING RETURNING delivery_id",
                            (delivery, source["id"], commit)).fetchone()
    if not inserted:
        existing = conn.execute("SELECT source_id,source_commit FROM hosting.github_builds WHERE delivery_id=%s",
                                (delivery,)).fetchone()
        if not existing or existing["source_id"] != source["id"] or existing["source_commit"] != commit:
            raise ValueError("Delivery identifier replay differs")
        return "REPLAYED"
    return "QUEUED"


class Handler(BaseHTTPRequestHandler):
    server_version = "DialGitHubHook/0.1"

    def reply(self, status, value):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/v1/github/push":
            return self.reply(404, {"error": "not_found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 1024 * 1024 or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.reply(413, {"error": "invalid_body"})
            body = self.rfile.read(size)
            if not verify(self.server.secret, body, self.headers.get("X-Hub-Signature-256")):
                return self.reply(401, {"error": "signature_invalid"})
            raw_id = self.headers.get("X-GitHub-Delivery", "")
            delivery = uuid.UUID(raw_id)
            if str(delivery) != raw_id:
                raise ValueError("Invalid delivery identifier")
            if self.headers.get("X-GitHub-Event") != "push":
                return self.reply(202, {"state": "IGNORED"})
            repo_id, full_name, ref, commit = parse_push(json.loads(body))
            with psycopg.connect(self.server.dsn, row_factory=dict_row, connect_timeout=5) as conn:
                with conn.transaction():
                    state = enqueue(conn, delivery, repo_id, full_name, ref, commit)
            return self.reply(202, {"state": state, "delivery_id": str(delivery)})
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.reply(400, {"error": "invalid_push"})
        except psycopg.Error:
            return self.reply(503, {"error": "unavailable"})


def main():
    dsn = database_dsn()
    path = Path(os.environ["GITHUB_WEBHOOK_SECRET_FILE"])
    # Compose mounts a host-only secret read-only into a single-purpose container.
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o022:
        raise RuntimeError("GitHub webhook secret must be a read-only private-container file")
    secret = path.read_bytes().strip()
    if len(secret) < 32:
        raise RuntimeError("GitHub webhook secret too short")
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        if conn.execute("SELECT current_user").fetchone()[0] != "hosting_hook":
            raise RuntimeError("The webhook receiver requires the restricted hook role")
    server = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
    server.secret, server.dsn = secret, dsn
    server.serve_forever()


if __name__ == "__main__":
    main()
