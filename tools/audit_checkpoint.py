#!/usr/bin/env python3
"""Anchor full control audit chains in a separately encrypted Restic snapshot."""
import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify as verify_schema
from recovery_catalog import HEX, NAME, protected, repository, restic, restic_env, snapshots


def config_file(path, allow_local=False):
    config = json.loads(protected(path).read_text())
    if set(config) != {"version", "anchor_id", "source_failure_domain", "recovery_failure_domain",
                       "repository", "password_file", "signing_key_file"} or config["version"] != 1:
        raise ValueError("Invalid audit checkpoint configuration")
    if any(not isinstance(config[key], str) or not NAME.fullmatch(config[key]) for key in
           ("anchor_id", "source_failure_domain", "recovery_failure_domain")) or \
            config["source_failure_domain"] == config["recovery_failure_domain"]:
        raise ValueError("Distinct source and recovery failure domains required")
    repository(config["repository"], allow_local=allow_local)
    protected(config["password_file"])
    key = protected(config["signing_key_file"]).read_bytes()
    if not 32 <= len(key) <= 4096:
        raise ValueError("Checkpoint signing key must have 32–4096 bytes")
    return config, key


def require_global_reader(conn):
    if os.environ.get("DB_USER") in SERVICE_ROLES:
        raise RuntimeError("Serving database role cannot anchor cross-tenant history")
    role = conn.execute("SELECT rolsuper OR rolbypassrls AS allowed FROM pg_roles WHERE rolname=current_user").fetchone()
    if not role or not role["allowed"]:
        raise RuntimeError("Checkpoint requires a protected full-tenant database reader")


def tenant_chain(conn, organization_id, bound=None):
    last_id, count, previous = 0, 0, ""
    digest = hashlib.sha256()
    while True:
        rows = conn.execute(
            "SELECT id,actor_sub,action,resource_id,request_id,previous_hash,event_hash,created_at "
            "FROM hosting.audit_events WHERE organization_id=%s AND id>%s "
            "AND (%s::bigint IS NULL OR id<=%s::bigint) ORDER BY id LIMIT 1000",
            (organization_id, last_id, bound, bound)).fetchall()
        if not rows:
            break
        for row in rows:
            calculated = hashlib.sha256((previous + row["actor_sub"] + row["action"] +
                                         str(row["resource_id"]) + str(row["request_id"])).encode()).hexdigest()
            if row["previous_hash"] != previous or row["event_hash"] != calculated:
                raise RuntimeError("Audit chain broken for tenant " + str(organization_id))
            digest.update(json.dumps([row["id"], row["actor_sub"], row["action"],
                                      str(row["resource_id"]), str(row["request_id"]),
                                      row["previous_hash"], row["event_hash"],
                                      row["created_at"].isoformat()], separators=(",", ":")).encode() + b"\n")
            previous, last_id = row["event_hash"], row["id"]
            count += 1
    return {"organization_id": str(organization_id), "count": count, "last_id": last_id,
            "last_hash": previous, "records_sha256": digest.hexdigest()}


def capture(conn, config):
    require_global_reader(conn)
    with conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        ids = conn.execute("SELECT id FROM hosting.organizations ORDER BY id").fetchall()
        tenants = [tenant_chain(conn, row["id"]) for row in ids]
    return {"version": 1, "anchor_id": config["anchor_id"],
            "source_failure_domain": config["source_failure_domain"],
            "intended_recovery_failure_domain": config["recovery_failure_domain"],
            "created_at": datetime.now(timezone.utc).isoformat(), "tenants": tenants}


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def publish(conn, config, key):
    document = capture(conn, config)
    signed = {"document": document, "signature": hmac.new(key, canonical(document), hashlib.sha256).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="dial-audit-anchor-") as directory:
        path = Path(directory) / "anchor.json"
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as file:
            file.write(canonical(signed))
            file.flush()
            os.fsync(file.fileno())
        with restic_env(config["repository"], config["password_file"]):
            output = restic(["backup", "--json", "--tag", "dial-audit-anchor", "--tag",
                             "anchor=" + config["anchor_id"], str(path)])
            summaries = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            ids = [item.get("snapshot_id") for item in summaries if item.get("message_type") == "summary"]
            if len(ids) != 1 or not isinstance(ids[0], str) or not HEX.fullmatch(ids[0]):
                raise RuntimeError("Encrypted audit checkpoint snapshot receipt missing")
            remote = snapshots().get(ids[0])
            if not remote or not {"dial-audit-anchor", "anchor=" + config["anchor_id"]}.issubset(
                    set(remote["tags"])):
                raise RuntimeError("Audit checkpoint remote provenance mismatch")
    return {"snapshot_id": ids[0], "tenants": len(document["tenants"]),
            "created_at": document["created_at"]}


def inspect_snapshot(conn, config, key, snapshot_id):
    require_global_reader(conn)
    if not isinstance(snapshot_id, str) or not HEX.fullmatch(snapshot_id):
        raise ValueError("Full Restic snapshot ID required")
    with restic_env(config["repository"], config["password_file"]):
        remote = snapshots().get(snapshot_id)
        if not remote or not {"dial-audit-anchor", "anchor=" + config["anchor_id"]}.issubset(
                set(remote["tags"])):
            raise RuntimeError("Audit checkpoint remote provenance mismatch")
        with tempfile.TemporaryDirectory(prefix="dial-audit-anchor-restore-") as directory:
            restic(["restore", snapshot_id, "--target", directory])
            files = [path for path in Path(directory).rglob("anchor.json")
                     if path.is_file() and not path.is_symlink()]
            if len(files) != 1 or files[0].stat().st_size > 16 * 1024 * 1024:
                raise RuntimeError("Restored checkpoint unavailable or oversized")
            signed = json.loads(files[0].read_bytes())
    if not isinstance(signed, dict) or set(signed) != {"document", "signature"} or \
            not isinstance(signed["signature"], str) or not hmac.compare_digest(
                signed["signature"], hmac.new(key, canonical(signed["document"]), hashlib.sha256).hexdigest()):
        raise RuntimeError("Audit checkpoint signature invalid")
    document = signed["document"]
    if document.get("version") != 1 or document.get("anchor_id") != config["anchor_id"] or \
            document.get("source_failure_domain") != config["source_failure_domain"] or \
            document.get("intended_recovery_failure_domain") != config["recovery_failure_domain"] or \
            not isinstance(document.get("tenants"), list):
        raise RuntimeError("Audit checkpoint scope mismatch")
    with conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        for expected in document["tenants"]:
            org = expected["organization_id"]
            if not conn.execute("SELECT 1 FROM hosting.organizations WHERE id=%s", (org,)).fetchone():
                raise RuntimeError("Anchored organization missing")
            if tenant_chain(conn, org, expected["last_id"]) != expected:
                raise RuntimeError("Database audit history differs from off-host checkpoint")
    return {"snapshot_id": snapshot_id, "tenants_verified": len(document["tenants"]),
            "state": "AUDIT_HISTORY_VERIFIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("publish")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("snapshot_id")
    args = parser.parse_args()
    config, key = config_file(args.config)
    with psycopg.connect(database_dsn(), row_factory=dict_row, autocommit=True, connect_timeout=5) as conn:
        verify_schema(conn)
        result = (publish(conn, config, key) if args.command == "publish" else
                  inspect_snapshot(conn, config, key, args.snapshot_id))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
