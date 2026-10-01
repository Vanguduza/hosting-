#!/usr/bin/env python3
"""Encrypted receiver queue snapshot with isolated semantic restore proof."""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


HEX = re.compile(r"[a-f0-9]{64}\Z")
FIELDS = "id,name,sequence,state,created_at,body_sha256,accepted_at,attempts,next_at,delivered_at"


def protected(path, directory=False):
    path = Path(path)
    if (path.is_symlink() or not (path.is_dir() if directory else path.is_file()) or
            path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077):
        raise RuntimeError("Receiver backup path must be owner-only")
    return path


def configuration(path, allow_local=False, require_source=True):
    config = json.loads(protected(path).read_text())
    if set(config) != {"database", "repository", "password_file", "evidence_dir", "tmp_dir"}:
        raise ValueError("Invalid receiver backup configuration")
    if not allow_local and not config["repository"].startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise ValueError("Encrypted off-host Restic repository required")
    if not config["repository"] or not isinstance(config["repository"], str):
        raise ValueError("Restic repository required")
    database = protected(config["database"]) if require_source else Path(config["database"])
    if not database.is_absolute() or database.is_symlink():
        raise ValueError("Absolute receiver database required")
    config["database"] = database
    config["password_file"] = protected(config["password_file"])
    config["evidence_dir"] = protected(config["evidence_dir"], directory=True)
    config["tmp_dir"] = protected(config["tmp_dir"], directory=True)
    return config


def restic(config, *args, timeout=600):
    env = {**os.environ, "RESTIC_REPOSITORY": config["repository"],
           "RESTIC_PASSWORD_FILE": str(config["password_file"])}
    result = subprocess.run(["restic", *args], capture_output=True, text=True,
                            timeout=timeout, check=False, env=env)
    if result.returncode:
        raise RuntimeError("Restic receiver backup operation failed")
    return result.stdout


def semantic(path):
    # Open read-only: an empty/new SQLite database must not masquerade as a restore.
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Receiver database integrity failure")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "alerts" not in tables:
            raise RuntimeError("Receiver alert ledger absent")
        digest = hashlib.sha256()
        count = 0
        for row in db.execute("SELECT " + FIELDS + " FROM alerts ORDER BY id"):
            digest.update(json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode() + b"\n")
            count += 1
        return {"alerts": count, "sha256": digest.hexdigest()}


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_receipt(config, receipt):
    path = config["evidence_dir"] / (receipt["snapshot_id"] + ".json")
    with tempfile.NamedTemporaryFile("w", dir=config["evidence_dir"], prefix=".receipt-",
                                     encoding="utf-8", delete=False) as output:
        temporary = Path(output.name)
        os.chmod(temporary, 0o600)
        json.dump(receipt, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(config["evidence_dir"], os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def backup(config):
    with tempfile.TemporaryDirectory(prefix="dial-alert-backup-", dir=config["tmp_dir"]) as directory:
        snapshot = Path(directory) / "alert-receiver.sqlite3"
        with closing(sqlite3.connect(config["database"].resolve().as_uri() + "?mode=ro", uri=True)) as source, \
                closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination)
        snapshot.chmod(0o600)
        expected = semantic(snapshot)
        archive_sha = file_hash(snapshot)
        lines = restic(config, "backup", "--json", "--tag", "dial-alert-receiver", str(snapshot)).splitlines()
        summaries = [json.loads(line) for line in lines if line.strip()]
        snapshots = [item.get("snapshot_id") for item in summaries
                     if item.get("message_type") == "summary"]
        if len(snapshots) != 1 or not isinstance(snapshots[0], str) or not HEX.fullmatch(snapshots[0]):
            raise RuntimeError("Restic snapshot ID unavailable")
        receipt = {"snapshot_id": snapshots[0], "archive_sha256": archive_sha,
                   "semantic": expected, "created_at": datetime.now(timezone.utc).isoformat(),
                   "state": "BACKUP_CREATED", "restore_verified_at": None}
        save_receipt(config, receipt)
        return receipt


def restore(config, snapshot_id):
    if not isinstance(snapshot_id, str) or not HEX.fullmatch(snapshot_id):
        raise ValueError("Full Restic snapshot ID required")
    receipt_path = protected(config["evidence_dir"] / (snapshot_id + ".json"))
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("snapshot_id") != snapshot_id or not HEX.fullmatch(receipt.get("archive_sha256", "")):
        raise RuntimeError("Receiver backup receipt differs")
    with tempfile.TemporaryDirectory(prefix="dial-alert-restore-", dir=config["tmp_dir"]) as directory:
        restic(config, "restore", snapshot_id, "--target", directory)
        matches = [p for p in Path(directory).rglob("alert-receiver.sqlite3")
                   if p.is_file() and not p.is_symlink()]
        if len(matches) != 1 or file_hash(matches[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored receiver archive differs")
        if semantic(matches[0]) != receipt["semantic"]:
            raise RuntimeError("Restored receiver alerts differ")
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    save_receipt(config, receipt)
    return receipt


def health(config, max_age_hours=36):
    receipts = [json.loads(protected(path).read_text()) for path in
                config["evidence_dir"].glob("*.json")]
    if not receipts:
        raise RuntimeError("Receiver backup evidence missing")
    latest = max(receipts, key=lambda item: item["created_at"])
    created = datetime.fromisoformat(latest["created_at"])
    verified = datetime.fromisoformat(latest["restore_verified_at"]) if latest["restore_verified_at"] else None
    now = datetime.now(timezone.utc)
    if (latest["state"] != "RESTORE_VERIFIED" or created.tzinfo is None or
            verified is None or verified.tzinfo is None or verified < created or
            created > now + timedelta(minutes=5) or now - created > timedelta(hours=max_age_hours)):
        raise RuntimeError("Receiver restore evidence stale or unverified")
    snapshots = json.loads(restic(config, "snapshots", "--json", "--tag", "dial-alert-receiver"))
    if not any(item.get("id") == latest["snapshot_id"] for item in snapshots):
        raise RuntimeError("Receiver snapshot missing from encrypted repository")
    return {"state": "RESTORE_VERIFIED", "snapshot_id": latest["snapshot_id"],
            "created_at": latest["created_at"]}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup-and-verify", "restore", "health"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--snapshot-id")
    args = parser.parse_args()
    if (args.action == "restore") != bool(args.snapshot_id):
        parser.error("--snapshot-id is required only for restore")
    config = configuration(args.config, require_source=args.action == "backup-and-verify")
    result = (restore(config, backup(config)["snapshot_id"]) if args.action == "backup-and-verify"
              else restore(config, args.snapshot_id) if args.action == "restore" else health(config))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
