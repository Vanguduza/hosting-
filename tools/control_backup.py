#!/usr/bin/env python3
"""Encrypted off-host control DB backup and isolated semantic restore drill."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


def run(args, *, timeout=3600):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed with exit {result.returncode}")
    return result.stdout


def environment():
    required = ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "PGHOST", "PGUSER", "PGDATABASE", "PGPASSFILE", "BACKUP_EVIDENCE_DIR")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Missing backup configuration: " + ", ".join(missing))
    repository = os.environ["RESTIC_REPOSITORY"]
    if not repository.startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise RuntimeError("Repository must be an off-host encrypted restic target")
    for name in ("RESTIC_PASSWORD_FILE", "PGPASSFILE"):
        path = Path(os.environ[name])
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise RuntimeError(name + " must be an owner-only file")
    evidence = Path(os.environ["BACKUP_EVIDENCE_DIR"]).resolve()
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.stat().st_mode & 0o077:
        raise RuntimeError("Evidence directory must be owner-only")
    return evidence


def snapshot_id(output):
    summaries = [json.loads(line) for line in output.splitlines() if line.strip()]
    summaries = [line for line in summaries if line.get("message_type") == "summary"]
    if len(summaries) != 1 or not re.fullmatch(r"[a-f0-9]{64}", summaries[0].get("snapshot_id", "")):
        raise RuntimeError("Restic did not issue one unambiguous snapshot ID")
    return summaries[0]["snapshot_id"]


def save_receipt(evidence, receipt):
    path = evidence / (receipt["snapshot_id"] + ".json")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(receipt, file, indent=2, sort_keys=True)
    return path


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup(evidence):
    with tempfile.TemporaryDirectory(prefix="dial-control-backup-") as temp:
        os.chmod(temp, 0o700)
        archive = Path(temp) / "control.dump"
        run(["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(archive)])
        digest = file_digest(archive)
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-control", str(archive)]))
        receipt = {"snapshot_id": snapshot, "archive_sha256": digest,
                   "database": os.environ["PGDATABASE"], "created_at": datetime.now(timezone.utc).isoformat(),
                   "state": "BACKUP_CREATED", "restore_verified_at": None}
        save_receipt(evidence, receipt)
        print(json.dumps(receipt, sort_keys=True))


def verify(evidence, snapshot):
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise RuntimeError("Snapshot must be a full restic ID")
    path = evidence / (snapshot + ".json")
    receipt = json.loads(path.read_text())
    if receipt["snapshot_id"] != snapshot:
        raise RuntimeError("Evidence/snapshot mismatch")
    database = "dial_restore_" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="dial-restore-check-") as temp:
        os.chmod(temp, 0o700)
        run(["restic", "restore", snapshot, "--target", temp])
        archives = list(Path(temp).rglob("control.dump"))
        if len(archives) != 1 or not archives[0].is_file() or archives[0].is_symlink():
            raise RuntimeError("Restore did not produce one regular archive")
        archive = archives[0]
        if file_digest(archive) != receipt["archive_sha256"]:
            raise RuntimeError("Restored archive digest differs from backup receipt")
        run(["pg_restore", "--list", str(archive)])
        created = False
        try:
            run(["createdb", "--maintenance-db=postgres", "--template=template0", database])
            created = True
            run(["pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "--dbname=" + database, str(archive)])
            query = ("SELECT json_build_object('organizations',(SELECT count(*) FROM hosting.organizations),"
                     "'projects',(SELECT count(*) FROM hosting.projects),"
                     "'applications',(SELECT count(*) FROM hosting.applications),"
                     "'releases',(SELECT count(*) FROM hosting.releases),"
                     "'orphan_projects',(SELECT count(*) FROM hosting.projects p LEFT JOIN hosting.organizations o "
                     "ON o.id=p.organization_id WHERE o.id IS NULL))")
            metrics = json.loads(run(["psql", "--dbname=" + database, "--no-psqlrc", "-Atc", query]).strip())
            if metrics["orphan_projects"] != 0:
                raise RuntimeError("Restored relational data failed semantic verification")
        finally:
            if created:
                run(["dropdb", "--maintenance-db=postgres", "--if-exists", "--force", database])
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    receipt["semantic_counts"] = metrics
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(receipt, file, indent=2, sort_keys=True)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backup")
    drill = commands.add_parser("verify")
    drill.add_argument("snapshot_id")
    args = parser.parse_args()
    evidence = environment()
    if args.command == "backup":
        backup(evidence)
    else:
        verify(evidence, args.snapshot_id)


if __name__ == "__main__":
    main()
