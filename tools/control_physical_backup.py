#!/usr/bin/env python3
"""Control PostgreSQL physical base backup with isolated recovery proof."""
import argparse
import fcntl
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from control_backup import environment, file_digest, run, snapshot_id


COUNTS = ("SELECT json_build_object('organizations',(SELECT count(*) FROM hosting.organizations),"
          "'projects',(SELECT count(*) FROM hosting.projects),"
          "'applications',(SELECT count(*) FROM hosting.applications),"
          "'releases',(SELECT count(*) FROM hosting.releases),"
          "'orphan_projects',(SELECT count(*) FROM hosting.projects p LEFT JOIN hosting.organizations o "
          "ON o.id=p.organization_id WHERE o.id IS NULL))")


def setup(offhost=True):
    evidence = environment(offhost)
    if evidence.name != "control-physical-evidence":
        raise RuntimeError("Control physical and logical receipts require separate directories")
    image = os.environ.get("CONTROL_POSTGRES_IMAGE", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}", image) or \
            not image.rsplit("/", 1)[-1].startswith("postgres:17@sha256:"):
        raise RuntimeError("Control physical recovery needs a pinned PostgreSQL 17 image")
    return evidence, image


def docker(args, timeout=3600):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Disposable PostgreSQL Docker operation failed (exit " + str(result.returncode) + ")")
    return result.stdout.decode()


def save(evidence, receipt):
    path = evidence / (receipt["snapshot_id"] + ".json")
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())


def backup(evidence):
    if run(["psql", "--no-psqlrc", "-Atc",
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname=current_user"]).strip() != "t":
        raise RuntimeError("Control physical backup role cannot see every tenant")
    with tempfile.TemporaryDirectory(prefix="dial-control-physical-") as temp:
        archive = Path(temp) / "control-base.tar"
        with open(archive, "xb") as file:
            os.chmod(archive, 0o600)
            result = subprocess.run(["pg_basebackup", "-h", os.environ["PGHOST"], "-p",
                                     os.environ.get("PGPORT", "5432"), "-U", os.environ["PGUSER"],
                                     "-D", "-", "-Ft", "-X", "fetch", "--manifest-checksums=SHA256",
                                     "-c", "fast", "-w"], stdout=file, stderr=subprocess.PIPE, timeout=3600)
            if result.returncode:
                raise RuntimeError("Control pg_basebackup failed (exit " + str(result.returncode) + ")")
            file.flush()
            os.fsync(file.fileno())
        if archive.stat().st_size == 0 or not tarfile.is_tarfile(archive):
            raise RuntimeError("Control physical base backup is empty or invalid")
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-control-physical", str(archive)]))
        receipt = {"snapshot_id": snapshot, "archive_sha256": file_digest(archive),
                   "database": os.environ["PGDATABASE"], "format": "pg_basebackup_tar_wal_fetch",
                   "created_at": datetime.now(timezone.utc).isoformat(), "state": "BACKUP_CREATED",
                   "restore_verified_at": None}
        save(evidence, receipt)
        return receipt


def verify(evidence, snapshot, image):
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = evidence / (snapshot + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
            path.stat().st_mode & 0o077:
        raise RuntimeError("Protected physical control receipt unavailable")
    receipt = json.loads(path.read_text())
    if receipt.get("snapshot_id") != snapshot or receipt.get("database") != os.environ["PGDATABASE"] or \
            receipt.get("format") != "pg_basebackup_tar_wal_fetch":
        raise RuntimeError("Control physical backup provenance mismatch")
    suffix = uuid.uuid4().hex
    container, network, volume = ("dial-control-physical-" + suffix,
                                  "dial-control-physical-net-" + suffix,
                                  "dial-control-physical-data-" + suffix)
    with tempfile.TemporaryDirectory(prefix="dial-control-physical-restore-") as temp:
        run(["restic", "restore", snapshot, "--target", temp])
        archives = [p for p in Path(temp).rglob("control-base.tar") if p.is_file() and not p.is_symlink()]
        if len(archives) != 1 or file_digest(archives[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored control physical archive differs from receipt")
        data = Path(temp) / "extracted"
        data.mkdir(mode=0o700)
        with tarfile.open(archives[0], "r:") as archive:
            archive.extractall(data, filter="data")
        if not (data / "PG_VERSION").is_file() or (data / "PG_VERSION").read_text().strip() != "17" or \
                not (data / "backup_manifest").is_file():
            raise RuntimeError("Control physical version or backup manifest invalid")
        made_network = made_volume = made_container = False
        try:
            docker(["network", "create", "--internal", network], 30)
            made_network = True
            docker(["volume", "create", volume], 30)
            made_volume = True
            docker(["run", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", "type=volume,src=" + volume + ",dst=/data",
                    "--mount", "type=bind,src=" + str(data) + ",dst=/backup,readonly", image,
                    "sh", "-c", "mkdir -p /data/pgdata && cp -a /backup/. /data/pgdata/ && "
                    "chown -R postgres:postgres /data/pgdata && "
                    "su postgres -s /bin/sh -c 'pg_verifybackup /data/pgdata'"], 3600)
            docker(["run", "-d", "--name", container, "--network", network,
                    "--read-only", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1",
                    "--tmpfs=/tmp:rw,nosuid,size=64m", "--tmpfs=/var/run/postgresql:rw,nosuid,size=16m",
                    "--mount", "type=volume,src=" + volume + ",dst=/var/lib/postgresql/data",
                    "-e", "PGDATA=/var/lib/postgresql/data/pgdata", image], 120)
            made_container = True
            deadline = time.monotonic() + 120
            while True:
                try:
                    docker(["exec", "-u", "postgres", container, "pg_isready", "-U", "postgres",
                            "-d", receipt["database"]], 15)
                    break
                except RuntimeError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("Control physical restore did not start")
                    time.sleep(2)
            counts = json.loads(docker(["exec", "-u", "postgres", container, "psql", "-X", "-At",
                                        "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", receipt["database"],
                                        "-c", COUNTS], 20).strip())
            if counts["orphan_projects"] != 0 or counts["organizations"] < 1:
                raise RuntimeError("Restored control physical relationships invalid")
        finally:
            if made_container:
                docker(["rm", "-f", container], 60)
            if made_volume:
                docker(["volume", "rm", volume], 30)
            if made_network:
                docker(["network", "rm", network], 30)
    receipt["semantic_counts"] = counts
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backup")
    commands.add_parser("backup-and-verify")
    drill = commands.add_parser("verify")
    drill.add_argument("snapshot_id")
    args = parser.parse_args()
    evidence, image = setup()
    fd = os.open(evidence / ".control-physical.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        created = backup(evidence) if args.command != "verify" else None
        receipt = verify(evidence, created["snapshot_id"] if created else args.snapshot_id, image) if \
            args.command != "backup" else created
        print(json.dumps(receipt, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
