#!/usr/bin/env python3
"""Encrypted PostgreSQL physical base backup with isolated verified recovery."""
import argparse
import fcntl
import hashlib
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

from postgres_backup import configuration, digest, ident, owned_instance, restore_probe, run, snapshot_id


def checked(args, timeout=3600):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(args[0] + " failed with exit " + str(result.returncode))
    return result.stdout.decode()


def evidence_directory(offhost=True):
    evidence, image = configuration(offhost)
    if not evidence.name == "physical-evidence":
        raise RuntimeError("Physical and logical backup receipts require separate evidence directories")
    return evidence, image


def save(evidence, receipt):
    path = evidence / (receipt["snapshot_id"] + ".json")
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())


def backup(instance, evidence):
    instance = ident(instance)
    container = owned_instance(instance)
    if run(["docker", "exec", "-u", "postgres", container, "psql", "-X", "-At", "-U", "postgres",
            "-d", "appdb", "-c", "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN "
            "('pg_default','pg_global')"], 15).strip() != "0":
        raise RuntimeError("External tablespaces require a separate physical recovery design")
    probe = restore_probe(instance)
    with tempfile.TemporaryDirectory(prefix="dial-pg-base-") as temp:
        archive = Path(temp) / "base.tar"
        with open(archive, "xb") as file:
            os.chmod(archive, 0o600)
            result = subprocess.run(["docker", "exec", "-u", "postgres", container,
                                     "pg_basebackup", "-D", "-", "-Ft", "-X", "fetch", "-U", "postgres",
                                     "--manifest-checksums=SHA256", "-c", "fast"], stdout=file,
                                    stderr=subprocess.PIPE, timeout=3600)
            if result.returncode:
                raise RuntimeError("pg_basebackup failed with exit " + str(result.returncode))
            file.flush()
            os.fsync(file.fileno())
        if archive.stat().st_size == 0 or not tarfile.is_tarfile(archive):
            raise RuntimeError("Physical base backup is empty or invalid")
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-client-postgres-physical",
                                    "--tag", "instance=" + instance, str(archive)]))
        receipt = {"instance_id": instance, "snapshot_id": snapshot, "archive_sha256": digest(archive),
                   "probe_sha256": hashlib.sha256(json.dumps(probe, sort_keys=True).encode()).hexdigest(),
                   "created_at": datetime.now(timezone.utc).isoformat(), "state": "BACKUP_CREATED",
                   "restore_verified_at": None, "format": "pg_basebackup_tar_wal_fetch"}
        save(evidence, receipt)
        return receipt


def verify(instance, snapshot, evidence, image):
    instance = ident(instance)
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = evidence / (snapshot + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
            path.stat().st_mode & 0o077:
        raise RuntimeError("Physical backup receipt must be owner-only")
    receipt = json.loads(path.read_text())
    if receipt.get("instance_id") != instance or receipt.get("snapshot_id") != snapshot or \
            receipt.get("format") != "pg_basebackup_tar_wal_fetch":
        raise RuntimeError("Physical snapshot provenance mismatch")
    probe = restore_probe(instance)
    if receipt["probe_sha256"] != hashlib.sha256(json.dumps(probe, sort_keys=True).encode()).hexdigest():
        raise RuntimeError("Physical backup semantic contract changed")
    suffix = uuid.uuid4().hex
    container, network, volume = ("dial-pg-physical-drill-" + suffix,
                                  "dial-pg-physical-net-" + suffix,
                                  "dial-pg-physical-data-" + suffix)
    with tempfile.TemporaryDirectory(prefix="dial-pg-physical-restore-") as temp:
        run(["restic", "restore", snapshot, "--target", temp])
        archives = [item for item in Path(temp).rglob("base.tar") if item.is_file() and not item.is_symlink()]
        if len(archives) != 1 or digest(archives[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored physical archive differs from receipt")
        data = Path(temp) / "extracted"
        data.mkdir(mode=0o700)
        with tarfile.open(archives[0], "r:") as archive:
            archive.extractall(data, filter="data")
        if not (data / "PG_VERSION").is_file() or (data / "PG_VERSION").read_text().strip() != "17" or \
                not (data / "backup_manifest").is_file():
            raise RuntimeError("Physical backup version or manifest invalid")
        network_created = volume_created = container_created = False
        try:
            checked(["docker", "network", "create", "--internal", network], 30)
            network_created = True
            checked(["docker", "volume", "create", volume], 30)
            volume_created = True
            checked(["docker", "run", "--rm", "--network", "none", "--user", "0:0",
                     "--mount", "type=volume,src=" + volume + ",dst=/data",
                     "--mount", "type=bind,src=" + str(data) + ",dst=/backup,readonly", image,
                     "sh", "-c", "mkdir -p /data/pgdata && cp -a /backup/. /data/pgdata/ && "
                     "chown -R postgres:postgres /data/pgdata && "
                     "su postgres -s /bin/sh -c 'pg_verifybackup /data/pgdata'"], 3600)
            checked(["docker", "run", "-d", "--name", container, "--network", network,
                     "--read-only", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1",
                     "--tmpfs=/tmp:rw,nosuid,size=64m", "--tmpfs=/var/run/postgresql:rw,nosuid,size=16m",
                     "--mount", "type=volume,src=" + volume + ",dst=/var/lib/postgresql/data",
                     "-e", "PGDATA=/var/lib/postgresql/data/pgdata", image], 120)
            container_created = True
            deadline = time.monotonic() + 120
            while True:
                try:
                    checked(["docker", "exec", "-u", "postgres", container, "pg_isready", "-U", "postgres",
                             "-d", "appdb"], 15)
                    break
                except RuntimeError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("Isolated physical PostgreSQL did not start")
                    time.sleep(2)
            output = checked(["docker", "exec", "-u", "postgres", container, "psql", "-X", "-At",
                              "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "appdb",
                              "-c", "BEGIN READ ONLY", "-c", "SET LOCAL statement_timeout = '5s'",
                              "-c", probe["sql"], "-c", "ROLLBACK"], 20).splitlines()
            if output != ["BEGIN", "SET", probe["expected"], "ROLLBACK"]:
                raise RuntimeError("Restored physical application semantic probe failed")
        finally:
            if container_created:
                checked(["docker", "rm", "-f", container], 60)
            if volume_created:
                checked(["docker", "volume", "rm", volume], 30)
            if network_created:
                checked(["docker", "network", "rm", network], 30)
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    receipt["semantic_probe"] = probe["name"]
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def all_instances(evidence, image):
    names = run(["docker", "ps", "-a", "--filter", "label=dial.postgres", "--format", "{{.Names}}"], 30).splitlines()
    volumes = run(["docker", "volume", "ls", "--filter", "label=dial.postgres",
                   "--format", "{{.Name}}"], 30).splitlines()
    instances = set()
    for name in names:
        if not name.startswith("dial-pg-"):
            raise RuntimeError("Unexpected PostgreSQL inventory member")
        instances.add(ident(name[len("dial-pg-"):]))
    if {"dial-pg-data-" + instance for instance in instances} != set(volumes) or not instances:
        raise RuntimeError("PostgreSQL physical backup inventory mismatch or empty")
    return {"state": "FLEET_PHYSICAL_BACKUP_VERIFIED", "instances": len(instances),
            "receipts": [verify(instance, (created := backup(instance, evidence))["snapshot_id"], evidence, image)
                         for instance in sorted(instances)]}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("backup")
    take.add_argument("instance_id")
    drill = sub.add_parser("verify")
    drill.add_argument("instance_id")
    drill.add_argument("snapshot_id")
    sub.add_parser("backup-all")
    args = parser.parse_args()
    evidence, image = evidence_directory()
    fd = os.open(evidence / ".physical-backup.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "backup-all":
            result = all_instances(evidence, image)
        elif args.command == "backup":
            result = backup(args.instance_id, evidence)
        else:
            result = verify(args.instance_id, args.snapshot_id, evidence, image)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
