#!/usr/bin/env python3
"""Off-host encrypted backup and isolated logical restore drill for client PostgreSQL."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def run(args, timeout=3600, stdout=None):
    result = subprocess.run(args, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        # Neither stderr nor untrusted command output may enter an API receipt.
        raise RuntimeError(args[0] + " failed (exit " + str(result.returncode) + ")")
    return result.stdout.decode() if stdout is None else None


def ident(value):
    parsed = str(uuid.UUID(value))
    if value != parsed:
        raise ValueError("Noncanonical instance ID")
    return parsed


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def snapshot_id(output):
    summaries = [json.loads(line) for line in output.splitlines() if line.strip()]
    summaries = [line for line in summaries if line.get("message_type") == "summary"]
    if len(summaries) != 1 or not re.fullmatch(r"[a-f0-9]{64}", summaries[0].get("snapshot_id", "")):
        raise RuntimeError("Restic backup did not confirm one full snapshot ID")
    return summaries[0]["snapshot_id"]


def configuration(offhost=True):
    required = ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "NODE_POSTGRES_IMAGE", "BACKUP_EVIDENCE_DIR")
    if missing := [name for name in required if not os.environ.get(name)]:
        raise RuntimeError("Missing database backup configuration: " + ", ".join(missing))
    repository = os.environ["RESTIC_REPOSITORY"]
    if offhost and not repository.startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise RuntimeError("Client backups require an off-host encrypted Restic target")
    password = Path(os.environ["RESTIC_PASSWORD_FILE"])
    if not password.is_file() or password.is_symlink() or password.stat().st_mode & 0o077:
        raise RuntimeError("Restic password must be an owner-only regular file")
    image = os.environ["NODE_POSTGRES_IMAGE"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}", image) or \
            not image.rsplit("/", 1)[-1].startswith("postgres:17@sha256:"):
        raise RuntimeError("Restore image must be a PostgreSQL 17 immutable digest")
    evidence = Path(os.environ["BACKUP_EVIDENCE_DIR"]).resolve()
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.is_symlink() or evidence.stat().st_mode & 0o077:
        raise RuntimeError("Backup evidence directory must be owner-only")
    return evidence, image


def owned_instance(instance):
    name = "dial-pg-" + ident(instance)
    obj = json.loads(run(["docker", "inspect", name], 15))[0]
    labels = obj["Config"]["Labels"]
    if labels.get("dial.postgres") != instance or not obj["State"]["Running"]:
        raise RuntimeError("Owned PostgreSQL instance is not running")
    network = "dial-pg-net-" + instance
    mounts = obj["Mounts"]
    if (network not in obj["NetworkSettings"]["Networks"] or
            not any(m.get("Name") == "dial-pg-data-" + instance and
                    m.get("Destination") == "/var/lib/postgresql/data" for m in mounts) or
            obj["HostConfig"].get("PortBindings")):
        raise RuntimeError("PostgreSQL isolation or volume ownership differs")
    return name


def save(evidence, receipt):
    path = evidence / (receipt["snapshot_id"] + ".json")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    return path


def restore_probe(instance):
    """Load an operator-reviewed, instance-specific semantic restore assertion."""
    directory = os.environ.get("BACKUP_PROBE_DIR")
    if not directory:
        raise RuntimeError("BACKUP_PROBE_DIR required for semantic restore verification")
    root = Path(directory)
    if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077 or \
            root.stat().st_uid != os.geteuid():
        raise RuntimeError("Restore probe directory must be owner-only")
    path = root / (ident(instance) + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or \
            path.stat().st_uid != os.geteuid():
        raise RuntimeError("Instance restore probe must be an owner-only regular file")
    contract = json.loads(path.read_text(encoding="utf-8"))
    if set(contract) != {"name", "sql", "expected"} or \
            not isinstance(contract["name"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", contract["name"]) or \
            not isinstance(contract["sql"], str) or not re.match(r"^SELECT\s", contract["sql"], re.I) or \
            len(contract["sql"]) > 2048 or ";" in contract["sql"] or \
            not isinstance(contract["expected"], str) or not 1 <= len(contract["expected"]) <= 256 or \
            "\n" in contract["expected"]:
        raise RuntimeError("Invalid instance restore probe contract")
    return contract


def backup(instance, evidence):
    container = owned_instance(instance)
    with tempfile.TemporaryDirectory(prefix="dial-client-backup-") as temp:
        os.chmod(temp, 0o700)
        archive = Path(temp) / "database.dump"
        with open(archive, "xb") as out:
            os.chmod(archive, 0o600)
            run(["docker", "exec", "-u", "postgres", container, "pg_dump", "-Fc", "--no-owner",
                 "--no-acl", "-U", "postgres", "-d", "appdb"], timeout=3600, stdout=out)
            out.flush()
            os.fsync(out.fileno())
        if archive.stat().st_size == 0:
            raise RuntimeError("PostgreSQL backup archive is empty")
        archive_hash = digest(archive)
        run(["docker", "exec", "-u", "postgres", container, "pg_isready", "-U", "postgres", "-d", "appdb"], 15)
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-client-postgres",
                                    "--tag", "instance=" + instance, str(archive)]))
        receipt = {"instance_id": instance, "snapshot_id": snapshot, "archive_sha256": archive_hash,
                   "archive_bytes": archive.stat().st_size, "created_at": datetime.now(timezone.utc).isoformat(),
                   "state": "BACKUP_CREATED", "restore_verified_at": None}
        save(evidence, receipt)
        return receipt


def restore_drill(instance, snapshot, evidence, image):
    ident(instance)
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = evidence / (snapshot + ".json")
    receipt = json.loads(path.read_text())
    if receipt["instance_id"] != instance or receipt["snapshot_id"] != snapshot:
        raise RuntimeError("Snapshot does not belong to the selected instance")
    probe = restore_probe(instance)
    drill = uuid.uuid4().hex
    container, network, volume = "dial-pg-drill-" + drill, "dial-pg-drill-net-" + drill, "dial-pg-drill-data-" + drill
    with tempfile.TemporaryDirectory(prefix="dial-client-restore-") as temp:
        os.chmod(temp, 0o700)
        run(["restic", "restore", snapshot, "--target", temp])
        archives = [p for p in Path(temp).rglob("database.dump") if p.is_file() and not p.is_symlink()]
        if len(archives) != 1 or digest(archives[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored archive differs from snapshot evidence")
        # Docker cp cannot write into a read-only root filesystem. Bind this
        # verified archive read-only; the host directory remains owner-only.
        os.chmod(archives[0], 0o644)
        password = Path(temp) / "drill_password"
        password.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
        os.chmod(password, 0o600)
        created_network = created_volume = created_container = False
        try:
            run(["docker", "network", "create", "--internal", network], 30)
            created_network = True
            run(["docker", "volume", "create", volume], 30)
            created_volume = True
            run(["docker", "run", "-d", "--name", container, "--network", network,
                 "--read-only", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1",
                 "--tmpfs=/tmp:rw,nosuid,size=512m", "--tmpfs=/var/run/postgresql:rw,nosuid,size=16m",
                 "--mount", "type=volume,src=" + volume + ",dst=/var/lib/postgresql/data",
                 "--mount", "type=bind,src=" + str(password) + ",dst=/run/secrets/drill_password,readonly",
                 "--mount", "type=bind,src=" + str(archives[0]) + ",dst=/tmp/database.dump,readonly",
                 "-e", "PGDATA=/var/lib/postgresql/data/pgdata", "-e", "POSTGRES_DB=appdb",
                 "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/drill_password", image], 120)
            created_container = True
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    run(["docker", "exec", "-u", "postgres", container, "pg_isready", "-U", "postgres", "-d", "appdb"], 15)
                    break
                except RuntimeError:
                    time.sleep(2)
            else:
                raise RuntimeError("Isolated restore PostgreSQL did not start")
            run(["docker", "exec", "-u", "postgres", container, "pg_restore", "--exit-on-error",
                 "--no-owner", "--no-acl", "-U", "postgres", "-d", "appdb", "/tmp/database.dump"], 3600)
            count = int(run(["docker", "exec", "-u", "postgres", container, "psql", "-X", "-At",
                             "-U", "postgres", "-d", "appdb", "-c",
                             "SELECT count(*) FROM pg_class WHERE relkind='r' AND relnamespace='public'::regnamespace"], 20).strip())
            # The probe runs inside a read-only transaction in the isolated
            # target. An operator-owned contract states the expected value;
            # a table count alone is not application-semantic evidence.
            output = run(["docker", "exec", "-u", "postgres", container, "psql", "-X", "-At",
                          "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "appdb",
                          "-c", "BEGIN READ ONLY", "-c", "SET LOCAL statement_timeout = '5s'",
                          "-c", probe["sql"], "-c", "ROLLBACK"], 20)
            lines = output.splitlines()
            if len(lines) != 4 or lines[0] != "BEGIN" or lines[1] != "SET" or \
                    lines[2] != probe["expected"] or lines[3] != "ROLLBACK":
                raise RuntimeError("Restored application semantic probe failed")
        finally:
            if created_container:
                run(["docker", "rm", "-f", container], 60)
            if created_volume:
                run(["docker", "volume", "rm", volume], 30)
            if created_network:
                run(["docker", "network", "rm", network], 30)
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    receipt["restored_table_count"] = count
    receipt["semantic_probe"] = probe["name"]
    receipt["semantic_probe_sha256"] = hashlib.sha256(
        json.dumps(probe, sort_keys=True).encode()).hexdigest()
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def backup_all(evidence, image):
    """Daily fleet pass: every discovered database gets a verified off-host snapshot."""
    lock_fd = os.open(evidence / ".backup-all.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        names = run(["docker", "ps", "-a", "--filter", "label=dial.postgres", "--format", "{{.Names}}"], 30).splitlines()
        volumes = run(["docker", "volume", "ls", "--filter", "label=dial.postgres",
                       "--format", "{{.Name}}"], 30).splitlines()
        inventory = set()
        for volume in volumes:
            match = re.fullmatch(r"dial-pg-data-([a-f0-9-]{36})", volume)
            if not match:
                raise RuntimeError("Unexpected PostgreSQL-labeled volume in inventory")
            inventory.add(ident(match.group(1)))
        found = set()
        for name in names:
            match = re.fullmatch(r"dial-pg-([a-f0-9-]{36})", name)
            if not match:
                raise RuntimeError("Unexpected PostgreSQL-labeled container in inventory")
            instance = ident(match.group(1))
            if instance not in inventory:
                raise RuntimeError("PostgreSQL container has no matching labeled volume")
            found.add(instance)
        if found != inventory:
            raise RuntimeError("PostgreSQL volume exists without a running or stopped owned container")
        results = []
        for instance in sorted(found):
            snapshot = backup(instance, evidence)
            results.append(restore_drill(instance, snapshot["snapshot_id"], evidence, image))
        return {"state": "FLEET_BACKUP_VERIFIED", "instances": len(results),
                "receipts": [{"instance_id": row["instance_id"], "snapshot_id": row["snapshot_id"]}
                             for row in results]}
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    command = commands.add_parser("backup")
    command.add_argument("instance_id")
    drill = commands.add_parser("verify")
    drill.add_argument("instance_id")
    drill.add_argument("snapshot_id")
    commands.add_parser("backup-all")
    args = parser.parse_args()
    evidence, image = configuration()
    if args.action == "backup-all":
        receipt = backup_all(evidence, image)
    elif args.action == "backup":
        receipt = backup(ident(args.instance_id), evidence)
    else:
        receipt = restore_drill(ident(args.instance_id), args.snapshot_id, evidence, image)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
