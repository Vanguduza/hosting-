#!/usr/bin/env python3
"""Managed PostgreSQL WAL stream, off-host receipts and isolated PITR."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from control_wal import SEGMENT, archive, load_receipt, pitr, protected, remote_ids
from postgres_backup import configuration, ident, owned_instance, restore_probe, run


SPOOL = "/var/lib/postgresql/data/wal-spool"
SLOT = "dial_client_wal"
TAG = "dial-client-postgres-wal"


def evidence_root(offhost=True):
    directory, image = configuration(offhost)
    if directory.name != "physical-evidence":
        raise RuntimeError("Managed WAL needs a distinct physical base backup receipt directory")
    root = protected(os.environ["POSTGRES_WAL_EVIDENCE_ROOT"], directory=True)
    return directory, root, image


def evidence(root, instance, create=False):
    path = root / ident(instance)
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    return protected(path, directory=True)


def source(instance):
    return owned_instance(ident(instance))


def postgres(container, args, timeout=30):
    return run(["docker", "exec", "-u", "postgres", container, *args], timeout).strip()


def identity(container):
    value = postgres(container, ["psql", "-X", "-At", "-U", "postgres", "-d", "appdb",
                                 "-c", "SELECT system_identifier FROM pg_control_system()"])
    if not re.fullmatch(r"[0-9]{15,21}", value):
        raise RuntimeError("Managed PostgreSQL system identity unavailable")
    return value


def members(container):
    output = postgres(container, ["ls", "-1", SPOOL])
    names = output.splitlines() if output else []
    if any(not SEGMENT.fullmatch(name) and not re.fullmatch(r"[0-9A-F]{24}\.partial", name)
           for name in names):
        raise RuntimeError("Unsafe managed WAL spool member")
    return names


def stream(instance):
    container = source(instance)
    postgres(container, ["mkdir", "-p", SPOOL])
    postgres(container, ["pg_receivewal", "--create-slot", "--if-not-exists", "--slot", SLOT,
                         "--no-password"], 30)
    os.execvp("docker", ["docker", "exec", "-u", "postgres", container, "pg_receivewal",
                         "-D", SPOOL, "-S", SLOT, "--synchronous", "--no-password"])


def ship(instance, root):
    container = source(instance)
    system = identity(container)
    directory = evidence(root, instance, create=True)
    names = members(container)
    with tempfile.TemporaryDirectory(prefix="dial-client-wal-") as temporary:
        local = Path(temporary)
        for name in names:
            if SEGMENT.fullmatch(name):
                run(["docker", "cp", container + ":" + SPOOL + "/" + name, str(local / name)], 60)
                (local / name).chmod(0o600)
        receipts = archive(local, directory, system, tag=TAG, instance_id=instance)
    for name in sorted((name for name in names if re.fullmatch(r"[0-9A-F]{24}", name)))[:-1]:
        load_receipt(directory / (system + "-" + name + ".json"), system, name)
        postgres(container, ["rm", "--", SPOOL + "/" + name], 30)
    return receipts


def status(instance, root, max_age=300):
    container = source(instance)
    system = identity(container)
    directory = evidence(root, instance)
    receipts = [load_receipt(path, system, path.name[len(system) + 1:-5])
                for path in directory.glob(system + "-*.json")]
    available = remote_ids(TAG, system)
    if not receipts or any(item.get("instance_id") != instance or item.get("tag") != TAG or
                           item["snapshot_id"] not in available for item in receipts):
        raise RuntimeError("Managed WAL archive evidence absent or invalid")
    slot = postgres(container, ["psql", "-X", "-At", "-U", "postgres", "-d", "appdb", "-c",
                                "SELECT active, coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), "
                                "restart_lsn), -1) FROM pg_replication_slots "
                                "WHERE slot_name='dial_client_wal'"])
    if not re.fullmatch(r"t\|[0-9]+(?:\.[0-9]+)?", slot) or float(slot.split("|")[1]) > 67108864:
        raise RuntimeError("Managed WAL receiver inactive or lagging")
    pending = [name for name in members(container) if SEGMENT.fullmatch(name) and
               not (directory / (system + "-" + name + ".json")).is_file()]
    if pending:
        oldest = min(float(postgres(container, ["stat", "-c", "%Y", SPOOL + "/" + name]))
                     for name in pending)
        if time.time() - oldest > max_age:
            raise RuntimeError("Managed WAL off-host upload overdue")
    return {"state": "MANAGED_WAL_HEALTHY", "instance_id": instance, "segments": len(receipts)}


def fleet():
    names = run(["docker", "ps", "-a", "--filter", "label=dial.postgres",
                 "--format", "{{.Names}}"], 30).splitlines()
    instances = sorted({ident(name[len("dial-pg-"):]) for name in names if name.startswith("dial-pg-")})
    if not instances or len(instances) != len(names):
        raise RuntimeError("Managed PostgreSQL WAL fleet missing or unexpected")
    for instance in instances:
        source(instance)
    return instances


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stream", "archive", "health", "switch", "reconcile",
                                           "archive-all", "health-all", "switch-all", "pitr"))
    parser.add_argument("instance_id", nargs="?")
    parser.add_argument("--snapshot-id")
    parser.add_argument("--target")
    args = parser.parse_args()
    physical, root, image = evidence_root()
    if args.action in ("reconcile", "archive-all", "health-all", "switch-all"):
        if args.instance_id:
            parser.error("Fleet operations take no instance ID")
        instances = fleet()
        if args.action == "reconcile":
            result = []
            for instance in instances:
                run(["systemctl", "enable", "--now", "dial-postgres-wal@" + instance + ".service"], 60)
                result.append(instance)
        else:
            result = [(ship(i, root) if args.action == "archive-all" else
                       status(i, root) if args.action == "health-all" else
                       postgres(source(i), ["psql", "-X", "-At", "-U", "postgres", "-d", "appdb",
                                            "-c", "SELECT pg_switch_wal()"] )) for i in instances]
    else:
        if not args.instance_id:
            parser.error("Instance ID required")
        instance = ident(args.instance_id)
        if args.action == "stream":
            stream(instance)
            return
        if args.action == "pitr":
            if not args.snapshot_id or not args.target:
                parser.error("PITR requires a base snapshot and target time")
            base = json.loads(protected(physical / (args.snapshot_id + ".json")).read_text())
            if base.get("instance_id") != instance:
                raise RuntimeError("Managed PITR base instance mismatch")
            probe = restore_probe(instance)
            result = pitr(evidence(root, instance), base["system_id"], physical,
                          args.snapshot_id, image, args.target,
                          {"sql": probe["sql"], "expected": probe["expected"]},
                          archive_name="base.tar", database="appdb", instance_id=instance)
        elif args.action == "archive":
            result = ship(instance, root)
        elif args.action == "health":
            result = status(instance, root)
        else:
            result = postgres(source(instance), ["psql", "-X", "-At", "-U", "postgres", "-d",
                                                 "appdb", "-c", "SELECT pg_switch_wal()"])
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
