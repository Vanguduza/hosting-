#!/usr/bin/env python3
"""Fail closed when a live resource lacks recent verified restore evidence."""
import argparse
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

KINDS = {
    "postgres": ("dial.postgres", "dial-pg-", "dial-pg-data-"),
    "valkey": ("dial.valkey", "dial-vk-", "dial-vk-data-"),
    "storage": ("dial.storage", "dial-s3-", "dial-s3-data-"),
}
HEX = re.compile(r"[a-f0-9]{64}\Z")


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("Backup inventory unavailable")
    return result.stdout.splitlines()


def inventory(kind):
    label, container_prefix, volume_prefix = KINDS[kind]
    def parse(values, prefix):
        result = set()
        for item in values:
            if not item.startswith(prefix):
                raise RuntimeError("Unexpected labeled backup inventory member")
            value = item[len(prefix):]
            if str(uuid.UUID(value)) != value:
                raise RuntimeError("Invalid labeled backup resource identifier")
            result.add(value)
        return result
    containers = parse(command(["docker", "ps", "-a", "--filter", "label=" + label,
                                "--format", "{{.Names}}"]), container_prefix)
    volumes = parse(command(["docker", "volume", "ls", "--filter", "label=" + label,
                             "--format", "{{.Name}}"]), volume_prefix)
    if containers != volumes:
        raise RuntimeError("Backup container and volume inventories differ")
    return containers


def timestamp(value):
    if not isinstance(value, str):
        raise RuntimeError("Backup receipt timestamp missing")
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        raise RuntimeError("Backup receipt timestamp must include a timezone")
    return moment.astimezone(timezone.utc)


def receipts(evidence):
    if evidence.is_symlink() or not evidence.is_dir() or evidence.stat().st_uid != os.geteuid() or \
            evidence.stat().st_mode & 0o077:
        raise RuntimeError("Backup evidence directory must be owner-only")
    result = []
    for path in evidence.iterdir():
        if not path.name.endswith(".json"):
            continue
        snapshot = path.stem
        if not HEX.fullmatch(snapshot) or path.is_symlink() or not path.is_file() or \
                path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
            raise RuntimeError("Unexpected or unprotected backup receipt")
        receipt = json.loads(path.read_text())
        if receipt.get("snapshot_id") != snapshot or not HEX.fullmatch(receipt.get("archive_sha256", "")):
            raise RuntimeError("Backup receipt integrity fields invalid")
        result.append(receipt)
    return result


def remote_snapshot_ids():
    if not os.environ.get("RESTIC_REPOSITORY") or not os.environ.get("RESTIC_PASSWORD_FILE"):
        raise RuntimeError("Restic repository configuration unavailable")
    password = Path(os.environ["RESTIC_PASSWORD_FILE"])
    if password.is_symlink() or not password.is_file() or password.stat().st_uid != os.geteuid() or \
            password.stat().st_mode & 0o077:
        raise RuntimeError("Restic password must be an owner-only regular file")
    result = subprocess.run(["restic", "snapshots", "--json"], capture_output=True,
                            text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError("Encrypted Restic repository unavailable")
    data = json.loads(result.stdout)
    if not isinstance(data, list) or any(not isinstance(item, dict) or not isinstance(item.get("id"), str)
                                         or not HEX.fullmatch(item["id"]) for item in data):
        raise RuntimeError("Restic snapshot inventory invalid")
    return {item["id"] for item in data}


def evaluate(kind, evidence, max_age_hours=36, min_instances=0, now=None, instances=None, check_remote=False):
    if kind not in (*KINDS, "control", "openbao"):
        raise ValueError("Unknown backup class")
    if type(max_age_hours) not in (int, float) or not 1 <= max_age_hours <= 720 or \
            type(min_instances) is not int or not 0 <= min_instances <= 100000:
        raise ValueError("Invalid backup freshness policy")
    now = now or datetime.now(timezone.utc)
    expected = {kind} if kind in ("control", "openbao") else inventory(kind) if instances is None else set(instances)
    if len(expected) < min_instances:
        raise RuntimeError("Backup resource count below required minimum")
    by_resource = {resource: [] for resource in expected}
    for row in receipts(Path(evidence)):
        if kind in ("control", "openbao") and "instance_id" in row:
            raise RuntimeError("Authority receipt has a resource ID")
        if kind == "openbao" and (not isinstance(row.get("cluster_id"), str) or
                                   not re.fullmatch(r"dial/data/resources/[0-9a-f-]{36}", row.get("probe_path", "")) or
                                   not HEX.fullmatch(row.get("probe_sha256", "")) or
                                   type(row.get("probe_version")) is not int or row["probe_version"] < 1):
            raise RuntimeError("OpenBao receipt lacks verified Raft provenance")
        resource = kind if kind in ("control", "openbao") else row.get("instance_id")
        if kind in KINDS:
            try:
                if str(uuid.UUID(resource)) != resource:
                    raise ValueError("Noncanonical UUID")
            except (ValueError, TypeError, AttributeError) as exc:
                raise RuntimeError("Resource receipt identifier invalid") from exc
        if resource in by_resource:
            by_resource[resource].append(row)
    results = []
    for resource in sorted(expected):
        entries = by_resource[resource]
        if not entries:
            raise RuntimeError("Missing backup evidence for resource " + resource)
        newest = max(entries, key=lambda x: timestamp(x.get("created_at")))
        created = timestamp(newest["created_at"])
        if created > now + timedelta(minutes=5) or now - created > timedelta(hours=max_age_hours):
            raise RuntimeError("Stale or future backup for resource " + resource)
        if newest.get("state") != "RESTORE_VERIFIED":
            raise RuntimeError("Latest backup lacks verified restore for resource " + resource)
        verified = timestamp(newest.get("restore_verified_at"))
        if verified < created or verified > now + timedelta(minutes=5):
            raise RuntimeError("Invalid restore verification timestamp for resource " + resource)
        results.append({"instance_id": resource, "snapshot_id": newest["snapshot_id"],
                        "created_at": newest["created_at"], "restore_verified_at": newest["restore_verified_at"]})
    if check_remote and results:
        available = remote_snapshot_ids()
        if any(item["snapshot_id"] not in available for item in results):
            raise RuntimeError("Verified backup snapshot missing from Restic repository")
    return {"state": "BACKUP_HEALTHY" if results else "BACKUP_INVENTORY_EMPTY", "kind": kind,
            "instances": len(results), "verified": results}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=[*KINDS, "control", "openbao"])
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--max-age-hours", type=int, default=36)
    parser.add_argument("--min-instances", type=int, default=0)
    parser.add_argument("--check-remote", action="store_true")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.kind, args.evidence_dir, args.max_age_hours, args.min_instances,
                              check_remote=args.check_remote),
                     sort_keys=True))


if __name__ == "__main__":
    main()
