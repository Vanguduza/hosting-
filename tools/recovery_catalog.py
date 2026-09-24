#!/usr/bin/env python3
"""Publish and inspect an encrypted, inventory-bound disaster recovery catalog."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backup_health import KINDS, evaluate, inventory, receipts, timestamp


TAGS = {"control": "dial-control", "control-physical": "dial-control-physical",
        "openbao": "dial-openbao", "postgres": "dial-client-postgres",
        "postgres-physical": "dial-client-postgres-physical",
        "valkey": "dial-client-valkey", "storage": "dial-client-storage"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def protected(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
            path.stat().st_mode & 0o077:
        raise RuntimeError("Catalog input must be an owner-only regular file")
    return path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def repository(value, allow_local=False):
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise ValueError("Invalid Restic repository")
    if not allow_local and not value.startswith(("s3:", "sftp:", "rest:", "rclone:", "b2:", "azure:", "gs:")):
        raise ValueError("Catalog requires an explicitly remote Restic repository")
    return value


def load_config(path, allow_local=False):
    data = json.loads(protected(path).read_text())
    if not isinstance(data, dict) or set(data) != {"version", "catalog_id", "host_id", "failure_domain",
                                                     "recovery_failure_domain", "catalog_repository",
                                                     "catalog_password_file", "classes"} or data["version"] != 1:
        raise ValueError("Invalid catalog configuration")
    if any(not isinstance(data[key], str) or not NAME.fullmatch(data[key]) for key in
           ("catalog_id", "host_id", "failure_domain", "recovery_failure_domain")) or \
            data["failure_domain"] == data["recovery_failure_domain"]:
        raise ValueError("Distinct named source and recovery failure domains required")
    repository(data["catalog_repository"], allow_local)
    protected(data["catalog_password_file"])
    classes = data["classes"]
    if not isinstance(classes, list) or not classes or len(classes) > len(TAGS):
        raise ValueError("Nonempty backup classes required")
    kinds = set()
    for item in classes:
        if not isinstance(item, dict) or set(item) != {"kind", "evidence_dir", "repository",
                                                   "password_file", "max_age_hours", "required_instances"}:
            raise ValueError("Invalid backup class")
        kind = item["kind"]
        if kind not in TAGS or kind in kinds:
            raise ValueError("Unknown or repeated backup class")
        kinds.add(kind)
        repository(item["repository"], allow_local)
        protected(item["password_file"])
        if type(item["max_age_hours"]) is not int or not 1 <= item["max_age_hours"] <= 720:
            raise ValueError("Invalid freshness policy")
        expected = item["required_instances"]
        if kind in KINDS:
            if not isinstance(expected, list) or not expected or any(not isinstance(value, str) for value in expected):
                raise ValueError("Node inventory requires at least one instance")
            try:
                if len(set(expected)) != len(expected) or any(str(uuid.UUID(value)) != value for value in expected):
                    raise ValueError("Noncanonical or repeated instance")
            except ValueError as exc:
                raise ValueError("Node inventory requires canonical instance identifiers") from exc
        elif expected != []:
            raise ValueError("Authority classes have no instance identifiers")
    return data


@contextmanager
def restic_env(repo, password_file):
    previous = {name: os.environ.get(name) for name in ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE")}
    os.environ["RESTIC_REPOSITORY"] = repo
    os.environ["RESTIC_PASSWORD_FILE"] = str(protected(password_file))
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def restic(args):
    result = subprocess.run(["restic", *args], capture_output=True, text=True, timeout=300, check=False)
    if result.returncode:
        raise RuntimeError("Encrypted Restic operation failed")
    return result.stdout


def snapshots():
    rows = json.loads(restic(["snapshots", "--json"]))
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not HEX.fullmatch(row.get("id", ""))
                                          or not isinstance(row.get("tags", []), list) for row in rows):
        raise RuntimeError("Invalid remote snapshot inventory")
    return {row["id"]: row for row in rows}


def backup_entries(config):
    entries = []
    for item in config["classes"]:
        kind = item["kind"]
        expected = set(item["required_instances"]) if kind in KINDS else {kind}
        if kind in KINDS and inventory(kind) != expected:
            raise RuntimeError("Live inventory differs from the required recovery inventory: " + kind)
        with restic_env(item["repository"], item["password_file"]):
            report = evaluate(kind, Path(item["evidence_dir"]), item["max_age_hours"],
                              min_instances=len(expected), instances=expected, check_remote=False)
            remote = snapshots()
        receipt_rows = {row["snapshot_id"]: row for row in receipts(Path(item["evidence_dir"]))}
        for verified in report["verified"]:
            snapshot = verified["snapshot_id"]
            tags = remote.get(snapshot, {}).get("tags", [])
            if TAGS[kind] not in tags or (kind in KINDS and "instance=" + verified["instance_id"] not in tags):
                raise RuntimeError("Restic snapshot provenance or resource tag mismatch")
            receipt = receipt_rows[snapshot]
            path = Path(item["evidence_dir"]) / (snapshot + ".json")
            entries.append({"kind": kind, "resource_id": verified["instance_id"],
                            "snapshot_id": snapshot, "archive_sha256": receipt["archive_sha256"],
                            "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "created_at": verified["created_at"],
                            "restore_verified_at": verified["restore_verified_at"],
                            "repository_sha256": hashlib.sha256(item["repository"].encode()).hexdigest(),
                            "max_age_hours": item["max_age_hours"]})
    return sorted(entries, key=lambda entry: (entry["kind"], entry["resource_id"]))


def publish(config, output_dir):
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or not output_dir.is_dir() or output_dir.stat().st_uid != os.geteuid() or \
            output_dir.stat().st_mode & 0o077:
        raise RuntimeError("Catalog output directory must be owner-only")
    entries = backup_entries(config)
    document = {"version": 1, "catalog_id": config["catalog_id"], "host_id": config["host_id"],
                "failure_domain": config["failure_domain"],
                "intended_recovery_failure_domain": config["recovery_failure_domain"],
                "created_at": datetime.now(timezone.utc).isoformat(), "entries": entries}
    name = "catalog-" + uuid.uuid4().hex + ".json"
    path = output_dir / name
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(canonical(document))
        file.flush()
        os.fsync(file.fileno())
    try:
        with restic_env(config["catalog_repository"], config["catalog_password_file"]):
            lines = restic(["backup", "--json", "--tag", "dial-dr-catalog", "--tag",
                            "catalog=" + config["catalog_id"], str(path)]).splitlines()
            summaries = [json.loads(line) for line in lines if json.loads(line).get("message_type") == "summary"]
            if len(summaries) != 1 or not HEX.fullmatch(summaries[0].get("snapshot_id", "")):
                raise RuntimeError("Catalog Restic receipt missing")
            snapshot_id = summaries[0]["snapshot_id"]
            if "dial-dr-catalog" not in snapshots().get(snapshot_id, {}).get("tags", []):
                raise RuntimeError("Catalog snapshot not remotely present")
        inspected = inspect(config, snapshot_id)
        if inspected["sha256"] != hashlib.sha256(canonical(document)).hexdigest():
            raise RuntimeError("Off-host catalog content differs from published bytes")
    except Exception:
        path.unlink()
        raise
    return {"state": "CATALOG_PUBLISHED", "snapshot_id": snapshot_id,
            "sha256": hashlib.sha256(canonical(document)).hexdigest(),
            "entries": len(entries), "local_path": str(path)}


def inspect(config, catalog_snapshot):
    if not HEX.fullmatch(catalog_snapshot):
        raise ValueError("Full catalog snapshot ID required")
    with restic_env(config["catalog_repository"], config["catalog_password_file"]):
        metadata = snapshots().get(catalog_snapshot, {})
        if not {"dial-dr-catalog", "catalog=" + config["catalog_id"]} <= set(metadata.get("tags", [])):
            raise RuntimeError("Catalog snapshot provenance invalid")
        with tempfile.TemporaryDirectory(prefix="dial-catalog-inspect-") as temp:
            restic(["restore", catalog_snapshot, "--target", temp])
            files = list(Path(temp).rglob("catalog-*.json"))
            if len(files) != 1 or files[0].is_symlink() or not files[0].is_file():
                raise RuntimeError("Catalog restore content invalid")
            document = json.loads(files[0].read_bytes())
    if not isinstance(document, dict) or set(document) != {"version", "catalog_id", "host_id", "failure_domain",
                                                             "intended_recovery_failure_domain", "created_at", "entries"} or \
            document["version"] != 1 or any(document[k] != config[source] for k, source in
                                             (("catalog_id", "catalog_id"), ("host_id", "host_id"),
                                              ("failure_domain", "failure_domain"),
                                              ("intended_recovery_failure_domain", "recovery_failure_domain"))):
        raise RuntimeError("Catalog authority or schema mismatch")
    if not isinstance(document["entries"], list) or not document["entries"]:
        raise RuntimeError("Catalog has no backup entries")
    now = datetime.now(timezone.utc)
    created = timestamp(document["created_at"])
    if created > now or (now - created).total_seconds() > 720 * 3600:
        raise RuntimeError("Catalog age invalid")
    expected_kinds = {item["kind"]: item for item in config["classes"]}
    expected = {(kind, value) for kind, item in expected_kinds.items() for value in
                (item["required_instances"] if kind in KINDS else [kind])}
    actual = set()
    remote = {}
    for entry in document["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"kind", "resource_id", "snapshot_id", "archive_sha256",
                                                       "receipt_sha256", "created_at", "restore_verified_at",
                                                       "repository_sha256", "max_age_hours"}:
            raise RuntimeError("Invalid catalog backup entry")
        kind, resource = entry["kind"], entry["resource_id"]
        if (kind, resource) not in expected or (kind, resource) in actual:
            raise RuntimeError("Missing, unknown or repeated recovery inventory")
        actual.add((kind, resource))
        item = expected_kinds[kind]
        if any(not HEX.fullmatch(entry[key]) for key in
               ("snapshot_id", "archive_sha256", "receipt_sha256", "repository_sha256")) or \
                entry["repository_sha256"] != hashlib.sha256(item["repository"].encode()).hexdigest() or \
                entry["max_age_hours"] != item["max_age_hours"]:
            raise RuntimeError("Catalog backup provenance mismatch")
        backed = timestamp(entry["created_at"])
        verified = timestamp(entry["restore_verified_at"])
        if backed > verified or verified > created or (now - backed).total_seconds() > entry["max_age_hours"] * 3600:
            raise RuntimeError("Catalog backup stale or restore timestamp invalid")
        if kind not in remote:
            with restic_env(item["repository"], item["password_file"]):
                remote[kind] = snapshots()
        tags = set(remote[kind].get(entry["snapshot_id"], {}).get("tags", []))
        if TAGS[kind] not in tags or (kind in KINDS and "instance=" + resource not in tags):
            raise RuntimeError("Catalog backup missing from the off-host repository")
    if actual != expected:
        raise RuntimeError("Catalog omits a required recovery resource")
    return {"state": "CATALOG_INSPECTED", "snapshot_id": catalog_snapshot,
            "sha256": hashlib.sha256(canonical(document)).hexdigest(),
            "entries": len(actual), "catalog": document}


def inspect_latest(config):
    with restic_env(config["catalog_repository"], config["catalog_password_file"]):
        matching = [row for row in snapshots().values() if
                    {"dial-dr-catalog", "catalog=" + config["catalog_id"]} <= set(row.get("tags", []))]
    if not matching:
        raise RuntimeError("No off-host disaster recovery catalog found")
    latest = max(matching, key=lambda row: timestamp(row["time"]))
    return inspect(config, latest["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--allow-local-repositories", action="store_true",
                        help="Disposable CI only; local repositories are not off-host recovery")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("publish").add_argument("output_dir", type=Path)
    sub.add_parser("inspect").add_argument("snapshot_id")
    sub.add_parser("inspect-latest")
    sub.add_parser("validate")
    args = parser.parse_args()
    config = load_config(args.config, args.allow_local_repositories)
    if args.command == "publish":
        result = publish(config, args.output_dir)
    elif args.command == "inspect":
        result = inspect(config, args.snapshot_id)
    elif args.command == "inspect-latest":
        result = inspect_latest(config)
    else:
        result = {"state": "CONFIG_VALID", "catalog_id": config["catalog_id"],
                  "classes": [entry["kind"] for entry in config["classes"]]}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
