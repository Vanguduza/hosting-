#!/usr/bin/env python3
"""Stream control PostgreSQL WAL and verify encrypted, off-host segment copies."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


SEGMENT = re.compile(r"(?:[0-9A-F]{24}|[0-9A-F]{8}\.history)\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
SLOT = "dial_control_wal"


def protected(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or \
            not (path.is_dir() if directory else path.is_file()) or \
            path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise RuntimeError("Protected WAL path required")
    return path


def config(require_source=True):
    spool = protected(os.environ["CONTROL_WAL_SPOOL"], directory=True) if require_source else None
    evidence = protected(os.environ["CONTROL_WAL_EVIDENCE"], directory=True)
    protected(os.environ["RESTIC_PASSWORD_FILE"])
    repository = os.environ["RESTIC_REPOSITORY"]
    if not repository or (not os.environ.get("CONTROL_WAL_ALLOW_LOCAL_TEST") and
                          not (repository.startswith("s3:") or repository.startswith("rest:") or
                               repository.startswith("sftp:") or repository.startswith("rclone:"))):
        raise RuntimeError("Encrypted off-host WAL repository required")
    return spool, evidence


def command(args, timeout=600):
    result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(args[0] + " failed with exit " + str(result.returncode))
    return result.stdout


def system_id():
    value = command(["psql", "-X", "-At", "-w", "-c",
                     "SELECT system_identifier FROM pg_control_system()"], 15).decode().strip()
    if not re.fullmatch(r"[0-9]{15,21}", value):
        raise RuntimeError("PostgreSQL system identity unavailable")
    return value


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def receipt_files(evidence):
    files = sorted(path for path in evidence.glob("*.json") if not path.name.startswith(".wal-evidence-"))
    for path in files:
        protected(path)
    return files


def evidence_snapshots(tag, identity):
    rows = json.loads(command(["restic", "snapshots", "--json", "--tag", tag,
                               "--tag", "system=" + identity], 60))
    return sorted((row for row in rows if SHA.fullmatch(row.get("id", ""))),
                  key=lambda row: row["time"], reverse=True)


def publish_evidence(evidence, identity, tag):
    evidence = protected(evidence, directory=True)
    files = receipt_files(evidence)
    segments = [path for path in files if path.name.startswith(identity + "-")]
    if not segments:
        raise RuntimeError("WAL evidence snapshot requires verified segments")
    for path in segments:
        load_receipt(path, identity, path.name[len(identity) + 1:-5])
    fingerprints = {path.name: file_digest(path) for path in files}
    marker = evidence / (".wal-evidence-" + identity + ".json")
    if marker.exists() or marker.is_symlink():
        previous = json.loads(protected(marker).read_text())
        if previous.get("files") == fingerprints and previous.get("snapshot_id") in \
                {row["id"] for row in evidence_snapshots(tag, identity)}:
            return previous["snapshot_id"]
    lines = command(["restic", "backup", "--json", "--tag", tag,
                     "--tag", "system=" + identity, str(evidence)], 600).splitlines()
    snapshots = [json.loads(line).get("snapshot_id") for line in lines
                 if json.loads(line).get("message_type") == "summary"]
    if len(snapshots) != 1 or not isinstance(snapshots[0], str) or not SHA.fullmatch(snapshots[0]):
        raise RuntimeError("WAL evidence snapshot ID unavailable")
    with tempfile.TemporaryDirectory(prefix="dial-wal-evidence-check-") as temp:
        command(["restic", "restore", snapshots[0], "--target", temp], 600)
        restored = [p for p in Path(temp).rglob(evidence.name) if p.is_dir() and
                    {f.name: file_digest(f) for f in receipt_files(p)} == fingerprints]
        if len(restored) != 1:
            raise RuntimeError("Off-host WAL receipt evidence differs")
    temporary = marker.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
        json.dump({"snapshot_id": snapshots[0], "files": fingerprints}, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, marker)
    return snapshots[0]


def recover_evidence(target, identity, tag):
    target = protected(target, directory=True)
    if list(target.iterdir()):
        raise RuntimeError("WAL recovery target must be empty")
    snapshots = evidence_snapshots(tag, identity)
    if not snapshots:
        raise RuntimeError("Off-host WAL evidence missing")
    with tempfile.TemporaryDirectory(prefix="dial-wal-evidence-restore-") as temp:
        command(["restic", "restore", snapshots[0]["id"], "--target", temp], 600)
        candidates = {p.parent for p in Path(temp).rglob(identity + "-*.json")}
        if len(candidates) != 1:
            raise RuntimeError("Restored WAL receipt directory ambiguous")
        source = candidates.pop()
        files = receipt_files(source)
        for path in files:
            if path.name.startswith(identity + "-"):
                receipt = load_receipt(path, identity, path.name[len(identity) + 1:-5])
                if not remote(receipt):
                    raise RuntimeError("Recovered WAL receipt lost its segment")
            elif not path.name.startswith("pitr-"):
                raise RuntimeError("Recovered WAL evidence contains unexpected receipt")
        for path in files:
            with path.open("rb") as item, os.fdopen(os.open(target / path.name,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
                shutil.copyfileobj(item, output)
                output.flush()
                os.fsync(output.fileno())
    return {"state": "WAL_EVIDENCE_RECOVERED", "snapshot_id": snapshots[0]["id"],
            "receipts": len(files)}


def evidence_health(evidence, identity, tag):
    marker = json.loads(protected(evidence / (".wal-evidence-" + identity + ".json")).read_text())
    if (marker.get("files") != {p.name: file_digest(p) for p in receipt_files(evidence)} or
            marker.get("snapshot_id") not in {r["id"] for r in evidence_snapshots(tag, identity)}):
        raise RuntimeError("Off-host WAL receipt evidence stale or absent")
    return marker["snapshot_id"]


def receipt_path(evidence, identity, name):
    if not SEGMENT.fullmatch(name):
        raise ValueError("Invalid WAL segment name")
    return evidence / (identity + "-" + name + ".json")


def remote_ids(tag, identity):
    output = command(["restic", "snapshots", "--json", "--tag", tag,
                      "--tag", "system=" + identity], 60)
    return {item.get("id") for item in json.loads(output)}


def remote(receipt):
    return receipt["snapshot_id"] in remote_ids(receipt.get("tag", "dial-control-wal"),
                                                receipt["system_id"])


def load_receipt(path, identity, name):
    item = json.loads(protected(path).read_text())
    if (item.get("system_id") != identity or item.get("name") != name or
            not SHA.fullmatch(item.get("sha256", "")) or
            not SHA.fullmatch(item.get("snapshot_id", "")) or
            item.get("state") != "RESTORE_VERIFIED"):
        raise RuntimeError("WAL receipt provenance mismatch")
    return item


def archive(spool, evidence, identity, tag="dial-control-wal", instance_id=None):
    results = []
    for source in sorted(spool.iterdir()):
        if source.name.endswith(".partial"):
            continue
        if not SEGMENT.fullmatch(source.name) or source.is_symlink() or not source.is_file() or \
                source.stat().st_mode & 0o077 or source.stat().st_uid != os.geteuid():
            raise RuntimeError("Unsafe WAL spool member")
        path = receipt_path(evidence, identity, source.name)
        digest = file_digest(source)
        if path.exists() or path.is_symlink():
            prior = load_receipt(path, identity, source.name)
            if prior["sha256"] != digest or prior.get("tag", "dial-control-wal") != tag or \
                    prior.get("instance_id") != instance_id or not remote(prior):
                raise RuntimeError("Existing WAL segment differs or is missing off-host")
            results.append(prior)
            continue
        lines = command(["restic", "backup", "--json", "--tag", tag,
                         "--tag", "system=" + identity, str(source)], 600).splitlines()
        snapshots = [json.loads(line).get("snapshot_id") for line in lines
                     if json.loads(line).get("message_type") == "summary"]
        if len(snapshots) != 1 or not isinstance(snapshots[0], str) or not SHA.fullmatch(snapshots[0]):
            raise RuntimeError("WAL snapshot ID unavailable")
        receipt = {"system_id": identity, "name": source.name, "sha256": digest,
                   "snapshot_id": snapshots[0], "created_at": datetime.now(timezone.utc).isoformat(),
                   "state": "RESTORE_VERIFIED", "tag": tag, "instance_id": instance_id}
        with tempfile.TemporaryDirectory(prefix="dial-wal-check-") as temp:
            command(["restic", "restore", snapshots[0], "--target", temp], 600)
            restored = [p for p in Path(temp).rglob(source.name) if p.is_file() and not p.is_symlink()]
            if len(restored) != 1 or file_digest(restored[0]) != digest or file_digest(source) != digest:
                raise RuntimeError("Off-host WAL segment differs from source")
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
            json.dump(receipt, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        results.append(receipt)
    # pg_receivewal uses the newest completed segment to resume. Keep that one;
    # older completed files have already been restored and verified off-host.
    complete = sorted((p for p in spool.iterdir() if SEGMENT.fullmatch(p.name) and
                       p.name.endswith(".history") is False), key=lambda p: p.name)
    for old in complete[:-1]:
        if receipt_path(evidence, identity, old.name).is_file():
            old.unlink()
    return results


def materialize(evidence, identity, target, start_name=None):
    target = protected(target, directory=True)
    receipts = []
    remote_sets = {}
    for path in sorted(evidence.glob(identity + "-*.json")):
        name = path.name[len(identity) + 1:-5]
        if start_name and re.fullmatch(r"[0-9A-F]{24}", name) and name < start_name:
            continue
        receipt = load_receipt(path, identity, name)
        tag = receipt.get("tag", "dial-control-wal")
        if tag not in remote_sets:
            remote_sets[tag] = remote_ids(tag, identity)
        if receipt["snapshot_id"] not in remote_sets[tag]:
            raise RuntimeError("Verified WAL snapshot missing off-host")
        with tempfile.TemporaryDirectory(prefix="dial-wal-restore-") as temp:
            command(["restic", "restore", receipt["snapshot_id"], "--target", temp], 600)
            matches = [p for p in Path(temp).rglob(name) if p.is_file() and not p.is_symlink()]
            if len(matches) != 1 or file_digest(matches[0]) != receipt["sha256"]:
                raise RuntimeError("Restored WAL segment differs from receipt")
            destination = target / name
            with matches[0].open("rb") as source, os.fdopen(
                    os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        receipts.append(receipt)
    if not receipts:
        raise RuntimeError("No verified off-host WAL segments")
    return receipts


def health(spool, evidence, identity, max_age=300):
    receipts = [load_receipt(path, identity, path.name[len(identity) + 1:-5])
                for path in evidence.glob(identity + "-*.json")]
    if not receipts:
        raise RuntimeError("Verified WAL evidence missing")
    remote_set = remote_ids("dial-control-wal", identity)
    if not all(receipt["snapshot_id"] in remote_set for receipt in receipts):
        raise RuntimeError("Off-host WAL evidence absent")
    slot = command(["psql", "-X", "-At", "-w", "-c",
                    "SELECT active, coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), -1) "
                    "FROM pg_replication_slots WHERE slot_name='dial_control_wal'"], 15).decode().strip()
    if not re.fullmatch(r"t\|[0-9]+(?:\.[0-9]+)?", slot) or float(slot.split("|")[1]) > 67108864:
        raise RuntimeError("WAL receiver inactive or replication slot lagging")
    pending = [p for p in spool.iterdir() if SEGMENT.fullmatch(p.name) and
               not receipt_path(evidence, identity, p.name).is_file()]
    if pending and datetime.now(timezone.utc).timestamp() - min(p.stat().st_mtime for p in pending) > max_age:
        raise RuntimeError("Completed WAL upload overdue")
    return {"state": "WAL_ARCHIVE_HEALTHY", "system_id": identity, "segments": len(receipts)}


def pitr(evidence, identity, base_evidence, base_snapshot, image, target_time, probe,
         archive_name="control-base.tar", database=None, instance_id=None):
    """Prove a selected recovery target in a disposable network and volume."""
    from control_physical_backup import docker

    if not SHA.fullmatch(base_snapshot) or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}"
                                                   r"@sha256:[a-f0-9]{64}", image) or \
            not image.rsplit("/", 1)[-1].startswith("postgres:17@sha256:"):
        raise ValueError("Full base snapshot and pinned PostgreSQL 17 image required")
    target = datetime.fromisoformat(target_time)
    if target.tzinfo is None or not isinstance(probe, dict) or set(probe) != {"sql", "expected"} or \
            not isinstance(probe["sql"], str) or not probe["sql"].strip().upper().startswith("SELECT ") or \
            len(probe["sql"]) > 2048 or ";" in probe["sql"] or \
            not isinstance(probe["expected"], str):
        raise ValueError("Timezone-aware target and read-only semantic probe required")
    base_receipt = json.loads(protected(base_evidence / (base_snapshot + ".json")).read_text())
    if (base_receipt.get("snapshot_id") != base_snapshot or
            base_receipt.get("system_id") != identity or
            base_receipt.get("instance_id") != instance_id or
            base_receipt.get("state") != "RESTORE_VERIFIED" or
            base_receipt.get("format") != "pg_basebackup_tar_wal_fetch" or
            not SHA.fullmatch(base_receipt.get("archive_sha256", "")) or
            target <= datetime.fromisoformat(base_receipt["created_at"])):
        raise RuntimeError("Verified base backup with matching PostgreSQL system identity required")
    suffix = uuid.uuid4().hex
    container, network, volume, wal_volume = ("dial-control-pitr-" + suffix,
                                              "dial-control-pitr-net-" + suffix,
                                              "dial-control-pitr-data-" + suffix,
                                              "dial-control-pitr-wal-" + suffix)
    with tempfile.TemporaryDirectory(prefix="dial-control-pitr-") as temporary:
        root = Path(temporary)
        archive_dir = root / "wal"
        archive_dir.mkdir(mode=0o700)
        command(["restic", "restore", base_snapshot, "--target", temporary], 600)
        archives = [p for p in root.rglob(archive_name) if p.is_file() and not p.is_symlink()]
        if len(archives) != 1 or file_digest(archives[0]) != base_receipt["archive_sha256"]:
            raise RuntimeError("Restored PITR base differs from receipt")
        extracted = root / "base"
        extracted.mkdir(mode=0o700)
        with tarfile.open(archives[0], "r:") as tar:
            tar.extractall(extracted, filter="data")
        if (extracted / "PG_VERSION").read_text().strip() != "17" or \
                not (extracted / "backup_manifest").is_file():
            raise RuntimeError("PITR base version or manifest invalid")
        label = (extracted / "backup_label").read_text()
        match = re.search(r"START WAL LOCATION:.*\(file ([0-9A-F]{24})\)", label)
        if not match:
            raise RuntimeError("PITR base WAL start unavailable")
        wal_receipts = materialize(evidence, identity, archive_dir, start_name=match.group(1))
        made_network = made_volume = made_wal_volume = made_container = False
        try:
            docker(["network", "create", "--internal", network], 30)
            made_network = True
            docker(["volume", "create", volume], 30)
            made_volume = True
            docker(["volume", "create", wal_volume], 30)
            made_wal_volume = True
            docker(["run", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", "type=volume,src=" + wal_volume + ",dst=/wal",
                    "--mount", "type=bind,src=" + str(archive_dir) + ",dst=/backup,readonly", image,
                    "sh", "-c", "cp -a /backup/. /wal/ && chown -R postgres:postgres /wal"], 3600)
            docker(["run", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", "type=volume,src=" + volume + ",dst=/data",
                    "--mount", "type=bind,src=" + str(extracted) + ",dst=/backup,readonly", image,
                    "sh", "-c", "mkdir -p /data/pgdata && cp -a /backup/. /data/pgdata/ && "
                    "chown -R postgres:postgres /data/pgdata && "
                    "su postgres -s /bin/sh -c 'pg_verifybackup /data/pgdata'"], 3600)
            settings = ("restore_command = 'cp /wal-archive/%f %p'\n"
                        "recovery_target_time = '" + target.astimezone(timezone.utc).isoformat() + "'\n"
                        "recovery_target_action = 'pause'\n")
            config_file = root / "recovery-settings"
            config_file.write_text(settings)
            config_file.chmod(0o600)
            docker(["run", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", "type=volume,src=" + volume + ",dst=/data",
                    "--mount", "type=bind,src=" + str(config_file) + ",dst=/settings,readonly", image,
                    "sh", "-c", "cat /settings >> /data/pgdata/postgresql.auto.conf && "
                    "touch /data/pgdata/recovery.signal && chown postgres:postgres "
                    "/data/pgdata/postgresql.auto.conf /data/pgdata/recovery.signal"], 60)
            docker(["run", "-d", "--name", container, "--network", network,
                    "--read-only", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1",
                    "--tmpfs=/tmp:rw,nosuid,size=64m", "--tmpfs=/var/run/postgresql:rw,nosuid,size=16m",
                    "--mount", "type=volume,src=" + volume + ",dst=/var/lib/postgresql/data",
                    "--mount", "type=volume,src=" + wal_volume + ",dst=/wal-archive,readonly",
                    "-e", "PGDATA=/var/lib/postgresql/data/pgdata", image], 120)
            made_container = True
            deadline = time.monotonic() + 120
            while True:
                try:
                    state = docker(["exec", "-u", "postgres", container, "psql", "-X", "-At",
                                    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d",
                                    database or base_receipt["database"], "-c",
                                    "SELECT pg_is_in_recovery(), pg_get_wal_replay_pause_state()"], 15).strip()
                    if state == "t|paused":
                        break
                except RuntimeError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("PITR target not reached and paused")
                time.sleep(2)
            output = docker(["exec", "-u", "postgres", container, "psql", "-X", "-At",
                             "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d",
                             database or base_receipt["database"], "-c", "BEGIN READ ONLY",
                             "-c", "SET LOCAL statement_timeout = '5s'",
                             "-c", probe["sql"], "-c", "ROLLBACK"], 20).splitlines()
            if output != ["BEGIN", "SET", probe["expected"], "ROLLBACK"]:
                raise RuntimeError("Point-in-time semantic probe failed")
        finally:
            if made_container:
                docker(["rm", "-f", container], 60)
            if made_volume:
                docker(["volume", "rm", volume], 30)
            if made_wal_volume:
                docker(["volume", "rm", wal_volume], 30)
            if made_network:
                docker(["network", "rm", network], 30)
    receipt = {"state": "PITR_VERIFIED", "system_id": identity, "base_snapshot": base_snapshot,
               "target_time": target.isoformat(), "wal_segments": len(wal_receipts),
               "verified_at": datetime.now(timezone.utc).isoformat(),
               "probe_sha256": hashlib.sha256(json.dumps(probe, sort_keys=True).encode()).hexdigest()}
    receipt_file = evidence / ("pitr-" + uuid.uuid4().hex + ".json")
    with os.fdopen(os.open(receipt_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
        json.dump(receipt, output, sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
    return receipt


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stream", "archive", "health", "materialize", "pitr",
                                           "publish-evidence", "recover-evidence"))
    parser.add_argument("--target")
    parser.add_argument("--base-evidence")
    parser.add_argument("--base-snapshot")
    parser.add_argument("--probe-file")
    args = parser.parse_args()
    spool, evidence = config(require_source=args.action not in ("materialize", "pitr", "recover-evidence"))
    identity = system_id() if args.action not in ("materialize", "pitr", "recover-evidence") \
        else os.environ["CONTROL_WAL_SYSTEM_ID"]
    if not re.fullmatch(r"[0-9]{15,21}", identity):
        raise RuntimeError("Invalid PostgreSQL system identity")
    if args.action == "stream":
        command(["pg_receivewal", "--create-slot", "--if-not-exists", "--slot", SLOT,
                 "--no-password"], 30)
        os.execvp("pg_receivewal", ["pg_receivewal", "--directory", str(spool),
                                    "--slot", SLOT, "--synchronous", "--no-password"])
    if args.action == "archive":
        rows = archive(spool, evidence, identity)
        result = {"segments": len(rows), "evidence_snapshot":
                  publish_evidence(evidence, identity, "dial-control-wal-evidence")}
    elif args.action == "health":
        result = health(spool, evidence, identity) | {
            "evidence_snapshot": evidence_health(evidence, identity, "dial-control-wal-evidence")}
    elif args.action == "publish-evidence":
        result = {"evidence_snapshot": publish_evidence(evidence, identity, "dial-control-wal-evidence")}
    elif args.action == "recover-evidence":
        result = recover_evidence(Path(args.target), identity, "dial-control-wal-evidence")
    elif args.action == "materialize":
        result = materialize(evidence, identity, args.target)
    else:
        result = pitr(evidence, identity, protected(args.base_evidence, directory=True),
                      args.base_snapshot, os.environ["CONTROL_POSTGRES_IMAGE"], args.target,
                      json.loads(protected(args.probe_file).read_text()))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
