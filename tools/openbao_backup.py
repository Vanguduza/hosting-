#!/usr/bin/env python3
"""Off-host OpenBao Raft snapshots and guarded isolated restore verification."""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def protected(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise RuntimeError("Credential or probe file must be regular and owner-only")
    return path


def origin(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or \
            parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("OpenBao origin must be an HTTPS origin without credentials or path")
    return value.rstrip("/")


def api(address, ca, token_file, method, path, body=None, output=None):
    token = protected(token_file).read_text().strip()
    if not token or "\n" in token:
        raise RuntimeError("Invalid token file")
    request = urllib.request.Request(origin(address) + "/v1/" + path, data=body,
                                     headers={"X-Vault-Token": token}, method=method)
    context = ssl.create_default_context(cafile=str(protected(ca)))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            raise RuntimeError("OpenBao redirected an authenticated backup request")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
    try:
        with opener.open(request, timeout=600) as response:
            if output:
                with open(output, "xb") as destination:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        destination.write(chunk)
                return None
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"OpenBao {method} {path} failed with HTTP {exc.code}") from None


def upload_snapshot(address, ca, token_file, archive):
    """Stream a potentially large Raft snapshot without holding it in memory."""
    parsed = urlsplit(origin(address))
    token = protected(token_file).read_text().strip()
    context = ssl.create_default_context(cafile=str(protected(ca)))
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=600)
    try:
        connection.putrequest("POST", "/v1/sys/storage/raft/snapshot-force")
        connection.putheader("X-Vault-Token", token)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(archive.stat().st_size))
        connection.endheaders()
        with open(archive, "rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                connection.send(chunk)
        response = connection.getresponse()
        response.read()
        if response.status < 200 or response.status >= 300:
            raise RuntimeError("Disposable OpenBao Raft restore failed with HTTP " + str(response.status))
    finally:
        connection.close()


def read_json(address, ca, token, path):
    return json.loads(api(address, ca, token, "GET", path))


def digest(path):
    hash_ = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hash_.update(chunk)
    return hash_.hexdigest()


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=3600)
    if result.returncode:
        raise RuntimeError(args[0] + " failed with exit " + str(result.returncode))
    return result.stdout


def config():
    required = ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "BACKUP_EVIDENCE_DIR",
                "BAO_ADDR", "BAO_CA_FILE", "BAO_BACKUP_TOKEN_FILE", "BAO_PROBE_FILE")
    absent = [name for name in required if not os.environ.get(name)]
    if absent:
        raise RuntimeError("Missing backup configuration: " + ", ".join(absent))
    if not os.environ["RESTIC_REPOSITORY"].startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise RuntimeError("Restic repository must be off-host")
    for name in ("RESTIC_PASSWORD_FILE", "BAO_CA_FILE", "BAO_BACKUP_TOKEN_FILE", "BAO_PROBE_FILE"):
        protected(os.environ[name])
    origin(os.environ["BAO_ADDR"])
    evidence = Path(os.environ["BACKUP_EVIDENCE_DIR"])
    if evidence.is_symlink():
        raise RuntimeError("Evidence directory cannot be a symlink")
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if evidence.stat().st_uid != os.geteuid() or evidence.stat().st_mode & 0o077:
        raise RuntimeError("Evidence directory must be owner-only")
    probe = json.loads(protected(os.environ["BAO_PROBE_FILE"]).read_text())
    if not re.fullmatch(r"dial/data/resources/[0-9a-f-]{36}", probe.get("path", "")) or \
            not re.fullmatch(r"[0-9a-f]{64}", probe.get("sha256", "")):
        raise RuntimeError("Probe needs a resource KV v2 path and expected data SHA256")
    return evidence, probe


def probe_data(address, ca, token, probe, version=None):
    path = probe["path"] + ("?version=" + str(version) if version is not None else "")
    result = read_json(address, ca, token, path)["data"]
    value = result["data"]
    hash_ = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if hash_ != probe["sha256"] or (version is not None and result["metadata"]["version"] != version):
        raise RuntimeError("OpenBao probe does not match the protected expected revision")
    return result["metadata"]["version"]


def save(evidence, receipt):
    path = evidence / (receipt["snapshot_id"] + ".json")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)


def backup(evidence, probe):
    address, ca, token = (os.environ[name] for name in ("BAO_ADDR", "BAO_CA_FILE", "BAO_BACKUP_TOKEN_FILE"))
    version = probe_data(address, ca, token, probe)
    cluster_id = read_json(address, ca, token, "sys/health")["cluster_id"]
    with tempfile.TemporaryDirectory(prefix="dial-bao-backup-") as temp:
        archive = Path(temp) / "raft.snap"
        api(address, ca, token, "GET", "sys/storage/raft/snapshot", output=archive)
        if archive.stat().st_size == 0:
            raise RuntimeError("Empty OpenBao snapshot")
        summaries = [json.loads(line) for line in run(["restic", "backup", "--json", "--tag", "dial-openbao", str(archive)]).splitlines()]
        snapshots = [line["snapshot_id"] for line in summaries if line.get("message_type") == "summary"]
        if len(snapshots) != 1 or not re.fullmatch(r"[0-9a-f]{64}", snapshots[0]):
            raise RuntimeError("Restic did not issue one full snapshot ID")
        receipt = {"snapshot_id": snapshots[0], "archive_sha256": digest(archive), "cluster_id": cluster_id,
                   "probe_path": probe["path"], "probe_version": version, "probe_sha256": probe["sha256"],
                   "created_at": datetime.now(timezone.utc).isoformat(), "state": "BACKUP_CREATED",
                   "restore_verified_at": None}
        save(evidence, receipt)
        return receipt


def verify(evidence, probe, snapshot, restore_address, restore_ca, restore_token, marker):
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    source = origin(os.environ["BAO_ADDR"])
    target = origin(restore_address)
    if source == target:
        raise RuntimeError("Refusing to restore into the source authority")
    protected(restore_ca)
    protected(restore_token)
    path = protected(evidence / (snapshot + ".json"))
    receipt = json.loads(path.read_text())
    if receipt["snapshot_id"] != snapshot or receipt["probe_path"] != probe["path"] or \
            receipt["probe_sha256"] != probe["sha256"]:
        raise RuntimeError("Snapshot receipt does not match this source probe")
    health = read_json(target, restore_ca, restore_token, "sys/health")
    if health["cluster_id"] == receipt["cluster_id"]:
        raise RuntimeError("Restore target belongs to the source cluster")
    # The operator puts a fresh unpredictable marker into the disposable target.
    # An unrelated running authority cannot accidentally pass this check.
    preflight = read_json(target, restore_ca, restore_token, "identity/entity/name/dial-disposable-restore")
    if preflight["data"].get("metadata", {}).get("nonce") != marker or len(marker) < 32:
        raise RuntimeError("Disposable restore target marker mismatch")
    with tempfile.TemporaryDirectory(prefix="dial-bao-restore-") as temp:
        run(["restic", "restore", snapshot, "--target", temp])
        archives = list(Path(temp).rglob("raft.snap"))
        if len(archives) != 1 or archives[0].is_symlink() or not archives[0].is_file() or \
                digest(archives[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored Raft archive differs from evidence")
        # A new cluster has different Shamir keys. Force restore is confined to the
        # explicitly marked disposable authority; the source is never modified.
        upload_snapshot(target, restore_ca, restore_token, archives[0])
    # After restore, the source's token and seal material belong to the restored state.
    # Operators must unseal the disposable server using the source recovery keys.
    receipt["state"] = "RESTORE_PENDING_UNSEAL"
    receipt["restore_target_cluster_id"] = health["cluster_id"]
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def confirm(evidence, probe, snapshot, restore_address, restore_ca):
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = protected(evidence / (snapshot + ".json"))
    receipt = json.loads(path.read_text())
    if receipt["snapshot_id"] != snapshot or receipt["state"] != "RESTORE_PENDING_UNSEAL" or \
            receipt["probe_path"] != probe["path"] or receipt["probe_sha256"] != probe["sha256"] or \
            origin(restore_address) == origin(os.environ["BAO_ADDR"]):
        raise RuntimeError("Snapshot has no isolated restore pending")
    protected(restore_ca)
    probe_data(restore_address, restore_ca, os.environ["BAO_BACKUP_TOKEN_FILE"], probe, receipt["probe_version"])
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("backup")
    restore = commands.add_parser("restore-to-disposable")
    restore.add_argument("snapshot_id")
    restore.add_argument("--target", required=True)
    restore.add_argument("--target-ca", required=True)
    restore.add_argument("--target-token-file", required=True)
    restore.add_argument("--marker", required=True)
    check = commands.add_parser("confirm")
    check.add_argument("snapshot_id")
    check.add_argument("--target", required=True)
    check.add_argument("--target-ca", required=True)
    args = parser.parse_args()
    evidence, probe = config()
    fd = os.open(evidence / ".openbao-backup.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "backup":
            result = backup(evidence, probe)
        elif args.command == "restore-to-disposable":
            result = verify(evidence, probe, args.snapshot_id, args.target, args.target_ca,
                            args.target_token_file, args.marker)
        else:
            result = confirm(evidence, probe, args.snapshot_id, args.target, args.target_ca)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
