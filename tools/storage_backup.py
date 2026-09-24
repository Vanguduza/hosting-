#!/usr/bin/env python3
"""Quiesced Garage volume backup and isolated S3 semantic restore drill."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("NODE_AGENT_PACKAGE_DIR",
                                  str(Path(__file__).resolve().parents[1] / "agents/node-agent")))
from node_agent.core import IMAGE, Node
from node_agent.storage import LAUNCH, _config, _private_probe, app_credentials, bucket_name, names
from node_agent.postgres import identifier
from postgres_backup import digest, run, save, snapshot_id


def configuration(offhost=True):
    required = ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "BACKUP_EVIDENCE_DIR", "BACKUP_TMP_DIR",
                "BACKUP_PROBE_DIR", "NODE_STATE_FILE", "NODE_SECRETS_DIR", "NODE_GARAGE_IMAGE",
                "NODE_STORAGE_SHELL_IMAGE")
    if missing := [key for key in required if not os.environ.get(key)]:
        raise RuntimeError("Missing storage backup configuration: " + ", ".join(missing))
    if offhost and not os.environ["RESTIC_REPOSITORY"].startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise RuntimeError("Storage backup requires an off-host encrypted Restic target")
    for key in ("RESTIC_PASSWORD_FILE",):
        path = Path(os.environ[key])
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
                path.stat().st_mode & 0o077:
            raise RuntimeError("Restic password must be an owner-only regular file")
    for key in ("BACKUP_EVIDENCE_DIR", "BACKUP_TMP_DIR", "BACKUP_PROBE_DIR", "NODE_SECRETS_DIR"):
        directory = Path(os.environ[key])
        if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != os.geteuid() or \
                directory.stat().st_mode & 0o077:
            raise RuntimeError(key + " must be an owner-only directory")
    image = os.environ["NODE_GARAGE_IMAGE"]
    helper = os.environ["NODE_STORAGE_SHELL_IMAGE"]
    if not IMAGE.fullmatch(image) or not image.rsplit("/", 1)[-1].startswith("garage:v2.3.0@") or \
            not IMAGE.fullmatch(helper) or not helper.rsplit("/", 1)[-1].startswith("busybox:1.37.0-musl@"):
        raise RuntimeError("Storage backup requires immutable Garage and helper digests")
    node = Node(os.environ["NODE_STATE_FILE"], secrets_dir=os.environ["NODE_SECRETS_DIR"])
    return Path(os.environ["BACKUP_EVIDENCE_DIR"]), node, helper


def launcher_tag(image, helper):
    source = "FROM " + helper + " AS helper\nFROM " + image + "\nCOPY --from=helper /bin/busybox /bin/sh\n"
    return "dial-s3-launcher:" + hashlib.sha256(source.encode()).hexdigest()


def owned_instance(node, instance):
    instance = identifier(instance)
    container, network, volume = names(instance)
    item = json.loads(run(["docker", "inspect", container], 15))[0]
    app = item["Config"]["Labels"].get("dial.application")
    if not app:
        raise RuntimeError("Storage application label missing")
    identifier(app)
    expected = launcher_tag(os.environ["NODE_GARAGE_IMAGE"], os.environ["NODE_STORAGE_SHELL_IMAGE"])
    if (item["Config"]["Labels"].get("dial.storage") != instance or
            item["Config"].get("Image") != expected or item["Config"].get("User") != "0:0" or
            not item["State"]["Running"] or item["HostConfig"].get("PortBindings") or
            not item["HostConfig"].get("ReadonlyRootfs") or
            "ALL" not in item["HostConfig"].get("CapDrop", []) or
            network not in item["NetworkSettings"]["Networks"] or
            set(item["NetworkSettings"]["Networks"]) != {network} or
            not any(m.get("Name") == volume and m.get("Destination") == "/var/lib/garage"
                    for m in item["Mounts"])):
        raise RuntimeError("Storage ownership, image or isolation mismatch")
    net = json.loads(run(["docker", "network", "inspect", network], 15))[0]
    vol = json.loads(run(["docker", "volume", "inspect", volume], 15))[0]
    if (not net["Internal"] or net["Labels"].get("dial.storage") != instance or
            vol["Labels"].get("dial.storage") != instance):
        raise RuntimeError("Storage network or volume ownership mismatch")
    from node_agent.storage import credential_files
    _, values = credential_files(node, instance, 1)
    config = _config(node, instance, values)
    mounted = app_credentials(node, instance, 1)
    expected_mounts = {"/etc/garage.toml": config,
                       "/run/secrets/access_key": mounted / "access_key",
                       "/run/secrets/secret_key": mounted / "secret_key"}
    for target, source in expected_mounts.items():
        if not any(m.get("Source") == str(source) and m.get("Destination") == target and
                   m.get("RW") is False for m in item["Mounts"]):
            raise RuntimeError("Storage bind mount differs from exact revision")
    if {m["Destination"] for m in item["Mounts"]} != {"/var/lib/garage", *expected_mounts}:
        raise RuntimeError("Unexpected storage mount")
    ip = item["NetworkSettings"]["Networks"][network]["IPAddress"]
    if not ip or not _private_probe(ip, bucket_name(instance)):
        raise RuntimeError("Storage private gateway unavailable")
    return {"container": container, "volume": volume, "app": app, "ip": ip,
            "image": expected, "config": config, "mounted": mounted}


def semantic_probe(instance):
    root = Path(os.environ["BACKUP_PROBE_DIR"])
    path = root / (identifier(instance) + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
            path.stat().st_mode & 0o077:
        raise RuntimeError("Instance storage probe must be an owner-only regular file")
    probe = json.loads(path.read_text())
    if set(probe) != {"key", "sha256", "size_bytes"} or not isinstance(probe["key"], str) or \
            not 1 <= len(probe["key"]) <= 256 or any(ord(c) < 32 for c in probe["key"]) or \
            not isinstance(probe["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", probe["sha256"]) or \
            type(probe["size_bytes"]) is not int or not 1 <= probe["size_bytes"] <= 1048576:
        raise RuntimeError("Invalid storage semantic probe")
    return probe


def check_object(instance, ip, mounted, probe):
    import boto3
    from botocore.config import Config
    client = boto3.client("s3", endpoint_url="http://" + ip + ":3900", region_name="garage",
                          aws_access_key_id=(mounted / "access_key").read_text(),
                          aws_secret_access_key=(mounted / "secret_key").read_text(),
                          config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    response = client.get_object(Bucket=bucket_name(instance), Key=probe["key"])
    if response["ContentLength"] != probe["size_bytes"]:
        raise RuntimeError("Storage semantic object length differs")
    data = response["Body"].read(probe["size_bytes"] + 1)
    response["Body"].close()
    if len(data) != probe["size_bytes"] or hashlib.sha256(data).hexdigest() != probe["sha256"]:
        raise RuntimeError("Storage semantic object differs")


def archive_volume(volume, helper, archive):
    with open(archive, "xb") as out:
        os.chmod(archive, 0o600)
        run(["docker", "run", "--rm", "--network=none", "--read-only", "--user=0:0",
             "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
             "--memory=256m", "--cpus=0.5",
             "--mount", "type=volume,src=" + volume + ",dst=/source,readonly",
             helper, "tar", "-C", "/source", "-cf", "-", "."], 3600, stdout=out)
        out.flush()
        os.fsync(out.fileno())
    if archive.stat().st_size < 1024:
        raise RuntimeError("Storage volume archive is empty")


def ready(container, network, bucket):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        item = json.loads(run(["docker", "inspect", container], 15))[0]
        ip = item["NetworkSettings"]["Networks"].get(network, {}).get("IPAddress")
        if item["State"]["Running"] and ip and _private_probe(ip, bucket):
            return ip
        time.sleep(2)
    raise RuntimeError("Garage did not return to private readiness")


def backup(instance, evidence, node, helper):
    instance = identifier(instance)
    owned = owned_instance(node, instance)
    probe = semantic_probe(instance)
    check_object(instance, owned["ip"], owned["mounted"], probe)
    with tempfile.TemporaryDirectory(prefix="dial-storage-backup-", dir=os.environ["BACKUP_TMP_DIR"]) as temp:
        os.chmod(temp, 0o700)
        archive = Path(temp) / "garage.tar"
        try:
            run(["docker", "stop", "--time", "30", owned["container"]], 50)
            archive_volume(owned["volume"], helper, archive)
        finally:
            state = json.loads(run(["docker", "inspect", owned["container"]], 15))[0]["State"]
            if not state["Running"]:
                run(["docker", "start", owned["container"]], 60)
        ip = ready(owned["container"], names(instance)[1], bucket_name(instance))
        check_object(instance, ip, owned["mounted"], probe)
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-client-storage",
                                    "--tag", "instance=" + instance, str(archive)]))
        receipt = {"instance_id": instance, "snapshot_id": snapshot, "archive_sha256": digest(archive),
                   "archive_bytes": archive.stat().st_size, "probe_sha256": hashlib.sha256(
                       json.dumps(probe, sort_keys=True).encode()).hexdigest(),
                   "created_at": datetime.now(timezone.utc).isoformat(),
                   "state": "BACKUP_CREATED", "restore_verified_at": None}
        save(evidence, receipt)
        return receipt


def restore_drill(instance, snapshot, evidence, node, helper):
    instance = identifier(instance)
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = evidence / (snapshot + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or \
            path.stat().st_mode & 0o077:
        raise RuntimeError("Storage backup evidence unavailable")
    receipt = json.loads(path.read_text())
    if receipt["instance_id"] != instance or receipt["snapshot_id"] != snapshot:
        raise RuntimeError("Snapshot does not belong to this storage resource")
    probe = semantic_probe(instance)
    if hashlib.sha256(json.dumps(probe, sort_keys=True).encode()).hexdigest() != receipt["probe_sha256"]:
        raise RuntimeError("Storage semantic probe changed since backup")
    owned = owned_instance(node, instance)
    marker = uuid.uuid4().hex
    container, network, volume = "dial-s3-drill-" + marker, "dial-s3-drill-net-" + marker, "dial-s3-drill-data-" + marker
    with tempfile.TemporaryDirectory(prefix="dial-storage-restore-", dir=os.environ["BACKUP_TMP_DIR"]) as temp:
        os.chmod(temp, 0o700)
        run(["restic", "restore", snapshot, "--target", temp])
        matches = [p for p in Path(temp).rglob("garage.tar") if p.is_file() and not p.is_symlink()]
        if len(matches) != 1 or matches[0].stat().st_size != receipt["archive_bytes"] or \
                digest(matches[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored Garage archive differs from snapshot evidence")
        os.chmod(matches[0], 0o444)
        made_net = made_volume = made_container = False
        try:
            run(["docker", "network", "create", "--internal", network], 30)
            made_net = True
            run(["docker", "volume", "create", volume], 30)
            made_volume = True
            run(["docker", "run", "--rm", "--network=none", "--read-only", "--user=0:0",
                 "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
                 "--memory=256m", "--cpus=0.5",
                 "--mount", "type=volume,src=" + volume + ",dst=/source",
                 "--mount", "type=bind,src=" + str(matches[0]) + ",dst=/run/archive/garage.tar,readonly",
                 helper, "tar", "-C", "/source", "-xf", "/run/archive/garage.tar"], 3600)
            run(["docker", "run", "-d", "--name", container, "--network", network,
                 "--read-only", "--user=0:0", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--pids-limit=128", "--memory=256m", "--cpus=0.5", "--tmpfs=/tmp:rw,nosuid,noexec,size=32m",
                 "--mount", "type=volume,src=" + volume + ",dst=/var/lib/garage",
                 "--mount", "type=bind,src=" + str(owned["config"]) + ",dst=/etc/garage.toml,readonly",
                 "--mount", "type=bind,src=" + str(owned["mounted"] / "access_key") +
                            ",dst=/run/secrets/access_key,readonly",
                 "--mount", "type=bind,src=" + str(owned["mounted"] / "secret_key") +
                            ",dst=/run/secrets/secret_key,readonly",
                 "-e", "GARAGE_DEFAULT_BUCKET=" + bucket_name(instance),
                 "--entrypoint", "/bin/sh", owned["image"], "-ec", LAUNCH], 120)
            made_container = True
            ip = ready(container, network, bucket_name(instance))
            check_object(instance, ip, owned["mounted"], probe)
        finally:
            if made_container:
                run(["docker", "rm", "-f", container], 60)
            if made_volume:
                run(["docker", "volume", "rm", volume], 30)
            if made_net:
                run(["docker", "network", "rm", network], 30)
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    receipt["semantic_probe"] = probe["key"]
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    return receipt


def backup_all(evidence, node, helper):
    containers = run(["docker", "ps", "-a", "--filter", "label=dial.storage",
                      "--format", "{{.Names}}"], 30).splitlines()
    volumes = run(["docker", "volume", "ls", "--filter", "label=dial.storage",
                   "--format", "{{.Name}}"], 30).splitlines()
    def discovered(values, prefix):
        result = set()
        for name in values:
            match = re.fullmatch(re.escape(prefix) + r"([a-f0-9-]{36})", name)
            if not match:
                raise RuntimeError("Unexpected labeled storage resource in inventory")
            result.add(identifier(match.group(1)))
        return result
    found = discovered(containers, "dial-s3-")
    if found != discovered(volumes, "dial-s3-data-"):
        raise RuntimeError("Storage container and volume inventory differ")
    if not found:
        return {"state": "FLEET_BACKUP_EMPTY", "instances": 0, "receipts": []}
    receipts = []
    for instance in sorted(found):
        receipt = backup(instance, evidence, node, helper)
        receipts.append(restore_drill(instance, receipt["snapshot_id"], evidence, node, helper))
    return {"state": "FLEET_BACKUP_VERIFIED", "instances": len(receipts),
            "receipts": [{"instance_id": x["instance_id"], "snapshot_id": x["snapshot_id"]} for x in receipts]}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    command = commands.add_parser("backup")
    command.add_argument("instance_id")
    command = commands.add_parser("verify")
    command.add_argument("instance_id")
    command.add_argument("snapshot_id")
    commands.add_parser("backup-all")
    args = parser.parse_args()
    evidence, node, helper = configuration()
    lock_fd = os.open(evidence / ".storage-backup.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "backup-all":
            receipt = backup_all(evidence, node, helper)
        elif args.action == "backup":
            receipt = backup(identifier(args.instance_id), evidence, node, helper)
        else:
            receipt = restore_drill(identifier(args.instance_id), args.snapshot_id, evidence, node, helper)
        print(json.dumps(receipt, sort_keys=True))
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    main()
