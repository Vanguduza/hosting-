#!/usr/bin/env python3
"""Quiesced Valkey AOF backup and isolated authenticated restore drill."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("NODE_AGENT_PACKAGE_DIR",
                                  str(Path(__file__).resolve().parents[1] / "agents/node-agent")))
from node_agent.core import IMAGE, Node, OperationError
from node_agent.postgres import identifier
from node_agent.valkey import names, probe, secret
from postgres_backup import digest, run, save, snapshot_id
from storage_backup import archive_volume


def protected_file(path):
    return (not path.is_symlink() and path.is_file() and path.stat().st_uid == os.geteuid()
            and not path.stat().st_mode & 0o077)


def configuration(offhost=True):
    required = ("RESTIC_REPOSITORY", "RESTIC_PASSWORD_FILE", "BACKUP_EVIDENCE_DIR", "BACKUP_TMP_DIR",
                "BACKUP_PROBE_DIR", "NODE_STATE_FILE", "NODE_SECRETS_DIR", "NODE_VALKEY_IMAGE",
                "NODE_STORAGE_SHELL_IMAGE")
    if missing := [key for key in required if not os.environ.get(key)]:
        raise RuntimeError("Missing Valkey backup configuration: " + ", ".join(missing))
    if offhost and not os.environ["RESTIC_REPOSITORY"].startswith(("s3:", "b2:", "rest:https://", "rclone:")):
        raise RuntimeError("Valkey backup requires an off-host encrypted Restic target")
    if not protected_file(Path(os.environ["RESTIC_PASSWORD_FILE"])):
        raise RuntimeError("Restic password must be an owner-only regular file")
    for key in ("BACKUP_EVIDENCE_DIR", "BACKUP_TMP_DIR", "BACKUP_PROBE_DIR", "NODE_SECRETS_DIR"):
        path = Path(os.environ[key])
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.geteuid() or \
                path.stat().st_mode & 0o077:
            raise RuntimeError(key + " must be an owner-only directory")
    image, helper = os.environ["NODE_VALKEY_IMAGE"], os.environ["NODE_STORAGE_SHELL_IMAGE"]
    if not IMAGE.fullmatch(image) or not image.rsplit("/", 1)[-1].startswith("valkey:9@") or \
            not IMAGE.fullmatch(helper) or not helper.rsplit("/", 1)[-1].startswith("busybox:1.37.0-musl@"):
        raise RuntimeError("Valkey backup requires immutable runtime and helper digests")
    return Path(os.environ["BACKUP_EVIDENCE_DIR"]), Node(os.environ["NODE_STATE_FILE"],
                                                          secrets_dir=os.environ["NODE_SECRETS_DIR"]), helper


def owned_instance(node, instance):
    instance = identifier(instance)
    container, network, volume = names(instance)
    item = json.loads(run(["docker", "inspect", container], 15))[0]
    labels = item["Config"]["Labels"]
    if labels.get("dial.valkey") != instance or not labels.get("dial.application"):
        raise RuntimeError("Valkey ownership label missing")
    identifier(labels["dial.application"])
    if item["Config"]["Image"] != os.environ["NODE_VALKEY_IMAGE"] or not item["State"]["Running"] or \
            item["HostConfig"].get("PortBindings") or not item["HostConfig"].get("ReadonlyRootfs") or \
            set(item["NetworkSettings"]["Networks"]) != {network}:
        raise RuntimeError("Valkey image or isolation mismatch")
    mounts = item["Mounts"]
    if not any(m.get("Name") == volume and m.get("Destination") == "/data" for m in mounts):
        raise RuntimeError("Valkey data volume mismatch")
    acl = node.secrets_dir / "vk-acl" / (instance + ".acl")
    password = secret(node, instance, 1)
    expected_acl = ("user default off\nuser dial_app on >" + password +
                    " ~* &* +@read +@write +@connection +@pubsub -@dangerous\n")
    if acl.is_symlink() or not acl.is_file() or acl.read_text() != expected_acl or \
            not any(m.get("Source") == str(acl) and m.get("Destination") == "/run/secrets/users.acl" and
                    m.get("RW") is False for m in mounts) or \
            {m["Destination"] for m in mounts} != {"/data", "/run/secrets/users.acl"}:
        raise RuntimeError("Valkey ACL mount differs from exact revision")
    net = json.loads(run(["docker", "network", "inspect", network], 15))[0]
    vol = json.loads(run(["docker", "volume", "inspect", volume], 15))[0]
    if not net["Internal"] or net["Labels"].get("dial.valkey") != instance or \
            vol["Labels"].get("dial.valkey") != instance:
        raise RuntimeError("Valkey network or volume ownership mismatch")
    ip = item["NetworkSettings"]["Networks"][network]["IPAddress"]
    probe(ip, password)
    return {"container": container, "network": network, "volume": volume,
            "image": item["Config"]["Image"], "acl": acl, "ip": ip,
            "password": password, "memory": item["HostConfig"]["Memory"]}


def semantic_probe(instance):
    path = Path(os.environ["BACKUP_PROBE_DIR"]) / (identifier(instance) + ".json")
    if not protected_file(path):
        raise RuntimeError("Valkey probe must be an owner-only regular file")
    contract = json.loads(path.read_text())
    if set(contract) != {"key", "sha256", "size_bytes"} or not isinstance(contract["key"], str) or \
            not re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", contract["key"]) or \
            not isinstance(contract["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", contract["sha256"]) or \
            type(contract["size_bytes"]) is not int or not 1 <= contract["size_bytes"] <= 1048576:
        raise RuntimeError("Invalid Valkey semantic probe")
    return contract


def exact(sock, size):
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            raise RuntimeError("Incomplete Valkey response")
        output.extend(chunk)
    return bytes(output)


def line(sock):
    result = bytearray()
    while len(result) < 32:
        result.extend(exact(sock, 1))
        if result.endswith(b"\r\n"):
            return bytes(result[:-2])
    raise RuntimeError("Oversized Valkey response header")


def command(sock, *parts):
    payload = b"*" + str(len(parts)).encode() + b"\r\n"
    for part in parts:
        value = part.encode()
        payload += b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"
    sock.sendall(payload)


def check_value(ip, password, contract):
    with socket.create_connection((ip, 6379), timeout=5) as sock:
        sock.settimeout(5)
        command(sock, "AUTH", "dial_app", password)
        if line(sock) != b"+OK":
            raise RuntimeError("Valkey restore authentication failed")
        command(sock, "GET", contract["key"])
        head = line(sock)
        if not head.startswith(b"$") or head[1:] != str(contract["size_bytes"]).encode():
            raise RuntimeError("Valkey semantic value missing or wrong length")
        content = exact(sock, contract["size_bytes"])
        if exact(sock, 2) != b"\r\n" or hashlib.sha256(content).hexdigest() != contract["sha256"]:
            raise RuntimeError("Valkey semantic value differs")


def ready(container, network, password):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        item = json.loads(run(["docker", "inspect", container], 15))[0]
        ip = item["NetworkSettings"]["Networks"].get(network, {}).get("IPAddress")
        if item["State"]["Running"] and ip:
            try:
                probe(ip, password)
                return ip
            except (OSError, OperationError):
                pass
        time.sleep(2)
    raise RuntimeError("Valkey did not return to private readiness")


def backup(instance, evidence, node, helper):
    instance = identifier(instance)
    owned = owned_instance(node, instance)
    contract = semantic_probe(instance)
    check_value(owned["ip"], owned["password"], contract)
    with tempfile.TemporaryDirectory(prefix="dial-valkey-backup-", dir=os.environ["BACKUP_TMP_DIR"]) as temp:
        archive = Path(temp) / "valkey.tar"
        try:
            run(["docker", "stop", "--time", "30", owned["container"]], 50)
            archive_volume(owned["volume"], helper, archive, read_non_root=True)
        finally:
            state = json.loads(run(["docker", "inspect", owned["container"]], 15))[0]["State"]
            if not state["Running"]:
                run(["docker", "start", owned["container"]], 60)
        check_value(ready(owned["container"], owned["network"], owned["password"]),
                    owned["password"], contract)
        snapshot = snapshot_id(run(["restic", "backup", "--json", "--tag", "dial-client-valkey",
                                    "--tag", "instance=" + instance, str(archive)]))
        receipt = {"instance_id": instance, "snapshot_id": snapshot, "archive_sha256": digest(archive),
                   "archive_bytes": archive.stat().st_size,
                   "probe_sha256": hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest(),
                   "created_at": datetime.now(timezone.utc).isoformat(), "state": "BACKUP_CREATED",
                   "restore_verified_at": None}
        save(evidence, receipt)
        return receipt


def restore_drill(instance, snapshot, evidence, node, helper):
    instance = identifier(instance)
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise ValueError("Full Restic snapshot ID required")
    path = evidence / (snapshot + ".json")
    if not protected_file(path):
        raise RuntimeError("Valkey backup evidence unavailable")
    receipt = json.loads(path.read_text())
    if receipt["snapshot_id"] != snapshot or receipt["instance_id"] != instance:
        raise RuntimeError("Valkey snapshot belongs to a different resource")
    contract = semantic_probe(instance)
    if hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest() != receipt["probe_sha256"]:
        raise RuntimeError("Valkey semantic probe changed since backup")
    owned = owned_instance(node, instance)
    marker = uuid.uuid4().hex
    container, network, volume = "dial-vk-drill-" + marker, "dial-vk-drill-net-" + marker, "dial-vk-drill-data-" + marker
    with tempfile.TemporaryDirectory(prefix="dial-valkey-restore-", dir=os.environ["BACKUP_TMP_DIR"]) as temp:
        run(["restic", "restore", snapshot, "--target", temp])
        files = [p for p in Path(temp).rglob("valkey.tar") if p.is_file() and not p.is_symlink()]
        if len(files) != 1 or files[0].stat().st_size != receipt["archive_bytes"] or \
                digest(files[0]) != receipt["archive_sha256"]:
            raise RuntimeError("Restored Valkey archive differs from evidence")
        os.chmod(files[0], 0o444)
        made_network = made_volume = made_container = False
        try:
            run(["docker", "network", "create", "--internal", network], 30)
            made_network = True
            run(["docker", "volume", "create", volume], 30)
            made_volume = True
            run(["docker", "run", "--rm", "--network=none", "--read-only", "--user=0:0",
                 "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE",
                 "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=256m",
                 "--mount", "type=volume,src=" + volume + ",dst=/source",
                 "--mount", "type=bind,src=" + str(files[0]) + ",dst=/run/archive/valkey.tar,readonly",
                 helper, "tar", "-C", "/source", "-xf", "/run/archive/valkey.tar"], 3600)
            run(["docker", "run", "-d", "--name", container, "--network", network,
                 "--read-only", "--security-opt=no-new-privileges", "--pids-limit=128",
                 "--memory=" + str(max(owned["memory"] // 1048576, 128)) + "m", "--cpus=0.5",
                 "--tmpfs=/tmp:rw,nosuid,noexec,size=32m",
                 "--mount", "type=volume,src=" + volume + ",dst=/data",
                 "--mount", "type=bind,src=" + str(owned["acl"]) + ",dst=/run/secrets/users.acl,readonly",
                 owned["image"], "valkey-server", "--aclfile", "/run/secrets/users.acl",
                 "--appendonly", "yes", "--dir", "/data", "--save", "",
                 "--maxmemory", str(max(owned["memory"] // 1048576, 128) * 7 // 10) + "mb",
                 "--maxmemory-policy", "allkeys-lru"], 120)
            made_container = True
            check_value(ready(container, network, owned["password"]), owned["password"], contract)
        finally:
            if made_container:
                run(["docker", "rm", "-f", container], 60)
            if made_volume:
                run(["docker", "volume", "rm", volume], 30)
            if made_network:
                run(["docker", "network", "rm", network], 30)
    receipt["state"] = "RESTORE_VERIFIED"
    receipt["restore_verified_at"] = datetime.now(timezone.utc).isoformat()
    receipt["semantic_probe"] = contract["key"]
    temp_receipt = path.with_suffix(".tmp")
    fd = os.open(temp_receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(receipt, file, sort_keys=True, indent=2)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temp_receipt, path)
    return receipt


def backup_all(evidence, node, helper):
    containers = run(["docker", "ps", "-a", "--filter", "label=dial.valkey",
                      "--format", "{{.Names}}"], 30).splitlines()
    volumes = run(["docker", "volume", "ls", "--filter", "label=dial.valkey",
                   "--format", "{{.Name}}"], 30).splitlines()
    def inventory(items, prefix):
        found = set()
        for item in items:
            match = re.fullmatch(re.escape(prefix) + r"([a-f0-9-]{36})", item)
            if not match:
                raise RuntimeError("Unexpected labeled Valkey resource")
            found.add(identifier(match.group(1)))
        return found
    found = inventory(containers, "dial-vk-")
    if found != inventory(volumes, "dial-vk-data-"):
        raise RuntimeError("Valkey container and volume inventory differ")
    receipts = []
    for instance in sorted(found):
        receipt = backup(instance, evidence, node, helper)
        receipts.append(restore_drill(instance, receipt["snapshot_id"], evidence, node, helper))
    return {"state": "FLEET_BACKUP_VERIFIED" if receipts else "FLEET_BACKUP_EMPTY",
            "instances": len(receipts), "receipts": [{"instance_id": item["instance_id"],
                                                     "snapshot_id": item["snapshot_id"]} for item in receipts]}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("backup-all")
    commands.add_parser("backup").add_argument("instance_id")
    verify = commands.add_parser("verify")
    verify.add_argument("instance_id")
    verify.add_argument("snapshot_id")
    args = parser.parse_args()
    evidence, node, helper = configuration()
    lock_fd = os.open(evidence / ".valkey-backup.lock", os.O_CREAT | os.O_RDWR, 0o600)
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
