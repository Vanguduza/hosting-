"""One persistent, authenticated Valkey on a private per-resource Docker bridge."""
import json
import os
import re
import socket
import time
import uuid

from .core import IMAGE, OperationError
from .postgres import identifier, inspect


def names(instance):
    return "dial-vk-" + instance, "dial-vk-net-" + instance, "dial-vk-data-" + instance


def secret(node, instance, version):
    path = node.secrets_dir / identifier(instance) / str(version) / "app_password"
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise OperationError("Exact Valkey credential revision unavailable")
    password = path.read_text()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password):
        raise OperationError("Invalid Valkey credential")
    return password


def password_mount(node, instance, version):
    password = secret(node, instance, version)
    from .secrets import install
    directory = node.secrets_dir / "vk-app-mount"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise OperationError("Valkey application mount directory unsafe")
    resource = uuid.uuid5(uuid.NAMESPACE_URL, "vk-app-mount/" + instance)
    path = install(directory, resource, version, {"password": password}) / "password"
    os.chmod(path, 0o444)
    return path


def _response(sock):
    data = sock.recv(512)
    if not data or data[0:1] == b"-":
        raise OperationError("Valkey authentication or probe rejected")
    return data


def probe(ip, password):
    # RESP wire messages keep credentials out of the process list and Docker API.
    with socket.create_connection((ip, 6379), timeout=3) as sock:
        sock.settimeout(3)
        raw = password.encode("ascii")
        sock.sendall(b"*3\r\n$4\r\nAUTH\r\n$8\r\ndial_app\r\n$" +
                     str(len(raw)).encode() + b"\r\n" + raw + b"\r\n")
        if _response(sock) != b"+OK\r\n":
            raise OperationError("Valkey authentication receipt invalid")
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        if _response(sock) != b"+PONG\r\n":
            raise OperationError("Valkey readiness receipt invalid")


def provision(node, data):
    if set(data) != {"instance_id", "application_id", "memory_mb", "cpu_milli", "secret_version"}:
        raise ValueError("Invalid Valkey operation")
    instance, app = identifier(data["instance_id"]), identifier(data["application_id"])
    memory, cpu, version = data["memory_mb"], data["cpu_milli"], data["secret_version"]
    if (type(memory) is not int or not 128 <= memory <= 16384 or
            type(cpu) is not int or not 100 <= cpu <= 16000 or
            type(version) is not int or version != 1):
        raise ValueError("Invalid Valkey allocation or credential revision")
    image = os.environ.get("NODE_VALKEY_IMAGE", "")
    if not IMAGE.fullmatch(image) or not image.rsplit("/", 1)[-1].startswith("valkey:9"):
        raise OperationError("Valkey 9 image must be configured by immutable digest")
    container, network, volume = names(instance)
    with node.lock, node.file_lock():
        password = secret(node, instance, version)
        existing = inspect(node, container)
        if existing:
            labels = existing.get("Config", {}).get("Labels", {})
            if labels.get("dial.valkey") != instance or labels.get("dial.application") != app or \
                    existing.get("Config", {}).get("Image") != image:
                raise OperationError("Existing Valkey ownership or image mismatch")
            if not existing.get("State", {}).get("Running"):
                node.runner(["docker", "start", container], 60)
        else:
            volume_info = inspect(node, volume)
            if volume_info and volume_info.get("Labels", {}).get("dial.valkey") != instance:
                raise OperationError("Valkey volume ownership mismatch")
            try:
                network_info = json.loads(node.runner(["docker", "network", "inspect", network], 15))[0]
            except OperationError:
                network_info = None
            except (ValueError, IndexError, TypeError) as exc:
                raise OperationError("Valkey network inspection invalid") from exc
            if network_info and (network_info.get("Labels", {}).get("dial.valkey") != instance or
                                 network_info.get("Internal") is not True):
                raise OperationError("Valkey network ownership mismatch")
            acl_dir = node.secrets_dir / "vk-acl"
            acl_dir.mkdir(mode=0o700, exist_ok=True)
            if acl_dir.is_symlink() or acl_dir.stat().st_mode & 0o077:
                raise OperationError("Valkey ACL directory unsafe")
            acl = acl_dir / (instance + ".acl")
            # ACL file lives under a root-only host directory. It is read-only
            # inside the container, where Valkey's unprivileged UID must read it.
            if acl.is_symlink():
                raise OperationError("Valkey ACL path unsafe")
            expected = "user default off\nuser dial_app on >" + password + \
                       " ~* &* +@read +@write +@connection +@pubsub -@dangerous\n"
            if acl.exists() and acl.read_text() != expected:
                raise OperationError("Valkey ACL differs from immutable secret revision")
            if not acl.exists():
                fd = os.open(acl, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with os.fdopen(fd, "w") as file:
                    file.write(expected)
                    file.flush()
                    os.fsync(file.fileno())
            node.runner(["docker", "pull", image], 300)
            if not network_info:
                node.runner(["docker", "network", "create", "--internal", "--label", "dial.valkey=" + instance,
                             network], 30)
            if not volume_info:
                node.runner(["docker", "volume", "create", "--label", "dial.valkey=" + instance, volume], 30)
            node.runner(["docker", "run", "-d", "--name", container,
                         "--label", "dial.valkey=" + instance, "--label", "dial.application=" + app,
                         "--network", network, "--restart=unless-stopped", "--read-only",
                         "--security-opt=no-new-privileges", "--pids-limit=128",
                         "--memory=" + str(memory) + "m", "--cpus=" + str(cpu / 1000),
                         "--tmpfs=/tmp:rw,nosuid,noexec,size=32m",
                         "--mount", "type=volume,src=" + volume + ",dst=/data",
                         "--mount", "type=bind,src=" + str(acl) + ",dst=/run/secrets/users.acl,readonly",
                         image, "valkey-server", "--aclfile", "/run/secrets/users.acl",
                         "--appendonly", "yes", "--dir", "/data", "--save", "",
                         "--maxmemory", str(memory * 7 // 10) + "mb", "--maxmemory-policy", "allkeys-lru"], 120)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            item = inspect(node, container)
            if item and item.get("State", {}).get("Running"):
                ip = item.get("NetworkSettings", {}).get("Networks", {}).get(network, {}).get("IPAddress")
                if ip:
                    try:
                        probe(ip, password)
                        return {"instance_id": instance, "state": "READY_PRIVATE", "host": container,
                                "port": 6379, "user": "dial_app", "secret_version": version}
                    except (OSError, OperationError):
                        pass
            time.sleep(2)
        raise OperationError("Valkey private readiness failed; volume preserved")


def attach(node, instance_id, application_id, release_id):
    instance, app, release = map(identifier, (instance_id, application_id, release_id))
    container, network, _ = names(instance)
    db, workload = inspect(node, container), inspect(node, node.container(release))
    if (not db or not workload or not db.get("State", {}).get("Running") or
            network not in db.get("NetworkSettings", {}).get("Networks", {}) or
            db.get("Config", {}).get("Labels", {}).get("dial.application") != app or
            workload.get("Config", {}).get("Labels", {}).get("dial.application") != app or
            workload.get("Config", {}).get("Labels", {}).get("dial.release") != release):
        raise OperationError("Valkey attachment ownership mismatch")
    if network not in workload.get("NetworkSettings", {}).get("Networks", {}):
        node.runner(["docker", "network", "connect", network, node.container(release)], 30)
    return {"instance_id": instance, "release_id": release, "state": "ATTACHED"}
