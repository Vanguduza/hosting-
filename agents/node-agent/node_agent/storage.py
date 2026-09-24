"""Private, persistent single-node Garage bucket bound to one application."""
import http.client
import hashlib
import json
import os
import re
import time
import uuid

from .core import IMAGE, OperationError
from .postgres import identifier, inspect


def names(instance):
    return "dial-s3-" + instance, "dial-s3-net-" + instance, "dial-s3-data-" + instance


def bucket_name(instance):
    return "dial-" + identifier(instance)


def credential_files(node, instance, version):
    root = node.secrets_dir / identifier(instance) / str(version)
    files = {name: root / name for name in ("access_key", "secret_key", "rpc_secret", "admin_token")}
    if any(not item.is_file() or item.is_symlink() or item.stat().st_mode & 0o077 for item in files.values()):
        raise OperationError("Exact storage credential revision unavailable")
    values = {name: item.read_text() for name, item in files.items()}
    if not re.fullmatch(r"GK[a-f0-9]{32}", values["access_key"]) or \
            any(not re.fullmatch(r"[a-f0-9]{64}", values[name])
                for name in ("secret_key", "rpc_secret", "admin_token")):
        raise OperationError("Invalid storage credential revision")
    return files, values


def app_credentials(node, instance, version):
    _, values = credential_files(node, instance, version)
    from .secrets import install
    directory = node.secrets_dir / "s3-app-mount"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise OperationError("Storage application credential directory unsafe")
    resource = uuid.uuid5(uuid.NAMESPACE_URL, "s3-app-mount/" + instance)
    mounted = install(directory, resource, version,
                      {key: values[key] for key in ("access_key", "secret_key")})
    for key in ("access_key", "secret_key"):
        os.chmod(mounted / key, 0o444)
    return mounted


def _config(node, instance, values):
    directory = node.secrets_dir / "s3-config"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise OperationError("Storage configuration directory unsafe")
    path = directory / (instance + ".toml")
    if path.is_symlink():
        raise OperationError("Storage configuration path unsafe")
    content = ('metadata_dir = "/var/lib/garage/meta"\n'
               'data_dir = "/var/lib/garage/data"\n'
               'db_engine = "sqlite"\n'
               'replication_factor = 1\n'
               'rpc_bind_addr = "0.0.0.0:3901"\n'
               'rpc_public_addr = "127.0.0.1:3901"\n'
               'rpc_secret = "' + values["rpc_secret"] + '"\n'
               '[s3_api]\ns3_region = "garage"\napi_bind_addr = "0.0.0.0:3900"\n'
               '[admin]\napi_bind_addr = "127.0.0.1:3903"\n'
               'admin_token = "' + values["admin_token"] + '"\n')
    if path.exists():
        if path.stat().st_mode & 0o077 or path.read_text() != content:
            raise OperationError("Storage configuration differs from exact secret revision")
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
    return path


def _private_probe(ip, bucket):
    connection = http.client.HTTPConnection(ip, 3900, timeout=3)
    try:
        connection.request("GET", "/" + bucket, headers={"Host": "localhost"})
        response = connection.getresponse()
        response.read(1024)
        # A live authenticated gateway rejects unsigned reads.
        return response.status == 403
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def launcher_image(node, image):
    """Add only a static shell to Garage's scratch image; retain both source digests."""
    helper = os.environ.get("NODE_STORAGE_SHELL_IMAGE", "")
    if not IMAGE.fullmatch(helper) or not helper.rsplit("/", 1)[-1].startswith("busybox:1.37.0-musl@"):
        raise OperationError("BusyBox musl 1.37.0 helper must be configured by immutable digest")
    directory = node.secrets_dir / "s3-launcher"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise OperationError("Storage launcher directory unsafe")
    dockerfile = directory / "Dockerfile"
    source = "FROM " + helper + " AS helper\nFROM " + image + "\nCOPY --from=helper /bin/busybox /bin/sh\n"
    if dockerfile.exists():
        if dockerfile.is_symlink() or dockerfile.read_text() != source:
            raise OperationError("Storage launcher image source differs")
    else:
        fd = os.open(dockerfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(source)
            file.flush()
            os.fsync(file.fileno())
    tag = "dial-s3-launcher:" + hashlib.sha256(source.encode()).hexdigest()
    node.runner(["docker", "pull", image], 300)
    node.runner(["docker", "pull", helper], 300)
    node.runner(["docker", "build", "--pull=false", "-t", tag, "-f", str(dockerfile), str(directory)], 300)
    return tag


def provision(node, data):
    if set(data) != {"instance_id", "application_id", "memory_mb", "cpu_milli", "secret_version"}:
        raise ValueError("Invalid storage operation")
    instance, app = identifier(data["instance_id"]), identifier(data["application_id"])
    memory, cpu, version = data["memory_mb"], data["cpu_milli"], data["secret_version"]
    if (type(memory) is not int or not 256 <= memory <= 16384 or
            type(cpu) is not int or not 100 <= cpu <= 16000 or
            type(version) is not int or version != 1):
        raise ValueError("Invalid storage allocation or credential revision")
    image = os.environ.get("NODE_GARAGE_IMAGE", "")
    if not IMAGE.fullmatch(image) or not image.rsplit("/", 1)[-1].startswith("garage:v2.3.0@"):
        raise OperationError("Garage 2.3.0 image must be configured by immutable digest")
    container, network, volume = names(instance)
    bucket = bucket_name(instance)
    with node.lock, node.file_lock():
        files, values = credential_files(node, instance, version)
        config = _config(node, instance, values)
        launcher = launcher_image(node, image)
        current = inspect(node, container)
        if current:
            labels = current.get("Config", {}).get("Labels", {})
            if labels.get("dial.storage") != instance or labels.get("dial.application") != app or \
                    current.get("Config", {}).get("Image") != launcher or \
                    network not in current.get("NetworkSettings", {}).get("Networks", {}) or \
                    current.get("HostConfig", {}).get("PortBindings") or \
                    not any(m.get("Name") == volume and m.get("Destination") == "/var/lib/garage"
                            for m in current.get("Mounts", [])):
                raise OperationError("Existing storage ownership, image or isolation mismatch")
            network_info = json.loads(node.runner(["docker", "network", "inspect", network], 15))[0]
            volume_info = inspect(node, volume)
            if (network_info.get("Labels", {}).get("dial.storage") != instance or
                    network_info.get("Internal") is not True or not volume_info or
                    volume_info.get("Labels", {}).get("dial.storage") != instance):
                raise OperationError("Existing storage network or volume ownership mismatch")
            if not current.get("State", {}).get("Running"):
                node.runner(["docker", "start", container], 60)
        else:
            volume_info = inspect(node, volume)
            if volume_info and volume_info.get("Labels", {}).get("dial.storage") != instance:
                raise OperationError("Storage volume ownership mismatch")
            try:
                network_info = json.loads(node.runner(["docker", "network", "inspect", network], 15))[0]
            except OperationError:
                network_info = None
            except (ValueError, IndexError, TypeError) as exc:
                raise OperationError("Storage network inspection invalid") from exc
            if network_info and (network_info.get("Labels", {}).get("dial.storage") != instance or
                                 network_info.get("Internal") is not True):
                raise OperationError("Storage network ownership mismatch")
            if not network_info:
                node.runner(["docker", "network", "create", "--internal", "--label", "dial.storage=" + instance,
                             network], 30)
            if not volume_info:
                node.runner(["docker", "volume", "create", "--label", "dial.storage=" + instance, volume], 30)
            # Keys enter through read-only files inside the container. Neither
            # the Docker command nor inspectable Config.Env contains their values.
            launch = ('IFS= read -r GARAGE_DEFAULT_ACCESS_KEY < /run/secrets/access_key || '
                      '[ -n "$GARAGE_DEFAULT_ACCESS_KEY" ]; '
                      'IFS= read -r GARAGE_DEFAULT_SECRET_KEY < /run/secrets/secret_key || '
                      '[ -n "$GARAGE_DEFAULT_SECRET_KEY" ]; '
                      'export GARAGE_DEFAULT_ACCESS_KEY GARAGE_DEFAULT_SECRET_KEY; '
                      'exec /garage server --single-node --default-bucket')
            node.runner(["docker", "run", "-d", "--name", container,
                         "--label", "dial.storage=" + instance, "--label", "dial.application=" + app,
                         "--network", network, "--restart=unless-stopped", "--read-only",
                         "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
                         "--memory=" + str(memory) + "m", "--cpus=" + str(cpu / 1000),
                         "--tmpfs=/tmp:rw,nosuid,noexec,size=32m",
                         "--mount", "type=volume,src=" + volume + ",dst=/var/lib/garage",
                         "--mount", "type=bind,src=" + str(config) + ",dst=/etc/garage.toml,readonly",
                         "--mount", "type=bind,src=" + str(files["access_key"]) +
                                    ",dst=/run/secrets/access_key,readonly",
                         "--mount", "type=bind,src=" + str(files["secret_key"]) +
                                    ",dst=/run/secrets/secret_key,readonly",
                         "-e", "GARAGE_DEFAULT_BUCKET=" + bucket,
                         "--entrypoint", "/bin/sh", launcher, "-ec", launch], 120)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            current = inspect(node, container)
            if current and current.get("State", {}).get("Running"):
                ip = current.get("NetworkSettings", {}).get("Networks", {}).get(network, {}).get("IPAddress")
                if ip and _private_probe(ip, bucket):
                    try:
                        node.runner(["docker", "exec", container, "/garage", "bucket", "info", bucket], 15)
                        return {"instance_id": instance, "state": "READY_PRIVATE", "host": container,
                                "port": 3900, "bucket": bucket, "region": "garage", "secret_version": version}
                    except OperationError:
                        pass
            time.sleep(2)
        raise OperationError("Storage private readiness failed; volume preserved")


def attach(node, instance_id, application_id, release_id):
    instance, app, release = map(identifier, (instance_id, application_id, release_id))
    container, network, _ = names(instance)
    storage, workload = inspect(node, container), inspect(node, node.container(release))
    if (not storage or not workload or not storage.get("State", {}).get("Running") or
            network not in storage.get("NetworkSettings", {}).get("Networks", {}) or
            storage.get("Config", {}).get("Labels", {}).get("dial.application") != app or
            workload.get("Config", {}).get("Labels", {}).get("dial.application") != app or
            workload.get("Config", {}).get("Labels", {}).get("dial.release") != release):
        raise OperationError("Storage attachment ownership mismatch")
    network_info = json.loads(node.runner(["docker", "network", "inspect", network], 15))[0]
    if (network_info.get("Labels", {}).get("dial.storage") != instance or
            network_info.get("Internal") is not True):
        raise OperationError("Storage attachment network isolation mismatch")
    if network not in workload.get("NetworkSettings", {}).get("Networks", {}):
        node.runner(["docker", "network", "connect", network, node.container(release)], 30)
    return {"instance_id": instance, "release_id": release, "state": "ATTACHED"}
