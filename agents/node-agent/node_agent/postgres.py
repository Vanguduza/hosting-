"""Dedicated PostgreSQL Docker resource; never publishes a host port."""
import json
import os
import re
import time
import uuid
from pathlib import Path

from .core import IMAGE, OperationError


def identifier(value):
    result = str(uuid.UUID(value))
    if result != value:
        raise ValueError("Noncanonical resource identifier")
    return result


def names(instance):
    return "dial-pg-" + instance, "dial-pg-net-" + instance, "dial-pg-data-" + instance


def inspect(node, name):
    try:
        return json.loads(node.runner(["docker", "inspect", name], 15))[0]
    except (OperationError, IndexError, ValueError, KeyError):
        return None


def application_password_mount(node, instance_id, version):
    instance = identifier(instance_id)
    origin = node.secrets_dir / instance / str(version) / "app_password"
    if not origin.is_file() or origin.is_symlink() or origin.stat().st_mode & 0o077:
        raise OperationError("PostgreSQL application credential unavailable")
    mount_dir = node.secrets_dir / "app-mount"
    mount_dir.mkdir(mode=0o700, exist_ok=True)
    if mount_dir.is_symlink() or mount_dir.stat().st_mode & 0o077:
        raise OperationError("PostgreSQL mount directory unsafe")
    # Atomic, immutable copy. The host parent is 0700; inside the workload,
    # an unprivileged UID needs read access to its own bind-mounted credential.
    from .secrets import install
    mount_resource = uuid.uuid5(uuid.NAMESPACE_URL, "pg-app-mount/" + instance)
    revision = install(mount_dir, mount_resource, version, {"password": origin.read_text()})
    target = revision / "password"
    os.chmod(target, 0o444)
    return target


def provision(node, data):
    if set(data) != {"instance_id", "application_id", "memory_mb", "cpu_milli", "secret_version"}:
        raise ValueError("Invalid PostgreSQL operation")
    instance = identifier(data["instance_id"])
    application = identifier(data["application_id"])
    if (type(data["memory_mb"]) is not int or not 256 <= data["memory_mb"] <= 32768 or
            type(data["cpu_milli"]) is not int or not 100 <= data["cpu_milli"] <= 32000 or
            type(data["secret_version"]) is not int or data["secret_version"] < 1):
        raise ValueError("Invalid PostgreSQL resource allocation")
    image = os.environ.get("NODE_POSTGRES_IMAGE", "")
    if not IMAGE.fullmatch(image) or not image.rsplit("/", 1)[-1].startswith("postgres:"):
        raise OperationError("PostgreSQL image must be digest pinned and configured")
    container, network, volume = names(instance)
    secret_dir = node.secrets_dir / instance / str(data["secret_version"])
    with node.lock, node.file_lock():
        password = secret_dir / "postgres_password"
        app_password = secret_dir / "app_password"
        if (not password.is_file() or password.is_symlink() or not app_password.is_file() or
                app_password.is_symlink() or password.stat().st_mode & 0o077 or app_password.stat().st_mode & 0o077):
            raise OperationError("Exact PostgreSQL secret revision unavailable")
        stored = inspect(node, container)
        if stored:
            labels = stored.get("Config", {}).get("Labels", {})
            if labels.get("dial.postgres") != instance or labels.get("dial.application") != application:
                raise OperationError("Existing PostgreSQL container has different ownership")
            if stored.get("Config", {}).get("Image") != image:
                raise OperationError("PostgreSQL image differs from existing persistent instance")
            if not stored.get("State", {}).get("Running"):
                node.runner(["docker", "start", container], 60)
        else:
            volume_info = inspect(node, volume)
            if volume_info and volume_info.get("Labels", {}).get("dial.postgres") != instance:
                raise OperationError("Existing PostgreSQL volume ownership mismatch")
            try:
                network_info = json.loads(node.runner(["docker", "network", "inspect", network], 15))[0]
            except (OperationError, ValueError, IndexError):
                network_info = None
            if network_info and (network_info.get("Labels", {}).get("dial.postgres") != instance or
                                 not network_info.get("Internal")):
                raise OperationError("Existing PostgreSQL network ownership mismatch")
            # Keep the init script outside the immutable OpenBao revision;
            # exact-version secret replay must never see a generated extra file.
            init_dir = node.secrets_dir / "pg-init"
            init_dir.mkdir(mode=0o700, exist_ok=True)
            if init_dir.is_symlink() or init_dir.stat().st_mode & 0o077:
                raise OperationError("PostgreSQL initialization directory unsafe")
            sql = init_dir / (instance + "-" + str(data["secret_version"]) + ".sql")
            raw_password = app_password.read_text()
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", raw_password):
                raise OperationError("Invalid generated PostgreSQL credential")
            sql.write_text("CREATE ROLE dial_app LOGIN PASSWORD '" + raw_password + "';\n"
                           "GRANT CONNECT ON DATABASE appdb TO dial_app;\n"
                           "\\connect appdb\nGRANT USAGE, CREATE ON SCHEMA public TO dial_app;\n")
            os.chmod(sql, 0o644)  # Container's postgres UID reads bind-mounted init script.
            node.runner(["docker", "pull", image], 300)
            if not network_info:
                node.runner(["docker", "network", "create", "--internal", "--label", "dial.postgres=" + instance,
                             network], 30)
            if not volume_info:
                node.runner(["docker", "volume", "create", "--label", "dial.postgres=" + instance, volume], 30)
            node.runner(["docker", "run", "-d", "--name", container,
                         "--label", "dial.postgres=" + instance, "--label", "dial.application=" + application,
                         "--network", network, "--restart=unless-stopped",
                         "--read-only", "--security-opt=no-new-privileges",
                         "--pids-limit=256", "--memory=" + str(data["memory_mb"]) + "m",
                         "--cpus=" + str(data["cpu_milli"] / 1000),
                         "--tmpfs=/tmp:rw,nosuid,noexec,size=64m",
                         "--tmpfs=/var/run/postgresql:rw,nosuid,noexec,size=16m",
                         "--mount", "type=volume,src=" + volume + ",dst=/var/lib/postgresql/data",
                         "--mount", "type=bind,src=" + str(password) + ",dst=/run/secrets/postgres_password,readonly",
                         "--mount", "type=bind,src=" + str(sql) + ",dst=/docker-entrypoint-initdb.d/init.sql,readonly",
                         "-e", "PGDATA=/var/lib/postgresql/data/pgdata",
                         "-e", "POSTGRES_DB=appdb", "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password",
                         "-e", "POSTGRES_INITDB_ARGS=--data-checksums --auth-host=scram-sha-256",
                         image], 120)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            stored = inspect(node, container)
            if stored and stored.get("State", {}).get("Running"):
                try:
                    # TCP credentials are separately checked by the disposable
                    # runtime test. Readiness here proves startup + role/schema.
                    result = node.runner(["docker", "exec", "-u", "postgres", container,
                                          "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "appdb", "-tAc",
                                          "SELECT 1 FROM pg_roles WHERE rolname='dial_app' AND NOT rolsuper"], 15)
                    if result.strip() == "1":
                        return {"instance_id": instance, "state": "READY_PRIVATE", "host": container,
                                "database": "appdb", "user": "dial_app", "secret_version": data["secret_version"]}
                except OperationError:
                    pass
            time.sleep(2)
        raise OperationError("PostgreSQL private startup or role check failed; volume preserved")


def attach(node, instance_id, application_id, release_id):
    instance, app, release = map(identifier, (instance_id, application_id, release_id))
    container, network, _ = names(instance)
    target = node.container(release)
    db = inspect(node, container)
    workload = inspect(node, target)
    if not db or not workload or not db.get("State", {}).get("Running") or \
            network not in db.get("NetworkSettings", {}).get("Networks", {}) or \
            db.get("Config", {}).get("Labels", {}).get("dial.application") != app or \
            workload.get("Config", {}).get("Labels", {}).get("dial.application") != app or \
            workload.get("Config", {}).get("Labels", {}).get("dial.release") != release:
        raise OperationError("PostgreSQL attachment ownership mismatch")
    if network not in workload.get("NetworkSettings", {}).get("Networks", {}):
        node.runner(["docker", "network", "connect", network, target], 30)
    return {"instance_id": instance, "release_id": release, "state": "ATTACHED"}
