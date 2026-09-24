"""Typed Docker operations; only this process receives access to its node daemon."""
import hashlib
import http.client
import ipaddress
import json
import os
import fcntl
import re
import sqlite3
import subprocess
import threading
import time
import uuid
import tempfile
from contextlib import contextmanager
from pathlib import Path

IMAGE = re.compile(r"^[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}$")
PATH = re.compile(r"^/[A-Za-z0-9/_-]{0,127}$")


class OperationError(Exception):
    pass


def command(args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise OperationError("Docker command failed: " + args[1] if len(args) > 1 else "Docker command failed")
    return result.stdout


def valid(request):
    required = {"operation_id", "application_id", "release_id", "image", "port", "health_path", "memory_mb", "cpu_milli"}
    optional = set(request) - required
    if not required <= set(request) or optional not in (
        set(), {"postgres_id", "postgres_version"}, {"valkey_id", "valkey_version"},
        {"postgres_id", "postgres_version", "valkey_id", "valkey_version"}):
        raise ValueError("Unexpected or missing deployment properties")
    for key in ("operation_id", "application_id", "release_id"):
        if not isinstance(request[key], str) or str(uuid.UUID(request[key])) != request[key]:
            raise ValueError("Invalid UUID: " + key)
    if not isinstance(request["image"], str) or not IMAGE.fullmatch(request["image"]):
        raise ValueError("An immutable image digest is required")
    if type(request["port"]) is not int or not 1 <= request["port"] <= 65535:
        raise ValueError("Invalid port")
    if not isinstance(request["health_path"], str) or not PATH.fullmatch(request["health_path"]):
        raise ValueError("Invalid health path")
    if type(request["memory_mb"]) is not int or not 64 <= request["memory_mb"] <= 32768:
        raise ValueError("Invalid memory")
    if type(request["cpu_milli"]) is not int or not 50 <= request["cpu_milli"] <= 32000:
        raise ValueError("Invalid CPU allocation")
    if "postgres_id" in request:
        from .postgres import identifier
        identifier(request["postgres_id"])
        if type(request["postgres_version"]) is not int or request["postgres_version"] < 1:
            raise ValueError("Invalid PostgreSQL secret version")
    if "valkey_id" in request:
        from .postgres import identifier
        identifier(request["valkey_id"])
        if type(request["valkey_version"]) is not int or request["valkey_version"] != 1:
            raise ValueError("Invalid Valkey secret version")
    return request


def probe(ip, port, path, timeout=3):
    ipaddress.ip_address(ip)
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": "localhost", "User-Agent": "DialHostingHealth/1"})
        response = conn.getresponse()
        response.read(1024)
        return 200 <= response.status < 300
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


class Node:
    def __init__(self, state_file, runner=command, health_probe=probe, network="dial-runtime", routes_dir=None, secrets_dir=None):
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.runner, self.health_probe, self.network = runner, health_probe, network
        self.routes_dir = Path(routes_dir) if routes_dir else self.state_file.parent / "routes"
        self.routes_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.routes_dir, 0o700)
        self.secrets_dir = Path(secrets_dir) if secrets_dir else self.state_file.parent / "secrets"
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.secrets_dir, 0o700)
        self.lock = threading.RLock()
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, input_hash TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS active (application_id TEXT PRIMARY KEY, release_id TEXT NOT NULL, container TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS routes (application_id TEXT PRIMARY KEY, release_id TEXT NOT NULL, hostname TEXT NOT NULL)")
        os.chmod(self.state_file, 0o600)

    def db(self):
        db = sqlite3.connect(self.state_file, timeout=20)
        db.row_factory = sqlite3.Row
        return db

    @contextmanager
    def file_lock(self):
        fd = os.open(str(self.state_file) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def container(release_id):
        return "dial-" + release_id

    @staticmethod
    def application_network(application_id):
        return "dial-app-net-" + application_id

    def inspect(self, container):
        try:
            raw = self.runner(["docker", "inspect", container], 15)
            obj = json.loads(raw)[0]
            running = obj["State"]["Running"]
            networks = obj["NetworkSettings"]["Networks"]
            labels = obj.get("Config", {}).get("Labels", {})
            network = (self.application_network(labels["dial.application"])
                       if labels.get("dial.release") else self.network)
            ip = networks[network]["IPAddress"]
            return running, ip
        except (OperationError, ValueError, KeyError, IndexError, TypeError):
            return False, None

    def network_ready(self, application_id):
        network = self.application_network(application_id)
        try:
            existing = json.loads(self.runner(["docker", "network", "inspect", network], 15))[0]
        except OperationError:
            self.runner(["docker", "network", "create", "--driver", "bridge",
                         "--label", "dial.application=" + application_id, network], 30)
            return
        except (ValueError, IndexError, TypeError):
            raise OperationError("Invalid application network inspection") from None
        if existing.get("Labels", {}).get("dial.application") != application_id or \
                existing.get("Driver") != "bridge":
            raise OperationError("Application network ownership mismatch")

    def deploy(self, data):
        request = valid(data)
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        operation_id = request["operation_id"]
        app_id, release_id = request["application_id"], request["release_id"]
        container = self.container(release_id)
        with self.lock, self.file_lock():
            with self.db() as db:
                existing = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
                if existing and existing["input_hash"] != digest:
                    raise OperationError("Idempotency key used for a different command")
                active = db.execute("SELECT * FROM active WHERE application_id=?", (app_id,)).fetchone()
                if existing and existing["state"] == "COMPLETE":
                    if not active or active["release_id"] != release_id:
                        raise OperationError("Completed operation has been superseded")
                    running, ip = self.inspect(container)
                    if running and ip and self.health_probe(ip, request["port"], request["health_path"]):
                        return json.loads(existing["receipt"])
                    # Stored success is not live evidence. Reconcile the same
                    # digest-pinned release before returning a new receipt.
                if active and active["release_id"] == release_id:
                    running, ip = self.inspect(container)
                    if running and ip and self.health_probe(ip, request["port"], request["health_path"]):
                        receipt = {"operation_id": operation_id, "release_id": release_id, "state": "HEALTHY_PRIVATE", "container": container}
                        db.execute("INSERT INTO operations(id,input_hash,state,receipt) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,receipt=excluded.receipt",
                                   (operation_id, digest, "COMPLETE", json.dumps(receipt)))
                        return receipt
                db.execute("INSERT INTO operations(id,input_hash,state) VALUES (?,?,'RUNNING') ON CONFLICT(id) DO UPDATE SET state='RUNNING'",
                           (operation_id, digest))
            try:
                self.network_ready(app_id)
                running, ip = self.inspect(container)
                if not running:
                    # A crash can leave a stopped container under the same release name.
                    if self.exists(container):
                        self.runner(["docker", "rm", "-f", container], 30)
                    self.runner(["docker", "pull", request["image"]], 300)
                    pg_flags = []
                    if "postgres_id" in request:
                        from .postgres import application_password_mount, names
                        secret_file = application_password_mount(self, request["postgres_id"],
                                                                 request["postgres_version"])
                        pg_container = names(request["postgres_id"])[0]
                        pg_flags = ["--mount", "type=bind,src=" + str(secret_file) +
                                    ",dst=/run/secrets/postgres_password,readonly",
                                    "-e", "DATABASE_HOST=" + pg_container, "-e", "DATABASE_NAME=appdb",
                                    "-e", "DATABASE_USER=dial_app",
                                    "-e", "DATABASE_PASSWORD_FILE=/run/secrets/postgres_password"]
                    vk_flags = []
                    if "valkey_id" in request:
                        from .valkey import names, password_mount
                        cache_file = password_mount(self, request["valkey_id"], request["valkey_version"])
                        cache_container = names(request["valkey_id"])[0]
                        vk_flags = ["--mount", "type=bind,src=" + str(cache_file) +
                                    ",dst=/run/secrets/valkey_password,readonly",
                                    "-e", "CACHE_HOST=" + cache_container, "-e", "CACHE_PORT=6379",
                                    "-e", "CACHE_USER=dial_app",
                                    "-e", "CACHE_PASSWORD_FILE=/run/secrets/valkey_password"]
                    self.runner([
                        "docker", "run", "-d", "--name", container,
                        "--label", "dial.application=" + app_id,
                        "--label", "dial.release=" + release_id,
                        "--network", self.application_network(app_id),
                        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                        "--pids-limit=256", "--memory=" + str(request["memory_mb"]) + "m",
                        "--cpus=" + str(request["cpu_milli"] / 1000),
                        "--user=10001:10001", "--tmpfs=/tmp:rw,nosuid,noexec,size=64m",
                        *pg_flags,
                        *vk_flags,
                        request["image"],
                    ], 120)
                if "postgres_id" in request:
                    from .postgres import attach
                    attach(self, request["postgres_id"], app_id, release_id)
                if "valkey_id" in request:
                    from .valkey import attach as attach_valkey
                    attach_valkey(self, request["valkey_id"], app_id, release_id)
                deadline = time.monotonic() + 90
                healthy = False
                while time.monotonic() < deadline:
                    running, ip = self.inspect(container)
                    if running and ip and self.health_probe(ip, request["port"], request["health_path"]):
                        healthy = True
                        break
                    time.sleep(2)
                if not healthy:
                    raise OperationError("Private application probe did not pass")
                receipt = {"operation_id": operation_id, "release_id": release_id, "state": "HEALTHY_PRIVATE", "container": container}
                with self.db() as db:
                    # The old container is retained until the new release is healthy.
                    db.execute("INSERT INTO active(application_id,release_id,container) VALUES (?,?,?) "
                               "ON CONFLICT(application_id) DO UPDATE SET release_id=excluded.release_id,container=excluded.container",
                               (app_id, release_id, container))
                    db.execute("UPDATE operations SET state='COMPLETE',receipt=? WHERE id=?", (json.dumps(receipt), operation_id))
                # The control database must commit the promotion before the
                # old container is retired by a separate idempotent command.
                return receipt
            except Exception:
                with self.db() as db:
                    db.execute("UPDATE operations SET state='FAILED' WHERE id=?", (operation_id,))
                if container != (active["container"] if active else None):
                    try:
                        self.runner(["docker", "rm", "-f", container], 30)
                    except OperationError:
                        pass
                raise

    def exists(self, container):
        try:
            self.runner(["docker", "inspect", container], 15)
            return True
        except OperationError:
            return False

    def retire(self, application_id, release_id):
        app_id, release_id = str(uuid.UUID(application_id)), str(uuid.UUID(release_id))
        container = self.container(release_id)
        with self.lock, self.file_lock():
            with self.db() as db:
                current = db.execute("SELECT release_id FROM active WHERE application_id=?", (app_id,)).fetchone()
                routed = db.execute("SELECT release_id FROM routes WHERE application_id=?", (app_id,)).fetchone()
            if current and current["release_id"] == release_id:
                raise OperationError("Cannot retire active release")
            if routed and routed["release_id"] == release_id:
                raise OperationError("Cannot retire publicly routed release")
            try:
                item = json.loads(self.runner(["docker", "inspect", container], 15))[0]
            except OperationError:
                return {"release_id": release_id, "state": "RETIRED"}
            labels = item.get("Config", {}).get("Labels", {})
            if labels.get("dial.application") != app_id or labels.get("dial.release") != release_id:
                raise OperationError("Container ownership labels do not match")
            self.runner(["docker", "rm", "-f", container], 30)
            return {"release_id": release_id, "state": "RETIRED"}

    def route(self, data):
        """Swap one application's Traefik file atomically after checking container ownership."""
        if set(data) != {"application_id", "release_id", "hostname", "port", "health_path"}:
            raise ValueError("Invalid route properties")
        app, release = str(uuid.UUID(data["application_id"])), str(uuid.UUID(data["release_id"]))
        from .routing import route_toml, valid_hostname
        if app != data["application_id"] or release != data["release_id"] or not valid_hostname(data["hostname"]):
            raise ValueError("Invalid route identifiers")
        if type(data["port"]) is not int or not 1 <= data["port"] <= 65535 or not PATH.fullmatch(data["health_path"]):
            raise ValueError("Invalid upstream")
        container = self.container(release)
        with self.lock, self.file_lock():
            ingress, _ = self.inspect("dial-ingress")
            if not ingress:
                raise OperationError("Ingress container unavailable")
            item = json.loads(self.runner(["docker", "inspect", container], 15))[0]
            labels = item.get("Config", {}).get("Labels", {})
            if labels.get("dial.application") != app or labels.get("dial.release") != release:
                raise OperationError("Route container ownership mismatch")
            running, ip = self.inspect(container)
            if not running or not ip or not self.health_probe(ip, data["port"], data["health_path"]):
                raise OperationError("Route upstream is not healthy")
            app_network = self.application_network(app)
            ingress_info = json.loads(self.runner(["docker", "inspect", "dial-ingress"], 15))[0]
            if app_network not in ingress_info.get("NetworkSettings", {}).get("Networks", {}):
                self.runner(["docker", "network", "connect", app_network, "dial-ingress"], 30)
            document = route_toml(app, release, data["hostname"], container, data["port"])
            route_file = self.routes_dir / (app + ".toml")
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.routes_dir,
                                             prefix=".route-", delete=False) as file:
                temporary = Path(file.name)
                try:
                    os.chmod(temporary, 0o600)
                    file.write(document)
                    file.flush()
                    os.fsync(file.fileno())
                except Exception:
                    temporary.unlink(missing_ok=True)
                    raise
            os.replace(temporary, route_file)
            with self.db() as db:
                db.execute("INSERT INTO routes(application_id,release_id,hostname) VALUES (?,?,?) "
                           "ON CONFLICT(application_id) DO UPDATE SET release_id=excluded.release_id,hostname=excluded.hostname",
                           (app, release, data["hostname"]))
            return {"application_id": app, "release_id": release, "hostname": data["hostname"], "state": "ROUTED"}

    def unroute(self, application_id, release_id):
        app, release = str(uuid.UUID(application_id)), str(uuid.UUID(release_id))
        with self.lock, self.file_lock(), self.db() as db:
            row = db.execute("SELECT release_id FROM routes WHERE application_id=?", (app,)).fetchone()
            if row and row["release_id"] != release:
                raise OperationError("A different release owns the public route")
            (self.routes_dir / (app + ".toml")).unlink(missing_ok=True)
            db.execute("DELETE FROM routes WHERE application_id=?", (app,))
        return {"application_id": app, "release_id": release, "state": "UNROUTED"}

    def application_state(self, data):
        """Pause/resume only the active labeled container after public routing is absent."""
        if not isinstance(data, dict) or set(data) != {"application_id", "release_id", "action", "port", "health_path"}:
            raise ValueError("Invalid application state request")
        app, release = (str(uuid.UUID(data[key])) for key in ("application_id", "release_id"))
        if app != data["application_id"] or release != data["release_id"] or \
                data["action"] not in ("pause", "resume") or \
                type(data["port"]) is not int or not 1 <= data["port"] <= 65535 or \
                not isinstance(data["health_path"], str) or not PATH.fullmatch(data["health_path"]):
            raise ValueError("Invalid application state properties")
        container = self.container(release)
        with self.lock, self.file_lock():
            with self.db() as db:
                active = db.execute("SELECT release_id FROM active WHERE application_id=?", (app,)).fetchone()
                routed = db.execute("SELECT release_id FROM routes WHERE application_id=?", (app,)).fetchone()
            if not active or active["release_id"] != release or routed or (self.routes_dir / (app + ".toml")).exists():
                raise OperationError("Application route or active release mismatch")
            try:
                item = json.loads(self.runner(["docker", "inspect", container], 15))[0]
                labels = item["Config"]["Labels"]
                if labels.get("dial.application") != app or labels.get("dial.release") != release:
                    raise OperationError("Container ownership mismatch")
                running = item["State"]["Running"]
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise OperationError("Container inspection invalid") from exc
            if data["action"] == "pause":
                if running:
                    self.runner(["docker", "stop", "--time=10", container], 30)
                if json.loads(self.runner(["docker", "inspect", container], 15))[0]["State"]["Running"]:
                    raise OperationError("Container did not stop")
                return {"application_id": app, "release_id": release, "state": "PAUSED"}
            if not running:
                self.runner(["docker", "start", container], 30)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                running, ip = self.inspect(container)
                if running and ip and self.health_probe(ip, data["port"], data["health_path"]):
                    return {"application_id": app, "release_id": release, "state": "RESUMED"}
                time.sleep(2)
            self.runner(["docker", "stop", "--time=10", container], 30)
            raise OperationError("Private application health did not recover")

    def abort(self, application_id, release_id, previous_release_id=None):
        """Compensate an unsuccessful release after public routing was restored."""
        app, release = str(uuid.UUID(application_id)), str(uuid.UUID(release_id))
        previous = str(uuid.UUID(previous_release_id)) if previous_release_id else None
        if previous == release:
            raise ValueError("Previous release must differ")
        container = self.container(release)
        with self.lock, self.file_lock():
            with self.db() as db:
                routed = db.execute("SELECT release_id FROM routes WHERE application_id=?", (app,)).fetchone()
                active = db.execute("SELECT release_id FROM active WHERE application_id=?", (app,)).fetchone()
            if routed and routed["release_id"] == release:
                raise OperationError("Failed release still publicly routed")
            if active and active["release_id"] == release and previous:
                old = self.container(previous)
                try:
                    item = json.loads(self.runner(["docker", "inspect", old], 15))[0]
                except (OperationError, ValueError, IndexError, KeyError) as exc:
                    raise OperationError("Previous release unavailable") from exc
                labels = item.get("Config", {}).get("Labels", {})
                if labels.get("dial.application") != app or labels.get("dial.release") != previous:
                    raise OperationError("Previous release ownership mismatch")
            try:
                item = json.loads(self.runner(["docker", "inspect", container], 15))[0]
            except OperationError:
                item = None
            if item:
                labels = item.get("Config", {}).get("Labels", {})
                if labels.get("dial.application") != app or labels.get("dial.release") != release:
                    raise OperationError("Failed release ownership mismatch")
                self.runner(["docker", "rm", "-f", container], 30)
            with self.db() as db:
                if active and active["release_id"] == release:
                    if previous:
                        db.execute("UPDATE active SET release_id=?,container=? WHERE application_id=?",
                                   (previous, self.container(previous), app))
                    else:
                        db.execute("DELETE FROM active WHERE application_id=?", (app,))
            return {"application_id": app, "release_id": release, "state": "ABORTED"}

    def observed(self, application_id):
        app_id = str(uuid.UUID(application_id))
        with self.db() as db:
            row = db.execute("SELECT * FROM active WHERE application_id=?", (app_id,)).fetchone()
        if not row:
            return {"application_id": app_id, "state": "ABSENT"}
        running, ip = self.inspect(row["container"])
        return {"application_id": app_id, "release_id": row["release_id"],
                "state": "RUNNING_PRIVATE" if running and ip else "UNREACHABLE"}

    def deliver_secrets(self, data):
        from .secrets import install
        if not isinstance(data, dict) or set(data) != {"resource_id", "version", "values"}:
            raise ValueError("Invalid secret delivery")
        with self.lock, self.file_lock():
            install(self.secrets_dir, data["resource_id"], data["version"], data["values"])
        return {"resource_id": data["resource_id"], "version": data["version"], "state": "STORED"}

    @staticmethod
    def capacity():
        with open("/proc/meminfo", encoding="utf-8") as file:
            memory_kib = int(next(line.split()[1] for line in file if line.startswith("MemTotal:")))
        reserve_mb = int(os.environ.get("NODE_RESERVE_MEMORY_MB", "1024"))
        reserve_cpu = int(os.environ.get("NODE_RESERVE_CPU_MILLI", "500"))
        available_memory = memory_kib // 1024 - reserve_mb
        available_cpu = (os.cpu_count() or 0) * 1000 - reserve_cpu
        if available_memory < 64 or available_cpu < 50:
            raise OperationError("Insufficient node capacity after host reservation")
        return {"cpu_milli": available_cpu, "memory_mb": available_memory}
