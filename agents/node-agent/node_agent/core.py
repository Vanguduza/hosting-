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
    if set(request) != {"operation_id", "application_id", "release_id", "image", "port", "health_path", "memory_mb", "cpu_milli"}:
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
    def __init__(self, state_file, runner=command, health_probe=probe, network="dial-runtime"):
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.runner, self.health_probe, self.network = runner, health_probe, network
        self.lock = threading.RLock()
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, input_hash TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS active (application_id TEXT PRIMARY KEY, release_id TEXT NOT NULL, container TEXT NOT NULL)")

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

    def inspect(self, container):
        try:
            raw = self.runner(["docker", "inspect", container], 15)
            obj = json.loads(raw)[0]
            running = obj["State"]["Running"]
            networks = obj["NetworkSettings"]["Networks"]
            ip = networks[self.network]["IPAddress"]
            return running, ip
        except (OperationError, ValueError, KeyError, IndexError, TypeError):
            return False, None

    def network_ready(self):
        try:
            self.runner(["docker", "network", "inspect", self.network], 15)
        except OperationError:
            self.runner(["docker", "network", "create", "--driver", "bridge", self.network], 30)

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
                if existing and existing["state"] == "COMPLETE":
                    return json.loads(existing["receipt"])
                active = db.execute("SELECT * FROM active WHERE application_id=?", (app_id,)).fetchone()
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
                self.network_ready()
                running, ip = self.inspect(container)
                if not running:
                    # A crash can leave a stopped container under the same release name.
                    if self.exists(container):
                        self.runner(["docker", "rm", "-f", container], 30)
                    self.runner(["docker", "pull", request["image"]], 300)
                    self.runner([
                        "docker", "run", "-d", "--name", container,
                        "--label", "dial.application=" + app_id,
                        "--label", "dial.release=" + release_id,
                        "--network", self.network,
                        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                        "--pids-limit=256", "--memory=" + str(request["memory_mb"]) + "m",
                        "--cpus=" + str(request["cpu_milli"] / 1000),
                        "--user=10001:10001", "--tmpfs=/tmp:rw,nosuid,noexec,size=64m",
                        request["image"],
                    ], 120)
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
            if current and current["release_id"] == release_id:
                raise OperationError("Cannot retire active release")
            try:
                item = json.loads(self.runner(["docker", "inspect", container], 15))[0]
            except OperationError:
                return {"release_id": release_id, "state": "RETIRED"}
            labels = item.get("Config", {}).get("Labels", {})
            if labels.get("dial.application") != app_id or labels.get("dial.release") != release_id:
                raise OperationError("Container ownership labels do not match")
            self.runner(["docker", "rm", "-f", container], 30)
            return {"release_id": release_id, "state": "RETIRED"}

    def observed(self, application_id):
        app_id = str(uuid.UUID(application_id))
        with self.db() as db:
            row = db.execute("SELECT * FROM active WHERE application_id=?", (app_id,)).fetchone()
        if not row:
            return {"application_id": app_id, "state": "ABSENT"}
        running, ip = self.inspect(row["container"])
        return {"application_id": app_id, "release_id": row["release_id"],
                "state": "RUNNING_PRIVATE" if running and ip else "UNREACHABLE"}

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
