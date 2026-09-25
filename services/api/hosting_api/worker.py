"""Durable deployment worker. PostgreSQL owns job state; the node owns Docker execution."""
import http.client
import ipaddress
import json
import os
import ssl
import socket
import time
import uuid
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

from .__main__ import database_dsn, record
from .domains import address_proves, txt_proves
from .secrets import OpenBao


PRIVATE_RANGES = [ipaddress.ip_network(cidr) for cidr in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8")]


def private_endpoint(node):
    parsed = urlsplit(node["endpoint"])
    try:
        address = ipaddress.IPv4Address(parsed.hostname)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("Node endpoint must be a literal private IPv4 address") from exc
    if (parsed.scheme != "https" or parsed.hostname != node["server_name"] or
            not parsed.port or parsed.path or parsed.query or parsed.fragment or
            not any(address in network for network in PRIVATE_RANGES)):
        raise ValueError("Invalid private node endpoint")
    return parsed


def node_request(node, data, certificate):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=450)
    try:
        connection.request("PUT", "/v1/deployments", body=json.dumps(data, separators=(",", ":")),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        content = response.read(8192)
        if response.status != 200:
            raise RuntimeError("Node rejected deployment")
        receipt = json.loads(content)
        if (receipt.get("operation_id") != data["operation_id"] or
                receipt.get("release_id") != data["release_id"] or
                receipt.get("state") != "HEALTHY_PRIVATE"):
            raise RuntimeError("Unexpected node receipt")
        return receipt
    finally:
        connection.close()


def route_request(node, data, certificate, remove=False):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=15)
    try:
        path = (f"/v1/routes/{data['application_id']}/{data['release_id']}" if remove else "/v1/routes")
        connection.request("DELETE" if remove else "PUT", path,
                           body=None if remove else json.dumps(data, separators=(",", ":")),
                           headers={} if remove else {"Content-Type": "application/json"})
        response = connection.getresponse()
        receipt = json.loads(response.read(4096))
        if response.status != 200 or receipt.get("release_id") != data["release_id"] or \
                receipt.get("state") != ("UNROUTED" if remove else "ROUTED"):
            raise RuntimeError("Node route operation was not proven")
        return receipt
    finally:
        connection.close()


def node_application_state(node, release, certificate, action):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=120)
    try:
        payload = {"application_id": str(release["application_id"]), "release_id": str(release["id"]),
                   "action": action, "port": release["port"], "health_path": release["health_path"]}
        connection.request("PUT", "/v1/application-state", body=json.dumps(payload, separators=(",", ":")),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        receipt = json.loads(response.read(4096))
        if (response.status != 200 or receipt.get("application_id") != payload["application_id"] or
                receipt.get("release_id") != payload["release_id"] or
                receipt.get("state") != ("PAUSED" if action == "pause" else "RESUMED")):
            raise RuntimeError("Node application state change was not proven")
        return receipt
    finally:
        connection.close()


def deliver_secrets(node, resource_id, version, certificate, bao=None):
    """Retrieve one exact OpenBao revision and install it over private mTLS."""
    bao = bao or OpenBao.environment()
    observed_version, values = bao.get(resource_id, version=version)
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=15)
    try:
        data = {"resource_id": str(resource_id), "version": observed_version, "values": values}
        connection.request("PUT", "/v1/resource-secrets", body=json.dumps(data, separators=(",", ":")),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        receipt = json.loads(response.read(2048))
        if (response.status != 200 or receipt.get("state") != "STORED" or
                receipt.get("resource_id") != str(resource_id) or receipt.get("version") != version):
            raise RuntimeError("Node secret revision not proven")
        return receipt
    finally:
        connection.close()


def public_probe(host, address, release, path):
    """Connect to the registered node address while verifying the hostname certificate."""
    context = ssl.create_default_context()
    with socket.create_connection((str(address), 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(5)
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: DialHostingHealth/1\r\n\r\n"
            tls.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            response.read(1024)
            return 200 <= response.status < 300 and response.getheader("X-Dial-Release") == str(release)


def restore_route(node, release, domain, certificate):
    payload = {"application_id": str(release["application_id"]), "release_id": str(release["id"]),
               "hostname": domain["hostname"], "port": release["port"], "health_path": release["health_path"]}
    if release["previous_release_id"]:
        old = {**payload, "release_id": str(release["previous_release_id"]),
               "port": release["previous_port"], "health_path": release["previous_health_path"]}
        route_request(node, old, certificate)
    else:
        route_request(node, payload, certificate, remove=True)


def publish(node, release, domain, certificate, probe_seconds=120):
    if not domain or not domain["verified_at"] or not node["public_ipv4"]:
        raise RuntimeError("Domain or public ingress unavailable")
    if not txt_proves(domain["hostname"], domain["verification_token"]):
        raise RuntimeError("Domain ownership proof no longer exists")
    if not address_proves(domain["hostname"], node["public_ipv4"]):
        raise RuntimeError("DNS does not target the selected ingress node")
    payload = {"application_id": str(release["application_id"]), "release_id": str(release["id"]),
               "hostname": domain["hostname"], "port": release["port"], "health_path": release["health_path"]}
    route_request(node, payload, certificate)
    try:
        deadline = time.monotonic() + probe_seconds
        while True:
            try:
                if public_probe(domain["hostname"], node["public_ipv4"], release["id"], release["health_path"]):
                    break
            except (OSError, ssl.SSLError, http.client.HTTPException):
                pass  # Initial certificate issuance and proxy reload can take time.
            if time.monotonic() >= deadline:
                raise RuntimeError("Public HTTPS release proof failed")
            time.sleep(3)
    except Exception:
        restore_route(node, release, domain, certificate)
        raise
    return {"release_id": str(release["id"]), "hostname": domain["hostname"], "state": "SERVING"}


def node_capacity(node, certificate):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=5)
    try:
        connection.request("GET", "/v1/capacity")
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("Node capacity unavailable")
        capacity = json.loads(response.read(4096))
        if (set(capacity) != {"cpu_milli", "memory_mb"} or
                type(capacity["cpu_milli"]) is not int or capacity["cpu_milli"] < 50 or
                type(capacity["memory_mb"]) is not int or capacity["memory_mb"] < 64):
            raise ValueError("Invalid node capacity receipt")
        return capacity
    finally:
        connection.close()


def node_retire(node, application_id, release_id, certificate):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=40)
    try:
        connection.request("DELETE", f"/v1/applications/{application_id}/releases/{release_id}")
        response = connection.getresponse()
        receipt = json.loads(response.read(4096))
        if response.status != 200 or receipt.get("state") != "RETIRED" or receipt.get("release_id") != str(release_id):
            raise RuntimeError("Retirement not proven")
    finally:
        connection.close()


def node_abort(node, release, certificate):
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=40)
    try:
        path = f"/v1/deployments/{release['application_id']}/{release['id']}"
        if release["previous_release_id"]:
            path += "/" + str(release["previous_release_id"])
        connection.request("DELETE", path)
        response = connection.getresponse()
        receipt = json.loads(response.read(4096))
        if response.status != 200 or receipt.get("state") != "ABORTED" or receipt.get("release_id") != str(release["id"]):
            raise RuntimeError("Node failed-release cleanup not proven")
    finally:
        connection.close()


def claim_traffic(conn):
    """Lease a reversible public-route transition; a crash leaves it retryable."""
    with conn.transaction():
        row = conn.execute(
            "SELECT a.id AS application_id,a.organization_id,a.active_release_id,a.traffic_state,"
            "a.traffic_requested_by,r.port,r.health_path,d.hostname,d.verified_at,d.verification_token,"
            "n.endpoint,n.server_name,n.public_ipv4 FROM hosting.applications a "
            "LEFT JOIN hosting.releases r ON r.id=a.active_release_id "
            "LEFT JOIN hosting.nodes n ON n.id=r.node_id "
            "LEFT JOIN hosting.domains d ON d.application_id=a.id "
            "WHERE a.traffic_state IN ('SUSPENDING','RESUMING','SUSPENDED') "
            "AND a.traffic_next_attempt_at <= now() "
            "AND (a.traffic_lease_until IS NULL OR a.traffic_lease_until < now()) "
            "ORDER BY CASE WHEN a.traffic_state='SUSPENDED' THEN 1 ELSE 0 END,"
            "a.traffic_next_attempt_at,a.id FOR UPDATE OF a SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not row:
            return None
        token = uuid.uuid4()
        conn.execute("UPDATE hosting.applications SET traffic_lease_token=%s,"
                     "traffic_lease_until=now()+interval '3 minutes' WHERE id=%s",
                     (token, row["application_id"]))
        return row, token


def finalize_traffic(conn, row, token, error=None):
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(row["application_id"]),))
        state = row["traffic_state"]
        if error:
            changed = conn.execute(
                "UPDATE hosting.applications SET traffic_lease_token=NULL,traffic_lease_until=NULL,"
                "traffic_last_error=%s,traffic_next_attempt_at=now()+interval '15 seconds' "
                "WHERE id=%s AND traffic_state=%s AND traffic_lease_token=%s RETURNING id",
                (str(error)[:120], row["application_id"], state, token)).fetchone()
            return bool(changed)
        target = "SUSPENDED" if state in ("SUSPENDING", "SUSPENDED") else "ACTIVE"
        changed = conn.execute(
            "UPDATE hosting.applications SET traffic_state=%s,traffic_lease_token=NULL,traffic_lease_until=NULL,"
            "traffic_last_error=NULL,"
            "traffic_updated_at=CASE WHEN %s='SUSPENDED' THEN traffic_updated_at ELSE now() END,"
            "traffic_next_attempt_at=CASE WHEN %s='SUSPENDED' THEN now()+interval '1 minute' ELSE now() END "
            "WHERE id=%s AND traffic_state=%s AND traffic_lease_token=%s RETURNING id",
            (target, state, target, row["application_id"], state, token)).fetchone()
        if changed and state != "SUSPENDED":
            if target == "SUSPENDED":
                conn.execute("UPDATE hosting.release_health_incidents SET closed_at=now(),resolution='SUSPENDED' "
                             "WHERE release_id=%s AND closed_at IS NULL", (row["active_release_id"],))
                conn.execute("UPDATE hosting.release_health SET state='UNKNOWN',consecutive_failures=0,"
                             "checked_at=NULL,next_probe_at=now(),lease_token=NULL,lease_until=NULL "
                             "WHERE release_id=%s", (row["active_release_id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (row["traffic_requested_by"],))
            record(conn, row["organization_id"], row["traffic_requested_by"],
                   "application." + target.lower(), row["application_id"], uuid.uuid4())
        return bool(changed)


def process_traffic_once(conn, certificate):
    claimed = claim_traffic(conn)
    if not claimed:
        return False
    row, token = claimed
    try:
        if row["active_release_id"]:
            if not row["endpoint"]:
                raise RuntimeError("Suspended application's node is unavailable")
            release = {"id": row["active_release_id"], "application_id": row["application_id"],
                       "port": row["port"], "health_path": row["health_path"], "previous_release_id": None}
            if row["traffic_state"] in ("SUSPENDING", "SUSPENDED"):
                route_request(row, {"application_id": str(row["application_id"]),
                                    "release_id": str(row["active_release_id"])}, certificate, remove=True)
                node_application_state(row, release, certificate, "pause")
            else:
                node_application_state(row, release, certificate, "resume")
                try:
                    publish(row, release, row, certificate)
                except Exception:
                    # Public proof failure must leave the workload stopped again.
                    route_request(row, {"application_id": str(row["application_id"]),
                                        "release_id": str(row["active_release_id"])}, certificate, remove=True)
                    node_application_state(row, release, certificate, "pause")
                    raise
        finalize_traffic(conn, row, token)
    except Exception as exc:
        finalize_traffic(conn, row, token, error=type(exc).__name__)
    return True


def sweep_failed(conn, certificate):
    failed = conn.execute("SELECT r.id,r.application_id,r.previous_release_id,r.node_id,r.cpu_milli,r.memory_mb,"
                          "r.port,r.health_path,p.port AS previous_port,p.health_path AS previous_health_path,"
                          "d.hostname,n.endpoint,n.server_name "
                          "FROM hosting.releases r JOIN hosting.nodes n ON n.id=r.node_id "
                          "LEFT JOIN hosting.releases p ON p.id=r.previous_release_id "
                          "LEFT JOIN hosting.domains d ON d.application_id=r.application_id "
                          "WHERE r.state='FAILED' AND r.cleanup_at IS NULL ORDER BY r.created_at LIMIT 20").fetchall()
    for row in failed:
        try:
            with conn.transaction():
                # The same application lock guards API suspension and release admission.
                # A delayed failed-release cleanup must never recreate a suspended route.
                conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(row["application_id"]),))
                state = conn.execute("SELECT traffic_state FROM hosting.applications WHERE id=%s",
                                     (row["application_id"],)).fetchone()
                if not state or state["traffic_state"] != "ACTIVE":
                    continue
                if row["hostname"]:
                    restore_route(row, row, row, certificate)
                node_abort(row, row, certificate)
                changed = conn.execute("UPDATE hosting.releases SET cleanup_at=now() "
                                       "WHERE id=%s AND state='FAILED' AND cleanup_at IS NULL RETURNING id",
                                       (row["id"],)).fetchone()
                if changed:
                    conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli-%s, "
                                 "reserved_memory_mb=reserved_memory_mb-%s WHERE id=%s",
                                 (row["cpu_milli"], row["memory_mb"], row["node_id"]))
        except (OSError, ssl.SSLError, ValueError, RuntimeError, psycopg.Error):
            continue


def sweep_retirements(conn, certificate):
    old = conn.execute("SELECT r.id,r.application_id,r.node_id,r.cpu_milli,r.memory_mb,"
                       "n.endpoint,n.server_name FROM hosting.releases r JOIN hosting.nodes n ON n.id=r.node_id "
                       "WHERE r.state='SUPERSEDED' ORDER BY r.created_at LIMIT 20").fetchall()
    for row in old:
        try:
            node_retire(row, row["application_id"], row["id"], certificate)
            with conn.transaction():
                changed = conn.execute("UPDATE hosting.releases SET state='RETIRED' "
                                       "WHERE id=%s AND state='SUPERSEDED' RETURNING id", (row["id"],)).fetchone()
                if changed:
                    conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli-%s, "
                                 "reserved_memory_mb=reserved_memory_mb-%s WHERE id=%s",
                                 (row["cpu_milli"], row["memory_mb"], row["node_id"]))
        except (OSError, ssl.SSLError, ValueError, RuntimeError, psycopg.Error):
            continue


def refresh_nodes(conn, certificate):
    nodes = conn.execute("SELECT id,endpoint,server_name FROM hosting.nodes WHERE enabled "
                         "AND observed_at < now()-interval '1 minute' ORDER BY id LIMIT 20").fetchall()
    for node in nodes:
        try:
            capacity = node_capacity(node, certificate)
            with conn.transaction():
                conn.execute("UPDATE hosting.nodes SET cpu_milli=%s,memory_mb=%s,observed_at=now() "
                             "WHERE id=%s AND reserved_cpu_milli<=%s AND reserved_memory_mb<=%s",
                             (capacity["cpu_milli"], capacity["memory_mb"], node["id"],
                              capacity["cpu_milli"], capacity["memory_mb"]))
        except (OSError, ssl.SSLError, ValueError, RuntimeError, psycopg.Error):
            # Old evidence will expire; placement will then fail closed.
            continue


def claim(conn):
    with conn.transaction():
        job = conn.execute(
            "SELECT id,release_id,organization_id,attempts FROM hosting.jobs "
            "WHERE attempts < 3 AND ((state='PENDING' AND next_attempt_at <= now()) "
            "OR (state='RUNNING' AND lease_until < now())) "
            "ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not job:
            return None
        release = conn.execute("SELECT * FROM hosting.releases WHERE id=%s", (job["release_id"],)).fetchone()
        node = conn.execute("SELECT * FROM hosting.nodes WHERE id=%s", (release["node_id"],)).fetchone()
        attempt = job["attempts"] + 1
        conn.execute("UPDATE hosting.jobs SET state='RUNNING',attempts=%s,lease_until=now()+interval '10 minutes' WHERE id=%s",
                     (attempt, job["id"]))
        conn.execute("UPDATE hosting.releases SET state='DEPLOYING' WHERE id=%s", (release["id"],))
        return job, release, node, attempt


def finalize(conn, job, release, attempt, receipt=None, failure=None):
    if receipt and (receipt.get("public", {}).get("release_id") != str(release["id"]) or
                    receipt["public"].get("state") != "SERVING"):
        raise ValueError("Public release proof required for promotion")
    with conn.transaction():
        current = conn.execute("SELECT state,attempts FROM hosting.jobs WHERE id=%s FOR UPDATE", (job["id"],)).fetchone()
        if current["state"] != "RUNNING" or current["attempts"] != attempt:
            return False  # An expired lease was reclaimed; stale worker cannot overwrite it.
        if receipt:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(release["application_id"]),))
            conn.execute("UPDATE hosting.applications SET active_release_id=%s WHERE id=%s",
                         (release["id"], release["application_id"]))
            conn.execute("UPDATE hosting.releases SET state='SERVING' WHERE id=%s", (release["id"],))
            if release["previous_release_id"]:
                conn.execute("UPDATE hosting.release_health_incidents SET closed_at=now(),"
                             "resolution='SUPERSEDED' WHERE release_id=%s AND closed_at IS NULL",
                             (release["previous_release_id"],))
            conn.execute("INSERT INTO hosting.release_health(release_id,organization_id,application_id) "
                         "VALUES (%s,%s,%s) ON CONFLICT (release_id) DO UPDATE "
                         "SET state='UNKNOWN',consecutive_failures=0,checked_at=NULL,next_probe_at=now(),"
                         "lease_token=NULL,lease_until=NULL",
                         (release["id"], release["organization_id"], release["application_id"]))
            conn.execute("UPDATE hosting.jobs SET state='COMPLETE',lease_until=NULL,receipt=%s::jsonb WHERE id=%s",
                         (json.dumps(receipt), job["id"]))
            if release["previous_release_id"]:
                conn.execute("UPDATE hosting.releases SET state='SUPERSEDED' WHERE id=%s AND state='SERVING'",
                             (release["previous_release_id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (release["requested_by"],))
            record(conn, release["organization_id"], release["requested_by"], "release.serving",
                   release["id"], uuid.uuid4())
        elif attempt < 3:
            delay = attempt * 15
            conn.execute("UPDATE hosting.jobs SET state='PENDING',lease_until=NULL,last_error=%s, "
                         "next_attempt_at=now()+(%s * interval '1 second') WHERE id=%s",
                         (str(failure)[:120], delay, job["id"]))
            conn.execute("UPDATE hosting.releases SET state='QUEUED' WHERE id=%s", (release["id"],))
        else:
            conn.execute("UPDATE hosting.jobs SET state='FAILED',lease_until=NULL,last_error=%s WHERE id=%s",
                         (str(failure)[:120], job["id"]))
            conn.execute("UPDATE hosting.releases SET state='FAILED' WHERE id=%s", (release["id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (release["requested_by"],))
            record(conn, release["organization_id"], release["requested_by"], "release.failed",
                   release["id"], uuid.uuid4())
        return True


def recover_expired(conn):
    # A process can die during the third attempt. The lease expiry is the
    # deterministic point at which that final attempt becomes a failed job.
    with conn.transaction():
        expired = conn.execute("SELECT j.id,j.release_id,r.organization_id,r.application_id,r.node_id,r.cpu_milli,r.memory_mb,r.requested_by "
                               "FROM hosting.jobs j JOIN hosting.releases r ON r.id=j.release_id "
                               "WHERE j.state='RUNNING' AND j.attempts=3 AND j.lease_until < now() "
                               "FOR UPDATE OF j SKIP LOCKED LIMIT 20").fetchall()
        for row in expired:
            conn.execute("UPDATE hosting.jobs SET state='FAILED',lease_until=NULL,last_error='lease expired' WHERE id=%s", (row["id"],))
            conn.execute("UPDATE hosting.releases SET state='FAILED' WHERE id=%s", (row["release_id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (row["requested_by"],))
            record(conn, row["organization_id"], row["requested_by"], "release.lease_expired",
                   row["release_id"], uuid.uuid4())


def claim_health(conn):
    with conn.transaction():
        row = conn.execute(
            "SELECT h.release_id,h.organization_id,h.application_id,h.state,h.consecutive_failures,"
            "r.health_path,d.hostname,d.verified_at,n.public_ipv4 FROM hosting.release_health h "
            "JOIN hosting.applications a ON a.id=h.application_id AND a.active_release_id=h.release_id "
            "JOIN hosting.releases r ON r.id=h.release_id AND r.state='SERVING' "
            "LEFT JOIN hosting.domains d ON d.application_id=a.id "
            "LEFT JOIN hosting.nodes n ON n.id=r.node_id "
            "WHERE a.traffic_state='ACTIVE' AND h.next_probe_at<=now() "
            "AND (h.lease_until IS NULL OR h.lease_until<now()) "
            "ORDER BY h.next_probe_at,h.release_id FOR UPDATE OF h SKIP LOCKED LIMIT 1"
        ).fetchone()
        if not row:
            return None
        token = uuid.uuid4()
        conn.execute("UPDATE hosting.release_health SET lease_token=%s,"
                     "lease_until=now()+interval '30 seconds' WHERE release_id=%s",
                     (token, row["release_id"]))
        return row, token


def finalize_health(conn, row, token, healthy):
    with conn.transaction():
        # The active release and traffic state may change while the network probe runs.
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(row["application_id"]),))
        current = conn.execute(
            "SELECT h.state,h.consecutive_failures FROM hosting.release_health h "
            "JOIN hosting.applications a ON a.id=h.application_id AND a.active_release_id=h.release_id "
            "JOIN hosting.releases r ON r.id=h.release_id AND r.state='SERVING' "
            "WHERE h.release_id=%s AND h.lease_token=%s AND h.lease_until>now() "
            "AND a.traffic_state='ACTIVE' FOR UPDATE OF h",
            (row["release_id"], token)).fetchone()
        if not current:
            return False
        failures = 0 if healthy else current["consecutive_failures"] + 1
        state = "UP" if healthy else "DOWN" if failures >= 3 else "DEGRADED"
        conn.execute("UPDATE hosting.release_health SET state=%s,consecutive_failures=%s,"
                     "checked_at=now(),next_probe_at=now()+interval '1 minute',"
                     "lease_token=NULL,lease_until=NULL WHERE release_id=%s",
                     (state, failures, row["release_id"]))
        action = ("release.health_down" if state == "DOWN" and current["state"] != "DOWN" else
                  "release.health_recovered" if healthy and current["state"] == "DOWN" else None)
        if action:
            if action == "release.health_down":
                conn.execute("INSERT INTO hosting.release_health_incidents "
                             "(organization_id,application_id,release_id) VALUES (%s,%s,%s)",
                             (row["organization_id"], row["application_id"], row["release_id"]))
            else:
                conn.execute("UPDATE hosting.release_health_incidents SET closed_at=now(),"
                             "resolution='RECOVERED' WHERE release_id=%s AND closed_at IS NULL",
                             (row["release_id"],))
            record(conn, row["organization_id"], "service:dial-health-worker", action,
                   row["release_id"], uuid.uuid4())
        return True


def process_health_once(conn):
    claimed = claim_health(conn)
    if not claimed:
        return False
    row, token = claimed
    healthy = False
    try:
        if (row["hostname"] and row["verified_at"] and row["public_ipv4"] and
                address_proves(row["hostname"], row["public_ipv4"])):
            healthy = public_probe(row["hostname"], row["public_ipv4"],
                                   row["release_id"], row["health_path"])
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        pass
    finalize_health(conn, row, token, healthy)
    return True


def process_once(conn, certificate):
    # Public containment takes priority over slow node probes and provisioning.
    if process_traffic_once(conn, certificate):
        return True
    refresh_nodes(conn, certificate)
    from .postgres_jobs import process_once as process_postgres
    from .valkey_jobs import process_once as process_valkey
    from .storage_jobs import process_once as process_storage
    if process_postgres(conn, certificate):
        return True
    if process_valkey(conn, certificate):
        return True
    if process_storage(conn, certificate):
        return True
    sweep_failed(conn, certificate)
    sweep_retirements(conn, certificate)
    recover_expired(conn)
    claimed = claim(conn)
    if not claimed:
        return process_health_once(conn)
    job, release, node, attempt = claimed
    if not node or not node["enabled"]:
        error = "Assigned node disabled or absent"
        finalize(conn, job, release, attempt, failure=error)
        return True
    payload = {"operation_id": str(job["id"]), "application_id": str(release["application_id"]),
               "release_id": str(release["id"]), "image": release["image"], "port": release["port"],
               "health_path": release["health_path"], "memory_mb": release["memory_mb"],
               "cpu_milli": release["cpu_milli"]}
    try:
        database = conn.execute("SELECT id,node_id,secret_version,state FROM hosting.postgres_instances "
                                "WHERE application_id=%s AND state IN ('QUEUED','PROVISIONING','READY','FAILED')",
                                (release["application_id"],)).fetchone()
        if database:
            if database["state"] != "READY" or database["node_id"] != release["node_id"]:
                raise RuntimeError("Assigned database unavailable or on a different node")
            payload["postgres_id"] = str(database["id"])
            payload["postgres_version"] = database["secret_version"]
        cache = conn.execute("SELECT id,node_id,secret_version,state FROM hosting.valkey_instances "
                             "WHERE application_id=%s", (release["application_id"],)).fetchone()
        if cache:
            if cache["state"] != "READY" or cache["node_id"] != release["node_id"]:
                raise RuntimeError("Assigned cache unavailable or on a different node")
            payload["valkey_id"] = str(cache["id"])
            payload["valkey_version"] = cache["secret_version"]
        storage = conn.execute("SELECT id,node_id,secret_version,state FROM hosting.object_storage_instances "
                               "WHERE application_id=%s", (release["application_id"],)).fetchone()
        if storage:
            if storage["state"] != "READY" or storage["node_id"] != release["node_id"]:
                raise RuntimeError("Assigned storage unavailable or on a different node")
            payload["storage_id"] = str(storage["id"])
            payload["storage_version"] = storage["secret_version"]
        receipt = node_request(node, payload, certificate)
        domain = conn.execute("SELECT hostname,verification_token,verified_at FROM hosting.domains "
                              "WHERE application_id=%s", (release["application_id"],)).fetchone()
        if release["previous_release_id"]:
            previous = conn.execute("SELECT port,health_path FROM hosting.releases WHERE id=%s",
                                    (release["previous_release_id"],)).fetchone()
            release = {**release, "previous_port": previous["port"],
                       "previous_health_path": previous["health_path"]}
        receipt["public"] = publish(node, release, domain, certificate)
        if not finalize(conn, job, release, attempt, receipt=receipt):
            restore_route(node, release, domain, certificate)
            raise RuntimeError("Stale deployment lease after public route activation")
    except Exception as exc:
        finalize(conn, job, release, attempt, failure=type(exc).__name__)
    return True


def main():
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD_FILE", "NODE_CA_FILE", "NODE_CERT_FILE", "NODE_KEY_FILE")
    if missing := [key for key in required if not os.environ.get(key)]:
        raise RuntimeError("Worker missing configuration: " + ", ".join(missing))
    certificate = {"ca": os.environ["NODE_CA_FILE"], "cert": os.environ["NODE_CERT_FILE"],
                   "key": os.environ["NODE_KEY_FILE"]}
    for file in certificate.values():
        if not os.path.isfile(file):
            raise RuntimeError("Worker certificate file unavailable")
    from .migrate import verify
    with psycopg.connect(database_dsn(), connect_timeout=5) as conn:
        verify(conn)
    while True:
        try:
            with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5, autocommit=True) as conn:
                did_work = process_once(conn, certificate)
            if not did_work:
                time.sleep(2)
        except psycopg.Error:
            time.sleep(5)


if __name__ == "__main__":
    main()
