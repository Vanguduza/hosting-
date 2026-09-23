"""Durable deployment worker. PostgreSQL owns job state; the node owns Docker execution."""
import http.client
import ipaddress
import json
import os
import ssl
import time
import uuid
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

from .__main__ import database_dsn, record


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
    with conn.transaction():
        current = conn.execute("SELECT state,attempts FROM hosting.jobs WHERE id=%s FOR UPDATE", (job["id"],)).fetchone()
        if current["state"] != "RUNNING" or current["attempts"] != attempt:
            return False  # An expired lease was reclaimed; stale worker cannot overwrite it.
        if receipt:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,1))", (str(release["application_id"]),))
            conn.execute("UPDATE hosting.applications SET active_release_id=%s WHERE id=%s",
                         (release["id"], release["application_id"]))
            conn.execute("UPDATE hosting.releases SET state='HEALTHY_PRIVATE' WHERE id=%s", (release["id"],))
            conn.execute("UPDATE hosting.jobs SET state='COMPLETE',lease_until=NULL,receipt=%s::jsonb WHERE id=%s",
                         (json.dumps(receipt), job["id"]))
            if release["previous_release_id"]:
                conn.execute("UPDATE hosting.releases SET state='SUPERSEDED' WHERE id=%s AND state='HEALTHY_PRIVATE'",
                             (release["previous_release_id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (release["requested_by"],))
            record(conn, release["organization_id"], release["requested_by"], "release.private_healthy",
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
            conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli-%s, "
                         "reserved_memory_mb=reserved_memory_mb-%s WHERE id=%s",
                         (release["cpu_milli"], release["memory_mb"], release["node_id"]))
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
            conn.execute("UPDATE hosting.nodes SET reserved_cpu_milli=reserved_cpu_milli-%s, "
                         "reserved_memory_mb=reserved_memory_mb-%s WHERE id=%s",
                         (row["cpu_milli"], row["memory_mb"], row["node_id"]))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (row["requested_by"],))
            record(conn, row["organization_id"], row["requested_by"], "release.lease_expired",
                   row["release_id"], uuid.uuid4())


def process_once(conn, certificate):
    refresh_nodes(conn, certificate)
    sweep_retirements(conn, certificate)
    recover_expired(conn)
    claimed = claim(conn)
    if not claimed:
        return False
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
        receipt = node_request(node, payload, certificate)
        finalize(conn, job, release, attempt, receipt=receipt)
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
