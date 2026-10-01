"""Durable dedicated PostgreSQL provisioning with OpenBao CAS credentials."""
import http.client
import json
import secrets
import ssl
import uuid

from .__main__ import record
from .secrets import OpenBao, SecretError
from .worker import deliver_secrets, private_endpoint


def claim(conn):
    with conn.transaction():
        job = conn.execute(
            "SELECT id,instance_id,attempts FROM hosting.postgres_jobs "
            "WHERE attempts<3 AND ((state='PENDING' AND next_attempt_at<=now()) OR "
            "(state='RUNNING' AND lease_until<now())) "
            "ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1").fetchone()
        if not job:
            return None
        instance = conn.execute("SELECT * FROM hosting.postgres_instances WHERE id=%s", (job["instance_id"],)).fetchone()
        node = conn.execute("SELECT * FROM hosting.nodes WHERE id=%s", (instance["node_id"],)).fetchone()
        attempt = job["attempts"] + 1
        conn.execute("UPDATE hosting.postgres_jobs SET state='RUNNING',attempts=%s,"
                     "lease_until=now()+interval '10 minutes' WHERE id=%s", (attempt, job["id"]))
        conn.execute("UPDATE hosting.postgres_instances SET state='PROVISIONING' WHERE id=%s", (instance["id"],))
        return job, instance, node, attempt


def finalize(conn, job, instance, attempt, receipt=None, failure=None):
    if receipt and (receipt.get("instance_id") != str(instance["id"]) or
                    receipt.get("state") != "READY_PRIVATE" or receipt.get("secret_version") != 1):
        raise ValueError("PostgreSQL readiness proof invalid")
    with conn.transaction():
        current = conn.execute("SELECT state,attempts FROM hosting.postgres_jobs WHERE id=%s FOR UPDATE",
                               (job["id"],)).fetchone()
        if current["state"] != "RUNNING" or current["attempts"] != attempt:
            return False
        if receipt:
            conn.execute("UPDATE hosting.postgres_instances SET state='READY',secret_version=1 WHERE id=%s",
                         (instance["id"],))
            conn.execute("UPDATE hosting.postgres_jobs SET state='COMPLETE',lease_until=NULL,receipt=%s::jsonb "
                         "WHERE id=%s", (json.dumps(receipt), job["id"]))
            action = "postgres.ready"
        elif attempt < 3:
            conn.execute("UPDATE hosting.postgres_jobs SET state='PENDING',lease_until=NULL,last_error=%s, "
                         "next_attempt_at=now()+(%s * interval '1 second') WHERE id=%s",
                         (str(failure)[:120], attempt * 15, job["id"]))
            conn.execute("UPDATE hosting.postgres_instances SET state='QUEUED' WHERE id=%s", (instance["id"],))
            return True
        else:
            conn.execute("UPDATE hosting.postgres_jobs SET state='FAILED',lease_until=NULL,last_error=%s WHERE id=%s",
                         (str(failure)[:120], job["id"]))
            conn.execute("UPDATE hosting.postgres_instances SET state='FAILED' WHERE id=%s", (instance["id"],))
            action = "postgres.failed"
        conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (instance["requested_by"],))
        record(conn, instance["organization_id"], instance["requested_by"], action, instance["id"], uuid.uuid4())
        return True


def recover_expired(conn):
    with conn.transaction():
        expired = conn.execute("SELECT j.id,j.instance_id,i.organization_id,i.requested_by "
                               "FROM hosting.postgres_jobs j JOIN hosting.postgres_instances i ON i.id=j.instance_id "
                               "WHERE j.state='RUNNING' AND j.attempts=3 AND j.lease_until<now() "
                               "FOR UPDATE OF j SKIP LOCKED LIMIT 20").fetchall()
        for row in expired:
            conn.execute("UPDATE hosting.postgres_jobs SET state='FAILED',lease_until=NULL,"
                         "last_error='lease expired' WHERE id=%s", (row["id"],))
            conn.execute("UPDATE hosting.postgres_instances SET state='FAILED' WHERE id=%s", (row["instance_id"],))
            conn.execute("SELECT set_config('hosting.actor_sub',%s,true)", (row["requested_by"],))
            record(conn, row["organization_id"], row["requested_by"], "postgres.lease_expired",
                   row["instance_id"], uuid.uuid4())


def credential_revision(bao, instance_id):
    try:
        version, values = bao.get(instance_id, version=1)
    except SecretError:
        values = {"postgres_password": secrets.token_urlsafe(48), "app_password": secrets.token_urlsafe(48)}
        try:
            version = bao.put(instance_id, values, cas=0)
        except SecretError:
            # Concurrent workers may have created it. Fetch exact version;
            # never overwrite another revision on a CAS conflict.
            version, values = bao.get(instance_id, version=1)
    if version != 1 or set(values) != {"postgres_password", "app_password"}:
        raise RuntimeError("PostgreSQL credential version mismatch")
    return version


def provision(node, instance, certificate, bao):
    version = credential_revision(bao, instance["id"])
    deliver_secrets(node, instance["id"], version, certificate, bao)
    parsed = private_endpoint(node)
    context = ssl.create_default_context(cafile=certificate["ca"])
    context.load_cert_chain(certificate["cert"], certificate["key"])
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=300)
    try:
        payload = {"instance_id": str(instance["id"]), "application_id": str(instance["application_id"]),
                   "memory_mb": instance["memory_mb"], "cpu_milli": instance["cpu_milli"],
                   "secret_version": version}
        connection.request("PUT", "/v1/postgres", body=json.dumps(payload, separators=(",", ":")),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        receipt = json.loads(response.read(4096))
        if response.status != 200 or receipt.get("instance_id") != str(instance["id"]) or \
                receipt.get("state") != "READY_PRIVATE" or receipt.get("secret_version") != version:
            raise RuntimeError("Node PostgreSQL readiness not proven")
        return receipt
    finally:
        connection.close()


def process_once(conn, certificate):
    recover_expired(conn)
    claimed = claim(conn)
    if not claimed:
        return False
    job, instance, node, attempt = claimed
    try:
        if not node or not node["enabled"]:
            raise RuntimeError("Assigned node disabled or absent")
        receipt = provision(node, instance, certificate, OpenBao.environment())
        finalize(conn, job, instance, attempt, receipt=receipt)
    except (OSError, ssl.SSLError, ValueError, RuntimeError, SecretError) as exc:
        # Upstream exception messages may contain response content. Persist only
        # the error class, never credentials, URLs or request bodies.
        finalize(conn, job, instance, attempt, failure=type(exc).__name__)
    return True
