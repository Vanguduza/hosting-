#!/usr/bin/env python3
"""Operator enrollment after private mTLS connectivity and live capacity proof."""
import argparse
import json
import os
import sys
import uuid
import ipaddress
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "api")))
from hosting_api.worker import node_capacity, private_endpoint


def register(conn, endpoint, server_name, public_ipv4, capacity):
    """Return the same node on a matching retry without duplicating inventory."""
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,2))", (endpoint,))
        existing = conn.execute("SELECT id,server_name,public_ipv4 FROM hosting.nodes "
                                "WHERE endpoint=%s FOR UPDATE", (endpoint,)).fetchone()
        if existing:
            if existing["server_name"] != server_name or str(existing["public_ipv4"]) != public_ipv4:
                raise ValueError("Existing node enrollment has a different identity")
            return existing["id"], True
        node_id = uuid.uuid4()
        conn.execute("INSERT INTO hosting.nodes(id,endpoint,server_name,public_ipv4,enabled,"
                     "cpu_milli,memory_mb,observed_at) VALUES (%s,%s,%s,%s,true,%s,%s,now())",
                     (node_id, endpoint, server_name, public_ipv4,
                      capacity["cpu_milli"], capacity["memory_mb"]))
        return node_id, False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True, help="Private https://FQDN:port")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--public-ipv4", required=True, help="Global IPv4 routed to ingress ports 80 and 443")
    args = parser.parse_args()
    if not ipaddress.IPv4Address(args.public_ipv4).is_global:
        parser.error("Public ingress address must be globally routable")
    parsed = urlsplit(args.endpoint)
    try:
        private_endpoint({"endpoint": args.endpoint, "server_name": parsed.hostname})
    except ValueError as exc:
        parser.error(str(exc))
    dsn = os.environ.get("HOSTING_MIGRATION_DSN")
    if not dsn:
        parser.error("HOSTING_MIGRATION_DSN required")
    node = {"endpoint": args.endpoint, "server_name": parsed.hostname}
    capacity = node_capacity(node, {"ca": args.ca_file, "cert": args.cert_file, "key": args.key_file})
    try:
        with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as conn:
            node_id, replayed = register(conn, args.endpoint, parsed.hostname, args.public_ipv4, capacity)
    except (ValueError, psycopg.errors.UniqueViolation):
        parser.error("Node identity already enrolled with a conflicting endpoint or address")
    print(json.dumps({"node_id": str(node_id), "capacity": capacity, "replayed": replayed}))


if __name__ == "__main__":
    main()
