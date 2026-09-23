#!/usr/bin/env python3
"""Operator enrollment after private mTLS connectivity and live capacity proof."""
import argparse
import json
import os
import sys
import uuid
from urllib.parse import urlsplit

import psycopg

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "api")))
from hosting_api.worker import node_capacity, private_endpoint


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True, help="Private https://FQDN:port")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args()
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
    node_id = uuid.uuid4()
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        conn.execute("INSERT INTO hosting.nodes(id,endpoint,server_name,enabled,cpu_milli,memory_mb,observed_at) "
                     "VALUES (%s,%s,%s,true,%s,%s,now())",
                     (node_id, args.endpoint, parsed.hostname, capacity["cpu_milli"], capacity["memory_mb"]))
    print(json.dumps({"node_id": str(node_id), "capacity": capacity}))


if __name__ == "__main__":
    main()
