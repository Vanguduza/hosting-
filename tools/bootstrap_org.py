#!/usr/bin/env python3
"""One-time organization enrollment by a trusted operator through a private DB session."""
import argparse
import os
import uuid

import psycopg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--owner-sub", required=True, help="Verified OIDC subject from the configured issuer")
    args = parser.parse_args()
    if not 1 <= len(args.name) <= 80 or not 1 <= len(args.owner_sub) <= 255:
        parser.error("invalid name or subject length")
    dsn = os.environ.get("HOSTING_MIGRATION_DSN")
    if not dsn:
        parser.error("HOSTING_MIGRATION_DSN required (migration role, private network only)")
    org_id, request_id = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        with conn.transaction():
            conn.execute("INSERT INTO hosting.organizations(id,name) VALUES (%s,%s)", (org_id, args.name))
            conn.execute(
                "INSERT INTO hosting.memberships(organization_id,actor_sub,role) VALUES (%s,%s,'owner')",
                (org_id, args.owner_sub),
            )
            conn.execute(
                "INSERT INTO hosting.audit_events(organization_id,actor_sub,action,resource_id,request_id,previous_hash,event_hash) "
                "VALUES (%s,%s,'organization.bootstrap',%s,%s,'',encode(public.digest(%s,'sha256'),'hex'))",
                (org_id, args.owner_sub, org_id, request_id,
                 args.owner_sub + "organization.bootstrap" + str(org_id) + str(request_id)),
            )
    print(org_id)


if __name__ == "__main__":
    main()
