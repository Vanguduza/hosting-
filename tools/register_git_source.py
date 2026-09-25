#!/usr/bin/env python3
"""Operator-only registration of a DIAL-controlled GitHub push build source."""
import argparse
import os
import re
import uuid

import psycopg


def main():
    parser = argparse.ArgumentParser()
    for name in ("organization_id", "application_id", "repository_id", "full_name", "branch",
                 "image_repository", "dockerfile", "builder", "policy_revision"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    try:
        org, app = uuid.UUID(args.organization_id), uuid.UUID(args.application_id)
        repo_id = int(args.repository_id)
        if str(org) != args.organization_id or str(app) != args.application_id or repo_id <= 0:
            raise ValueError()
    except ValueError:
        parser.error("Canonical IDs required")
    patterns = {"full_name": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                "branch": r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}",
                "image_repository": r"[a-z0-9][a-z0-9./:_-]{1,240}",
                "dockerfile": r"[A-Za-z0-9][A-Za-z0-9_./-]{0,159}",
                "builder": r"[A-Za-z0-9_-]{1,64}",
                "policy_revision": r"[A-Za-z0-9._-]{1,64}"}
    for name, pattern in patterns.items():
        value = getattr(args, name)
        if not re.fullmatch(pattern, value) or (name in ("branch", "dockerfile") and ".." in value):
            parser.error("Invalid source property: " + name)
    if ":" in args.image_repository.rsplit("/", 1)[-1]:
        parser.error("Image repository must not include a tag")
    dsn = os.environ.get("HOSTING_MIGRATION_DSN")
    if not dsn:
        parser.error("Protected migration connection required")
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        with conn.transaction():
            current = conn.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
            if not current or not any(current):
                raise RuntimeError("Source registration requires the protected operator role")
            registered = conn.execute("INSERT INTO hosting.git_sources "
                                      "(id,organization_id,application_id,repository_id,full_name,branch,"
                                      "image_repository,dockerfile,builder,policy_revision) "
                                      "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                                      (uuid.uuid4(), org, app, repo_id, args.full_name, args.branch,
                                       args.image_repository, args.dockerfile, args.builder,
                                       args.policy_revision)).fetchone()
    print(registered[0])


if __name__ == "__main__":
    main()
