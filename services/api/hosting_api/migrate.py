"""Transactional control-schema migrations with immutable SHA-256 history."""
import hashlib
import os
import re
from pathlib import Path

import psycopg

from .__main__ import database_dsn


SCHEMA = Path(__file__).resolve().parents[1] / "schema"
SERVICE_ROLES = {"hosting_api", "hosting_worker", "hosting_hook", "hosting_admitter", "hosting_buildworker"}


def files(directory=SCHEMA):
    scripts = sorted(directory.glob("*.sql"))
    if not scripts or [p.name for p in scripts] != sorted(p.name for p in scripts):
        raise RuntimeError("Migration files unavailable")
    for number, path in enumerate(scripts, 1):
        if not re.fullmatch(rf"{number:03d}_[a-z0-9_]+\.sql", path.name) or path.is_symlink():
            raise RuntimeError("Migration sequence invalid")
    return [(number, path.name, hashlib.sha256(path.read_bytes()).hexdigest(), path.read_text())
            for number, path in enumerate(scripts, 1)]


def apply(conn, directory=SCHEMA):
    scripts = files(directory)
    # A single transaction covers the history check, SQL execution and
    # history writes. The transaction-scoped lock serializes parallel starts.
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(7865487513380)")
        identity = conn.execute("SELECT current_user,rolsuper,rolbypassrls FROM pg_roles "
                                "WHERE rolname=current_user").fetchone()
        if not identity or identity[0] in SERVICE_ROLES:
            raise RuntimeError("Serving credentials cannot run schema migrations")
        if not conn.execute("SELECT has_database_privilege(current_user,current_database(),'CREATE')").fetchone()[0]:
            raise RuntimeError("Migration role requires database CREATE privilege")
        present = conn.execute("SELECT to_regnamespace('hosting') IS NOT NULL, "
                               "to_regclass('hosting.schema_migrations') IS NOT NULL").fetchone()
        if present == (True, False):
            raise RuntimeError("Existing untracked schema: audit and adopt its migration history first")
        conn.execute("CREATE SCHEMA IF NOT EXISTS hosting")
        conn.execute("CREATE TABLE IF NOT EXISTS hosting.schema_migrations ("
                     "version integer PRIMARY KEY CHECK (version>0),filename text NOT NULL,"
                     "sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),"
                     "applied_at timestamptz NOT NULL DEFAULT now())")
        installed = conn.execute("SELECT version,filename,sha256 FROM hosting.schema_migrations "
                                 "ORDER BY version").fetchall()
        if len(installed) > len(scripts):
            raise RuntimeError("Database contains unknown future migrations")
        for index, (number, filename, checksum) in enumerate(installed):
            if (number, filename, checksum) != scripts[index][:3]:
                raise RuntimeError("Migration history differs from repository")
        for number, filename, checksum, sql in scripts[len(installed):]:
            conn.execute(sql)
            conn.execute("INSERT INTO hosting.schema_migrations(version,filename,sha256) VALUES (%s,%s,%s)",
                         (number, filename, checksum))
        return len(scripts) - len(installed)


def verify(conn, directory=SCHEMA):
    """Refuse to serve when the database history differs from this image."""
    expected = [entry[:3] for entry in files(directory)]
    with conn.transaction():
        installed = conn.execute(
            "SELECT version,filename,sha256 FROM hosting.schema_migrations ORDER BY version"
        ).fetchall()
        if installed != expected:
            raise RuntimeError("Control schema differs from service image; run the protected migrator")


def main():
    if os.environ.get("DB_USER") in SERVICE_ROLES:
        raise RuntimeError("Serving credentials cannot run schema migrations")
    with psycopg.connect(database_dsn(), autocommit=True, connect_timeout=5) as conn:
        count = apply(conn)
    print(f"Control schema: {count} migrations applied; {len(files())} verified")


if __name__ == "__main__":
    main()
