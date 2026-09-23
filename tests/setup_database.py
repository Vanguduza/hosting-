"""Prepare disposable CI database only; never call against a persistent endpoint."""
import os

import psycopg


dsn = os.environ["TEST_SETUP_DSN"]
if "localhost" not in dsn and "127.0.0.1" not in dsn:
    raise RuntimeError("Test setup only accepts a local disposable PostgreSQL server")
with psycopg.connect(dsn, autocommit=True) as conn:
    conn.execute("CREATE ROLE hosting_api LOGIN PASSWORD 'api-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
    conn.execute("CREATE ROLE hosting_worker LOGIN PASSWORD 'worker-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
    conn.execute("CREATE ROLE hosting_admitter LOGIN PASSWORD 'admitter-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
    conn.execute("CREATE DATABASE hosting_ci")
