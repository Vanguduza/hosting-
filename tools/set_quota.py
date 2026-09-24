"""Set a tenant CPU/memory reservation ceiling with an operator audit record."""
import argparse
import os
import sys
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api"))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify


def set_quota(conn, organization_id, cpu_milli, memory_mb, operator, reason):
    if not 1 <= len(operator) <= 128 or not 10 <= len(reason) <= 500:
        raise ValueError("Operator or reason length invalid")
    if not 1 <= cpu_milli <= 2**63 - 1 or not 1 <= memory_mb <= 2**63 - 1:
        raise ValueError("Quota limits must be positive signed 64-bit integers")
    with conn.transaction():
        conn.execute("SELECT set_config('hosting.quota_operator',%s,true)", (operator,))
        conn.execute("SELECT set_config('hosting.quota_reason',%s,true)", (reason,))
        row = conn.execute(
            "INSERT INTO hosting.organization_quotas(organization_id,cpu_milli_limit,memory_mb_limit) "
            "VALUES (%s,%s,%s) ON CONFLICT (organization_id) DO UPDATE SET "
            "cpu_milli_limit=EXCLUDED.cpu_milli_limit,memory_mb_limit=EXCLUDED.memory_mb_limit "
            "RETURNING organization_id,cpu_milli_limit,memory_mb_limit,updated_at",
            (organization_id, cpu_milli, memory_mb)).fetchone()
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("organization_id", type=uuid.UUID)
    parser.add_argument("--cpu-milli", type=int, required=True)
    parser.add_argument("--memory-mb", type=int, required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--confirm", required=True, choices=["set_quota"])
    args = parser.parse_args()
    if os.environ.get("DB_USER") in SERVICE_ROLES:
        raise RuntimeError("Protected operator database credentials required")
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        row = set_quota(conn, args.organization_id, args.cpu_milli, args.memory_mb,
                        args.operator, args.reason)
    print("Tenant %s: %s milliCPU, %s MiB" %
          (row["organization_id"], row["cpu_milli_limit"], row["memory_mb_limit"]))


if __name__ == "__main__":
    main()
