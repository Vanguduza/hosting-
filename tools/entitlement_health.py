#!/usr/bin/env python3
"""Read-only operator check for required, valid and bounded hosting assignments."""
import json
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services/api'))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify


def inspect(conn):
    if conn.execute('SELECT current_user AS role').fetchone()['role'] in SERVICE_ROLES:
        raise PermissionError('Protected operator credentials required')
    rows = conn.execute('SELECT o.id,v.id AS version_id,v.valid_from<=statement_timestamp() AND '
        'v.valid_until>statement_timestamp() AS active,q.organization_id IS NOT NULL AND '
        'q.cpu_milli_limit<=v.cpu_milli_limit AND q.memory_mb_limit<=v.memory_mb_limit AS quota_bounded,'
        'p.require_assigned FROM hosting.organizations o CROSS JOIN hosting.entitlement_policy p '
        'LEFT JOIN hosting.organization_entitlements e ON e.organization_id=o.id '
        'LEFT JOIN hosting.entitlement_versions v ON (v.organization_id,v.id)=(e.organization_id,e.version_id) '
        'LEFT JOIN hosting.organization_quotas q ON q.organization_id=o.id ORDER BY o.id').fetchall()
    required = rows[0]['require_assigned'] if rows else conn.execute(
        'SELECT require_assigned FROM hosting.entitlement_policy WHERE singleton').fetchone()['require_assigned']
    result = {'requires_assignment':required,
        'unassigned':[str(row['id']) for row in rows if not row['version_id']],
        'expired':[str(row['id']) for row in rows if row['version_id'] and not row['active']],
        'unbounded_quota':[str(row['id']) for row in rows if row['version_id'] and not row['quota_bounded']]}
    result['state'] = 'ENFORCED' if required and not any(result[key] for key in ('unassigned','expired','unbounded_quota')) else 'POLICY_GAPS'
    return result


def main():
    with psycopg.connect(database_dsn(),row_factory=dict_row,connect_timeout=5) as conn:
        verify(conn)
        result = inspect(conn)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['state']=='ENFORCED' else 2


if __name__=='__main__':
    raise SystemExit(main())
