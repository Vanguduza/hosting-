#!/usr/bin/env python3
"""Import a hosting-local plan assignment using protected operator credentials."""
import argparse
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services/api'))
from hosting_api.__main__ import database_dsn
from hosting_api.migrate import SERVICE_ROLES, verify
from set_quota import set_quota

FEATURES = {'release', 'postgres', 'valkey', 'storage', 'domain', 'domain_registration', 'build'}
COUNTS = ('project_limit', 'application_limit', 'domain_limit', 'registration_limit')
CAPACITY = ('cpu_milli_limit', 'memory_mb_limit')
FIELDS = ('id', 'organization_id', 'plan_ref', 'evidence_ref', 'features', *CAPACITY, *COUNTS,
          'valid_from', 'valid_until')


def reference(value, kind):
    if not isinstance(value, str) or not re.fullmatch(kind + r'://[a-zA-Z0-9/_-]{1,120}', value):
        raise ValueError('Invalid plan or evidence reference')
    return value


def protected(conn, operator):
    if not isinstance(operator, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}', operator):
        raise ValueError('Invalid operator identity')
    if conn.execute('SELECT current_user AS role').fetchone()['role'] in SERVICE_ROLES:
        raise PermissionError('Protected operator credentials required')
    conn.execute("SELECT set_config('hosting.entitlement_operator',%s,true)", (operator,))


def assignment(value):
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError('Exact typed assignment fields required')
    result = dict(value)
    for name in ('id', 'organization_id'):
        if not isinstance(result[name], str) or str(uuid.UUID(result[name])) != result[name]:
            raise ValueError('Canonical assignment and tenant UUIDs required')
        result[name] = uuid.UUID(result[name])
    reference(result['plan_ref'], 'plan')
    reference(result['evidence_ref'], 'entitlement')
    features = result['features']
    if not isinstance(features, list) or any(not isinstance(item, str) for item in features) or \
            len(features) != len(set(features)) or not set(features) <= FEATURES:
        raise ValueError('Unique supported features required')
    result['features'] = sorted(features)
    for name in (*CAPACITY, *COUNTS):
        low, high = (1, 2**63-1) if name in CAPACITY else (0, 100000)
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise ValueError('Invalid plan limit')
    for name in ('valid_from', 'valid_until'):
        if not isinstance(result[name], str):
            raise ValueError('Explicit timezone required')
        result[name] = datetime.fromisoformat(result[name])
        if result[name].tzinfo is None:
            raise ValueError('Explicit timezone required')
    if result['valid_until'] <= result['valid_from']:
        raise ValueError('Entitlement expiry must follow activation')
    return result


def assign(conn, value, operator):
    value = assignment(value)
    with conn.transaction():
        protected(conn, operator)
        conn.execute('SELECT 1 FROM hosting.entitlement_policy WHERE singleton FOR SHARE')
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,7))', (str(value['organization_id']),))
        # UUIDs identify immutable assignments, including historical retries.
        previous = conn.execute('SELECT * FROM hosting.entitlement_versions WHERE id=%s', (value['id'],)).fetchone()
        if previous:
            if any(previous[name] != value[name] for name in FIELDS) or previous['issued_by'] != operator:
                raise ValueError('Entitlement idempotency conflict')
        else:
            conn.execute('INSERT INTO hosting.entitlement_versions (' + ','.join(FIELDS) + ',issued_by) VALUES (' +
                         ','.join(['%s'] * (len(FIELDS)+1)) + ')', tuple(value[name] for name in FIELDS) + (operator,))
            set_quota(conn, value['organization_id'], value['cpu_milli_limit'], value['memory_mb_limit'],
                      operator, 'Hosting entitlement assignment ' + str(value['id']))
            conn.execute('INSERT INTO hosting.organization_entitlements(organization_id,version_id) VALUES (%s,%s) '
                         'ON CONFLICT (organization_id) DO UPDATE SET version_id=EXCLUDED.version_id',
                         (value['organization_id'], value['id']))
        current = conn.execute('SELECT version_id FROM hosting.organization_entitlements WHERE organization_id=%s',
                               (value['organization_id'],)).fetchone()
        return {'id': str(value['id']), 'organization_id': str(value['organization_id']),
                'current': bool(current and current['version_id'] == value['id']), 'replayed': bool(previous)}


def enable(conn, operator, evidence):
    reference(evidence, 'entitlement')
    with conn.transaction():
        protected(conn, operator)
        conn.execute('SELECT require_assigned FROM hosting.entitlement_policy WHERE singleton FOR UPDATE')
        previous = conn.execute('SELECT operator_name,evidence_ref FROM hosting.entitlement_policy_changes').fetchone()
        if previous:
            if previous['operator_name'] != operator or previous['evidence_ref'] != evidence:
                raise ValueError('Enforcement evidence idempotency conflict')
            return {'requires_assignment': True, 'replayed': True}
        conn.execute("SELECT set_config('hosting.entitlement_evidence',%s,true)", (evidence,))
        conn.execute('UPDATE hosting.entitlement_policy SET require_assigned=true WHERE singleton')
        return {'requires_assignment': True, 'replayed': False}


def private_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate assignment field')
            result[key] = value
        return result
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, encoding='utf-8') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size>16384:
            raise ValueError('Assignment requires an owner-only regular file')
        value = json.loads(file.read(16385), object_pairs_hook=unique)
    assignment(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    imported = commands.add_parser('assign')
    imported.add_argument('--file', required=True)
    imported.add_argument('--confirm', choices=['assign_entitlement'], required=True)
    enabled = commands.add_parser('enable')
    enabled.add_argument('--evidence-ref', required=True)
    enabled.add_argument('--confirm', choices=['require_entitlements'], required=True)
    args = parser.parse_args()
    value = private_json(args.file) if args.command == 'assign' else None
    with psycopg.connect(database_dsn(), row_factory=dict_row, connect_timeout=5) as conn:
        verify(conn)
        result = assign(conn, value, args.operator) if value else enable(conn, args.operator, args.evidence_ref)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
