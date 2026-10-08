#!/usr/bin/env python3
"""Import reviewed profile evidence using protected hosting operator credentials."""
import argparse
import json
import os
import stat
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'services/api'))
from hosting_api.__main__ import database_dsn
from hosting_api.intent_contract import unique_object
from hosting_api.execution_profiles import validate
from hosting_api.migrate import verify
from set_entitlement import protected

KEYS=('template_id','template_version','environment_profile')


def private_json(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,encoding='utf-8') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>65536:
            raise ValueError('Owned, private bounded regular profile file required')
        value=json.loads(file.read(65537),object_pairs_hook=unique_object)
    return validate(value)


def import_profile(conn,value,operator):
    validate(value)
    with conn.transaction():
        protected(conn,operator)
        # UUID first, tenant second, node rows in UUID order, then audit.
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,13))',(value['id'],))
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,12))',(value['organization_id'],))
        previous=conn.execute('SELECT payload,issued_by FROM hosting.execution_profile_versions WHERE id=%s',(value['id'],)).fetchone()
        if previous:
            if previous['payload']!=value or previous['issued_by']!=operator:raise ValueError('Profile idempotency conflict')
        else:
            conn.execute('INSERT INTO hosting.execution_profile_versions(id,organization_id,payload,issued_by) VALUES (%s,%s,%s,%s)',
                         (value['id'],value['organization_id'],Jsonb(value),operator))
        current=conn.execute('SELECT id FROM hosting.execution_profile_versions WHERE organization_id=%s AND '
            "payload->>'template_id'=%s AND payload->>'template_version'=%s AND payload->>'environment_profile'=%s ORDER BY revision DESC LIMIT 1",
            (value['organization_id'],*(value[k] for k in KEYS))).fetchone()
        return {'id':value['id'],'organization_id':value['organization_id'],'current':str(current['id'])==value['id'],'replayed':bool(previous)}


def node_binding(conn,node_id,operator):
    with conn.transaction():
        protected(conn,operator)
        row=conn.execute('SELECT id,hosting.execution_node_fingerprint(id) AS fingerprint FROM hosting.nodes WHERE id=%s',(node_id,)).fetchone()
        if not row:raise ValueError('Unknown node')
        return {'node_id':str(row['id']),'configuration_sha256':row['fingerprint']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('import').add_argument('--profile-file',required=True)
    commands.add_parser('node-binding').add_argument('node_id')
    args=parser.parse_args()
    try:
        with psycopg.connect(database_dsn(),row_factory=dict_row,connect_timeout=5) as conn:
            verify(conn)
            result=import_profile(conn,private_json(args.profile_file),args.operator) if args.command=='import' else node_binding(conn,args.node_id,args.operator)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Profile operation failed; check private input, protected credentials, reviewed evidence and migration ledger')


if __name__=='__main__':main()
