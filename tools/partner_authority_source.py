#!/usr/bin/env python3
"""Register or disable a tenant's trusted Partner publisher using protected credentials."""
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
from hosting_api.migrate import verify
from hosting_api.partner_authority import validate
from set_entitlement import protected


def private_json(path, source=True):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,encoding='utf-8') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>65536:
            raise ValueError('Owner-only bounded regular file required')
        value=json.loads(file.read(65537),object_pairs_hook=unique_object)
    return validate(value,source=source)


def register(conn, value, operator):
    validate(value,source=True)
    with conn.transaction():
        protected(conn,operator)
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,10))',(value['organization_id'],))
        previous=conn.execute('SELECT payload,issued_by FROM hosting.partner_authority_sources WHERE id=%s',(value['id'],)).fetchone()
        if previous:
            if previous['payload']!=value or previous['issued_by']!=operator:
                raise ValueError('Publisher source idempotency conflict')
        else:
            conn.execute('INSERT INTO hosting.partner_authority_sources(id,organization_id,payload,issued_by) VALUES (%s,%s,%s,%s)',
                         (value['id'],value['organization_id'],Jsonb(value),operator))
        current=conn.execute('SELECT id FROM hosting.partner_authority_sources WHERE organization_id=%s ORDER BY revision DESC LIMIT 1',
                             (value['organization_id'],)).fetchone()
        return {'id':value['id'],'organization_id':value['organization_id'],'current':str(current['id'])==value['id'],'replayed':bool(previous)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-file',required=True)
    parser.add_argument('--operator',required=True)
    args=parser.parse_args()
    try:
        value=private_json(args.source_file)
        with psycopg.connect(database_dsn(),row_factory=dict_row,connect_timeout=5) as conn:
            verify(conn)
            result=register(conn,value,args.operator)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Publisher registration failed; check the private input, protected credentials and migration ledger')


if __name__=='__main__': main()
