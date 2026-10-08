#!/usr/bin/env python3
"""Import scoped secret authority and check exact OpenBao versions; never print values."""
import argparse
import json
import os
import stat
import sys
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'services/api'))
from hosting_api.__main__ import database_dsn
from hosting_api.intent_contract import unique_object
from hosting_api.partner_secrets import validate
from hosting_api.secrets import OpenBao,SecretError
from hosting_api.migrate import verify
from set_entitlement import protected


def private_json(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,encoding='utf-8') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>16384:
            raise ValueError('Owned private bounded regular binding file required')
        value=json.loads(file.read(16385),object_pairs_hook=unique_object)
    return validate(value)


def binding_key(value):
    return ':'.join(value[k] for k in ('organization_id','application_id','secret_ref'))


def import_binding(conn,value,operator):
    validate(value)
    with conn.transaction():
        protected(conn,operator)
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,15))',(value['id'],))
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,14))',(binding_key(value),))
        previous=conn.execute('SELECT payload,issued_by FROM hosting.partner_secret_bindings WHERE id=%s',(value['id'],)).fetchone()
        if previous:
            if previous['payload']!=value or previous['issued_by']!=operator:raise ValueError('Binding idempotency conflict')
        else:
            conn.execute('INSERT INTO hosting.partner_secret_bindings(id,organization_id,application_id,payload,issued_by) VALUES (%s,%s,%s,%s,%s)',
                         (value['id'],value['organization_id'],value['application_id'],Jsonb(value),operator))
        current=conn.execute("SELECT id FROM hosting.partner_secret_bindings WHERE organization_id=%s AND application_id=%s AND payload->>'secret_ref'=%s ORDER BY revision DESC LIMIT 1",
            (value['organization_id'],value['application_id'],value['secret_ref'])).fetchone()
        return {'id':value['id'],'current':str(current['id'])==value['id'],'replayed':bool(previous)}


def check_binding(conn,binding_id,operator,check_id=None,bao=None):
    binding_id=uuid.UUID(str(binding_id));check_id=uuid.UUID(str(check_id)) if check_id else uuid.uuid4()
    with conn.transaction():
        protected(conn,operator)
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,16))',(str(check_id),))
        previous=conn.execute('SELECT id,binding_id,state,issued_by FROM hosting.partner_secret_checks WHERE id=%s',(check_id,)).fetchone()
        if previous:
            if previous['binding_id']!=binding_id or previous['issued_by']!=operator:raise ValueError('Check idempotency conflict')
            return {'id':str(check_id),'state':previous['state'],'replayed':True}
        binding=conn.execute('SELECT * FROM hosting.partner_secret_bindings WHERE id=%s',(binding_id,)).fetchone()
        if not binding:raise ValueError('Unknown binding')
        value=binding['payload']
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,14))',(binding_key(value),))
        # The database trigger checks newest enabled binding and current validity again.
        allowed=conn.execute("SELECT id=%s AND payload->'enabled'='true'::jsonb AND (payload->>'valid_from')::timestamptz<=clock_timestamp() AND (payload->>'valid_until')::timestamptz>clock_timestamp() AS allowed FROM hosting.partner_secret_bindings WHERE organization_id=%s AND application_id=%s AND payload->>'secret_ref'=%s ORDER BY revision DESC LIMIT 1",
            (binding_id,binding['organization_id'],binding['application_id'],value['secret_ref'])).fetchone()
        if not allowed or not allowed['allowed']:raise ValueError('Binding is no longer current and active')
        state='UNAVAILABLE'
        try:
            client=bao if bao is not None else OpenBao.environment()
            if client.address!=value['bao_address'] or client.mount!=value['bao_mount']:
                raise SecretError('OpenBao authority differs from binding')
            version,values=client.get_partner(value['organization_id'],value['application_id'],value['resource_id'],value['kv_version'])
            secret=values.get(value['value_key'])
            if version==value['kv_version'] and isinstance(secret,str) and 1<=len(secret)<=8192:state='AVAILABLE'
            # Values and their hashes are never part of the check, audit or stdout.
            del values,secret
        except (SecretError,OSError,ValueError,TypeError,AttributeError):
            pass
        conn.execute('INSERT INTO hosting.partner_secret_checks(id,organization_id,application_id,binding_id,state,issued_by) VALUES (%s,%s,%s,%s,%s,%s)',
                     (check_id,binding['organization_id'],binding['application_id'],binding_id,state,operator))
        return {'id':str(check_id),'state':state,'replayed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('import').add_argument('--binding-file',required=True)
    checked=commands.add_parser('check');checked.add_argument('binding_id');checked.add_argument('--check-id')
    args=parser.parse_args()
    try:
        with psycopg.connect(database_dsn(),row_factory=dict_row,connect_timeout=5) as conn:
            verify(conn)
            result=import_binding(conn,private_json(args.binding_file),args.operator) if args.command=='import' else check_binding(conn,args.binding_id,args.operator,args.check_id)
        print(json.dumps(result))
        if result.get('state')=='UNAVAILABLE':raise SystemExit(1)
    except Exception:
        raise SystemExit('Secret operation failed; check private input, protected credentials, scoped authority and migration ledger')


if __name__=='__main__':main()
