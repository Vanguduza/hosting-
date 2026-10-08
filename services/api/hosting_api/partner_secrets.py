"""Protected secret references and redacted, bounded availability observations."""
import json
from datetime import datetime,timedelta
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator,FormatChecker

SCHEMA=json.loads((Path(__file__).parent/'contracts/partner-secret-binding-v1.schema.json').read_text())
VALIDATOR=Draft202012Validator(SCHEMA,format_checker=FormatChecker())
STATES=('NOT_REQUESTED','UNCONFIGURED','BINDING_DISABLED','NOT_YET_VALID','EXPIRED','CHECK_REQUIRED','CHECK_FAILED','MATCHED')


def validate(value):
    if not VALIDATOR.is_valid(value):raise ValueError('Invalid Partner secret binding')
    if type(value['kv_version']) is not int or int(value['secret_ref'].rsplit('#',1)[1])!=value['kv_version']:
        raise ValueError('Reference revision must equal the pinned KV version')
    port=urlsplit(value['bao_address']).port
    if port is not None and not 1<=port<=65535:raise ValueError('Invalid OpenBao port')
    start,end=(datetime.fromisoformat(value[k]) for k in ('valid_from','valid_until'))
    if not start<end<=start+timedelta(days=90):raise ValueError('Binding validity must span at most 90 days')
    return value


def handle(conn,org,app,intent):
    result=conn.execute('SELECT hosting.partner_secret_readback(%s,%s,%s) AS result',(org,app,intent)).fetchone()['result']
    return (200,result) if result else (404,{'error':'not_found'})
