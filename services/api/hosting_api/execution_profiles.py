"""Protected reviewed execution profiles; matching is not platform certification."""
import json
from datetime import datetime,timedelta
from pathlib import Path

from jsonschema import Draft202012Validator,FormatChecker

SCHEMA=json.loads((Path(__file__).parent/'contracts/execution-profile-v1.schema.json').read_text())
VALIDATOR=Draft202012Validator(SCHEMA,format_checker=FormatChecker())
STATES=('UNCONFIGURED','DISABLED','NOT_YET_VALID','EXPIRED','PROFILE_MISMATCH','ARTIFACT_UNADMITTED',
        'BUDGET_EXCEEDED','NO_ELIGIBLE_NODE','PLACEMENT_MISMATCH','MATCHED')


def validate(value):
    if not VALIDATOR.is_valid(value):raise ValueError('Invalid execution profile contract')
    if any(type(v) is not int for v in value['resource_ceiling'].values()):raise ValueError('Integer resource ceilings required')
    nodes=[v['node_id'] for v in value['node_bindings']]
    if len(nodes)!=len(set(nodes)):raise ValueError('Unique node bindings required')
    start,end=(datetime.fromisoformat(value[k]) for k in ('valid_from','valid_until'))
    if not start<end<=start+timedelta(days=90):raise ValueError('Profile validity must span at most 90 days')
    return value


def handle(conn,org,app,intent):
    result=conn.execute('SELECT hosting.execution_profile_readback(%s,%s,%s) AS result',(org,app,intent)).fetchone()['result']
    return (200,result) if result else (404,{'error':'not_found'})
