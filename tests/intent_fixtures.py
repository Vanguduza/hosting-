"""Typed desired-state fixtures; no external authority or estate credentials."""
import uuid
from datetime import datetime, timedelta, timezone


def intent_fixture(project=None, **changes):
    return {'schema_version':'1.0', 'partner_id':'partner-private-marker',
        'dial_business_account_id':'business-private-marker', 'project_id':str(project or uuid.uuid4()),
        'template_id':'supplier', 'template_version':'1.0', 'environment_profile':'development',
        'runtime_class':'docker-http-v1', 'domain_intent':{'hostname':'supplier.example.org'},
        'database_profile':'none', 'storage_profile':'none', 'backup_profile':'encrypted-offhost-v1',
        'observability_profile':'release-health-v1', 'resource_budget':{'cpu_milli':500, 'memory_mb':1024},
        'release_artifact_ref':'registry.example.org/team/app@sha256:'+'a'*64,
        'secret_refs':['secret://private-marker/password#1'], 'tenant_admin_refs':['admin-private-marker'],
        'commercial_entitlement_ref':'commercial-private-marker', 'requested_by':'requester-private-marker',
        'request_id':str(uuid.uuid4()), **changes}


def evidence_fixture(intent):
    now = datetime.now(timezone.utc)
    release, node = str(uuid.uuid4()), str(uuid.uuid4())
    return {'observed_at':now.isoformat(), 'application':{'id':str(uuid.uuid4()),
        'project_id':intent['project_id'], 'environment':intent['environment_profile'], 'traffic_state':'ACTIVE'},
        'release':{'id':release, 'node_id':node, 'state':'SERVING', 'image':intent['release_artifact_ref'],
                   'cpu_milli':250, 'memory_mb':256},
        'node':{'id':node, 'enabled':True, 'observed_at':now.isoformat()},
        'health':{'release_id':release, 'state':'UP', 'checked_at':now.isoformat()},
        'domain':{'hostname':intent['domain_intent']['hostname'], 'verified_at':(now-timedelta(minutes=1)).isoformat()},
        'postgres':None, 'storage':None, 'artifact_admitted':True,
        'reservations':{'cpu_milli':'250', 'memory_mb':'256'},
        'organization_reserved':{'cpu_milli':'250', 'memory_mb':'256'},
        'plan':{'id':str(uuid.uuid4()), 'features':['release','domain','postgres','storage'],
                'valid_from':(now-timedelta(minutes=1)).isoformat(), 'valid_until':(now+timedelta(days=1)).isoformat(),
                'cpu_milli_limit':'2000', 'memory_mb_limit':'4096'},
        'quota':{'cpu_milli_limit':'2000', 'memory_mb_limit':'4096'}}
