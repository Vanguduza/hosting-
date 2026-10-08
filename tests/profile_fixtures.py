"""Reviewed-profile fixture values are disposable and never installation evidence."""
import uuid
from datetime import datetime,timedelta,timezone

from tests.intent_fixtures import intent_fixture


def profile_fixture(org=None,node=None,intent=None,**changes):
    intent=intent or intent_fixture()
    now=datetime.now(timezone.utc)
    return {'schema_version':'1.0','id':str(uuid.uuid4()),'organization_id':str(org or uuid.uuid4()),
        **{key:intent[key] for key in ('template_id','template_version','environment_profile','runtime_class','release_artifact_ref',
                                      'database_profile','storage_profile','backup_profile','observability_profile')},
        'resource_ceiling':{'cpu_milli':2000,'memory_mb':4096},
        'node_bindings':[{'node_id':str(node or uuid.uuid4()),'configuration_sha256':'b'*64}],
        'enabled':True,'valid_from':(now-timedelta(minutes=1)).isoformat(),'valid_until':(now+timedelta(days=1)).isoformat(),
        'qualification_refs':{key:key+'-proof://private-profile-marker' for key in ('template','runtime','estate','compatibility')},**changes}
