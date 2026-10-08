"""Disposable reference authority, never real authorization or credentials."""
import uuid
from datetime import datetime,timedelta,timezone


def binding_fixture(org=None,app=None,**changes):
    now=datetime.now(timezone.utc)
    return {'schema_version':'1.0','id':str(uuid.uuid4()),'organization_id':str(org or uuid.uuid4()),
        'application_id':str(app or uuid.uuid4()),'secret_ref':'secret://private-marker/password#1',
        'bao_address':'https://bao.example.org','bao_mount':'dial','resource_id':str(uuid.uuid4()),
        'kv_version':1,'value_key':'password','enabled':True,'valid_from':(now-timedelta(minutes=1)).isoformat(),
        'valid_until':(now+timedelta(days=1)).isoformat(),'authorization_ref':'secret-proof://private-secret-proof',**changes}


class FakeBao:
    address='https://bao.example.org'
    mount='dial'

    def __init__(self,values=None):
        self.values=values if values is not None else {'password':'private-secret-value'}
        self.calls=[]

    def get_partner(self,org,app,resource,version):
        self.calls.append((org,app,resource,version))
        return version,self.values
