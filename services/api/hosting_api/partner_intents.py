"""Durable HostingIntent intake and observation; no resource provisioning authority."""
import uuid
from datetime import datetime, timedelta

from psycopg.types.json import Jsonb

from .intent_contract import validate

PUBLIC_DESIRED = ('project_id','template_id','template_version','environment_profile','runtime_class',
                  'domain_intent','database_profile','storage_profile','backup_profile','observability_profile',
                  'resource_budget','release_artifact_ref')


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None:
        raise ValueError('Explicit observation timezone required')
    return result


def in_window(value, earliest, latest):
    try:
        return earliest<=timestamp(value)<=latest
    except (ValueError,TypeError,AttributeError):
        return False


def active_plan(plan, now):
    try:
        return timestamp(plan['valid_from']) <= now < timestamp(plan['valid_until'])
    except (ValueError, TypeError, AttributeError):
        return False


def evaluate(intent, digest, evidence):
    if not evidence:
        raise ValueError('Hosting evidence unavailable')
    now = timestamp(evidence['observed_at'])
    stages = []
    def stage(name, state, reason):
        stages.append({'stage':name,'state':state,'reason':reason})

    stage('intake','RECORDED','Typed desired state is recorded without transformations')
    authority = evidence.get('partner_authority') or {}
    approved = authority.get('state') == 'ACTIVE'
    stage('commercial_authority','MATCHED' if approved else 'BLOCKED',
          'Registered Partner publisher asserts the exact intent and current hosting plan' if approved else
          'Current trusted Partner approval is unavailable: ' + authority.get('state','UNCONFIGURED'))
    profile = evidence.get('execution_profile') or {}
    matched_profile = profile.get('state') == 'MATCHED'
    stage('profile_qualification','MATCHED' if matched_profile else 'BLOCKED',
          'Requested setup matches the current operator-reviewed template/runtime/estate profile and measured node bindings' if matched_profile else
          'Current reviewed execution profile is unavailable: ' + profile.get('state','UNCONFIGURED'))
    stage('tenant_admin_bindings','MATCHED' if approved else 'BLOCKED',
          'Publisher-bound administrator references resolve to current tenant owners or admins' if approved else
          'Current trusted administrator bindings are unavailable')
    secrets=evidence.get('partner_secrets') or {}
    matched_secrets=secrets.get('state')=='MATCHED' and secrets.get('requested_count')==len(intent['secret_refs']) and secrets.get('matched_count')==len(intent['secret_refs'])
    stage('secret_bindings',('MATCHED' if matched_secrets else 'BLOCKED') if intent['secret_refs'] else 'NOT_REQUESTED',
          ('All requested references have current scoped bindings and fresh exact-version OpenBao availability checks; no values are delivered' if matched_secrets else
           'Current scoped secret availability is missing: '+secrets.get('state','UNCONFIGURED')) if intent['secret_refs'] else 'No secret references requested')
    stage('backups','BLOCKED','Independent backup and restore evidence is not integrated into intent readback')

    app, release, node, health, domain = (evidence[key] for key in ('application','release','node','health','domain'))
    same_environment = app['project_id']==intent['project_id'] and app['environment']==intent['environment_profile']
    stage('tenant_project_environment','MATCHED' if same_environment else 'BLOCKED',
          'Recorded application belongs to the requested project and environment' if same_environment else 'Application binding differs from intent')
    supported = intent['database_profile'] in ('none','postgres-private-v1') and (
        intent['storage_profile']=='none' or (intent['storage_profile']=='garage-development-v1' and intent['environment_profile']=='development'))
    plan, quota = evidence['plan'], evidence['quota']
    required = {'release','domain'}
    if intent['database_profile']!='none': required.add('postgres')
    if intent['storage_profile']!='none': required.add('storage')
    budget, reservations, org_reserved = intent['resource_budget'], evidence['reservations'], evidence['organization_reserved']
    policy = bool(plan and quota and supported and active_plan(plan,now) and required<=set(plan['features']))
    if policy:
        for name in ('cpu_milli','memory_mb'):
            ceiling = min(int(plan[name+'_limit']),int(quota[name+'_limit']))
            policy = policy and int(org_reserved[name])-int(reservations[name])+budget[name]<=ceiling
    stage('hosting_plan','MATCHED' if policy else 'BLOCKED',
          'Current hosting assignment supports the requested features and budget headroom; no capacity is reserved' if policy else 'Valid hosting assignment, compatible features or budget headroom is missing')
    stage('artifact_admission','MATCHED' if evidence['artifact_admitted'] else 'BLOCKED',
          'Requested digest has an immutable hosting admission record' if evidence['artifact_admitted'] else 'Requested digest has no hosting admission record')
    bound = bool(same_environment and release and release['image']==intent['release_artifact_ref'] and release['state']=='SERVING')
    placed = bool(bound and node and node['enabled'] and in_window(node['observed_at'],now-timedelta(minutes=5),now))
    stage('runtime_placement','OBSERVED' if placed else 'BLOCKED',
          'Requested serving artifact has a recently observed enabled node' if placed else 'Requested serving artifact or fresh node placement evidence is missing')
    ownership = bool(domain and domain['hostname']==intent['domain_intent']['hostname'] and domain['verified_at'])
    stage('domain_ownership','MATCHED' if ownership else 'BLOCKED',
          'Requested hostname has matching tenant ownership proof' if ownership else 'Requested hostname lacks matching ownership proof')
    fresh = bool(health and in_window(health['checked_at'],now-timedelta(minutes=3),now))
    proof_precedes_health = bool(ownership and fresh and in_window(domain['verified_at'],
        datetime.min.replace(tzinfo=now.tzinfo), timestamp(health['checked_at'])))
    healthy = bool(bound and placed and proof_precedes_health and health['release_id']==release['id'] and
                   health['state']=='UP' and app['traffic_state']=='ACTIVE')
    stage('route_tls','OBSERVED' if healthy else 'BLOCKED',
          'Fresh public health evidence observes the requested hostname and serving release' if healthy else 'Fresh requested-hostname and release-bound public health evidence is missing')
    resources = True
    for key, profile in (('postgres','database_profile'),('storage','storage_profile')):
        row = evidence[key]
        compatible = intent[profile]=='postgres-private-v1' if key=='postgres' else (
            intent[profile]=='garage-development-v1' and intent['environment_profile']=='development')
        matched = row is None if intent[profile]=='none' else bool(compatible and row and row['state']=='READY' and
            (not release or row['node_id']==release['node_id']))
        resources = resources and matched
        stage(key,'MATCHED' if matched else 'BLOCKED',
              'Private service presence and supported profile match intent' if matched else 'Private service presence, readiness, profile or placement differs from intent')
    within = bound and resources and all(int(reservations[name])<=budget[name] for name in ('cpu_milli','memory_mb'))
    stage('resource_budget','MATCHED' if within else 'BLOCKED',
          'All open application reservations fit the requested CPU and memory budget' if within else 'Requested runtime/services are absent or open application reservations exceed the budget')
    stage('release_health','OBSERVED_HEALTHY' if healthy else 'BLOCKED',
          'Fresh health is bound to the requested serving artifact, environment and active traffic' if healthy else 'Fresh requested-artifact health evidence is missing or traffic is suspended')
    stage('observability','OBSERVED' if healthy else 'BLOCKED',
          'Current release-health observations are present' if healthy else 'Current requested-release observations are unavailable')
    return {'controller_version':'hosting-readback-v1','request_id':intent['request_id'],'intent_sha256':digest,
            'state':'NOT_QUALIFIED','observed_at':evidence['observed_at'],'resource_mutations_performed':False,
            'transformations':[],'stages':stages}


def public(row):
    result = {name:row[name] for name in ('id','application_id','intent_sha256','created_at')}
    result['state'] = 'RECORDED'
    result['desired'] = {name:row['payload'][name] for name in PUBLIC_DESIRED}
    result['evaluation'] = row.get('evaluation')
    return result


def observe(conn, row, actor, evaluation_id):
    evidence = conn.execute('SELECT hosting.partner_intent_evidence(%s,%s,%s) AS evidence',
                           (row['organization_id'],row['application_id'],row['id'])).fetchone()['evidence']
    receipt = evaluate(row['payload'],row['intent_sha256'],evidence)
    return conn.execute('INSERT INTO hosting.partner_intent_evaluations '
        '(organization_id,application_id,intent_id,id,receipt,evaluated_by) VALUES (%s,%s,%s,%s,%s,%s) '
        'RETURNING id,revision,created_at,receipt',
        (row['organization_id'],row['application_id'],row['id'],evaluation_id,Jsonb(receipt),actor)).fetchone()


def handle(handler, conn, org, app, actor, body, method, intent_id=None, reconcile=False):
    if method=='POST' and intent_id and not reconcile:
        return 404, {'error':'not_found'}
    if handler.membership(conn,org,actor) not in ('owner','admin'):
        return 404, {'error':'not_found'}
    if not conn.execute('SELECT 1 FROM hosting.applications WHERE organization_id=%s AND id=%s',(org,app)).fetchone():
        return 404, {'error':'not_found'}
    if method=='GET' and not reconcile:
        if intent_id:
            row = conn.execute('SELECT * FROM hosting.partner_intents WHERE organization_id=%s AND application_id=%s AND id=%s',
                               (org,app,intent_id)).fetchone()
            if not row: return 404, {'error':'not_found'}
            history = conn.execute('SELECT id,revision,created_at,receipt FROM hosting.partner_intent_evaluations '
                                  'WHERE organization_id=%s AND intent_id=%s ORDER BY revision DESC LIMIT 20',(org,intent_id)).fetchall()
            row['evaluation'] = history[0] if history else None
            return 200, {'intent':public(row),'evaluations':history}
        rows = conn.execute('SELECT i.*,e.evaluation FROM hosting.partner_intents i LEFT JOIN LATERAL '
            '(SELECT jsonb_build_object(\'id\',id,\'revision\',revision,\'created_at\',created_at,\'receipt\',receipt) AS evaluation '
            'FROM hosting.partner_intent_evaluations WHERE organization_id=i.organization_id AND intent_id=i.id '
            'ORDER BY revision DESC LIMIT 1) e ON true WHERE i.organization_id=%s AND i.application_id=%s '
            'ORDER BY i.created_at DESC,i.id LIMIT 50',(org,app)).fetchall()
        return 200, {'intents':[public(row) for row in rows]}
    if method!='POST': return 404, {'error':'not_found'}
    if reconcile:
        try:
            if set(body)!={'idempotency_key'}: raise ValueError()
            evaluation_id = uuid.UUID(body['idempotency_key'])
            if str(evaluation_id)!=body['idempotency_key']: raise ValueError()
        except (ValueError,TypeError,AttributeError):
            return 400, {'error':'invalid_reconciliation'}
    else:
        try:
            if set(body)!={'intent'}: raise ValueError()
            validate(body['intent'])
            intent_id = uuid.UUID(body['intent']['request_id'])
        except (ValueError,TypeError,KeyError):
            return 400, {'error':'invalid_hosting_intent'}
    if reconcile:
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,9))',(str(org)+':'+str(evaluation_id),))
    conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,8))',(str(org)+':'+str(intent_id),))
    row = conn.execute('SELECT * FROM hosting.partner_intents WHERE organization_id=%s AND id=%s',(org,intent_id)).fetchone()
    if reconcile:
        if not row or row['application_id']!=app: return 404, {'error':'not_found'}
        previous = conn.execute('SELECT intent_id,id,revision,created_at,receipt FROM hosting.partner_intent_evaluations '
                                'WHERE organization_id=%s AND id=%s',(org,evaluation_id)).fetchone()
        if previous:
            if previous.pop('intent_id')!=intent_id: return 409, {'error':'idempotency_conflict'}
            return 200, {'evaluation':previous,'replayed':True}
        return 201, {'evaluation':observe(conn,row,actor,evaluation_id),'replayed':False}
    if row:
        if row['application_id']!=app or row['payload']!=body['intent']:
            return 409, {'error':'idempotency_conflict'}
        history = conn.execute('SELECT id,revision,created_at,receipt FROM hosting.partner_intent_evaluations '
                              'WHERE organization_id=%s AND intent_id=%s ORDER BY revision DESC LIMIT 1',(org,intent_id)).fetchone()
        row['evaluation'] = history
        return 200, {'intent':public(row),'replayed':True}
    row = conn.execute('INSERT INTO hosting.partner_intents(organization_id,application_id,id,payload,submitted_by) '
                       'VALUES (%s,%s,%s,%s,%s) RETURNING *',(org,app,intent_id,Jsonb(body['intent']),actor)).fetchone()
    row['evaluation'] = observe(conn,row,actor,uuid.uuid4())
    return 201, {'intent':public(row),'replayed':False}
