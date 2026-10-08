"""Public contract for the implemented, versioned control API only."""
import re


UUID = {"type": "string", "format": "uuid", "description": "Canonical lowercase UUID"}
STRING = {"type": "string"}
INT = {"type": "integer"}
DATE = {"type": "string", "format": "date-time"}
BOOL = {"type": "boolean"}


def obj(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


def array(item):
    return {"type": "array", "items": item}


def response(schema, description="Successful operation"):
    return {"description": description, "content": {"application/json": {"schema": schema}}}


def operation(operation_id, summary, code, output, request=None, public=False, description=None):
    item = {"operationId": operation_id, "summary": summary,
            "responses": {str(code): response(output), "default": {"$ref": "#/components/responses/Error"}}}
    if description:
        item["description"] = description
    if request is not None:
        item["requestBody"] = {"required": True, "content": {"application/json": {"schema": request}}}
    if public:
        item["security"] = []
    return item


def document():
    from .intent_contract import SCHEMA as intent_schema
    identity = {"id": UUID}
    audit = {"request_id": UUID}
    resource = obj({"id": UUID, "node_id": UUID, "memory_mb": INT, "cpu_milli": INT,
                    "state": STRING, "secret_version": INT}, ("id", "node_id", "memory_mb", "cpu_milli",
                                                                "state", "secret_version"))
    def allocation(min_memory, max_memory, min_cpu, max_cpu):
        return obj({"idempotency_key": UUID,
                    "memory_mb": {"type": "integer", "minimum": min_memory, "maximum": max_memory},
                    "cpu_milli": {"type": "integer", "minimum": min_cpu, "maximum": max_cpu}},
                   ("idempotency_key", "memory_mb", "cpu_milli"))
    release_request = obj({"idempotency_key": UUID,
                           "image": {"type": "string", "pattern": "^[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}$"},
                           "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                           "health_path": {"type": "string", "pattern": "^/[A-Za-z0-9/_-]{0,127}$"},
                           "memory_mb": {"type": "integer", "minimum": 64, "maximum": 32768},
                           "cpu_milli": {"type": "integer", "minimum": 50, "maximum": 32000}},
                          ("idempotency_key", "image", "port", "health_path", "memory_mb", "cpu_milli"))
    queued = obj({**identity, "job_id": UUID, "state": {"const": "QUEUED"}, **audit},
                 ("id", "job_id", "state", "request_id"))
    org = "/v1/organizations/{organization_id}"
    app = org + "/applications/{application_id}"
    features = {'type': 'array', 'uniqueItems': True, 'maxItems': 7,
                'items': {'enum': ['release','postgres','valkey','storage','domain','domain_registration','build']}}
    decimal = {'type': 'string', 'pattern': '^[0-9]{1,19}$', 'description': 'Decimal integer, preserving 64-bit precision'}
    plan_fields = {'id': UUID, 'plan_ref': STRING, 'features': features, 'valid_from': DATE, 'valid_until': DATE,
                   'cpu_milli_limit': decimal, 'memory_mb_limit': decimal,
                   **{name: {'type': 'integer', 'minimum': 0, 'maximum': 100000}
                      for name in ('project_limit','application_limit','domain_limit','registration_limit')}}
    entitlement = obj({'authority': {'const': 'OPERATOR_ASSIGNED'},
                       'status': {'enum': ['UNCONFIGURED','ACTIVE','EXPIRED']}, 'requires_assignment': BOOL,
                       'version': {'oneOf': [obj(plan_fields, tuple(plan_fields)), {'type':'null'}]},
                       'usage': obj({'cpu_milli': decimal, 'memory_mb': decimal,
                                     **{name: {'type':'integer','minimum':0} for name in ('projects','applications','domains','registrations')}},
                                    ('cpu_milli','memory_mb','projects','applications','domains','registrations'))},
                      ('authority','status','requires_assignment','version','usage'))
    registration_request = obj({"idempotency_key": UUID,
        "hostname": {"type": "string", "pattern": "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.(com|co\\.zw)$"},
        "term_years": {"type": "integer", "minimum": 1, "maximum": 5},
        "registrant_ref": {"type": "string", "pattern": "^registrant://[a-z0-9/_-]{1,120}$"}},
        ("idempotency_key", "hostname", "term_years", "registrant_ref"))
    registration_receipt = obj({"id": UUID, "state": STRING, "replayed": BOOL, "fulfillment_mode": {"const": "MANUAL"}}, ("id", "state"))
    quote_payload = obj({"quote_id": UUID, "hostname": registration_request["properties"]["hostname"],
        "term_years": registration_request["properties"]["term_years"],
        "registrant_ref": registration_request["properties"]["registrant_ref"],
        "registrar": {"type": "string", "minLength": 1, "maxLength": 128},
        "provider": {"enum": ["OPENSRS", "ZISPA_MEMBER"]},
        "initial_amount_minor": {"type": "integer", "minimum": 1, "maximum": 2147483647},
        "renewal_amount_minor": {"type": "integer", "minimum": 0, "maximum": 2147483647},
        "renewal_term_years": {"const": 1}, "currency": {"enum": ["USD", "ZAR", "ZWG"]},
        "expires_at": DATE, "terms_text": {"type": "string", "minLength": 10, "maxLength": 4000},
        "provider_quote_ref": {"type": "string", "pattern": "^quote://[a-zA-Z0-9/_-]{1,120}$"},
        "fulfillment_mode": {"const": "MANUAL"}},
        ("quote_id", "hostname", "term_years", "registrant_ref", "registrar", "provider",
         "initial_amount_minor", "renewal_amount_minor", "renewal_term_years", "currency", "expires_at",
         "terms_text", "provider_quote_ref", "fulfillment_mode"))
    digest = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    registration_readback = obj({"id": UUID,
        **{name: registration_request["properties"][name] for name in ("hostname", "term_years", "registrant_ref")},
        "state": {"enum": ["REQUESTED", "QUOTED", "APPROVED", "PROCESSING", "FULFILLMENT_RECORDED", "CANCELLED", "FAILED"]},
        "created_at": DATE, "updated_at": DATE,
        "approved_at": {"oneOf": [DATE, {"type": "null"}]},
        "fulfilled_at": {"oneOf": [DATE, {"type": "null"}]},
        "receipt_sha256": {"oneOf": [digest, {"type": "null"}]},
        "quote": {"oneOf": [obj({"id": UUID, "sha256": digest, "payload": quote_payload},
                                  ("id", "sha256", "payload")), {"type": "null"}]}},
        ("id", "hostname", "term_years", "registrant_ref", "state", "created_at", "updated_at",
         "approved_at", "fulfilled_at", "receipt_sha256", "quote"))
    paths = {
        "/v1/auth/config": {"get": operation("loginConfiguration", "Read configured public-client sign-in settings", 200,
            {"oneOf": [obj({"enabled": {"const": False}}, ("enabled",)),
                obj({"enabled": {"const": True}, "issuer": STRING, "client_id": STRING,
                     "authorization_url": STRING, "redirect_uri": STRING, "scopes": array(STRING)},
                    ("enabled", "issuer", "client_id", "authorization_url", "redirect_uri", "scopes"))]}, public=True)},
        "/live": {"get": operation("live", "Process liveness only", 200,
                                     obj({"status": {"const": "process_alive"}}, ("status",)), public=True)},
        "/ready": {"get": operation("ready", "Authenticated database reachability", 200,
                                      obj({"status": {"const": "database_reachable"}}, ("status",)))},
        "/openapi.json": {"get": operation("openApi", "Read this API contract", 200,
                                             {"type": "object"}, public=True)},
        "/v1/organizations": {"get": operation("listOrganizations", "List memberships", 200,
            obj({"organizations": array(obj({"id": UUID, "name": STRING,
                                               "role": {"enum": ["owner", "admin", "viewer"]}},
                                              ("id", "name", "role")))}, ("organizations",)))},
        org + "/audit": {"get": {**operation("listAuditEvents", "Read verified tenant audit chain", 200,
            obj({"events": array(obj({"id": INT, "actor_sub": STRING, "action": STRING,
                                       "resource_id": UUID, "request_id": UUID,
                                       "previous_hash": STRING, "event_hash": STRING,
                                       "created_at": DATE},
                                      ("id", "actor_sub", "action", "resource_id", "request_id",
                                       "previous_hash", "event_hash", "created_at"))),
                 "next_after": INT, "has_more": BOOL}, ("events", "next_after", "has_more"))),
            "parameters": [{"name": "after", "in": "query", "required": False,
                            "schema": {"type": "integer", "minimum": 0, "maximum": 9223372036854775807},
                            "description": "Exclusive committed event ID cursor; default 0."}]}},
        org + "/capacity": {"get": {**operation("readCapacityIntervals", "Read reserved capacity intervals", 200,
            obj({"from": DATE, "to": DATE, "coverage_start": DATE,
                 "allocations": array(obj({"resource_type": {"enum": ["release", "postgres", "valkey", "storage"]},
                                           "reservations": INT, "reserved_cpu_milli_ms": INT,
                                           "reserved_memory_mb_ms": INT},
                                          ("resource_type", "reservations", "reserved_cpu_milli_ms",
                                           "reserved_memory_mb_ms")))},
                ("from", "to", "coverage_start", "allocations")),
            description="Reserved CPU and memory, not measured consumption or a bill. The window must be within the ledger coverage epoch."),
            "parameters": [{"name": name, "in": "query", "required": True,
                            "schema": {"type": "string", "format": "date-time"},
                            "description": "UTC timestamp with second precision; to is exclusive."}
                           for name in ("from", "to")]}},
        org + '/entitlements': {'get': operation('readHostingEntitlements', 'Read the current hosting plan and limits', 200,
            entitlement, description='Human tenant membership required. Operator evidence is private. Expired assignments block new work and hold queued execution. This is hosting-local policy, not a billing or commercial entitlement authority.')},
        org + "/quotas": {"get": operation("readReservationQuota", "Read active reservation ceiling", 200,
            obj({"mode": {"enum": ["OPERATOR_SET", "UNBOUNDED"]},
                 "quota": {"oneOf": [obj({"cpu_milli_limit": INT, "memory_mb_limit": INT,
                                           "updated_at": DATE},
                                          ("cpu_milli_limit", "memory_mb_limit", "updated_at")),
                                      {"type": "null"}]},
                 "reserved": obj({"cpu_milli": INT, "memory_mb": INT},
                                 ("cpu_milli", "memory_mb"))},
                ("mode", "quota", "reserved")),
            description="Operator-set limits on active reservations; UNBOUNDED means no tenant ceiling. Node capacity still applies.")},
        "/v1/team/invitations/accept": {"post": operation("acceptInvitation", "Accept one-time team invitation", 200,
            obj({"organization_id": UUID, "role": STRING, "state": {"const": "JOINED"},
                 "replayed": BOOL, **audit}, ("organization_id", "role", "state", "replayed", "request_id")),
            obj({"token": {"type": "string", "minLength": 43, "maxLength": 43}}, ("token",)))},
        org + "/service-accounts": {
            "get": operation("listServiceAccounts", "List application service grants (owner)", 200,
                obj({"service_accounts": array(obj({"id": UUID, "application_id": UUID,
                    "client_id": STRING, "actor_sub": STRING, "created_by": STRING,
                    "created_at": DATE, "revoked_at": {"type": ["string", "null"], "format": "date-time"}},
                    ("id", "application_id", "client_id", "actor_sub", "created_by", "created_at",
                     "revoked_at")))}, ("service_accounts",))),
            "post": operation("createServiceAccount", "Grant one application release access (owner)", 201,
                obj({"id": UUID, "application_id": UUID, **audit},
                    ("id", "application_id", "request_id")),
                obj({"application_id": UUID, "client_id": {"type": "string", "minLength": 1, "maxLength": 128},
                     "actor_sub": {"type": "string", "minLength": 1, "maxLength": 255}},
                    ("application_id", "client_id", "actor_sub")),
                description="Register the exact issuer client_id and subject for a token with the separate service audience.")},
        org + "/service-accounts/revoke": {"post": operation("revokeServiceAccount", "Revoke service grant (owner)", 200,
            obj({"state": {"const": "REVOKED"}, **audit}, ("state", "request_id")),
            obj({"id": UUID, "confirm": {"const": "revoke_service_account"}},
                ("id", "confirm")))},
        org + "/projects": {
            "get": operation("listProjects", "List tenant projects", 200,
                obj({"projects": array(obj({"id": UUID, "name": STRING, "created_at": DATE},
                                           ("id", "name", "created_at")))}, ("projects",))),
            "post": operation("createProject", "Create tenant project", 201,
                obj({**identity, "name": STRING, **audit}, ("id", "name", "request_id")),
                obj({"name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$"}},
                    ("name",)))},
        org + "/team/invitations": {
            "get": operation("listInvitations", "List tenant invitations (owner)", 200,
                obj({"invitations": array(obj({"id": UUID, "role": STRING, "issued_by": STRING,
                    "expires_at": DATE, "created_at": DATE, "accepted_by": {"type": ["string", "null"]},
                    "accepted_at": {"type": ["string", "null"], "format": "date-time"},
                    "revoked_at": {"type": ["string", "null"], "format": "date-time"}},
                    ("id", "role", "issued_by", "expires_at", "created_at")))}, ("invitations",))),
            "post": operation("createInvitation", "Issue one-time tenant invitation (owner)", 201,
                obj({**identity, "token": STRING, "expires_at": DATE, "role": STRING, **audit},
                    ("id", "token", "expires_at", "role", "request_id")),
                obj({"idempotency_key": UUID, "role": {"enum": ["admin", "viewer"]},
                     "expires_hours": {"type": "integer", "minimum": 1, "maximum": 72},
                     "confirm": {"enum": ["invite_admin", "invite_viewer"]}},
                    ("idempotency_key", "role", "expires_hours", "confirm")),
                description="A matching retry returns 200 without the plaintext token.")},
        org + "/team/invitations/revoke": {"post": operation("revokeInvitation", "Revoke invitation (owner)", 200,
            obj({"state": {"const": "REVOKED"}, **audit}, ("state", "request_id")),
            obj({"invitation_id": UUID}, ("invitation_id",)))},
        org + "/team/members": {"get": operation("listMembers", "List tenant members (owner)", 200,
            obj({"members": array(obj({"actor_sub": STRING, "role": STRING},
                                      ("actor_sub", "role")))}, ("members",)))},
        org + "/team/members/remove": {"post": operation("removeMember", "Remove tenant member (owner)", 200,
            obj({"state": {"const": "REMOVED"}, **audit}, ("state", "request_id")),
            obj({"actor_sub": STRING, "confirm": {"const": "remove_member"}},
                ("actor_sub", "confirm")))},
        org + "/projects/{project_id}/applications": {
            "get": operation("listApplications", "List project applications", 200,
                obj({"applications": array(obj({"id": UUID, "name": STRING, "environment": STRING,
                    "active_release_id": {"type": ["string", "null"], "format": "uuid"},
                    "created_at": DATE}, ("id", "name", "environment", "created_at")))},
                    ("applications",))),
            "post": operation("createApplication", "Create project application", 201,
                obj({**identity, **audit}, ("id", "request_id")),
                obj({"name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}$"},
                    "environment": {"type": "string",
                    "pattern": "^[a-z][a-z0-9-]{0,31}$"}}, ("name", "environment")))},
        app + "/traffic": {
            "get": operation("getApplicationTraffic", "Read public traffic control state", 200,
                obj({"traffic": obj({"traffic_state": {"enum": ["ACTIVE", "SUSPENDING", "SUSPENDED", "RESUMING"]},
                    "traffic_reason": {"type": ["string", "null"]},
                    "traffic_requested_by": {"type": ["string", "null"]},
                    "traffic_updated_at": DATE,
                    "traffic_last_error": {"type": ["string", "null"]}},
                    ("traffic_state", "traffic_reason", "traffic_requested_by", "traffic_updated_at",
                     "traffic_last_error"))}, ("traffic",))),
            "post": operation("changeApplicationTraffic", "Request owner-controlled route suspension or resume", 202,
                obj({"state": {"enum": ["SUSPENDING", "RESUMING"]}, **audit}, ("state", "request_id")),
                obj({"action": {"enum": ["suspend", "resume"]},
                     "reason": {"type": "string", "minLength": 3, "maxLength": 240},
                     "confirm": {"enum": ["suspend_application", "resume_application"]}},
                    ("action", "reason", "confirm")),
                description="Owner only. A 202 is intent; poll GET until SUSPENDED or ACTIVE for route proof.")},
        app + "/domain": {
            "get": operation("getDomain", "Read domain and pending TXT challenge", 200,
                obj({"domain": {"oneOf": [{"type": "null"}, obj({"id": UUID, "hostname": STRING,
                    "verified_at": {"type": ["string", "null"], "format": "date-time"},
                    "challenge_expires_at": DATE, "txt_name": STRING, "txt_value": STRING},
                    ("id", "hostname", "verified_at", "challenge_expires_at"))]}}, ("domain",))),
            "post": operation("registerDomain", "Reserve domain and return TXT challenge", 201,
                obj({**identity, "hostname": STRING, "txt_name": STRING, "txt_value": STRING,
                     **audit}, ("id", "hostname", "txt_name", "txt_value", "request_id")),
                obj({"hostname": STRING}, ("hostname",)))},
        app + "/domain/verify": {"post": operation("verifyDomain", "Prove domain TXT ownership", 200,
            obj({**identity, "verified_at": DATE}, ("id", "verified_at")), obj({}, ()))},
        app + "/builds": {"get": operation("listBuilds", "Read registered GitHub build status", 200,
            obj({"builds": array(obj({"delivery_id": UUID, "source_commit": STRING,
                "state": STRING, "attempts": INT, "image": {"type": ["string", "null"]},
                "last_error": {"type": ["string", "null"]}, "created_at": DATE,
                "source_id": UUID, "full_name": STRING, "branch": STRING},
                ("delivery_id", "source_commit", "state", "attempts", "created_at",
                 "source_id", "full_name", "branch")))}, ("builds",)))},
        app + "/health": {"get": operation("getReleaseHealth", "Read observed public release health", 200,
            obj({"state": {"enum": ["NOT_DEPLOYED", "SUSPENDING", "SUSPENDED", "RESUMING",
                                      "UNKNOWN", "UP", "DEGRADED", "DOWN"]},
                 "release_id": {"type": ["string", "null"], "format": "uuid"},
                 "checked_at": {"type": ["string", "null"], "format": "date-time"},
                 "consecutive_failures": INT},
                ("state", "release_id", "checked_at", "consecutive_failures")),
            description="The current serving release is checked every minute. Observations older than three minutes are UNKNOWN; suspended traffic has its own state.")},
        app + "/health/incidents": {"get": operation("listReleaseHealthIncidents", "Read recent public outage episodes", 200,
            obj({"incidents": array(obj({"id": UUID, "release_id": UUID, "opened_at": DATE,
                "closed_at": {"type": ["string", "null"], "format": "date-time"},
                "resolution": {"enum": ["RECOVERED", "SUSPENDED", "SUPERSEDED", None]}},
                ("id", "release_id", "opened_at", "closed_at", "resolution")))}, ("incidents",)),
            description="Up to 100 most recent third-failure episodes. An open episode does not override a stale UNKNOWN observation.")},
        app + "/releases": {
            "get": operation("listReleases", "Read release history", 200,
                obj({"releases": array(obj({"id": UUID, "image": STRING, "state": STRING,
                    "node_id": UUID, "previous_release_id": {"type": ["string", "null"], "format": "uuid"},
                    "rollback_of_release_id": {"type": ["string", "null"], "format": "uuid"},
                    "created_at": DATE}, ("id", "image", "state", "node_id", "created_at")))},
                    ("releases",))),
            "post": operation("queueRelease", "Queue admitted immutable release", 202,
                obj({**queued["properties"], "rollback_of_release_id": {"type": "null"}},
                    (*queued["required"], "rollback_of_release_id")), release_request,
                description="Requires a verified domain, admitted digest and live node reservation; 200 on matching replay.")},
        app + "/rollback": {"post": operation("queueRollback", "Queue previous release as a new deployment", 202,
            obj({**queued["properties"], "rollback_of_release_id": UUID},
                (*queued["required"], "rollback_of_release_id")),
            obj({"target_release_id": UUID, "idempotency_key": UUID},
                ("target_release_id", "idempotency_key")))},
        app + "/postgres": {
            "get": operation("getPostgres", "Read dedicated PostgreSQL state", 200,
                obj({"postgres": {"oneOf": [{"type": "null"}, resource]}}, ("postgres",))),
            "post": operation("queuePostgres", "Provision dedicated PostgreSQL", 202, queued,
                              allocation(256, 32768, 100, 32000))},
        app + "/valkey": {
            "get": operation("getValkey", "Read private Valkey state", 200,
                obj({"valkey": {"oneOf": [{"type": "null"}, resource]}}, ("valkey",))),
            "post": operation("queueValkey", "Provision private Valkey", 202, queued,
                              allocation(128, 16384, 100, 16000))},
        app + "/storage": {
            "get": operation("getStorage", "Read private object storage state", 200,
                obj({"storage": {"oneOf": [{"type": "null"}, resource]}}, ("storage",))),
            "post": operation("queueStorage", "Provision an application-bound private S3 bucket", 202,
                              queued, allocation(256, 16384, 100, 16000),
                              description="Single-node persistent Garage profile; no public endpoint or redundancy.")},
    }
    from .partner_intents import PUBLIC_DESIRED
    intent_stage = obj({'stage': STRING, 'state': {'enum': ['RECORDED', 'MATCHED', 'OBSERVED',
        'OBSERVED_HEALTHY', 'BLOCKED', 'NOT_REQUESTED']}, 'reason': STRING}, ('stage', 'state', 'reason'))
    intent_receipt = obj({'controller_version': {'const': 'hosting-readback-v1'}, 'request_id': UUID,
        'intent_sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}, 'state': {'const': 'NOT_QUALIFIED'},
        'observed_at': DATE, 'resource_mutations_performed': {'const': False},
        'transformations': {'type': 'array', 'maxItems': 0}, 'stages': array(intent_stage)},
        ('controller_version', 'request_id', 'intent_sha256', 'state', 'observed_at',
         'resource_mutations_performed', 'transformations', 'stages'))
    intent_evaluation = obj({'id': UUID, 'revision': {'type': 'integer', 'minimum': 1},
        'created_at': DATE, 'receipt': intent_receipt}, ('id', 'revision', 'created_at', 'receipt'))
    intent_summary = obj({'id': UUID, 'application_id': UUID,
        'intent_sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}, 'state': {'const': 'RECORDED'},
        'created_at': DATE, 'desired': obj({key: intent_schema['properties'][key] for key in PUBLIC_DESIRED}, PUBLIC_DESIRED),
        'evaluation': {'oneOf': [{'type': 'null'}, intent_evaluation]}},
        ('id', 'application_id', 'intent_sha256', 'state', 'created_at', 'desired', 'evaluation'))
    intent_submission = obj({'intent': intent_summary, 'replayed': {'type': 'boolean'}}, ('intent', 'replayed'))
    intent_reconciliation = obj({'evaluation': intent_evaluation, 'replayed': {'type': 'boolean'}}, ('evaluation', 'replayed'))
    intents = app + '/intents'
    paths[intents] = {
        'get': operation('listHostingIntents', 'Read up to 50 recorded intents and latest observations', 200,
            obj({'intents': {**array(intent_summary), 'maxItems': 50}}, ('intents',)),
            description='Human owners and administrators only. Private authority and secret references are excluded.'),
        'post': operation('recordHostingIntent', 'Record immutable desired state and initial observation', 201,
            intent_submission, obj({'intent': intent_schema}, ('intent',)),
            description='Human owners and administrators only. Existing project/environment binding is required. No resources are provisioned or commercial authority granted.')}
    paths[intents]['post']['responses']['200'] = response(intent_submission, 'Matching immutable request replay')
    paths[intents + '/{intent_id}'] = {'get': operation('getHostingIntent', 'Read intent and up to 20 historical observations', 200,
        obj({'intent': intent_summary, 'evaluations': {**array(intent_evaluation), 'maxItems': 20}}, ('intent', 'evaluations')))}
    paths[intents + '/{intent_id}/reconcile'] = {'post': operation('reconcileHostingIntent', 'Record a consistent hosting-state observation', 201,
        intent_reconciliation, obj({'idempotency_key': UUID}, ('idempotency_key',)),
        description='Human owners and administrators only. Matching key replays the original historical observation; use a fresh key to observe again. All receipts remain NOT_QUALIFIED.')}
    paths[intents + '/{intent_id}/reconcile']['post']['responses']['200'] = response(intent_reconciliation, 'Original historical observation replay')
    from .partner_authority import RECEIPT_SCHEMA
    nullable_uuid = {'oneOf': [UUID, {'type': 'null'}]}
    nullable_date = {'oneOf': [DATE, {'type': 'null'}]}
    authority_summary = obj({'organization_id': UUID, 'application_id': UUID, 'intent_id': UUID,
        'observed_at': DATE, 'state': {'enum': ['UNCONFIGURED','SOURCE_DISABLED','AWAITING_RECEIPT',
            'REVOKED','SOURCE_CHANGED','EXPIRED','PLAN_UNAVAILABLE','PLAN_CHANGED','ADMIN_UNBOUND','ACTIVE']},
        'source_version_id': nullable_uuid, 'receipt_id': nullable_uuid,
        'sequence': {'oneOf': [{'type': 'string', 'pattern': '^[1-9][0-9]{0,18}$'}, {'type': 'null'}]},
        'issued_at': nullable_date, 'valid_until': nullable_date, 'hosting_entitlement_version_id': nullable_uuid},
        ('organization_id','application_id','intent_id','observed_at','state','source_version_id','receipt_id',
         'sequence','issued_at','valid_until','hosting_entitlement_version_id'))
    authority_ack = obj({'id': UUID,'state': {'const':'RECORDED'},
        'sequence': {'type':'string','pattern':'^[1-9][0-9]{0,18}$'},'replayed': {'type':'boolean'}},
        ('id','state','sequence','replayed'))
    paths[intents + '/{intent_id}/authority'] = {
        'get': operation('readPartnerAuthority','Read current redacted approval status',200,authority_summary,
            description='Human owners and administrators only. Current checks are separate from immutable historical intent observations.'),
        'post': operation('publishPartnerAuthority','Record an existing external Partner decision',201,authority_ack,
            obj({'receipt': RECEIPT_SCHEMA},('receipt',)),
            description='Registered machine publisher only, with exact verified issuer, service audience, client and subject. Tenant source version, intent hash, monotonic sequence, expiry, current hosting plan and existing administrator bindings are checked. No resources, memberships or business records are changed.')}
    paths[intents + '/{intent_id}/authority']['post']['responses']['200'] = response(authority_ack,'Original immutable receipt replay; does not reactivate an approval')
    from .execution_profiles import STATES as profile_states
    profile_summary = obj({'organization_id':UUID,'application_id':UUID,'intent_id':UUID,
        'intent_sha256':{'type':'string','pattern':'^[a-f0-9]{64}$'},'observed_at':DATE,
        'state':{'enum':list(profile_states)},'profile_version_id':nullable_uuid,
        'profile_sha256':{'oneOf':[{'type':'string','pattern':'^[a-f0-9]{64}$'},{'type':'null'}]},
        'valid_from':nullable_date,'valid_until':nullable_date},
        ('organization_id','application_id','intent_id','intent_sha256','observed_at','state',
         'profile_version_id','profile_sha256','valid_from','valid_until'))
    paths[intents + '/{intent_id}/profile'] = {'get':operation('readExecutionProfile','Read current reviewed setup compatibility',200,profile_summary,
        description='Human owners and administrators only. Checks the latest protected profile version, exact desired setup, admitted digest, bounded budget and fresh measured node bindings. Private qualification evidence and estate details are excluded. A match does not certify the estate or authorize resource execution.')}
    replay = response(obj({"id": UUID, "state": STRING, "replayed": {"const": True}},
                          ("id", "state", "replayed")), "Matching idempotent replay")
    registrations = org + "/domain-registrations"
    paths[registrations] = {
        "get": operation("listDomainRegistrations", "Owner registration/quote/fulfillment readback", 200,
            obj({"registrations": {**array(registration_readback), "maxItems": 25}, "fulfillment_mode": {"const": "MANUAL"}},
                ("registrations", "fulfillment_mode"))),
        "post": operation("requestDomainRegistration", "Request a registrar quote; no purchase", 201,
            registration_receipt, registration_request,
            description="Organization owners only. .co.zw uses a one-year term. Opaque registrant references exclude identity documents.")}
    paths[registrations]["post"]["responses"]["200"] = response(registration_receipt, "Matching request replay")
    paths[registrations + "/{registration_id}/approve"] = {"post": operation("approveRegistrationQuote",
        "Approve the exact immutable quote; no payment is performed", 200, registration_receipt,
        obj({"quote_id": UUID, "quote_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
             "confirm": {"const": "approve_registration_quote"}}, ("quote_id", "quote_sha256", "confirm")))}
    paths[registrations + "/{registration_id}/cancel"] = {"post": operation("cancelDomainRegistration",
        "Cancel before registrar processing starts", 200, registration_receipt,
        obj({"confirm": {"const": "cancel_registration"}}, ("confirm",)))}
    credential = {"type": "string", "minLength": 1, "maxLength": 16384}
    nonce = {"type": "string", "pattern": "^[A-Za-z0-9_-]{43,128}$"}
    subject = {"type": "string", "minLength": 1, "maxLength": 255}
    login_receipt = obj({"access_token": credential, "refresh_token": {"oneOf": [credential, {"type": "null"}]},
                         "expires_at": {"type": "integer", "minimum": 1}, "subject": subject},
                        ("access_token", "refresh_token", "expires_at", "subject"))
    for suffix, operation_id, summary, body in (
        ("exchange", "exchangeLoginCode", "Exchange PKCE code and validate signed identity",
         obj({"code": {"type": "string", "minLength": 1, "maxLength": 2048},
              "code_verifier": {"type": "string", "pattern": "^[A-Za-z0-9._~-]{43,128}$"}, "nonce": nonce},
             ("code", "code_verifier", "nonce"))),
        ("refresh", "refreshLogin", "Renew the same human subject with issuer refresh credentials",
         obj({"refresh_token": credential, "nonce": nonce, "subject": subject}, ("refresh_token", "nonce", "subject")))):
        paths["/v1/auth/" + suffix] = {"post": operation(operation_id, summary, 200, login_receipt, body, public=True,
            description="Requires JSON and an Origin matching the configured callback origin. No cookies, client secret or tenant authority is accepted.")}
    for path in (app + "/releases", app + "/rollback", app + "/postgres", app + "/valkey", app + "/storage"):
        paths[path]["post"]["responses"]["200"] = replay
    paths[org + "/team/invitations"]["post"]["responses"]["200"] = response(
        obj({"id": UUID, "expires_at": DATE, "replayed": {"const": True}},
            ("id", "expires_at", "replayed")), "Matching invitation replay; token is not returned")
    paths[app + "/traffic"]["post"]["responses"]["200"] = response(
        obj({"state": STRING, "replayed": {"const": True}}, ("state", "replayed")),
        "Existing state; no new transition")
    for path, item in paths.items():
        names = re.findall(r"\{([a-z_]+)\}", path)
        if names:
            item["parameters"] = [{"name": name, "in": "path", "required": True,
                                   "schema": UUID} for name in names]
    return {"openapi": "3.1.0", "info": {"title": "DIAL Hosting Control API", "version": "0.1.0",
            "description": "Implemented private development profile. A process or database health check is not a production qualification."},
            "servers": [{"url": "/"}], "security": [{"bearerAuth": []}], "paths": paths,
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer",
                "bearerFormat": "JWT", "description": "Dedicated API audience; tenant roles are read from the database."}},
                "responses": {"Error": response(obj({"error": STRING}, ("error",)),
                                              "Typed error; status is 400, 401, 404, 409, 413 or 503.")}}}
