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
    paths = {
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
    }
    replay = response(obj({"id": UUID, "state": STRING, "replayed": {"const": True}},
                          ("id", "state", "replayed")), "Matching idempotent replay")
    for path in (app + "/releases", app + "/rollback", app + "/postgres", app + "/valkey"):
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
