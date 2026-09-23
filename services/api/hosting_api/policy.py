import re


PERMISSIONS = {
    "owner": frozenset({"project:read", "project:create", "application:read", "application:create", "release:create", "release:read", "release:rollback"}),
    "admin": frozenset({"project:read", "project:create", "application:read", "application:create", "release:create", "release:read", "release:rollback"}),
    "viewer": frozenset({"project:read", "application:read", "release:read"}),
}


def allowed(role, action):
    return action in PERMISSIONS.get(role, frozenset())


def valid_name(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}", value))


def valid_release(body):
    if set(body) != {"idempotency_key", "image", "port", "health_path", "memory_mb", "cpu_milli"}:
        return False
    import uuid
    try:
        if str(uuid.UUID(body["idempotency_key"])) != body["idempotency_key"]:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    return (isinstance(body["image"], str) and
            bool(re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}", body["image"])) and
            type(body["port"]) is int and 1 <= body["port"] <= 65535 and
            isinstance(body["health_path"], str) and
            bool(re.fullmatch(r"/[A-Za-z0-9/_-]{0,127}", body["health_path"])) and
            type(body["memory_mb"]) is int and 64 <= body["memory_mb"] <= 32768 and
            type(body["cpu_milli"]) is int and 50 <= body["cpu_milli"] <= 32000)
