import re


PERMISSIONS = {
    "owner": frozenset({"project:read", "project:create"}),
    "admin": frozenset({"project:read", "project:create"}),
    "viewer": frozenset({"project:read"}),
}


def allowed(role, action):
    return action in PERMISSIONS.get(role, frozenset())


def valid_name(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}", value))
