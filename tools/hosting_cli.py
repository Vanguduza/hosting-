#!/usr/bin/env python3
"""Operator client for the implemented DIAL Hosting control API."""
import argparse
import json
import os
import re
import ssl
import stat
import sys
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPHandler, HTTPRedirectHandler, Request, build_opener


def private_file(value, label):
    fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "r", encoding="utf-8") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or \
                info.st_mode & 0o077 or info.st_size > 16384:
            raise ValueError(label + " must be an owner-only regular file of at most 16 KiB")
        data = file.read(16385).strip()
    if not data or any(char.isspace() for char in data):
        raise ValueError(label + " is empty or contains whitespace")
    return data


def origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or \
            parsed.username or parsed.password or parsed.query or parsed.fragment or \
            parsed.path not in ("", "/") or not parsed.port:
        raise ValueError("Base URL must be an HTTPS origin with an explicit port")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("Plain HTTP is limited to the local development loopback")
    return value.rstrip("/")


def identifier(value):
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Identifier must be a canonical UUID") from exc
    if parsed != value:
        raise ValueError("Identifier must be a canonical UUID")
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise ValueError("Redirect rejected; bearer tokens cannot cross origins")


def call(base, path, token=None, body=None, ca_file=None, opener=None):
    base = origin(base)
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid API route")
    if opener is None:
        context = ssl.create_default_context(cafile=ca_file)
        opener = build_opener(HTTPSHandler(context=context), HTTPHandler(), NoRedirect())
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, data=payload, headers=headers,
                      method="POST" if payload is not None else "GET")
    try:
        with opener.open(request, timeout=15) as response:
            status, data = response.status, response.read(65537)
    except HTTPError as exc:
        status, data = exc.code, exc.read(65537)
    if len(data) > 65536:
        raise ValueError("API response exceeds limit")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("API response must be a JSON object")
    return status, result


def parser():
    result = argparse.ArgumentParser(description="DIAL Hosting control API operator client")
    result.add_argument("--base-url", required=True, help="HTTPS origin (or local loopback HTTP)")
    result.add_argument("--token-file", help="Owner-only file containing a JWT for the control API audience")
    result.add_argument("--ca-file", help="Trusted custom CA bundle; TLS verification remains enabled")
    commands = result.add_subparsers(dest="command", required=True)
    arguments = {
        "live": (), "ready": (), "openapi": (), "orgs": (),
        "audit": ("org",), "capacity": ("org", "from_utc", "to_utc"), "quotas": ("org",),
        "projects": ("org",), "project-create": ("org", "name"),
        "applications": ("org", "project"),
        "application-create": ("org", "project", "name", "environment"),
        "traffic": ("org", "app"), "suspend": ("org", "app", "reason"),
        "resume": ("org", "app", "reason"),
        "domain": ("org", "app"), "domain-register": ("org", "app", "hostname"),
        "domain-verify": ("org", "app"), "builds": ("org", "app"),
        "releases": ("org", "app"), "release-queue": ("org", "app", "image", "port",
                                                     "health_path", "memory_mb", "cpu_milli"),
        "rollback": ("org", "app", "target_release_id"),
        "postgres": ("org", "app"), "postgres-create": ("org", "app", "memory_mb", "cpu_milli"),
        "valkey": ("org", "app"), "valkey-create": ("org", "app", "memory_mb", "cpu_milli"),
        "storage": ("org", "app"), "storage-create": ("org", "app", "memory_mb", "cpu_milli"),
        "team-invitations": ("org",), "team-invite": ("org", "role", "expires_hours"),
        "team-revoke": ("org", "invitation_id"), "team-members": ("org",),
        "team-remove": ("org", "actor_sub"), "team-accept": (),
        "service-accounts": ("org",), "service-grant": ("org", "app", "client_id", "actor_sub"),
        "service-revoke": ("org", "id"),
    }
    for name, fields in arguments.items():
        command = commands.add_parser(name)
        for field in fields:
            command.add_argument(field, type=int if field in ("port", "memory_mb", "cpu_milli", "expires_hours") else str)
        if name in ("team-invite", "release-queue", "rollback", "postgres-create", "valkey-create", "storage-create"):
            command.add_argument("--idempotency-key", type=identifier)
        if name == "team-accept":
            command.add_argument("--invitation-file", required=True, help="Owner-only invitation token file")
        if name == "audit":
            command.add_argument("--after", type=int, default=0, help="Exclusive committed event ID cursor")
    return result


def request_for(args):
    name = args.command
    if name in ("live", "ready", "openapi", "orgs"):
        return {"live": "/live", "ready": "/ready", "openapi": "/openapi.json",
                "orgs": "/v1/organizations"}[name], None, None
    if name == "team-accept":
        return "/v1/team/invitations/accept", {"token": private_file(args.invitation_file, "Invitation token")}, None
    org = "/v1/organizations/" + identifier(args.org)
    if name == "audit":
        if not 0 <= args.after <= 9223372036854775807:
            raise ValueError("Audit cursor out of range")
        return org + "/audit" + ("?after=" + str(args.after) if args.after else ""), None, None
    if name == "quotas":
        return org + "/quotas", None, None
    if name == "capacity":
        pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
        if not re.fullmatch(pattern, args.from_utc) or not re.fullmatch(pattern, args.to_utc):
            raise ValueError("Capacity timestamps must be UTC seconds")
        return org + "/capacity?from=" + args.from_utc + "&to=" + args.to_utc, None, None
    if name in ("service-accounts", "service-grant", "service-revoke"):
        path = org + "/service-accounts"
        if name == "service-revoke":
            return path + "/revoke", {"id": identifier(args.id),
                                      "confirm": "revoke_service_account"}, None
        if name == "service-grant":
            return path, {"application_id": identifier(args.app), "client_id": args.client_id,
                          "actor_sub": args.actor_sub}, None
        return path, None, None
    if name in ("projects", "project-create"):
        return org + "/projects", ({"name": args.name} if name == "project-create" else None), None
    if name.startswith("team-"):
        if name == "team-invitations":
            return org + "/team/invitations", None, None
        if name == "team-members":
            return org + "/team/members", None, None
        if name == "team-revoke":
            return org + "/team/invitations/revoke", {"invitation_id": identifier(args.invitation_id)}, None
        if name == "team-remove":
            return org + "/team/members/remove", {"actor_sub": args.actor_sub,
                                                   "confirm": "remove_member"}, None
        if args.role not in ("admin", "viewer"):
            raise ValueError("Invitation role must be admin or viewer")
        key = args.idempotency_key or str(uuid.uuid4())
        return org + "/team/invitations", {"idempotency_key": key, "role": args.role,
            "expires_hours": args.expires_hours, "confirm": "invite_" + args.role}, key
    if name in ("applications", "application-create"):
        path = org + "/projects/" + identifier(args.project) + "/applications"
        return path, ({"name": args.name, "environment": args.environment}
                      if name == "application-create" else None), None
    app = org + "/applications/" + identifier(args.app)
    if name in ("traffic", "suspend", "resume"):
        return app + "/traffic", (None if name == "traffic" else
            {"action": name, "reason": args.reason, "confirm": name + "_application"}), None
    if name in ("domain", "domain-register", "domain-verify"):
        return app + ("/domain/verify" if name == "domain-verify" else "/domain"), \
            ({"hostname": args.hostname} if name == "domain-register" else
             {} if name == "domain-verify" else None), None
    if name in ("builds", "releases", "postgres", "valkey", "storage"):
        return app + "/" + name, None, None
    if name == "release-queue":
        key = args.idempotency_key or str(uuid.uuid4())
        return app + "/releases", {"idempotency_key": key, "image": args.image,
            "port": args.port, "health_path": args.health_path, "memory_mb": args.memory_mb,
            "cpu_milli": args.cpu_milli}, key
    if name == "rollback":
        key = args.idempotency_key or str(uuid.uuid4())
        return app + "/rollback", {"idempotency_key": key,
                                   "target_release_id": identifier(args.target_release_id)}, key
    if name in ("postgres-create", "valkey-create", "storage-create"):
        key = args.idempotency_key or str(uuid.uuid4())
        resource = name.removesuffix("-create")
        return app + "/" + resource, {"idempotency_key": key, "memory_mb": args.memory_mb,
                                        "cpu_milli": args.cpu_milli}, key
    raise ValueError("Unknown operator command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        path, body, key = request_for(args)
        token = None if args.command in ("live", "openapi") else private_file(
            args.token_file, "Control API token") if args.token_file else None
        if args.command not in ("live", "openapi") and not token:
            raise ValueError("Control API token file required")
        status, result = call(args.base_url, path, token, body, args.ca_file)
        output = {"status": status, "body": result}
        if key:
            output["idempotency_key"] = key
        print(json.dumps(output, default=str, sort_keys=True))
        return 0 if 200 <= status < 300 else 1
    except (ValueError, OSError, URLError, json.JSONDecodeError) as exc:
        # Avoid printing token contents, request body, or provider exception
        # details (which may include credentials or private origins).
        print(json.dumps({"error": "operator_request_failed", "type": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
