"""OpenBao KV v2 client with AppRole auth and mandatory CAS writes."""
import json
import os
import re
import ssl
import urllib.error
import urllib.request
import uuid
from pathlib import Path


class SecretError(RuntimeError):
    pass


def private_file(path):
    item = Path(path)
    if not item.is_file() or item.is_symlink() or item.stat().st_mode & 0o077:
        raise SecretError("OpenBao credential file must be owner-only")
    data = item.read_text(encoding="utf-8").strip()
    if not data or len(data) > 8192:
        raise SecretError("OpenBao credential file invalid")
    return data


def secret_path(resource_id):
    return "resources/" + str(uuid.UUID(str(resource_id)))


class OpenBao:
    def __init__(self, address, ca_file, role_file, secret_id_file, mount="dial"):
        from urllib.parse import urlsplit
        parsed = urlsplit(address)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise SecretError("OpenBao address must be an HTTPS origin")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", mount):
            raise SecretError("Invalid OpenBao mount")
        self.address = address.rstrip("/")
        self.mount = mount
        self.ca_file = ca_file
        self.role_file = role_file
        self.secret_id_file = secret_id_file
        self.context = ssl.create_default_context(cafile=ca_file)

    @classmethod
    def environment(cls):
        required = ("BAO_ADDR", "BAO_CA_FILE", "BAO_ROLE_ID_FILE", "BAO_SECRET_ID_FILE")
        if missing := [name for name in required if not os.environ.get(name)]:
            raise SecretError("OpenBao missing configuration: " + ", ".join(missing))
        return cls(os.environ["BAO_ADDR"], os.environ["BAO_CA_FILE"],
                   os.environ["BAO_ROLE_ID_FILE"], os.environ["BAO_SECRET_ID_FILE"],
                   os.environ.get("BAO_KV_MOUNT", "dial"))

    def request(self, method, path, payload=None, token=None):
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        if payload is not None:
            headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.address + "/v1/" + path, body, headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10, context=self.context) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            # Never propagate a body, URL with path metadata, or a token.
            if exc.code in (400, 404) and "options" in (payload or {}):
                raise SecretError("OpenBao CAS rejected version or path") from None
            raise SecretError("OpenBao request rejected: HTTP " + str(exc.code)) from None
        except (OSError, ValueError) as exc:
            raise SecretError("OpenBao unavailable or returned invalid JSON") from None

    def login(self):
        result = self.request("POST", "auth/approle/login", {
            "role_id": private_file(self.role_file), "secret_id": private_file(self.secret_id_file)})
        token = result.get("auth", {}).get("client_token")
        if not isinstance(token, str) or not token:
            raise SecretError("OpenBao login did not issue a token")
        return token

    def put(self, resource_id, values, cas):
        if type(cas) is not int or cas < 0 or not isinstance(values, dict) or not values:
            raise ValueError("Invalid secret version or values")
        if not all(isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
                   and isinstance(value, str) and 1 <= len(value) <= 8192
                   for key, value in values.items()):
            raise ValueError("Invalid secret value or key")
        path = secret_path(resource_id)
        result = self.request("POST", self.mount + "/data/" + path,
                              {"options": {"cas": cas}, "data": values}, token=self.login())
        version = result.get("data", {}).get("version")
        if type(version) is not int or version != cas + 1:
            raise SecretError("OpenBao did not confirm requested secret version")
        return version

    def get(self, resource_id, version=None):
        if version is not None and (type(version) is not int or version < 1):
            raise ValueError("Invalid secret version")
        path = self.mount + "/data/" + secret_path(resource_id)
        if version is not None:
            path += "?version=" + str(version)
        result = self.request("GET", path, token=self.login()).get("data", {})
        values = result.get("data")
        metadata = result.get("metadata", {})
        if (not isinstance(values, dict) or not values or
                type(metadata.get("version")) is not int or
                (version is not None and metadata["version"] != version)):
            raise SecretError("OpenBao secret data or version missing")
        return metadata["version"], values

