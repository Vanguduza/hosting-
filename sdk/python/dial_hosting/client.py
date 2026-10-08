"""Narrow client for the machine-token release contract; the issuer owns token renewal."""
import json
import re
import ssl
import uuid
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class ClientError(Exception):
    """Invalid request, token or response. Never includes bearer token contents."""


class ApiError(ClientError):
    def __init__(self, status, code):
        self.status = status
        self.code = code
        super().__init__(f"Hosting API returned {status}: {code}")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise ClientError("Expected a canonical UUID") from exc
    return value


def _origin(value):
    try:
        parts = urlsplit(value)
        port = parts.port
    except (ValueError, TypeError) as exc:
        raise ClientError("Invalid API origin") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname or not port or \
            parts.username or parts.password or parts.path not in ("", "/") or \
            parts.query or parts.fragment or \
            (parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "::1")):
        raise ClientError("Expected an HTTPS origin with an explicit port")
    return value.rstrip("/")


class ReleaseClient:
    """One organization/application pair; no administrative operations are exposed."""

    def __init__(self, base_url, organization_id, application_id, token_provider, *, ca_file=None):
        self._base = _origin(base_url)
        self._path = ("/v1/organizations/" + _uuid(organization_id) +
                      "/applications/" + _uuid(application_id) + "/releases")
        if not callable(token_provider):
            raise ClientError("A callable token provider is required")
        self._token_provider = token_provider
        self._opener = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
                                    HTTPHandler(), _NoRedirect())

    def _request(self, payload=None):
        token = self._token_provider()
        if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
            raise ClientError("Token provider returned an invalid bearer token")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self._base + self._path, data=data, headers=headers,
                          method="POST" if data is not None else "GET")
        try:
            with self._opener.open(request, timeout=15) as response:
                status, content = response.status, response.read(65537)
        except HTTPError as exc:
            status, content = exc.code, exc.read(65537)
        if len(content) > 65536:
            raise ClientError("API response too large")
        try:
            result = json.loads(content)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ClientError("API response is not JSON") from exc
        if not isinstance(result, dict):
            raise ClientError("API response is not an object")
        if not 200 <= status < 300:
            code = result.get("error")
            raise ApiError(status, code if isinstance(code, str) and len(code) <= 80 else "request_failed")
        return status, result

    def list_releases(self):
        status, result = self._request()
        if status != 200 or not isinstance(result.get("releases"), list):
            raise ClientError("Unexpected release list response")
        return result["releases"]

    def queue_release(self, image, port, health_path, memory_mb, cpu_milli, *, idempotency_key):
        # Require a caller-owned stable key: after a network timeout the same
        # key may be safely reused without accidentally starting two releases.
        key = _uuid(idempotency_key)
        if not isinstance(image, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9./:_-]{1,240}@sha256:[a-f0-9]{64}", image) or \
                type(port) is not int or not 1 <= port <= 65535 or \
                not isinstance(health_path, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]{0,127}", health_path) or \
                type(memory_mb) is not int or not 64 <= memory_mb <= 32768 or \
                type(cpu_milli) is not int or not 50 <= cpu_milli <= 32000:
            raise ClientError("Invalid release specification")
        status, result = self._request({"idempotency_key": key, "image": image, "port": port,
                                        "health_path": health_path, "memory_mb": memory_mb,
                                        "cpu_milli": cpu_milli})
        if status not in (200, 202) or "id" not in result:
            raise ClientError("Unexpected release queue response")
        return result
