"""Public-client OIDC code/refresh exchange through a fixed, configured issuer."""
import json
import base64
import hashlib
import hmac
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

import jwt

MAX_RESPONSE = 65536
TOKEN = re.compile(r"[^\s\x00-\x1f\x7f]{1,16384}")
NONCE = re.compile(r"[A-Za-z0-9_-]{43,128}")
LOGIN_VARS = ("OIDC_LOGIN_CLIENT_ID", "OIDC_AUTHORIZATION_URL", "OIDC_TOKEN_URL", "OIDC_LOGIN_REDIRECT_URI")


def human_audience(audience):
    api = os.environ["OIDC_AUDIENCE"]
    if audience == api:
        return True
    portal = os.environ.get("OIDC_LOGIN_CLIENT_ID")
    return bool(isinstance(audience, list) and 1 <= len(audience) <= 2 and
                all(isinstance(value, str) for value in audience) and len(set(audience)) == len(audience) and
                api in audience and all(value == api or portal and value == portal for value in audience) and
                os.environ["OIDC_SERVICE_AUDIENCE"] not in audience)


def secure_url(value, *, loopback=False):
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or "\\" in value or \
            any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or \
            (parsed.scheme != "https" and not (loopback and parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1"))):
        raise RuntimeError("Invalid OIDC login URL")
    # Validate a supplied port even when only the origin is subsequently used.
    parsed.port
    return parsed


def origin(parsed):
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    port = parsed.port
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        host += ":" + str(port)
    return f"{parsed.scheme}://{host}"


def configuration():
    values = [os.environ.get(name, "") for name in LOGIN_VARS]
    if not any(values) and not os.environ.get("OIDC_LOGIN_SCOPES"):
        return None
    if not all(values):
        raise RuntimeError("Incomplete OIDC login configuration")
    client, authorization, token, redirect = values
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", client):
        raise RuntimeError("Invalid OIDC client identifier")
    if client in (os.environ["OIDC_AUDIENCE"], os.environ["OIDC_SERVICE_AUDIENCE"]):
        raise RuntimeError("Portal client and API audiences must differ")
    issuer = os.environ["OIDC_ISSUER"]
    issuer_url = secure_url(issuer)
    if origin(secure_url(authorization)) != origin(issuer_url) or origin(secure_url(token)) != origin(issuer_url):
        raise RuntimeError("Login endpoints must use the configured issuer origin")
    callback = secure_url(redirect, loopback=True)
    if callback.path != "/portal":
        raise RuntimeError("Login callback must be the exact portal URL")
    scopes = (os.environ.get("OIDC_LOGIN_SCOPES") or "openid offline_access").split()
    if not 1 <= len(scopes) <= 12 or "openid" not in scopes or len(set(scopes)) != len(scopes) or \
            any(not re.fullmatch(r"[A-Za-z0-9:._/-]{1,200}", scope) for scope in scopes):
        raise RuntimeError("Invalid OIDC login scopes")
    return {"issuer": issuer, "client_id": client, "authorization_url": authorization,
            "token_url": token, "redirect_uri": redirect, "scopes": scopes}


def public_configuration():
    config = configuration()
    return {"enabled": False} if config is None else {"enabled": True,
        **{key: config[key] for key in ("issuer", "client_id", "authorization_url", "redirect_uri", "scopes")}}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise PermissionError("Issuer redirect rejected")


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate issuer response field")
        result[name] = value
    return result


def token_request(config, fields, opener=None):
    request = Request(config["token_url"], data=urlencode(fields).encode("ascii"), method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"})
    opener = opener or build_opener(HTTPSHandler(), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise PermissionError("Issuer exchange rejected")
            raw = response.read(MAX_RESPONSE + 1)
    except HTTPError as exc:
        exc.close()
        raise PermissionError("Issuer exchange rejected") from None
    except (URLError, OSError):
        raise RuntimeError("Issuer unavailable") from None
    if len(raw) > MAX_RESPONSE:
        raise ValueError("Issuer response too large")
    payload = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(payload, dict) or payload.get("token_type", "").lower() != "bearer":
        raise ValueError("Invalid issuer response")
    return payload


def token_claims(token, client, config, audience):
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise PermissionError("Invalid issuer token")
    try:
        key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256"], issuer=config["issuer"],
                            audience=audience, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
    except (jwt.PyJWTError, ValueError):
        raise PermissionError("Invalid issuer token") from None
    if not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 255 or \
            type(claims["exp"]) is not int or claims["exp"] <= time.time() + 10:
        raise PermissionError("Invalid issuer claims")
    return claims


def receipt(payload, client, config, nonce, *, subject=None, refresh_token=None):
    access = token_claims(payload.get("access_token"), client, config, os.environ["OIDC_AUDIENCE"])
    # Accept only the API audience plus its explicitly configured portal client;
    # mixed human/machine and unrelated resource audiences remain excluded.
    if not human_audience(access["aud"]) or subject is not None and access["sub"] != subject:
        raise PermissionError("Invalid human token audience or subject")
    id_token = payload.get("id_token")
    if subject is None or id_token is not None:
        identity = token_claims(id_token, client, config, config["client_id"])
        audiences = identity["aud"] if isinstance(identity["aud"], list) else [identity["aud"]]
        if identity["sub"] != access["sub"] or identity.get("azp", config["client_id"]) != config["client_id"] or \
                len(audiences) > 1 and identity.get("azp") != config["client_id"] or \
                (subject is None or "nonce" in identity) and identity.get("nonce") != nonce:
            raise PermissionError("Invalid OIDC identity binding")
        if "at_hash" in identity:
            expected = base64.urlsafe_b64encode(hashlib.sha256(payload["access_token"].encode("ascii")).digest()[:16]).rstrip(b"=").decode("ascii")
            if not isinstance(identity["at_hash"], str) or not hmac.compare_digest(identity["at_hash"], expected):
                raise PermissionError("Invalid OIDC access token binding")
    refreshed = payload.get("refresh_token", refresh_token)
    if refreshed is not None and (not isinstance(refreshed, str) or not TOKEN.fullmatch(refreshed)):
        raise PermissionError("Invalid refresh token")
    expires = payload.get("expires_in")
    if type(expires) is not int or not 10 < expires <= 86400:
        raise ValueError("Invalid token expiry")
    return {"access_token": payload["access_token"], "refresh_token": refreshed,
            "expires_at": min(access["exp"], int(time.time()) + expires), "subject": access["sub"]}


def handle(handler, method, path, query):
    """Handle only exact auth routes; API/tenant routes retain bearer authority."""
    routes = {"/v1/auth/config": "GET", "/v1/auth/exchange": "POST", "/v1/auth/refresh": "POST"}
    if path not in routes:
        return False
    try:
        if method != routes[path] or query:
            handler.reply(404, {"error": "not_found"})
            return True
        config = configuration()
        if path == "/v1/auth/config":
            handler.reply(200, public_configuration())
            return True
        if config is None:
            handler.reply(503, {"error": "login_unavailable"})
            return True
        if handler.headers.get("Origin") != origin(urlsplit(config["redirect_uri"])) or \
                handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            handler.reply(403, {"error": "login_origin_rejected"})
            return True
        length = int(handler.headers.get("Content-Length", "0"))
        if handler.headers.get("Transfer-Encoding") or len(handler.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("Invalid login request framing")
        if not 1 <= length <= 20000:
            handler.reply(413, {"error": "body_size"})
            return True
        body = json.loads(handler.rfile.read(length), object_pairs_hook=unique_object)
        fields = {"code", "code_verifier", "nonce"} if path.endswith("exchange") else {"refresh_token", "nonce", "subject"}
        if not isinstance(body, dict) or set(body) != fields or not isinstance(body["nonce"], str) or not NONCE.fullmatch(body["nonce"]):
            raise ValueError("Invalid login request")
        common = {"client_id": config["client_id"]}
        if path.endswith("exchange"):
            if not isinstance(body["code"], str) or not re.fullmatch(r"[!-~]{1,2048}", body["code"]) or \
                    not isinstance(body["code_verifier"], str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", body["code_verifier"]):
                raise ValueError("Invalid code exchange")
            params = {**common, "grant_type": "authorization_code", "code": body["code"],
                      "code_verifier": body["code_verifier"], "redirect_uri": config["redirect_uri"]}
            result = receipt(token_request(config, params), handler.server.jwks, config, body["nonce"])
        else:
            if not isinstance(body["refresh_token"], str) or not TOKEN.fullmatch(body["refresh_token"]) or \
                    not isinstance(body["subject"], str) or not 1 <= len(body["subject"]) <= 255:
                raise ValueError("Invalid refresh request")
            params = {**common, "grant_type": "refresh_token", "refresh_token": body["refresh_token"]}
            result = receipt(token_request(config, params), handler.server.jwks, config, body["nonce"],
                             subject=body["subject"], refresh_token=body["refresh_token"])
        handler.reply(200, result)
    except PermissionError:
        handler.reply(401, {"error": "login_rejected"})
    except (ValueError, UnicodeError, json.JSONDecodeError):
        handler.reply(400, {"error": "invalid_login_request"})
    except Exception:
        handler.reply(503, {"error": "login_unavailable"})
    return True
