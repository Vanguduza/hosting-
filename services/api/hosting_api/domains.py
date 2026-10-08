"""Public DNS proof and strict host validation for tenant domains."""
import ipaddress
import re
import secrets
import socket

import dns.exception
import dns.resolver


def valid_hostname(host):
    if not isinstance(host, str) or len(host) > 253 or host != host.lower() or not host.isascii():
        return False
    parts = host.split(".")
    return (len(parts) >= 2 and len(parts[-1]) >= 2 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in parts
    ) and not host.endswith(".local") and not host.endswith(".internal"))


def new_token():
    return secrets.token_urlsafe(32)


def txt_proves(host, token, resolver=None):
    if not valid_hostname(host) or not isinstance(token, str):
        return False
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        answers = resolver.resolve("_dial-verify." + host, "TXT", search=False)
        return any(b"".join(answer.strings).decode("ascii", "strict") == "dial-hosting=" + token
                   for answer in answers)
    except (dns.exception.DNSException, UnicodeError):
        return False


def address_proves(host, expected):
    """All published A addresses must point at the registered ingress node."""
    if not valid_hostname(host):
        return False
    try:
        expected_ip = ipaddress.IPv4Address(str(expected))
        if not expected_ip.is_global:
            return False
        addresses = {ipaddress.IPv4Address(item[4][0]) for item in
                     socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
        return addresses == {expected_ip}
    except (ValueError, OSError):
        return False
