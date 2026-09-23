"""Render file-provider configuration from constrained, typed route fields."""
import re


def valid_hostname(host):
    if not isinstance(host, str) or len(host) > 253 or host != host.lower() or not host.isascii():
        return False
    labels = host.split(".")
    return len(labels) >= 2 and len(labels[-1]) >= 2 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)


def route_document(app, release, host, container, port):
    name = "app-" + app
    return {"http": {"routers": {name: {"rule": "Host(`" + host + "`)", "entryPoints": ["websecure"],
                                        "tls": {"certResolver": "acme"}, "service": name,
                                        "middlewares": [name + "-receipt"]}},
                     "services": {name: {"loadBalancer": {"servers": [{"url": "http://" + container + ":" + str(port)}]}}},
                     "middlewares": {name + "-receipt": {"headers": {"customResponseHeaders": {
                         "X-Dial-Release": release}}}}}}
