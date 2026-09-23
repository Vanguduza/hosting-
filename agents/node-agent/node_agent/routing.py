"""Render file-provider configuration from constrained, typed route fields."""
import json
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


def route_toml(app, release, host, container, port):
    """Traefik's file provider reads TOML/YAML, not JSON route documents."""
    name = "app-" + app
    value = lambda text: json.dumps(text)
    return (f'[http.routers.{value(name)}]\n'
            f'rule = {value("Host(`" + host + "`)")}\n'
            'entryPoints = ["websecure"]\n'
            f'service = {value(name)}\n'
            f'middlewares = [{value(name + "-receipt")}]\n'
            f'[http.routers.{value(name)}.tls]\n'
            'certResolver = "acme"\n'
            f'[http.services.{value(name)}.loadBalancer]\n'
            f'[[http.services.{value(name)}.loadBalancer.servers]]\n'
            f'url = {value("http://" + container + ":" + str(port))}\n'
            f'[http.middlewares.{value(name + "-receipt")}.headers.customResponseHeaders]\n'
            f'"X-Dial-Release" = {value(release)}\n')
