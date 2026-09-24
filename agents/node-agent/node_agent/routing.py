"""Render file-provider configuration from constrained, typed route fields."""
import json
import re


def valid_hostname(host):
    if not isinstance(host, str) or len(host) > 253 or host != host.lower() or not host.isascii():
        return False
    labels = host.split(".")
    return len(labels) >= 2 and len(labels[-1]) >= 2 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)


def rate_policy(average=20, burst=40, period="1s"):
    if (type(average) is not int or not 1 <= average <= 1000 or
            type(burst) is not int or not 1 <= burst <= 2000 or
            not isinstance(period, str) or not re.fullmatch(r"[1-9][0-9]{0,3}s", period)):
        raise ValueError("invalid ingress rate policy")
    return {"average": average, "burst": burst, "period": period}


def route_document(app, release, host, container, port, *, average=20, burst=40, period="1s"):
    policy = rate_policy(average, burst, period)
    name = "app-" + app
    return {"http": {"routers": {name: {"rule": "Host(`" + host + "`)", "entryPoints": ["websecure"],
                                        "tls": {"certResolver": "acme"}, "service": name,
                                        "middlewares": [name + "-rate", name + "-receipt"]}},
                     "services": {name: {"loadBalancer": {"servers": [{"url": "http://" + container + ":" + str(port)}]}}},
                     "middlewares": {name + "-rate": {"rateLimit": policy},
                                     name + "-receipt": {"headers": {"customResponseHeaders": {
                         "X-Dial-Release": release}}}}}}


def route_toml(app, release, host, container, port, *, average=20, burst=40, period="1s"):
    """Traefik's file provider reads TOML/YAML, not JSON route documents."""
    policy = rate_policy(average, burst, period)
    name = "app-" + app
    value = lambda text: json.dumps(text)
    return (f'[http.routers.{value(name)}]\n'
            f'rule = {value("Host(`" + host + "`)")}\n'
            'entryPoints = ["websecure"]\n'
            f'service = {value(name)}\n'
            f'middlewares = [{value(name + "-rate")}, {value(name + "-receipt")}]\n'
            f'[http.routers.{value(name)}.tls]\n'
            'certResolver = "acme"\n'
            f'[http.services.{value(name)}.loadBalancer]\n'
            f'[[http.services.{value(name)}.loadBalancer.servers]]\n'
            f'url = {value("http://" + container + ":" + str(port))}\n'
            f'[http.middlewares.{value(name + "-rate")}.rateLimit]\n'
            f'average = {policy["average"]}\n'
            f'burst = {policy["burst"]}\n'
            f'period = {value(policy["period"])}\n'
            f'[http.middlewares.{value(name + "-receipt")}.headers.customResponseHeaders]\n'
            f'"X-Dial-Release" = {value(release)}\n')
