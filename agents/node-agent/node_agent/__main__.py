"""Private mTLS server exposing only typed node actions."""
import json
import ipaddress
import os
import ssl
import uuid
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .core import Node, OperationError


class Handler(BaseHTTPRequestHandler):
    server_version = "DialNode/0.1"

    def reply(self, code, value):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        peer = self.connection.getpeercert()
        names = [v for fields in peer.get("subject", ()) for key, v in fields if key == "commonName"]
        return names == [self.server.client_cn]

    def do_GET(self):
        if not self.authorized():
            return self.reply(403, {"error": "forbidden"})
        path = urlsplit(self.path).path
        if path == "/live":
            return self.reply(200, {"status": "agent_alive"})
        if path == "/v1/capacity":
            try:
                return self.reply(200, self.server.node.capacity())
            except OperationError:
                return self.reply(503, {"error": "capacity_unavailable"})
        if path.startswith("/v1/applications/"):
            try:
                app = str(uuid.UUID(path.removeprefix("/v1/applications/")))
                if path != "/v1/applications/" + app:
                    raise ValueError()
                return self.reply(200, self.server.node.observed(app))
            except ValueError:
                return self.reply(400, {"error": "invalid_application_id"})
        return self.reply(404, {"error": "not_found"})

    def do_PUT(self):
        if not self.authorized():
            return self.reply(403, {"error": "forbidden"})
        if urlsplit(self.path).path not in ("/v1/deployments", "/v1/routes", "/v1/resource-secrets", "/v1/postgres", "/v1/valkey"):
            return self.reply(404, {"error": "not_found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= (65536 if urlsplit(self.path).path == "/v1/resource-secrets" else 4096):
                return self.reply(413, {"error": "invalid_body_size"})
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError()
            if urlsplit(self.path).path == "/v1/postgres":
                from .postgres import provision
                receipt = provision(self.server.node, data)
            elif urlsplit(self.path).path == "/v1/valkey":
                from .valkey import provision
                receipt = provision(self.server.node, data)
            elif urlsplit(self.path).path == "/v1/deployments":
                receipt = self.server.node.deploy(data)
            elif urlsplit(self.path).path == "/v1/routes":
                receipt = self.server.node.route(data)
            else:
                receipt = self.server.node.deliver_secrets(data)
            return self.reply(200, receipt)
        except (ValueError, json.JSONDecodeError):
            return self.reply(400, {"error": "invalid_request"})
        except OperationError:
            return self.reply(409, {"error": "deployment_failed"})
        except Exception:
            return self.reply(503, {"error": "unavailable"})

    def do_DELETE(self):
        if not self.authorized():
            return self.reply(403, {"error": "forbidden"})
        path = urlsplit(self.path).path
        route = re.fullmatch(r"/v1/routes/([0-9a-f-]{36})/([0-9a-f-]{36})", path)
        if route:
            try:
                return self.reply(200, self.server.node.unroute(*route.groups()))
            except ValueError:
                return self.reply(400, {"error": "invalid_id"})
            except OperationError:
                return self.reply(409, {"error": "route_conflict"})
        abort = re.fullmatch(r"/v1/deployments/([0-9a-f-]{36})/([0-9a-f-]{36})(?:/([0-9a-f-]{36}))?", path)
        if abort:
            try:
                return self.reply(200, self.server.node.abort(*abort.groups()))
            except ValueError:
                return self.reply(400, {"error": "invalid_id"})
            except OperationError:
                return self.reply(409, {"error": "abort_blocked"})
        prefix = "/v1/applications/"
        if not path.startswith(prefix) or "/releases/" not in path:
            return self.reply(404, {"error": "not_found"})
        try:
            app, release = path[len(prefix):].split("/releases/")
            if path != prefix + str(uuid.UUID(app)) + "/releases/" + str(uuid.UUID(release)):
                raise ValueError()
            return self.reply(200, self.server.node.retire(app, release))
        except ValueError:
            return self.reply(400, {"error": "invalid_id"})
        except OperationError:
            return self.reply(409, {"error": "retirement_blocked"})


def main():
    required = ("NODE_BIND", "NODE_PORT", "NODE_CA_FILE", "NODE_CERT_FILE", "NODE_KEY_FILE", "NODE_CLIENT_CN", "NODE_STATE_FILE")
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise RuntimeError("Missing node configuration: " + ", ".join(missing))
    address = ipaddress.IPv4Address(os.environ["NODE_BIND"])
    private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8")
    if not any(address in ipaddress.ip_network(cidr) for cidr in private):
        raise RuntimeError("Node agent must bind to a private or loopback IPv4 address")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=os.environ["NODE_CA_FILE"])
    context.load_cert_chain(os.environ["NODE_CERT_FILE"], os.environ["NODE_KEY_FILE"])
    server = ThreadingHTTPServer((os.environ["NODE_BIND"], int(os.environ["NODE_PORT"])), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.node = Node(os.environ["NODE_STATE_FILE"], routes_dir=os.environ.get("NODE_ROUTES_DIR"),
                       secrets_dir=os.environ.get("NODE_SECRETS_DIR"))
    server.client_cn = os.environ["NODE_CLIENT_CN"]
    server.serve_forever()


if __name__ == "__main__":
    main()
