from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import socket


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        if os.environ.get("DATABASE_HOST"):
            try:
                with open(os.environ["DATABASE_PASSWORD_FILE"], encoding="utf-8") as file:
                    if len(file.read()) < 32:
                        raise ValueError("short credential")
                with socket.create_connection((os.environ["DATABASE_HOST"], 5432), timeout=2):
                    pass
            except (OSError, ValueError):
                self.send_error(503)
                return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
