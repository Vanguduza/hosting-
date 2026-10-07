"""Same-origin development portal; tenant data is fetched through the control API."""
from pathlib import Path

ASSETS = {
    "/portal": ("index.html", "text/html; charset=utf-8"),
    "/portal/": ("index.html", "text/html; charset=utf-8"),
    "/portal/portal.css": ("portal.css", "text/css; charset=utf-8"),
    "/portal/portal.mjs": ("portal.mjs", "text/javascript; charset=utf-8"),
    "/portal/login.mjs": ("login.mjs", "text/javascript; charset=utf-8"),
}
ROOT = Path(__file__).with_name("portal")
HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                               "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "X-Frame-Options": "DENY",
}


def serve(handler, path):
    """Return true only for an exact static asset; no token or database access."""
    asset = ASSETS.get(path)
    if asset is None:
        return False
    filename, content_type = asset
    body = (ROOT / filename).read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    for name, value in HEADERS.items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)
    return True
