# Python release client

Install from this checkout with `python -m pip install ./sdk/python`. Register the machine token's `client_id` and `sub` for one application as described in [service grants](../../docs/SERVICE_ACCOUNTS.md). The token provider must return a current bearer JWT from the configured service audience. A file rotated by an external OIDC client works:

```python
from pathlib import Path
from dial_hosting import ReleaseClient

client = ReleaseClient(
    "https://api.example.org:443", "<organization UUID>", "<application UUID>",
    lambda: Path("/run/secrets/hosting-service-token").read_text().strip(),
)
receipt = client.queue_release(
    "registry.example.org/team/app@sha256:" + "a" * 64,
    8080, "/health", 128, 100,
    idempotency_key="<stable canonical UUID>",
)
print(receipt["id"], receipt["state"])
```

Keep the idempotency UUID for a retry after an uncertain network outcome. The client never follows redirects with the bearer token, verifies HTTPS, limits response size and confines requests to one application's release list and queue routes. An HTTP origin is accepted only for local loopback tests. `ApiError.status` and `.code` expose sanitized API failures; the client does not manage IdP credentials or retry side effects automatically.
