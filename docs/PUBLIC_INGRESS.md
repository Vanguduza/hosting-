# Public application ingress

This profile runs Traefik on the selected application node. The operator supplies
an immutable Traefik v3 image digest and an ACME account email; the installer
does not need a Docker socket inside Traefik. The node agent writes one validated
file-provider document per application. Each HTTPS response includes
`X-Dial-Release`, and the worker verifies that header over a trusted TLS
connection to the registered public node IP before committing `SERVING`.
Each application runs on its own labeled Docker bridge. The node agent joins
Traefik to that application's bridge only after verifying container ownership
and private health; unrelated application containers cannot resolve each
other through a shared runtime bridge. The ingress remains a trusted component
with access to the networks of currently routed applications.

## Prepare the selected node

1. Install the private node agent and its mTLS credentials following
   `agents/node-agent/README.md`. Ensure port 8443 is reachable only on the
   control network, while ports 80 and 443 are reachable from the internet.
2. Set `DIAL_INGRESS_IMAGE` to a reviewed Traefik v3 image **digest** and
   `DIAL_ACME_EMAIL` to the operator's account email. Run
   `deploy/node-agent/install-ingress.sh` as root. It creates the dedicated
   route and certificate directories and publishes ports 80 and 443. It
   refuses to replace a running ingress container automatically.
3. Register the node using `tools/register_node.py --public-ipv4 <global IPv4>`
   along with the private mTLS endpoint and certificate flags. The public IP
   must route to this exact node; capacity and private identity are checked.
4. Back up `/var/lib/dial-hosting/ingress/acme.json` encrypted off-host and
   restore it with mode 0600 before replacing ingress. Also back up
   `/var/lib/dial-hosting/node-agent/` for route state. Certificates are
   recoverable through ACME, but restoring the store avoids rate limits and
   prevents accidental loss of existing account state.

## Claim and deploy a hostname

Call `POST /v1/organizations/{org}/applications/{app}/domain` with
`{"hostname":"app.example.org"}` using an owner/admin OIDC token. Create
the exact TXT record and value returned at `_dial-verify.app.example.org`,
then call `POST .../domain/verify` with `{}`. Publish one A record resolving
only to the node's registered global IPv4 address. The worker rechecks TXT
ownership and A resolution before each release, and rejects publication
when either proof fails. The API admits releases only for verified domains.

The worker pulls the admitted immutable image, waits for private health,
swaps the route, waits up to 120 seconds for a valid public HTTPS certificate
and matching release header, then commits the active release. On public
failure it restores the previous route, or removes the route for a first
release, and retries the job. A terminal failure keeps its capacity reserved
until the node proves the failed container was removed. The old container is retired only after
successful promotion. A missing DNS record or unreachable ACME challenge
therefore results in a failed release rather than a false healthy result.

Limitations requiring operational qualification: this profile has one
public ingress node per application, IPv4 only, and one domain per app.
Multiple public IPs, a CDN, DNS failover, and replacement node migration
require another explicit profile and tests before activation. The ACME
store must never be mounted by multiple active Traefik instances.
