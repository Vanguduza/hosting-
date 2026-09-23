# Control plane local profile

This profile is a **private development environment** for the implemented organization/project API; it is not a production PaaS deployment. It does not start any named dependency from the full blueprint until its exact version and placement are admitted.

1. Install a Docker Engine and Compose plugin on an isolated developer host.
2. Copy `.env.example` to `.env` and set a real OIDC issuer, audience and JWKS URL; obtain a JWT for that audience. Create `.secrets/pg_admin`, `.secrets/pg_api`, and `.secrets/pg_worker` with independent random passwords (at least 32 characters) and mode 0600. Compose file secrets are local files, not a production secret store.
3. Run `docker compose --env-file .env up --build`. The first database initialization creates the restricted API role and executes `services/api/schema/001_control.sql`. This only occurs on a fresh PostgreSQL volume; do not expect a schema upgrade by restarting Compose.
4. To create the first organization, run `tools/bootstrap_org.py` against a private database-admin connection (`HOSTING_MIGRATION_DSN`) and pass an independently verified `sub` from the issuer. The command refuses the serving role. Protect and audit this operator credential; enrollment is separate from ordinary API permissions.
5. Keep the API loopback-only. Add a TLS/identity-aware ingress and rate limiting before any remote access.

## Deployment worker

The separate `worker.compose.yaml` only starts after a private runtime node and its node agent have been enrolled. Place the node CA certificate and distinct client certificate/key in `.secrets/node_ca.pem`, `.secrets/node_client.pem`, `.secrets/node_client.key`. The node agent requires the client CN and its own server key/cert. Enroll via `tools/register_node.py` on a private operator connection; it obtains live capacity over mTLS. Admit an immutable signed image with `tools/admit_image.py`, which executes Cosign, Trivy and Syft before writing its evidence receipt. Then run:

```bash
docker compose -f deploy/control/compose.yaml -f deploy/control/worker.compose.yaml \
  --env-file deploy/control/.env up --build
```

Only the project/application/release API routes are implemented. A successful release is `HEALTHY_PRIVATE`: there is no public ingress, certificate, database, secret injection, backup, billing or portal outcome yet. Do not expose this profile to clients. Image admission and node enrollment must use audited protected operator credentials and private networking.

The `/live` probe means only that the process exists; `/ready` requires a valid JWT and successful database query. Neither asserts deployment or hosting health. Do not point a public hostname at this API until authenticated rate limits, TLS and production readiness have been verified.
