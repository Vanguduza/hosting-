# Control plane local profile

This profile is a **private development environment** for the implemented organization/project API; it is not a production PaaS deployment. It does not start any named dependency from the full blueprint until its exact version and placement are admitted.

1. Install a Docker Engine and Compose plugin on an isolated developer host.
2. Copy `.env.example` to `.env` and set a real OIDC issuer, audience and JWKS URL; obtain a JWT for that audience. Create `.secrets/pg_admin` and `.secrets/pg_api` with independent random passwords (at least 32 characters) and mode 0600. Compose file secrets are local files, not a production secret store.
3. Run `docker compose --env-file .env up --build`. The first database initialization creates the restricted API role and executes `services/api/schema/001_control.sql`. This only occurs on a fresh PostgreSQL volume; do not expect a schema upgrade by restarting Compose.
4. To create the first organization, run `tools/bootstrap_org.py` against a private migration-role connection and pass an independently verified `sub` from the issuer. This operator enrollment is separate from ordinary API permissions.
5. Keep the API loopback-only. Add a TLS/identity-aware ingress and rate limiting before any remote access.

The `/live` probe means only that the process exists; `/ready` requires a valid JWT and successful database query. Neither asserts deployment or hosting health. Do not point a public hostname at this API until authenticated rate limits, TLS and production readiness have been verified.
