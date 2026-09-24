# DIAL Self-Hosted Client Cloud

This repository binds the DIAL hosting blueprint to source control and contains implemented control-plane contracts. The attached [Rev 1 blueprint](development-pack/BLUEPRINT_REV_1.md) remains the requirements source; [Review Rev 2](development-pack/REVIEW_REV_2.md) records corrections and execution gates.

The private control API exposes its currently implemented OpenAPI 3.1 contract at `GET /openapi.json` without a bearer token. It lists only existing routes and validates in CI; it is a client integration contract, not evidence of production qualification. `DU-005` remains partial because a production API gateway and external ingress policy are not installed.

`python3 tools/hosting_cli.py --base-url https://control.example:443 --token-file /private/control.jwt orgs` runs the operator client against the implemented control API. It accepts an owner-only OIDC token file for the API audience, verifies TLS, refuses cross-origin redirects, and reports an idempotency key for commands that can be retried. Run `--help` for the implemented commands; authentication and production ingress remain separate deployment gates.

## Current certification

`BUILD_READY=false`, `RUNTIME_QUALIFIED=false`, `PRODUCTION_QUALIFIED=false`. The repository contains authenticated tenant/project/application APIs with one-time owner-created team invitations; trusted-source build, scan, sign and digest admission; a signed GitHub push receiver and durable isolated builder for registered trusted sources with optional per-repository read-only deploy keys; private release scheduling and an mTLS Docker node agent; rollback and a durable worker with domain proof, Traefik HTTPS routing and public release probes; OpenBao KV v2 credential transport; dedicated private PostgreSQL and Valkey provisioning with application attachment; and a development-only private single-node Garage S3 resource. Operator-configured control/client PostgreSQL, Valkey and Garage backup tools use encrypted off-host Restic targets, isolated semantic restore drills, daily timers and hourly checks for fresh verified receipts and remote snapshot presence. OpenBao Integrated Storage Raft has an off-host encrypted snapshot and guarded disposable-authority restore workflow; CI exercises it against separate disposable Raft servers. The GitHub path has disposable signed HTTP and database tests, but no live rootless build or private-source qualification. Public ingress and resource provisioning have code and disposable tests, but no live deployment qualification. A production OpenBao HA cluster and cross-host recovery, production object-store durability, PR previews, physical managed PostgreSQL backup and PITR, credential rotation, managed Supabase, billing, provider IAM setup and the client portal have **not** been implemented or certified. A missing capability is omitted rather than represented by a fake route or green status.

## Local control-plane verification

```bash
python3 tools/packcheck.py
python3 -m unittest discover -s tests -v
docker compose -f deploy/control/compose.yaml --env-file deploy/control/.env up --build
```

The last command requires Docker, a real OIDC issuer, and the values described in [the control profile](deploy/control/README.md). The worker and agent have separate setup paths. No example credentials are active defaults. PostgreSQL is private to the Compose network. The HTTP API binds loopback; a TLS/identity-aware ingress is needed before remote access. See the [node agent](agents/node-agent/README.md), [backup](docs/BACKUP_AND_RESTORE.md), [Valkey](docs/MANAGED_VALKEY.md) and [object storage](docs/OBJECT_STORAGE.md) runbooks.

## Design boundaries

- Platform IAM and each hosted application's IAM remain separate.
- All tenant reads and writes require membership in the canonical database; mutable JWT user metadata cannot authorize tenant access.
- Image digests, provider credentials, host topology, and resource budgets are external inputs, never guessed in source.
- The 8 GB Netcup node is an orchestration target only after measured capacity admission. Production app, database, registry, and Supabase placement remains configurable.

Read [the review](development-pack/REVIEW_REV_2.md) before adding infrastructure. No certificate may be promoted by documentation or by passing a unit test alone.
