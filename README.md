# DIAL Self-Hosted Client Cloud

This repository binds the DIAL hosting blueprint to source control and contains the first implemented control-plane contracts. The attached [Rev 1 blueprint](development-pack/BLUEPRINT_REV_1.md) remains the requirements source; [Review Rev 2](development-pack/REVIEW_REV_2.md) records corrections and execution gates.

## Current certification

`BUILD_READY=false`, `RUNTIME_QUALIFIED=false`, `PRODUCTION_QUALIFIED=false`. The repository contains authenticated tenant/project/application APIs; a trusted-source build, scan, sign and digest admission command; private release scheduling and an mTLS Docker node agent; a durable worker with idempotent private health receipts and delayed old-release retirement; control-database backup and isolated restore drill tooling. Public ingress, GitHub webhook automation, managed Supabase, hosted client data backups, billing, secrets, provider IAM setup and the client portal have **not** been implemented or certified. A missing capability is omitted rather than represented by a fake route or green status.

## Local control-plane verification

```bash
python3 tools/packcheck.py
python3 -m unittest discover -s tests -v
docker compose -f deploy/control/compose.yaml --env-file deploy/control/.env up --build
```

The last command requires Docker, a real OIDC issuer, and the values described in [the control profile](deploy/control/README.md). The worker and agent have separate setup paths. No example credentials are active defaults. PostgreSQL is private to the Compose network. The HTTP API binds loopback; a TLS/identity-aware ingress is needed before remote access. See the [node agent](agents/node-agent/README.md) and [control backup](docs/BACKUP_AND_RESTORE.md) runbooks.

## Design boundaries

- Platform IAM and each hosted application's IAM remain separate.
- All tenant reads and writes require membership in the canonical database; mutable JWT user metadata cannot authorize tenant access.
- Image digests, provider credentials, host topology, and resource budgets are external inputs, never guessed in source.
- The 8 GB Netcup node is an orchestration target only after measured capacity admission. Production app, database, registry, and Supabase placement remains configurable.

Read [the review](development-pack/REVIEW_REV_2.md) before adding infrastructure. No certificate may be promoted by documentation or by passing a unit test alone.
