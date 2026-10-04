# DIAL Self-Hosted Client Cloud

This repository binds the DIAL hosting blueprint to source control and contains the first implemented control-plane contracts. The foundational Rev 1 blueprint and Rev 2 review currently live on branch `codex/hosting-foundation-20260923`; they are not present on `main`, so this README does not treat broken relative paths as current-main artifacts. Their requirements/corrections remain provenance for the implemented control-plane contracts until those pack artifacts are deliberately reconciled onto the canonical branch.

## Current certification

`BUILD_READY=false`, `RUNTIME_QUALIFIED=false`, `PRODUCTION_QUALIFIED=false`. The repository contains working tenant/project intent and audit code, database schema, deterministic pack validation, and a local control-plane profile. Deployment, node agents, build, billing, managed Supabase, restores, and client portal have **not** been implemented or certified. A missing capability is omitted rather than represented by a fake route or green status.


## DIAL Partner Business Platform integration

This control plane is the infrastructure authority for DIAL-built supplier and service-provider applications produced by the Partner App Factory. It accepts typed hosting desired state; it does not become supplier, catalogue, pricing, order, booking, payment or marketplace authority.

See [the Partner Platform Integration Contract](docs/PARTNER_PLATFORM_INTEGRATION.md). This cross-repository contract does not change the certification flags above.

## Local control-plane verification

```bash
python3 tools/packcheck.py
python3 -m unittest discover -s tests -v
docker compose -f deploy/control/compose.yaml --env-file deploy/control/.env up --build
```

The last command requires Docker, a real OIDC issuer, and the values described in [the control profile](deploy/control/README.md). No example credentials are active defaults. PostgreSQL is private to the Compose network. The HTTP API binds loopback; a TLS/identity-aware ingress is needed before remote access.

## Design boundaries

- Platform IAM and each hosted application's IAM remain separate.
- All tenant reads and writes require membership in the canonical database; mutable JWT user metadata cannot authorize tenant access.
- Image digests, provider credentials, host topology, and resource budgets are external inputs, never guessed in source.
- The 8 GB Netcup node is an orchestration target only after measured capacity admission. Production app, database, registry, and Supabase placement remains configurable.

Before adding infrastructure, reconcile changes against the foundational Rev 2 review on `codex/hosting-foundation-20260923` and current repository evidence. No certificate may be promoted by documentation or by passing a unit test alone.
