# Repository assessment and completion sequence

Assessment date: 2026-10-07.

## Verified starting state

| Track | Commit | Actual contents / evidence |
| --- | --- | --- |
| `main` | `fabda27032f877fcc06ec4187201e80a2de4d355` | Only README and Partner Platform integration specification. Its claimed local commands had no executable files on this branch. |
| Draft PR #1, `codex/hosting-foundation-20260923` | `43769794fb9667683a1e9951813713f89f916546` | 276 files: control API, 25 migrations, agents, workers, SDK, recovery/monitoring tools, deploy packages, requirements and tests. |
| Foundation verification | GitHub Actions `36857616984` | All eight jobs passed on that exact foundation head: contracts, disposable PostgreSQL, Compose startup, Docker/Traefik, managed PostgreSQL, Valkey, S3 and OpenBao. |

The branches diverged from `baeb36c8b0c771c537fa0c85d64805befca296ed`.
The Partner Platform document on main is preserved in this continuation and the
README describes the executable foundation. The foundation must remain a draft
until its remaining requirements and qualification gates are satisfied.

## This continuation

The [development client portal](CLIENT_PORTAL.md) provides tenant project and
application selection, real health/incident/release/domain/service/quota readback,
project/application creation, domain proof, durable service provisioning and
release submission. It uses existing authenticated API contracts and adds no
new database authority or infrastructure success state. Browser asset and client
contract tests are included in CI. The Partner Platform specification remains
specified; this portal is not a HostingIntent provisioning controller.

## Completion sequence

1. Reconcile the tested foundation with canonical main, preserving the Partner
   Platform contract. Keep false readiness flags until their evidence exists.
2. Complete supply-chain and host setup qualification: real private source clone,
   isolated rootless builder, immutable registry, selected IdP and private mTLS
   nodes, measured placement and public domains.
3. Install off-host backups, WAL streams, external monitors, event/alert receivers
   and independent key custody. Run cross-host recovery with source loss and
   measure recovery objectives and retention.
4. Complete stateful-service production operations: rotation, quota, upgrade,
   pooling/TLS, PostgreSQL and Valkey failure/recovery policies; qualify redundant
   S3 and coherent managed Supabase recovery before enabling those products.
5. Implement typed Partner HostingIntent orchestration with qualified profiles,
   canonical entitlement references, visible transformations and per-stage
   receipts; do not treat a specification or portal as a successful deployment.
6. Complete the commercial workspace: issuer login/renewal, team/audit UI,
   notifications, measured metering, plans/entitlements/billing and guarded
   transfer/export/offboarding. Complete abuse detection, stronger untrusted-code
   isolation, node quarantine and untrusted PR previews.
7. Gather exact-version/license evidence and estate-level acceptance against all
   80 development units before production and owner-acceptance promotion.

The manifest now tracks **41 partial units** and no complete production
certificate. The original blueprint is the full scope; this sequence groups
dependencies and does not remove requirements. The portal advances DU-053,
DU-054 and DU-055; their live/complete commercial requirements remain open.

## Continuation verification

Five Python portal/recovery-catalog tests and ten JavaScript client tests pass
locally. Pack consistency, Python compilation, workflow YAML parsing and
whitespace checks pass. The recovery-catalog test now explicitly creates the
unsafe file permissions it intends to reject, so it also works under a private
process umask. The full suite cannot run in this workspace: psycopg and the
OpenAPI validator are unavailable, dependency installation did not succeed,
network sockets and Docker daemon access are denied, and Chromium cannot launch.
The new HTTP/browser and existing disposable runtime checks remain to be run by
CI on the continuation commit. The cited eight-job CI success applies to the
original foundation commit only. GitHub upload has not completed in this session;
no remote update or new CI success is claimed.

## Remaining deployment inputs

Production placement and host access, the real identity provider, production
domains, registry/build credentials, independent encrypted backup targets and
key custody, external monitoring/receiver placement, SMTP delivery and commercial
provider decisions are unset. No such credentials or host identities were
configured in this managed workspace. They cannot be replaced with examples or
inferred from disposable CI. Full platform completion requires those inputs and
live evidence; repository edits alone cannot establish it.
