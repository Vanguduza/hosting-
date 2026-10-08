# Repository assessment and completion sequence

Assessment date: 2026-10-08.

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

## Reviewed execution profile continuation

Migration 030 implements protected immutable imports for tenant/template/version/environment
profiles, with admitted image digests, typed supported setup, bounded resource
ceilings, independent review provenance and measured node configuration bindings.
Current readback validates the newest version, expiry/withdrawal, fresh enabled
node evidence, configuration/capacity/lifecycle drift and requested-artifact
placement. API/portal/CLI readback excludes private review and estate details.
Intent rechecks share one statement snapshot with earlier authority/runtime
observations; matching a profile does not certify the estate or execute resources.
[The runbook](EXECUTION_PROFILES.md) defines the protected attestation boundary.

Live profile review and upstream factory installation, Partner secret resolution,
independent backup integration and automatic intent execution remain open. All
readiness and acceptance flags remain false. The API now has 39 paths and 52
operations; the control schema has 30 migrations.

## Trusted Partner approval continuation

Migration 029 adds a protected, immutable tenant publisher registry and exact-intent
commercial/admin decision intake. Registered service identity, source version,
intent hash, monotonic sequence, bounded validity, current hosting plan and existing
administrator membership are checked. Current redacted readback and historical
intent evaluation remain separate; revocation, expiry and source/plan/admin changes
fail closed without falling back to older approval. Portal and CLI readback and a
private-file publisher helper are implemented. No resources or memberships are
mutated by this adapter. [The runbook](PARTNER_AUTHORITY.md) pins the inspected
upstream canon and explains the trust boundary and uninstalled factory.

No live publisher configuration, upstream commercial authority, template/estate
review evidence, Partner secret resolution, independent backup integration or
automatic intent execution is installed. All readiness and qualification flags
remain false. The API now exposes 38 paths and 51 operations, with 29 migrations.

## This continuation

The [development client portal](CLIENT_PORTAL.md) provides tenant project and
application selection, real health/incident/release/domain/service/quota readback,
project/application creation, domain proof, durable service provisioning and
release submission and rollback. The resumed build adds paginated audit history,
owner-managed invitation/membership/service-grant screens, invitation acceptance,
private token redaction/clearing and stricter unauthorized/stream failure handling.
It uses existing authenticated API contracts and adds no
new deployment authority or infrastructure success state. Browser asset and client
contract tests are included in CI. A [typed Partner HostingIntent preflight](PARTNER_PREFLIGHT.md)
now validates all contract fields and compares authenticated project/environment,
artifact-bound health, domain and service readback. It exposes unavailable commercial,
profile, admin, secret and backup authority explicitly. Durable HostingIntent
provisioning remains unimplemented.

The next continuation implements [manual domain registration](DOMAIN_REGISTRATION.md):
owner-only `.com`/`.co.zw` requests, immutable quotes and historical consent,
exact quote approval, pre-processing cancellation and protected operator
fulfillment. Migration 026 restricts API writes, enforces tenant row policies and
duplicate purchase exclusion, and records transactional audit/outbox facts.
Unknown registrar outcomes remain pending reconciliation. Actual registrar
accounts, automatic ordering and renewals are not configured.

The following continuation implements [public-client issuer sign-in](ISSUER_LOGIN.md),
PKCE callback validation and serialized in-memory renewal. JWT signatures,
issuer, audience, subject, nonce and supplied token hashes are checked; failed
renewals and late disconnected-session replies fail closed. This advances
DU-003/DU-053/DU-054 without creating an issuer account or promoting live IAM
qualification. Hosting roles still come from the canonical database.

A prior continuation implements [hosting-local entitlement controls](HOSTING_ENTITLEMENTS.md):
immutable operator assignments, tenant readback, feature/count/capacity admission,
worker execution holds and renewal, and registrar purchase-start checks. Migration
027 preserves existing tenants in an explicit compatibility mode; production
requires the protected one-way required-assignment switch. Live canonical commercial
records, billing and offboarding remain open. This advances DU-004 and
DU-046 while all readiness/acceptance flags remain false.

The next continuation adds [durable Partner intent intake and reconciliation
receipts](PARTNER_INTENTS.md): immutable tenant/application-bound requests,
consistent hosting evidence, historical retry receipts, transactional audit/outbox
and owner/admin portal/CLI readback. Migration 028 enforces payload/receipt
validation, tenant access and immutable history. It advances intake and readback;
automatic multi-resource provisioning and live canonical authority remain open.

Runtime verification found and corrected a private-umask Valkey ACL permission
failure, added immutable retry repair, and made API/fixture Docker copies readable
by their unprivileged users. Local private ingress/S3 probes retain local routing
while outbound traffic keeps the inherited proxy. API builds accept an optional
CA bundle as a BuildKit secret; no environment CA or credential is checked in.

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
6. Complete the commercial workspace: live issuer/login qualification, step-up protection,
   notifications, measured metering, plans/entitlements/billing and guarded
   transfer/export/offboarding. Complete abuse detection, stronger untrusted-code
   isolation, node quarantine and untrusted PR previews.
7. Gather exact-version/license evidence and estate-level acceptance against all
   80 development units before production and owner-acceptance promotion.

The manifest now tracks **42 partial units** and no complete production
certificate. The original blueprint is the full scope; this sequence groups
dependencies and does not remove requirements. The portal advances DU-053,
DU-054, DU-055 and DU-058; their live/complete commercial requirements remain open.

## Continuation verification

Network and runtime access were restored. Before the registration continuation,
the Python suite ran 102 tests: 68 passed without runtime fixtures and 34
integration checks skipped in that invocation.
All 22 disposable PostgreSQL integration tests passed separately. Twenty JavaScript
client tests and the Chromium browser contract suite pass, including mobile layout,
owner access, private tokens, audit paging, rollback and expired-session behavior.
The recovery-catalog permission test is independent of inherited umask.

Disposable Docker/mTLS deployment, trusted TLS ingress/isolation/rate-limit,
private PostgreSQL, Valkey, Garage S3, OpenBao credential/CAS and independent
Raft recovery checks pass. Encrypted control backup/semantic restore, selected
point-in-time recovery after source WAL loss, client data-service recovery and
alert queue recovery pass. These are local disposable proofs, not estate certificates.
The API image also builds with verified TLS through the environment's proxy CA.

The reconciled continuation was pushed to draft PR #1. GitHub Actions
[37575502254](https://github.com/Vanguduza/hosting-/actions/runs/37575502254)
passed all nine jobs on `753533308133fe4690483bbda7026c18971e8085`, including the
new portal browser job. Follow-up run
[37576709683](https://github.com/Vanguduza/hosting-/actions/runs/37576709683)
also passed all nine jobs on `60e00d52af87da978b1146ea41f4d55c9863ce59`, verifying
the typed preflight and runtime repairs. Subsequent schema validation rejects
trailing whitespace and malformed top-level domain labels; its focused tests pass
and its head checks are available from the draft PR. Pack consistency, compilation
and whitespace checks also pass.

The manual registration continuation passes 71 fixture-free Python tests (47
runtime checks skip in that invocation), all 22 existing database tests and 13
registration database/HTTP tests separately, and 21 JavaScript client tests.
Chromium exercises request, quote review, consent, cancellation, tenant isolation,
unavailable readback and mobile layout. Fresh Compose startup applies all 26
migrations and refuses source/ledger drift. These local checks precede publication
and final-head CI; the draft PR check results are authoritative for the pushed head.

The issuer continuation passes 81 fixture-free Python tests (47 runtime tests
skip in that invocation), 29 JavaScript client tests, the full intercepted PKCE
redirect/renewal browser proof and the existing workspace browser proof. Pack
consistency, compilation, OpenAPI validation and Compose configuration pass.
Publication and final-head CI are recorded on draft PR #1.

Issuer run [37600427716](https://github.com/Vanguduza/hosting-/actions/runs/37600427716)
passed all nine jobs on `7c34b854cb4006702fef7f32b938c09940a4954b`, including
the pinned Playwright 1.55 navigation fixture. Entitlement verification and final-head
CI are recorded on the same draft PR.

The entitlement continuation passes all 15 dedicated disposable database tests,
the existing 22 database tests and 13 registration tests, 84 fixture-free Python
tests (62 runtime tests skip in that invocation), 30 JavaScript tests and both
browser proofs. OpenAPI advertises 34 paths / 45 operations. Fresh Compose startup
expects 27 migrations and rejects schema drift. Required-assignment mode remains
a protected installation step; no production flag is promoted by these tests.

The durable intent continuation passes 12 dedicated disposable database tests,
the 22 existing database tests, 13 registration tests and 15 entitlement tests.
The fixture-free Python suite passes 91 tests, with 74 runtime checks skipped in
that invocation (165 total); all 31 JavaScript tests and both browser proofs pass.
OpenAPI advertises 37 paths / 49 operations, and fresh startup expects 28 migrations.
These are software/fixture checks; all readiness and qualification flags remain false.
The storage CI fixture installs pinned Restic 0.18.1 from its verified archive,
with bounded HTTPS download attempts, after a runner stalled in Ubuntu package
installation. Production tool installation remains a separate deployment step.

The trusted publisher continuation passes 97 fixture-free Python tests, with 89
runtime checks skipped in that invocation, and 32 JavaScript client tests. All 15
new PostgreSQL authority tests pass, including signed-JWT HTTP intake, publisher
isolation, source disable serialization, exact bindings, expiry/revocation, plan
and membership changes, retry races, immutable/private history and audit rollback.
The existing 62 PostgreSQL tests and both Chromium browser proofs pass separately.
OpenAPI advertises 38 paths / 51 operations; startup applies 29 migrations and
refuses ledger drift. Exact-head CI evidence is recorded on draft PR #1; none of
these disposable checks promotes production qualification.

The reviewed profile continuation passes 102 fixture-free Python tests, with 105
runtime checks skipped in that invocation (207 total), and 33 JavaScript tests.
All 16 profile database checks pass, alongside the 77 prior PostgreSQL tests and
both browser proofs. The API image packages all four contracts and 30 migrations;
OpenAPI validates 39 paths / 52 operations. Pack, compilation and whitespace
checks pass. Exact-head CI evidence is recorded on draft PR #1; disposable
fixtures and protected import interfaces do not promote live qualification.

## Remaining deployment inputs

The owner expects Zimbabwean customers using `.co.zw` and `.com`, including new
domain registrations. [The launch recommendation](ZIMBABWE_HOSTING_AND_DOMAINS.md)
separates a ZISPA member registration workflow from an OpenSRS `.com` reseller
integration. DNS proof and the audited manual registration workflow work;
automatic registrar ordering, readback and renewal remain open.

Production placement and host access, the real identity provider, production
domains, registry/build credentials, independent encrypted backup targets and
key custody, external monitoring/receiver placement, SMTP delivery and commercial
provider decisions are unset. No such credentials or host identities were
configured in this managed workspace. They cannot be replaced with examples or
inferred from disposable CI. Full platform completion requires those inputs and
live evidence; repository edits alone cannot establish it.
