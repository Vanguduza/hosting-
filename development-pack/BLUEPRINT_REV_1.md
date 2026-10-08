# DIAL Self-Hosted Client Cloud
## PRD → Deterministic Development Pack — Rev 1 — Standard-Conformant Consolidated Blueprint

**Pack ID:** `DIAL-HOSTING-PLATFORM-DDP-R1`  
**Project:** DIAL Self-Hosted Client Cloud (working project identity; commercial product name not yet locked)  
**Pack type:** Greenfield platform / managed hosting / self-hosted PaaS / client cloud  
**Governing standards:**  
- `PRD_TO_DETERMINISTIC_DEVELOPMENT_PACK_PROJECT_PREPARATION_GUIDE_REV_1`
- `DIAL-FFDRM-R1-PRD-DDP-R2` / Fable Forensic Development & Remediation Method

**Compilation date:** 2026-09-23  
**Repository:** `NOT_YET_BOUND`  
**Canonical branch:** `NOT_YET_BOUND`  
**Baseline SHA:** `NOT_YET_BOUND`  
**Authority mode:** `OWNER → PLATFORM_POLICY → DETERMINISTIC_CONTROLLERS → NODE_AGENTS`  
**FORENSIC_BUILD_READY:** `false`  
**BUILD_READY:** `false`  
**Reason:** This document defines the target Product Truth, architecture, contracts, Development Units, failure model, implementation DAG and verification obligations, but repository baseline, exact tool/version qualification, environment certification, external-provider credentials, production topology, measured capacity limits, recovery drills, live integration evidence and owner acceptance do not yet exist. No readiness or runtime certification is implied by this blueprint.

> **Canonical rule:** documentation is not implementation. A service, route, class, container, screen, registry entry or test does not count as a completed capability unless the production causal path, authority path, state path, failure/recovery behavior and observable postcondition are evidenced.

---

# 00. PACK MANIFEST

```yaml
schema_version: 1
pack_id: DIAL-HOSTING-PLATFORM-DDP-R1
project_id: dial-hosting-platform
project_name: DIAL Self-Hosted Client Cloud
project_kind: MULTI_TENANT_SELF_HOSTED_PAAS
revision: 1
status: PREDEVELOPMENT_BLUEPRINT
governing_standards:
  - PRD_TO_DETERMINISTIC_DEVELOPMENT_PACK_PROJECT_PREPARATION_GUIDE_REV_1
  - DIAL_FABLE_FORENSIC_PREDEVELOPMENT_STANDARD
authority_mode: OWNER_TO_PLATFORM_POLICY_TO_TYPED_CONTROLLERS
repository:
  name: NOT_YET_BOUND
  branch: NOT_YET_BOUND
  baseline_sha: NOT_YET_BOUND
product_truth_revision: DHPC-PT-R1
development_unit_registry_revision: DHPC-DU-R1
feature_registry_revision: DHPC-FTR-R1
screen_registry_revision: DHPC-SCR-R1
architecture_revision: DHPC-ARCH-R1
implementation_dag_revision: DHPC-DAG-R1
research_coverage_revision: DHPC-RCM-R1
build_ready_state: false
forensic_build_ready_state: false
runtime_qualified: false
production_qualified: false
owner_accepted: false
```

## 00.1 Required canonical artifact tree

At repository admission, this consolidated blueprint SHALL be decomposed into the canonical pack structure:

```text
development-pack/
├── 00-governance/
│   ├── PACK_MANIFEST.yaml
│   ├── PRODUCT_TRUTH.md
│   ├── SCOPE_AND_NON_GOALS.md
│   ├── AUTHORITY_MAP.yaml
│   ├── DECISION_REGISTER.yaml
│   ├── AMBIGUITY_REGISTER.yaml
│   └── BLOCKERS.yaml
├── 01-prd/
│   ├── REQUIREMENTS.yaml
│   ├── ACCEPTANCE_CONTRACTS.yaml
│   └── OWNER_CONSTRAINTS.yaml
├── 02-development-units/
│   ├── DEVELOPMENT_UNIT_REGISTRY.yaml
│   ├── DEPENDENCY_GRAPH.json
│   └── READINESS_MANIFEST.yaml
├── 03-product-graph/
│   ├── FEATURES.yaml
│   ├── FEATURE_GRAPH.json
│   ├── SCREENS.yaml
│   ├── SCREEN_FEATURE_EDGES.yaml
│   ├── NAVIGATION_GRAPH.json
│   ├── STATE_MACHINES/
│   ├── WORKFLOWS/
│   └── EVENTS.yaml
├── 04-contracts/
│   ├── DATA_MODELS/
│   ├── APIS/
│   ├── ACTION_REGISTRY.yaml
│   ├── CAPABILITY_REGISTRY.yaml
│   └── VERIFICATION_REGISTRY.yaml
├── 05-research/
│   ├── COVERAGE_MANIFEST.yaml
│   ├── SOURCE_REGISTRY.yaml
│   ├── MISSIONS/
│   ├── ARTIFACTS/
│   ├── KNOWLEDGE_CAPSULES/
│   ├── CONTRADICTIONS.yaml
│   └── REFERENCES.yaml
├── 06-design/
│   ├── DESIGN_AUTHORITY.md
│   ├── DESIGN_SYSTEM.yaml
│   ├── SCREEN_QUALITY_PACKETS/
│   ├── INTERACTION_REGISTRY.yaml
│   └── MOTION_REGISTRY.yaml
├── 07-architecture/
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── RUNTIME_TOPOLOGY.md
│   ├── COMPONENT_REGISTRY.yaml
│   ├── FAILURE_MODEL.yaml
│   ├── SECURITY_MODEL.md
│   ├── PERFORMANCE_MODEL.md
│   └── OBSERVABILITY_MODEL.md
├── 08-implementation/
│   ├── IMPLEMENTATION_DAG.json
│   ├── WORKSTREAMS.yaml
│   └── PACKETS/
├── 09-verification/
│   ├── TEST_STRATEGY.md
│   ├── EVIDENCE_PLAN.yaml
│   ├── COMPONENT_LEDGER.yaml
│   ├── COUNTEREXAMPLES.yaml
│   ├── MUTATIONS.yaml
│   └── E2E_PLAN.md
└── 10-certification/
    ├── PREDEVELOPMENT_FORENSIC_CERTIFICATE.json
    ├── BUILD_READY_CERTIFICATE.md
    ├── RUNTIME_QUALIFICATION.md
    ├── OWNER_ACCEPTANCE.md
    └── BLOCKERS.yaml
```

---

# 01. EXECUTIVE CONTRACT

The product is a self-hosted managed application cloud for DIAL-owned products and applications built for paying clients.

It SHALL combine the strongest proven patterns of modern self-hosted PaaS and infrastructure control systems without becoming a source-code splice of Dokploy, Coolify or Komodo.

The platform SHALL provide, through one coherent control plane:

```text
CLIENT / OWNER INTENT
        ↓
IDENTITY + TENANT AUTHORITY
        ↓
DECLARATIVE DESIRED STATE
        ↓
POLICY / QUOTA / BILLING CHECK
        ↓
DURABLE RESOURCE WORKFLOW
        ↓
BUILD / PROVISION / DEPLOY / RESTORE
        ↓
NODE-LOCAL TYPED EXECUTION
        ↓
OBSERVE ACTUAL STATE
        ↓
RECONCILE
        ↓
EVIDENCE + AUDIT + CLIENT READBACK
```

The platform SHALL support the full lifecycle of a client application:

```text
client organization
→ project
→ environments
→ source connection
→ build
→ immutable release
→ application runtime
→ domain + TLS
→ database / Supabase / storage
→ secrets
→ backups
→ observability
→ billing
→ support
→ ownership transfer or export
```

The platform SHALL be self-hostable on ordinary Linux VPS infrastructure and SHALL start with Docker/Compose rather than requiring Kubernetes. Cluster orchestration, microVM isolation and multi-region scheduling are extension runtimes, not baseline dependencies.

---

# 02. OWNER INTENT / PRD NORMALIZATION

## 02.1 Requirement atoms

| ID | Type | Requirement | Acceptance direction |
|---|---|---|---|
| REQ-001 | PRODUCT | Operate one self-hosted control plane for DIAL projects and paying client projects. | Multi-tenant organization/project/environment model is production reachable. |
| REQ-002 | TENANCY | Every client is an isolated organization with delegated administration. | Cross-tenant access tests fail closed. |
| REQ-003 | IAM | Platform login supports Google, Apple, email/password, email OTP, phone/SMS OTP, password reset and MFA/passkeys. | Provider and recovery E2E evidence. |
| REQ-004 | IAM | Infrastructure IAM and hosted-application end-user IAM are separate security domains. | Separate issuers/datastores/policies. |
| REQ-005 | APP_AUTH | Hosted apps may receive dedicated self-hosted Supabase Auth. | Dedicated project auth stack can be provisioned and destroyed safely. |
| REQ-006 | PAAS | Deploy Git repositories, Dockerfiles, OCI images and Docker Compose workloads. | Immutable release deploy and rollback proof. |
| REQ-007 | BUILD | Build compute is separated from production runtime where configured. | Build node creates image; runtime only pulls digest. |
| REQ-008 | GIT | GitHub is first-class; provider interface permits GitLab/Gitea later. | Webhook/poll/credential contracts versioned. |
| REQ-009 | PREVIEW | Pull requests may create isolated preview environments with TTL and automatic cleanup. | PR open/update/close E2E. |
| REQ-010 | DATABASE | Host managed PostgreSQL resources. | Provision, connect, backup, restore, rotate credentials. |
| REQ-011 | SUPABASE | Host complete local/self-hosted Supabase projects as first-class resources. | One project can be created, upgraded, backed up and restored from platform. |
| REQ-012 | CACHE | Host Valkey/Redis-compatible cache resources. | Provision/connect/backup policy where applicable. |
| REQ-013 | STORAGE | Offer S3-compatible object storage and project-scoped buckets. | Tenant isolation, quota and object lifecycle evidence. |
| REQ-014 | DOMAIN | Provision and manage domains, DNS records and automatic TLS. | Domain ownership + DNS + certificate state machine. |
| REQ-015 | EDGE | Reverse proxy, routing, rate limits and WAF protection are centrally managed. | Policy tests + live route proof. |
| REQ-016 | SECRETS | Secrets are never canonical in Git or normal application database rows. | OpenBao-backed secret references and audit evidence. |
| REQ-017 | SUPPLY_CHAIN | Production images are immutable, scanned and attestable. | image digest + scan + SBOM + signature evidence. |
| REQ-018 | ROLLBACK | Rollback uses previously admitted immutable artifacts, not source rebuild. | failed deployment rollback drill. |
| REQ-019 | BACKUP | Backups support encrypted off-host targets and routine restore testing. | backup is insufficient without successful restore evidence. |
| REQ-020 | DR | Recovery procedures exist for control plane, databases, Supabase, registry and object storage. | scheduled recovery drill. |
| REQ-021 | OBS | Metrics, logs and traces use an OpenTelemetry-compatible ingestion boundary. | correlated release/deployment trace. |
| REQ-022 | STATUS | Clients receive service health and incident/status pages. | status system survives primary platform outage by separate failure domain. |
| REQ-023 | BILLING | Platform meters usage and maps usage to plans, entitlements and invoices. | idempotent usage ledger. |
| REQ-024 | QUOTA | Plans enforce resource and feature entitlements before execution. | over-quota request rejected without side effect. |
| REQ-025 | COMM | Transactional email, campaigns, SMS and OTP delivery use provider adapters. | failover/retry/delivery receipt proof. |
| REQ-026 | MAIL | Self-hosted SMTP may use BillionMail; listmonk may provide campaign/transactional template workflows. | tools remain replaceable behind messaging contracts. |
| REQ-027 | CLIENT_PORTAL | Clients see apps, domains, deployments, database health, backups, usage, invoices, incidents and support. | live data only; no decorative fake health. |
| REQ-028 | WHITE_LABEL | Client portal supports organization branding and custom domains. | tenant-specific brand projection. |
| REQ-029 | SUPPORT | Support tickets/chat/knowledge base integrate without becoming platform authority. | Chatwoot or equivalent adapter. |
| REQ-030 | ANALYTICS | Hosted clients may enable privacy-oriented analytics as a service. | optional project-scoped service. |
| REQ-031 | FLAGS | Hosted apps may enable feature flags/remote config. | optional project-scoped service. |
| REQ-032 | HANDOVER | DIAL can transfer project ownership to a client without redeployment or data migration. | authority/billing transfer E2E. |
| REQ-033 | EXPORT | A client can export its app definition, images, DB, objects, DNS records and history within policy. | portability package validates. |
| REQ-034 | NODE | Routine operations use authenticated node agents; root SSH is bootstrap/recovery only. | typed RPC and mTLS identity. |
| REQ-035 | NETWORK | Control-plane management traffic uses private authenticated networking. | no public node-management ports required. |
| REQ-036 | WORKFLOW | Long-running provisioning and deployment operations survive controller restart. | crash/replay tests. |
| REQ-037 | EVENT | Async events are replayable but are not canonical business state. | event loss/replay tests. |
| REQ-038 | AUDIT | Every sensitive control action is attributable to human/service identity and immutable-enough audit evidence. | actor/action/resource/result correlation. |
| REQ-039 | TERMINAL | Shell/DB console access is JIT, scoped, time-limited and audited. | lease expiry and revocation tests. |
| REQ-040 | ISOLATION | Runtime isolation class is explicit per workload. | shared/dedicated policy enforced. |
| REQ-041 | UNTRUSTED_CODE | Arbitrary customer-supplied code requires stronger isolation than ordinary shared containers. | microVM/dedicated runtime gate before enablement. |
| REQ-042 | POLICY | Admission and high-risk actions use deterministic policy checks. | policy decision is persisted and testable. |
| REQ-043 | SCHEDULING | Placement respects tenant isolation, capacity, architecture, labels and affinity constraints. | deterministic placement fixtures. |
| REQ-044 | UPGRADES | Platform and managed service upgrades are staged, reversible and evidence-bound. | canary + backup + compatibility gate. |
| REQ-045 | CLIENT_DATA | Deletion, retention, export and legal-hold behavior are explicit. | lifecycle state machine. |
| REQ-046 | ABUSE | Public hosting includes abuse, spam and malicious workload controls. | suspend/quarantine workflow. |
| REQ-047 | SLA | Product distinguishes design targets from paid SLA commitments. | no unmeasured SLA claim. |
| REQ-048 | API | All primary control-plane functions are available by documented API, not UI-only. | OpenAPI contract tests. |
| REQ-049 | CLI | Operators have a typed CLI using the same API and policy boundaries as the UI. | parity tests. |
| REQ-050 | HERMES | Hermes may become a tightly scoped authenticated client, never the deployment authority. | deploy-only/service-account permission proof. |
| REQ-051 | DETERMINISM | Same desired state + admitted artifact + policy version must converge to semantically equivalent runtime state. | replay/convergence tests. |
| REQ-052 | RECONCILIATION | Desired, admitted, deployed, serving and healthy states are distinct. | UI/API expose each state independently. |
| REQ-053 | EVIDENCE | “deployed” and “healthy” require runtime evidence bound to release + environment. | receipt validator. |
| REQ-054 | COST | Small installations do not require k3s, Ceph or HA databases. | single-node profile passes full acceptance. |
| REQ-055 | SCALE | Architecture permits dedicated nodes, clusters and regions without rewriting project model. | runtime-driver contract. |
| REQ-056 | CLIENT_BILLING | Manual invoice, subscription and usage-based billing are supported by adapters. | payment processor not hard-coded. |
| REQ-057 | EMAIL_DELIVERABILITY | Self-hosted mail is optional, not required for control-plane viability. | external SMTP provider can replace it. |
| REQ-058 | STATUS_INDEPENDENCE | Public status plane should not fail with the primary hosting plane. | external/separate-region deployment requirement. |
| REQ-059 | NO_LOCK_IN | Core customer workload data is exportable in standard formats. | export verification. |
| REQ-060 | CERTIFICATION | Normal development starts only after FORENSIC_BUILD_READY. | certificate bound to baseline and pack hashes. |

## 02.2 Explicit non-goals

```text
NOT a fork made by merging Dokploy + Coolify + Komodo source trees
NOT a crypto/authentication implementation written from first principles
NOT a mandatory Kubernetes platform in v1
NOT a general public “run arbitrary code” cloud in v1
NOT a substitute for upstream volumetric DDoS protection
NOT a place to store plaintext long-lived secrets
NOT a single shared Supabase project used for unrelated clients
NOT an excuse to expose Docker sockets, Postgres or node agents publicly
NOT a second Hermes authority plane
NOT a system where CI green == live production healthy
```

---

# 03. CANONICAL PRODUCT TRUTH

| ID | Canonical statement |
|---|---|
| PT-001 | The platform is a multi-tenant managed hosting control plane for DIAL-owned and client-owned applications. |
| PT-002 | The control plane owns desired-state orchestration; node agents execute typed bounded operations. |
| PT-003 | Human/client identity is provided by a hardened IAM engine; authorization is additionally enforced by platform RBAC/policy. |
| PT-004 | Platform IAM and each hosted application's end-user IAM are separate. |
| PT-005 | ZITADEL is the preferred platform-IAM candidate because organizations map cleanly to B2B tenants and delegated administration. |
| PT-006 | Supabase Auth is a preferred hosted-app IAM implementation for projects that provision self-hosted Supabase. |
| PT-007 | The platform control database is PostgreSQL and does not depend on a hosted client Supabase project. |
| PT-008 | Docker/Compose is the baseline runtime. k3s is an optional higher-scale runtime driver after qualification. |
| PT-009 | Build execution and deployment execution are separable roles. |
| PT-010 | Releases are immutable and identified by image digest plus configuration revision. |
| PT-011 | Desired state is versionable and exportable; live state is reconciled against it. |
| PT-012 | NATS/event transport may move state-change facts but does not replace PostgreSQL as control truth. |
| PT-013 | Temporal may provide durable workflow execution but does not own domain authority. |
| PT-014 | OpenBao is the preferred secret-management candidate; applications receive scoped references/leases, not platform master secrets. |
| PT-015 | Routine server control occurs through mTLS node agents on private networking; SSH is bootstrap/recovery. |
| PT-016 | Traefik is the baseline dynamic ingress/reverse-proxy candidate. |
| PT-017 | A WAF/reputation layer is subordinate to route policy and cannot silently alter canonical configuration. |
| PT-018 | Managed Supabase is one isolated project stack per provisioned Supabase resource unless a later qualified architecture explicitly changes this. |
| PT-019 | Self-hosted Supabase upstream runs as one project; this platform supplies the missing multi-client/multi-project management plane. |
| PT-020 | Client resources must be independently transferable/exportable. |
| PT-021 | Billing consumes an authoritative usage ledger; billing calculations do not modify measured usage. |
| PT-022 | Client project suspension is reversible and distinct from deletion. |
| PT-023 | Backups are not certified merely because a backup job succeeded; restoration must be tested. |
| PT-024 | Public status communications must occupy a different failure domain from primary hosting where practical. |
| PT-025 | Untrusted arbitrary customer code is deferred until stronger runtime isolation is certified. |
| PT-026 | Client-facing UI shows real state from canonical services, never fake health, fabricated metrics or placeholder success. |
| PT-027 | Hermes may invoke approved platform actions through a service identity but cannot bypass IAM, policy, quota or deployment gates. |
| PT-028 | Tool adoption is by bounded adapter and qualification; no external tool becomes product authority by convenience. |

---

# 04. AUTHORITY MODEL

## 04.1 Authority chain

```text
OWNER / CLIENT
    │ authenticated intent
    ▼
PLATFORM IAM (identity proof)
    │
    ▼
PLATFORM AUTHZ / POLICY (permission + entitlement + risk)
    │
    ▼
RESOURCE CONTROLLER (desired state)
    │
    ▼
TEMPORAL WORKFLOW (durability, not authority)
    │
    ▼
NODE / BUILD / SERVICE ADAPTER (typed execution)
    │
    ▼
EXTERNAL SIDE EFFECT
    │
    ▼
OBSERVATION + RECONCILIATION
    │
    ▼
CONTROL DB + AUDIT + CLIENT READBACK
```

## 04.2 Single-owner authority map

| Subject | Canonical owner | Execution/provider |
|---|---|---|
| Tenant identity | ZITADEL / platform IAM | Login UI, Google, Apple, email/SMS transport |
| Tenant authorization | Platform policy database + policy engine | API middleware / OPA candidate |
| Project desired state | Control-plane PostgreSQL + Git export | Resource controllers |
| Deployment workflow | Deployment controller | Temporal durable execution |
| Node command authority | Control API | Node agent |
| Secret truth | OpenBao | secret injector |
| Build artifact truth | Harbor OCI digest | BuildKit |
| Production release selection | Release controller | runtime driver |
| Runtime actual state | Node/runtime adapter observation | Docker/k3s |
| DNS desired state | Domain controller | PowerDNS/external provider adapter |
| TLS state | Certificate controller | ACME/Traefik |
| Database state | DB controller | PostgreSQL/Supabase driver |
| Billing usage | Usage ledger | collectors/adapters |
| Invoice state | Billing controller | Lago/payment adapter |
| Backup catalog | Backup controller | object-store target |
| Audit truth | Audit service | append-only store + observability export |
| Client support record | Support adapter | Chatwoot candidate |
| App analytics | project service | Umami candidate |
| Public uptime status | status adapter | OpenStatus candidate |

## 04.3 Sensitive action requirements

Actions below require explicit policy and auditable actor identity:

```text
delete project
delete database
restore database
open shell
open database console
read secret value
rotate secret
change DNS zone
transfer project ownership
change billing owner
disable backups
alter retention
change organization owner
grant platform-admin role
disable MFA requirement
register production node
remove production node
deploy unsigned/unadmitted artifact
enable untrusted-code runtime
```

High-risk actions SHALL support step-up authentication and/or explicit confirmation.

---

# 05. DECISION REGISTER

| Decision | State | Rationale |
|---|---|---|
| DEC-001 Build a new platform rather than merge competitor codebases. | ACCEPTED | avoids architecture/license coupling and preserves deterministic authority. |
| DEC-002 Docker/Compose is baseline runtime. | ACCEPTED | lowest operational burden; satisfies initial estate. |
| DEC-003 k3s is an optional future runtime driver. | DEFERRED | only when HA/scheduling need is measured. |
| DEC-004 ZITADEL is preferred platform IAM. | CANDIDATE_ACCEPTED | B2B organizations, delegated administration, social login, OTP/MFA/passkeys. Must pass exact-version qualification. |
| DEC-005 Supabase Auth remains app-level IAM for managed Supabase projects. | ACCEPTED | keeps client app identities isolated from hosting IAM. |
| DEC-006 Go is preferred control-plane and node-agent language. | PROPOSED | static binaries, concurrency, operational simplicity. Benchmark/owner lock required. |
| DEC-007 React + TypeScript + Vite is preferred portal stack. | PROPOSED | consistent modern DIAL frontend direction; API remains independent. |
| DEC-008 PostgreSQL is canonical control-plane state. | ACCEPTED | transactional domain truth. |
| DEC-009 Temporal is durable workflow substrate. | CANDIDATE_ACCEPTED | survives controller/network interruptions. |
| DEC-010 NATS JetStream is asynchronous event/replay substrate. | CANDIDATE_ACCEPTED | low-latency events without moving canonical state out of Postgres. |
| DEC-011 OpenBao is preferred secrets engine. | CANDIDATE_ACCEPTED | dynamic/leased secrets, auditability, API. |
| DEC-012 Harbor is preferred OCI registry. | CANDIDATE_ACCEPTED | project scoping, robots, scanning/replication. |
| DEC-013 Rootless BuildKit is default isolated image builder. | CANDIDATE_ACCEPTED | separation from runtime and reduced root exposure. |
| DEC-014 Trivy + SBOM + Cosign form minimum artifact admission gate. | CANDIDATE_ACCEPTED | vulnerability/secret/SBOM/signature evidence. |
| DEC-015 Traefik is default dynamic ingress. | CANDIDATE_ACCEPTED | Docker discovery and dynamic routing fit baseline runtime. |
| DEC-016 PowerDNS is preferred self-hosted authoritative DNS. | CANDIDATE_ACCEPTED | API-driven zones/DNSSEC; external DNS adapters remain supported. |
| DEC-017 SeaweedFS is preferred scalable S3 candidate, behind storage driver. | RESEARCH_REQUIRED | benchmark operational maturity and backup/repair behavior before lock. |
| DEC-018 CloudNativePG is optional PostgreSQL HA path under k3s. | DEFERRED | PITR/HA useful only after k3s phase. |
| DEC-019 Lago is preferred billing/metering engine behind platform billing contracts. | CANDIDATE_ACCEPTED | avoid custom invoice/metering engine. |
| DEC-020 BillionMail is optional self-hosted SMTP/MTA candidate. | RESEARCH_REQUIRED | deliverability, abuse controls and operational burden require qualification. |
| DEC-021 listmonk is optional campaign/template layer, not SMTP authority. | ACCEPTED_AS_OPTIONAL | campaign/transactional API, replaceable. |
| DEC-022 NetBird is preferred private management network candidate. | CANDIDATE_ACCEPTED | WireGuard-based private access and policy. |
| DEC-023 CrowdSec AppSec is preferred edge-security candidate. | CANDIDATE_ACCEPTED | Traefik integration and virtual patching. |
| DEC-024 OpenTelemetry is canonical telemetry ingestion boundary. | ACCEPTED | avoids binding instrumentation to one backend. |
| DEC-025 VictoriaMetrics/Loki/Tempo/Grafana are baseline observability candidates. | RESEARCH_REQUIRED | validate footprint/retention on target estate. |
| DEC-026 OpenStatus public status is deployed outside primary failure domain. | CANDIDATE_ACCEPTED | incident communications must survive host outage. |
| DEC-027 Chatwoot is optional client-support/knowledge-base adapter. | CANDIDATE_ACCEPTED | mature self-hosted support surface. |
| DEC-028 Umami is optional analytics-as-a-service resource. | CANDIDATE_ACCEPTED | lightweight client analytics. |
| DEC-029 Flagsmith is optional feature-flags resource. | CANDIDATE_ACCEPTED | app teams gain feature management without custom implementation. |
| DEC-030 Firecracker is deferred strong-isolation runtime for untrusted code. | DEFERRED | v1 hosts code created/controlled by DIAL; microVM complexity not yet justified. |

---

# 06. DEVELOPMENT UNIT REGISTRY

Every material feature SHALL map to one or more stable Development Units.

| DU | Development Unit | Depends on | Verification class |
|---|---|---|---|
| DU-001 | Canon/pack/repository admission | — | forensic/static |
| DU-002 | Control-plane domain model + migrations | 001 | schema/migration |
| DU-003 | Platform IAM integration | 002 | auth/E2E/security |
| DU-004 | Tenant/RBAC/policy/entitlements | 002,003 | contract/security |
| DU-005 | API gateway + OpenAPI | 002-004 | contract/integration |
| DU-006 | Audit ledger | 002,003 | integration/mutation |
| DU-007 | Durable workflow integration | 002,005 | restart/replay |
| DU-008 | Event fabric | 002,005 | replay/idempotency |
| DU-009 | Server enrollment/bootstrap | 003-006 | runtime/security |
| DU-010 | Node agent + mTLS protocol | 009 | runtime/failure |
| DU-011 | Capacity inventory + labels | 010 | runtime |
| DU-012 | Deterministic scheduler | 004,011 | golden fixtures |
| DU-013 | Docker runtime driver | 010,012 | live runtime |
| DU-014 | Compose runtime driver | 013 | E2E |
| DU-015 | Network/overlay driver | 009,010 | security/runtime |
| DU-016 | Build worker admission | 009-012 | runtime/security |
| DU-017 | Rootless BuildKit pipeline | 016 | build/E2E |
| DU-018 | Source provider adapters | 005,017 | integration/provider |
| DU-019 | SBOM/scan/sign admission | 017 | security/mutation |
| DU-020 | Harbor registry integration | 017,019 | integration |
| DU-021 | Immutable release model | 002,020 | contract |
| DU-022 | Deployment controller | 007,012,013,021 | E2E |
| DU-023 | Health/postcondition verifier | 022 | runtime |
| DU-024 | Rollback controller | 021-023 | failure injection |
| DU-025 | Preview environments | 018,022 | Git E2E |
| DU-026 | Domain resource controller | 005,022 | provider/E2E |
| DU-027 | DNS provider driver | 026 | provider |
| DU-028 | TLS/certificate lifecycle | 026,027 | runtime/failure |
| DU-029 | Traefik ingress driver | 013,026 | E2E |
| DU-030 | WAF/rate-limit/security edge | 029 | security |
| DU-031 | Managed PostgreSQL resource | 010,012 | DB/E2E |
| DU-032 | Managed Supabase resource | 031,026,028 | full-stack E2E |
| DU-033 | Valkey/Redis resource | 010,012 | service E2E |
| DU-034 | S3/object-storage resource | 010,012 | storage E2E |
| DU-035 | Project storage/bucket IAM | 004,034 | security |
| DU-036 | Secrets/OpenBao integration | 003,004 | security/revocation |
| DU-037 | Secret injection + rotation | 036,022 | E2E/revocation |
| DU-038 | Backup engine | 031-035 | backup |
| DU-039 | Restore/recovery engine | 038 | restore/failure |
| DU-040 | DR catalog + runbooks | 006,038,039 | live drill |
| DU-041 | OpenTelemetry pipeline | 008,010 | observability |
| DU-042 | Metrics/logs/traces backends | 041 | load/retention |
| DU-043 | Alerting/incident engine | 041,042 | failure |
| DU-044 | Public uptime/status integration | 043 | external/runtime |
| DU-045 | Usage metering ledger | 002,041 | accounting/invariant |
| DU-046 | Plans/quotas/entitlements | 004,045 | policy |
| DU-047 | Billing/Lago adapter | 045,046 | integration |
| DU-048 | Invoice/payment-provider adapters | 047 | provider |
| DU-049 | Notification gateway | 005,007 | integration |
| DU-050 | Transactional email transport | 049 | provider |
| DU-051 | SMS/OTP transport adapters | 049 | provider/security |
| DU-052 | Campaign/list service | 049,050 | integration |
| DU-053 | Client portal shell | 003-005 | UI/E2E |
| DU-054 | Client project/resource UI | 053,022,031-35 | UI/live |
| DU-055 | Deployment/log/health UI | 053,022,041 | UI/live |
| DU-056 | Backup/restore UI | 053,038,039 | UI/step-up |
| DU-057 | Billing/usage/invoice UI | 053,045-048 | UI/live |
| DU-058 | Team/IAM/admin UI | 053,003,004 | UI/security |
| DU-059 | Support/knowledge-base integration | 053 | provider |
| DU-060 | Analytics-as-a-service template | 022,031 | service |
| DU-061 | Feature-flags-as-a-service template | 022,031 | service |
| DU-062 | White-label/custom-domain portal | 026,053 | UI/provider |
| DU-063 | Ownership-transfer workflow | 003,004,047 | authority/E2E |
| DU-064 | Export/portability package | 021,031,034,026 | recovery/export |
| DU-065 | Suspension/quarantine/abuse workflow | 004,022 | security |
| DU-066 | JIT shell/DB-console lease | 003,004,036 | security/runtime |
| DU-067 | Operator CLI | 005 | parity |
| DU-068 | SDK / service-account integration | 005,003 | contract |
| DU-069 | Hermes restricted client adapter | 004,068 | authority/security |
| DU-070 | Single-node production profile | 001-069 applicable | E2E |
| DU-071 | Dedicated-client-node profile | 070 | E2E |
| DU-072 | k3s runtime driver | 070 | deferred/runtime |
| DU-073 | CloudNativePG HA profile | 072 | deferred/DR |
| DU-074 | Firecracker runtime class | 070 | deferred/security |
| DU-075 | Multi-region placement/failover | 071-073 | deferred/DR |
| DU-076 | Client ownership/offboarding closure | 063,064 | owner acceptance |
| DU-077 | Platform upgrade manager | all core | compatibility/rollback |
| DU-078 | Compliance/data-retention controls | 004,006,038 | policy/security |
| DU-079 | Template/service catalog | 022,031-35 | E2E |
| DU-080 | Release/certification automation | all core | forensic/certification |

## 06.1 Dependency critical path

```text
DU-001 canon
→ DU-002 control state
→ DU-003/004 IAM + policy
→ DU-005 API
→ DU-009/010 node admission
→ DU-011/012 capacity + scheduler
→ DU-013 runtime
→ DU-016/017 build
→ DU-019/020 artifact admission
→ DU-021 release
→ DU-022 deploy
→ DU-023 health proof
→ DU-024 rollback
→ DU-031 database
→ DU-032 Supabase
→ DU-038/039 backup + restore
→ DU-041 observability
→ DU-045 metering
→ DU-053 client portal
→ DU-070 single-node certification
```

No optional service (analytics, feature flags, campaigns, k3s, Firecracker) may block the v1 critical path.

---

# 07. FEATURE REGISTRY

## 07.1 Core platform features

```yaml
FTR-001: tenant-organizations
FTR-002: delegated-client-administration
FTR-003: google-sign-in
FTR-004: apple-sign-in
FTR-005: email-password-sign-in
FTR-006: email-otp
FTR-007: phone-sms-otp
FTR-008: password-reset
FTR-009: mfa-and-passkeys
FTR-010: service-accounts
FTR-011: project-environment-model
FTR-012: git-source-connection
FTR-013: dockerfile-build
FTR-014: oci-image-deploy
FTR-015: compose-deploy
FTR-016: preview-environment
FTR-017: immutable-release
FTR-018: deployment-health
FTR-019: rollback
FTR-020: domain-dns
FTR-021: automatic-tls
FTR-022: ingress-routing
FTR-023: waf-rate-limit
FTR-024: managed-postgresql
FTR-025: managed-supabase
FTR-026: managed-valkey
FTR-027: object-storage
FTR-028: secret-management
FTR-029: scheduled-backup
FTR-030: point-in-time-recovery-capable-profile
FTR-031: restore
FTR-032: logs-metrics-traces
FTR-033: alerts-incidents
FTR-034: public-status
FTR-035: resource-metering
FTR-036: plans-quotas-entitlements
FTR-037: invoicing
FTR-038: transactional-email
FTR-039: sms-gateway
FTR-040: campaigns
FTR-041: client-dashboard
FTR-042: support
FTR-043: analytics-service
FTR-044: feature-flags-service
FTR-045: white-label-portal
FTR-046: project-transfer
FTR-047: full-export
FTR-048: jit-console
FTR-049: audit-trail
FTR-050: api-cli-sdk
FTR-051: hermes-scoped-automation
FTR-052: single-node-profile
FTR-053: dedicated-node-profile
FTR-054: optional-k3s-profile
FTR-055: optional-microvm-profile
```

---

# 08. SCREEN REGISTRY AND EXPERIENCE CONTRACT

UI does not prove functionality. Every surface below must bind to live canonical state and must expose loading, stale, degraded, error and permission-denied states.

| Screen | Audience | Primary live bindings |
|---|---|---|
| SCR-001 Platform Overview | platform owner | fleet health, incidents, usage, pending actions |
| SCR-002 Clients | owner/operator | organizations, plan, status, usage |
| SCR-003 Client Detail | owner/operator | users, projects, billing, support, limits |
| SCR-004 Project Overview | client/operator | environments, resources, health |
| SCR-005 Environment | client/operator | releases, variables refs, domains, resource graph |
| SCR-006 Applications | client/operator | desired/actual/serving/healthy states |
| SCR-007 Deployment Detail | client/operator | Git SHA, image digest, config rev, trace, checks |
| SCR-008 Build Detail | operator/client | build stages, scan, SBOM, signature |
| SCR-009 Preview Environments | client | PR previews, age, cost, cleanup |
| SCR-010 Databases | client | DB type, status, connections, backups |
| SCR-011 Supabase Project | client | Auth/REST/Realtime/Storage/Studio endpoint status |
| SCR-012 Object Storage | client | buckets, usage, policies |
| SCR-013 Domains & TLS | client | DNS proof, routing, cert expiry/state |
| SCR-014 Backups | client | recovery points, integrity, restore tests |
| SCR-015 Restore Wizard | client/operator | target, point, destructive impact, progress |
| SCR-016 Observability | client | metrics/logs/traces filtered to tenant |
| SCR-017 Incidents | client/operator | active/history/updates |
| SCR-018 Usage | client | measured usage by resource |
| SCR-019 Billing | client | plan, invoices, credits, payment state |
| SCR-020 Team & Access | client | users, roles, sessions, MFA posture |
| SCR-021 Secrets | client | metadata/version/rotation; values restricted |
| SCR-022 Support | client | conversations/tickets/KB |
| SCR-023 Settings & Branding | client | domain, logo, notification policies |
| SCR-024 Ownership Transfer | client/owner | parties, authority transition, billing transition |
| SCR-025 Export & Offboarding | client/owner | export package, retention/deletion state |
| SCR-026 Fleet/Servers | platform operator | node identity, capacity, labels, runtime health |
| SCR-027 Build Workers | platform operator | build capacity, queues, caches |
| SCR-028 Registry & Supply Chain | operator | images, scans, signatures, retention |
| SCR-029 Security Center | operator | findings, WAF, abuse, secret rotations |
| SCR-030 Audit Explorer | authorized | actor/action/resource/result/time |
| SCR-031 Platform Settings | owner | IAM, DNS, storage, billing, mail/SMS adapters |
| SCR-032 Service Catalog | client | provisionable databases/services/templates |

## 08.1 Screen × Feature anti-gap rules

- Every owner/client-visible feature has at least one canonical surface or explicit API-only rationale.
- Every destructive control maps to an `ACTION_REGISTRY` action and authority check.
- Every status chip is backed by a named state field with timestamp and provenance.
- “Healthy” must come from runtime verification, not last command success.
- “Backed up” must distinguish `BACKUP_CREATED` from `RESTORE_VERIFIED`.
- “Deployed” must distinguish `DESIRED`, `ADMITTED`, `SCHEDULED`, `RUNNING`, `SERVING`, `HEALTHY`.

---

# 09. CANONICAL STATE MACHINES

## 09.1 Application release

```text
DRAFT
→ SOURCE_RESOLVED
→ BUILDING
→ BUILT
→ SECURITY_CHECKING
→ ADMITTED
→ DEPLOY_QUEUED
→ DEPLOYING
→ RUNNING
→ SERVING
→ HEALTHY
→ SUPERSEDED

Failure branches:
BUILD_FAILED
ADMISSION_REJECTED
DEPLOY_FAILED
RUNNING_UNHEALTHY
ROLLED_BACK
QUARANTINED
```

## 09.2 Supabase resource

```text
REQUESTED
→ VALIDATED
→ SECRETS_CREATED
→ STORAGE_CREATED
→ DATABASE_PROVISIONING
→ SERVICES_PROVISIONING
→ ROUTING_PROVISIONING
→ HEALTH_CHECKING
→ READY

READY
→ UPGRADING
→ READY

READY
→ BACKING_UP
→ READY

READY
→ RESTORING
→ HEALTH_CHECKING
→ READY

Failure/degraded:
PROVISION_FAILED
DEGRADED
RESTORE_FAILED
UPGRADE_FAILED
QUARANTINED
DELETION_PENDING
DELETED
```

## 09.3 Backup

```text
SCHEDULED
→ SNAPSHOTTING
→ UPLOADING
→ VERIFYING
→ AVAILABLE
→ RESTORE_TEST_PENDING
→ RESTORE_VERIFIED

or:
FAILED
CORRUPT
EXPIRED
DELETED
```

## 09.4 Domain / TLS

```text
REQUESTED
→ OWNERSHIP_PENDING
→ DNS_PENDING
→ ROUTE_PENDING
→ ACME_PENDING
→ ACTIVE
→ RENEWING
→ ACTIVE

failure:
DNS_MISMATCH
ACME_FAILED
CERT_EXPIRED
ROUTE_FAILED
```

## 09.5 Client lifecycle

```text
PROSPECT
→ ACTIVE
→ GRACE
→ SUSPENDED
→ ACTIVE

ACTIVE/SUSPENDED
→ OFFBOARDING
→ EXPORT_READY
→ RETENTION_WINDOW
→ DELETION_APPROVED
→ DELETED
```

`SUSPENDED != DELETED`.

## 09.6 Node lifecycle

```text
DISCOVERED
→ BOOTSTRAP_PENDING
→ IDENTITY_ISSUED
→ ENROLLED
→ QUALIFYING
→ READY
→ DRAINING
→ DRAINED
→ REMOVED

side states:
DEGRADED
UNREACHABLE
QUARANTINED
CERT_EXPIRED
```

---

# 10. CAUSAL PATH CONTRACTS

## 10.1 Deploy application

```text
TRIGGER
client presses Deploy / approved API call / admitted webhook
→ CALLER
Portal/API/Git integration
→ INGRESS
POST /v1/environments/{id}/deployments
→ IDENTITY
ZITADEL token or service identity
→ AUTHORITY
tenant role + environment permission + plan entitlement + policy
→ DOMAIN LOGIC
resolve desired state + source + release policy
→ BUILD
isolated BuildKit worker
→ ADMISSION
tests + SBOM + vulnerability/secret scan + signature
→ STATE
release immutable digest stored
→ SCHEDULING
scheduler chooses qualified node
→ EXECUTION
node agent applies runtime spec
→ EDGE
routing/cert updated if necessary
→ OBSERVATION
runtime + health probes
→ RECONCILIATION
actual state matched to release
→ READBACK
deployment timeline + logs + health
→ POSTCONDITION
release is HEALTHY or failed with explicit failure state
```

## 10.2 Provision Supabase

```text
Create Supabase
→ API
→ tenant/plan/policy check
→ reserve CPU/RAM/storage/domain
→ generate secrets in OpenBao
→ create dedicated Postgres volume/resource
→ launch pinned Supabase service template
→ configure Auth URLs/SMTP/SMS/OAuth
→ configure Storage backend
→ create internal route
→ issue external route/TLS if requested
→ verify Auth/PostgREST/Realtime/Storage/DB
→ persist endpoints + secret references
→ project UI shows READY
```

No state may become `READY` solely because Compose returned exit code 0.

## 10.3 Restore database

```text
Restore request
→ step-up authentication
→ authority + plan check
→ select verified recovery point
→ calculate impact
→ freeze writes or create replacement target
→ restore
→ integrity checks
→ application compatibility check
→ route/switch target
→ observe
→ owner/client readback
→ RESTORE_VERIFIED receipt
```

## 10.4 Ownership transfer

```text
current owner initiates
→ target organization validated
→ target admin accepts
→ outstanding billing/abuse/legal gates checked
→ platform atomically changes project authority
→ billing responsibility changes
→ old organization roles recalculated
→ secrets/access tokens rotated where policy requires
→ no workload redeploy
→ both parties receive audit receipt
```

---

# 11. DATA MODEL

Minimum canonical entities:

```text
Organization
UserBinding
RoleAssignment
ServiceAccount
Project
Environment
Resource
ResourceRevision
DesiredState
ActualState
Server
NodeIdentity
NodeCapability
CapacitySnapshot
Placement
SourceConnection
Build
Artifact
SBOM
SecurityFinding
Release
Deployment
HealthCheck
Domain
DNSZone
DNSRecord
Certificate
Database
SupabaseProject
ObjectBucket
SecretReference
Backup
RecoveryPoint
RestoreRun
MetricBinding
LogBinding
TraceBinding
AlertRule
Incident
UsageEvent
UsageAggregate
Plan
Entitlement
Subscription
Invoice
PaymentBinding
Notification
ProviderCredentialRef
SupportBinding
AuditEvent
PolicyDecision
Approval
Transfer
ExportJob
RetentionPolicy
AbuseCase
RuntimeQualification
EvidenceReceipt
```

## 11.1 Invariants

```text
organization_id is mandatory on all tenant-owned resources
project belongs to exactly one organization at a time
environment belongs to exactly one project
release artifact digest is immutable
deployment always references one admitted release
secret values never appear in ResourceRevision
usage events are append-only/idempotent
invoice lines reference immutable usage aggregate revisions
backup deletion respects retention/legal hold
ownership transfer cannot orphan billing or IAM
node identity is unique and revocable
actual state cannot overwrite desired state
audit actor may be human or service identity, never “system” without specific principal
```

---

# 12. API AND ACTION CONTRACT

## 12.1 API style

- Versioned REST API with OpenAPI as canonical external contract.
- SSE/WebSocket only for live event projection; not required for command correctness.
- Every mutation accepts/returns a request/correlation ID.
- Mutations that can be retried require idempotency keys.
- Long operations return a workflow/operation resource rather than holding HTTP connections.
- Errors use typed semantic codes, not only HTTP status.

## 12.2 Representative API

```text
POST   /v1/organizations
GET    /v1/organizations/{id}
POST   /v1/projects
POST   /v1/projects/{id}/transfer
POST   /v1/environments
POST   /v1/apps
POST   /v1/apps/{id}/deployments
POST   /v1/deployments/{id}/rollback
GET    /v1/deployments/{id}
POST   /v1/resources/postgresql
POST   /v1/resources/supabase
POST   /v1/resources/valkey
POST   /v1/resources/buckets
POST   /v1/backups
POST   /v1/restores
POST   /v1/domains
POST   /v1/domains/{id}/verify
POST   /v1/secrets/{id}/rotate
POST   /v1/servers/enrollment-tokens
POST   /v1/servers/{id}/drain
POST   /v1/consoles/leases
GET    /v1/usage
GET    /v1/invoices
POST   /v1/exports
GET    /v1/audit
```

## 12.3 Action registry properties

Every command SHALL define:

```yaml
action_id:
requester:
required_permissions:
required_entitlements:
step_up_auth:
policy_inputs:
idempotency_scope:
state_preconditions:
side_effects:
timeout:
retry_policy:
compensation:
audit_event:
observable_postcondition:
evidence:
falsified_by:
```

---

# 13. IDENTITY, AUTHENTICATION AND TENANCY

## 13.1 Platform IAM

Preferred engine: **self-hosted ZITADEL**, after exact-version qualification.

Required methods:

```text
Google
Apple
email + password
email OTP
phone as login identifier
SMS OTP / second factor
password reset
TOTP
passkeys/WebAuthn
service accounts
OIDC/OAuth2
organization-scoped policies
```

Tenant mapping:

```text
ZITADEL Instance
└── DIAL Hosting Platform
    ├── DIAL Internal Organization
    ├── Client Organization A
    ├── Client Organization B
    └── ...
```

Platform roles SHALL not simply mirror ZITADEL administrator roles. The application has its own domain permissions such as:

```text
organization.read
organization.admin
project.create
project.transfer
deployment.execute
deployment.rollback
resource.create
resource.delete
backup.restore
secret.metadata.read
secret.value.read
console.open
billing.read
billing.admin
audit.read
support.manage
server.manage
platform.admin
```

## 13.2 Hosted application IAM

For a managed Supabase project:

```text
Client Application
→ dedicated Supabase Auth
→ client users
```

It is not legal for an application user's Supabase JWT to authenticate into the hosting control plane.

## 13.3 Password and OTP boundaries

The platform SHALL NOT implement:

```text
password hashing primitives
OAuth state/PKCE cryptography
OTP generation/verification algorithms
JWT signature implementation
session cryptography
```

These remain responsibilities of qualified IAM engines.

The platform SHALL implement transport adapters and policy around those engines.

## 13.4 Authentication communications

```text
IAM/Auth engine
     │ challenge payload
     ▼
Notification Transport Adapter
     ├── self-hosted SMTP (BillionMail candidate)
     ├── external SMTP
     ├── SMS provider A
     ├── SMS provider B
     └── provider-compatible bridge
```

Auth engine remains challenge authority. Notification gateway only transports the challenge.

---

# 14. CONTROL-PLANE ARCHITECTURE

```text
                         ┌──────────────────────┐
                         │ OWNER / CLIENT PORTAL│
                         └──────────┬───────────┘
                                    │ HTTPS/OIDC
                         ┌──────────▼───────────┐
                         │     ZITADEL IAM      │
                         └──────────┬───────────┘
                                    │ token
                         ┌──────────▼───────────┐
                         │ API / POLICY GATEWAY │
                         └──────┬─────┬─────────┘
                                │     │
                   ┌────────────┘     └───────────────┐
                   ▼                                  ▼
          ┌─────────────────┐               ┌─────────────────┐
          │ CONTROL POSTGRES │               │    OPENBAO      │
          │ canonical state  │               │ secrets/leases  │
          └───────┬─────────┘               └─────────────────┘
                  │
       ┌──────────┼───────────┬─────────────────────┐
       ▼          ▼           ▼                     ▼
   TEMPORAL     NATS      SCHEDULER          RESOURCE CONTROLLERS
   workflows    events    placement       app/db/storage/dns/etc.
       │                                      │
       └──────────────────┬───────────────────┘
                          ▼
                PRIVATE CONTROL NETWORK
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
        NODE AGENT    BUILD AGENT   STORAGE/DB AGENT
             │            │
        Docker/Traefik  BuildKit
```

### 14.1 Control-plane component boundaries

**API Gateway** validates identity, tenant scope, request contract, idempotency and rate limits.

**Policy service** decides authorization, entitlement, risk and approval requirements.

**Resource controllers** own desired-state reconciliation for each resource type.

**Temporal** persists workflow progress and timers; it does not decide who may deploy.

**NATS JetStream** distributes semantic events and live projections; source-of-truth remains PostgreSQL.

**Scheduler** chooses eligible nodes deterministically from declared constraints and measured capacity.

**OpenBao** stores and issues sensitive credentials.

**Audit service** persists actor/action/policy/result with correlation IDs.

---

# 15. NODE AND FLEET ARCHITECTURE

## 15.1 Admission

1. Operator creates one-use enrollment token.
2. Bootstrap uses SSH/manual script to install prerequisites and node agent.
3. Agent creates node keypair locally.
4. Control plane validates enrollment and issues short-lived/rotatable machine certificate.
5. Agent reports capability inventory.
6. Qualification checks kernel, Docker, disk, cgroups, networking, clock, required security settings.
7. Node enters `READY` only when all mandatory checks pass.
8. Routine root SSH is removed from normal workflow.

## 15.2 Node-agent contract

The agent SHALL expose typed operations, not an arbitrary remote shell API:

```text
inspect
pull_image
apply_release
stop_release
probe_release
create_volume
snapshot_volume
restore_volume
configure_traefik_fragment
collect_runtime_state
stream_scoped_logs
rotate_runtime_secret
drain
upgrade_agent
```

Arbitrary shell access is a separate break-glass/JIT capability.

## 15.3 Private networking

NetBird or another qualified WireGuard-based mesh SHOULD carry:

```text
control → node RPC
database maintenance
registry private access
backup network
internal observability
operator JIT access
```

Public ports SHOULD normally be limited to application ingress and explicitly public services.

---

# 16. RUNTIME PROFILES

## Profile P1 — Single-node production

For early/smaller installations:

```text
control plane
runtime
Traefik
Postgres control DB
selected client workloads
```

Supported, but client workloads and control services receive explicit quotas and backup boundaries.

## Profile P2 — Split control/build/runtime

Preferred steady-state:

```text
Control Node
Build Node
Runtime Node(s)
Backup/Object Storage
```

Build scripts never execute on production runtime nodes.

## Profile P3 — Dedicated client node

For higher-value or isolation-sensitive clients:

```text
client organization → node affinity → dedicated runtime node
```

## Profile P4 — k3s cluster

Deferred until justified by:

```text
replica scheduling
node failover
rolling cluster workloads
CloudNativePG
strong multi-node orchestration need
```

## Profile P5 — MicroVM isolation

Firecracker or equivalent is required before admitting arbitrary untrusted customer code onto shared physical hosts.

---

# 17. BUILD AND SOFTWARE SUPPLY CHAIN

```text
Git provider
   ↓
ephemeral source checkout
   ↓
secret scan
   ↓
tests / lint / typecheck
   ↓
rootless BuildKit
   ↓
OCI image
   ↓
SBOM generation
   ↓
Trivy vulnerability/license scan
   ↓
policy gate
   ↓
Cosign signature / attestation
   ↓
Harbor
   ↓
immutable digest
   ↓
release admission
```

### Mandatory invariants

- Production never deploys `latest`.
- Release references an OCI digest.
- Registry credentials are scoped robot/service accounts.
- Build credentials are short-lived where possible.
- Build logs redact secrets.
- Pull-request builds from untrusted forks do not receive production secrets.
- Vulnerability exceptions are explicit, expiring and attributable.
- Rebuilding the same source does not silently overwrite an admitted release identity.
- SBOM and scan evidence are attached to the release record.

---

# 18. MANAGED POSTGRESQL

V1 supports dedicated PostgreSQL resources under Docker with:

```text
dedicated credentials
resource limits
private networking
TLS where applicable
connection pooling option
extension allow-list
scheduled logical + physical backup policy
WAL archival profile where supported
restore testing
credential rotation
maintenance windows
versioned upgrade workflow
```

Shared database-server tenancy MAY be introduced only with explicit isolation and noisy-neighbor policy.

For the later k3s profile, CloudNativePG is the preferred HA/PITR candidate.

---

# 19. MANAGED SELF-HOSTED SUPABASE

## 19.1 Product model

A Supabase resource is a managed project stack, not merely “a Postgres database”.

```text
SupabaseProject
├── PostgreSQL
├── Auth
├── PostgREST
├── Realtime
├── Storage
├── Edge Runtime / Functions where enabled
├── API Gateway
├── connection pooler
└── Studio administration surface
```

Self-hosted Supabase is upstream single-project; this platform supplies multi-organization and multi-project orchestration around many isolated Supabase stacks.

## 19.2 Isolation

Default:

```text
one client Supabase resource
→ one database
→ one secret namespace
→ one network namespace/project network
→ one storage prefix/bucket boundary
→ one backup catalog
→ one versioned template revision
```

No cross-client service-role keys.

## 19.3 Provisioning

The controller SHALL:

1. select a qualified node;
2. reserve resources;
3. create OpenBao secret paths;
4. create/pin template revision;
5. provision Postgres/volumes;
6. configure JWT/key material;
7. configure SMTP/SMS/Auth providers;
8. configure public URLs/callbacks;
9. configure S3-compatible Storage if selected;
10. route API endpoint and TLS;
11. verify database, Auth, REST, Realtime and Storage;
12. emit an evidence receipt;
13. expose only appropriate credentials to the client.

## 19.4 Studio

Studio SHALL NOT be exposed with reusable shared basic credentials.

Preferred patterns:

```text
portal-proxied short-lived access
or
private-network/JIT access
or
dedicated SSO gateway after qualification
```

## 19.5 Upgrade

```text
backup
→ compatibility check
→ canary/clone when required
→ pinned service version update
→ migrations
→ health probes
→ client application smoke test
→ commit new template revision
→ retain rollback/recovery point
```

---

# 20. OBJECT STORAGE

A driver abstraction SHALL support:

```text
SeaweedFS candidate
S3
Cloudflare R2
other S3-compatible targets
```

Capabilities:

```text
bucket isolation
tenant/project scoped credentials
quotas
versioning
retention/lifecycle
optional object lock
server-side encryption
replication
offsite backup
presigned URLs
access logs
```

Supabase Storage may use this S3-compatible layer rather than project-local files where appropriate.

---

# 21. DNS, INGRESS, TLS AND EDGE SECURITY

## 21.1 DNS

Self-hosted default candidate: PowerDNS Authoritative.

Adapter interface:

```text
CreateZone
DeleteZone
UpsertRecord
DeleteRecord
VerifyRecord
EnableDNSSEC
ReadZoneState
```

External adapters may support Cloudflare or other DNS providers without changing project semantics.

## 21.2 Ingress

Traefik candidate provides:

```text
host/path routing
TLS termination
service discovery
middleware
rate limiting
health-aware upstreams
access logs
```

Configuration is generated from canonical resource state; operators do not manually edit production Traefik files except break-glass recovery.

## 21.3 WAF

CrowdSec AppSec is a candidate edge-defense layer.

Rules/policies must support:

```text
observe-only rollout
tenant/global policies
exceptions with expiry
audit attribution
fail-mode explicitly defined
```

The platform SHALL still allow an external CDN/DDoS provider in front because a self-hosted WAF cannot stop upstream-link saturation.

---

# 22. SECRETS AND KEY MANAGEMENT

OpenBao candidate roles:

```text
platform service secrets
database dynamic/static credentials
registry robot credentials
DNS provider credentials
SMTP/SMS provider credentials
OAuth provider secrets
certificate material where applicable
short-lived console credentials
encryption-as-a-service where justified
```

Rules:

- Secret values are never returned in normal list APIs.
- Secret metadata and value permissions are separate.
- Every reveal is audited.
- Client export excludes platform secrets and includes only secrets they are entitled to own.
- Rotation is a workflow with downstream reconciliation.
- Revocation is testable.
- Two audit sinks SHOULD be configured for OpenBao where operationally feasible.
- Root/master recovery material is outside ordinary platform runtime.

---

# 23. BACKUP, RESTORE AND DISASTER RECOVERY

## 23.1 Backup classes

```text
B1 control-plane PostgreSQL
B2 platform IAM
B3 OpenBao storage/recovery material
B4 Harbor metadata/artifacts
B5 client PostgreSQL
B6 client Supabase Postgres
B7 object storage
B8 named volumes
B9 configuration/desire-state export
B10 audit history
```

## 23.2 Backup rule

```text
BACKUP_JOB_SUCCESS != RECOVERY_PROVEN
```

Every critical backup class requires scheduled restore tests.

## 23.3 Tier model

Provisional tiers; exact RPO/RTO become measured service contracts only after qualification.

```text
STANDARD:
  daily recovery point
  off-host copy
  periodic restore test

BUSINESS:
  more frequent database recovery points
  longer retention
  priority restore

DEDICATED:
  client-specific RPO/RTO
  isolated backup target option
  HA/PITR option
```

## 23.4 Control-plane recovery order

```text
network/DNS access
→ control DB
→ IAM
→ OpenBao
→ workflow/event infrastructure
→ registry
→ resource controllers
→ node reconciliation
→ client workloads
→ observability/status reconciliation
```

---

# 24. OBSERVABILITY

## 24.1 Canonical ingestion

OpenTelemetry Collector is the telemetry boundary.

```text
Apps / platform / nodes
      ↓ OTLP
OpenTelemetry Collector
      ├── metrics → VictoriaMetrics candidate
      ├── logs → Loki candidate
      └── traces → Tempo candidate
                         ↓
                      Grafana
```

## 24.2 Required correlation fields

```text
organization_id
project_id
environment_id
resource_id
release_id
deployment_id
workflow_id
request_id
actor_id
node_id
```

## 24.3 Tenant isolation

Client log/metric/trace queries must be filtered server-side by tenant authority. Browser-provided tenant IDs are never trusted.

## 24.4 Health semantics

```text
COMMAND_ACCEPTED
DESIRED_STATE_WRITTEN
NODE_APPLIED
PROCESS_RUNNING
ROUTE_SERVING
HEALTHCHECK_PASSING
DEPENDENCIES_HEALTHY
APPLICATION_HEALTHY
```

The portal must show these distinctions when diagnosing failures.

---

# 25. STATUS, INCIDENTS AND SUPPORT

Public status SHOULD be in a separate provider/region/failure domain.

Status components can map to:

```text
platform control plane
build service
registry
DNS
region/runtime node groups
managed databases
client-specific public services where purchased
```

Incident state:

```text
INVESTIGATING
→ IDENTIFIED
→ MONITORING
→ RESOLVED
```

Chatwoot or equivalent may provide client conversations and knowledge-base content. It SHALL not be the canonical incident or entitlement store.

---

# 26. BILLING, USAGE AND ENTITLEMENTS

## 26.1 Usage ledger

Authoritative events:

```text
cpu_seconds
memory_gib_seconds
persistent_storage_gib_hours
object_storage_gib_hours
egress_bytes
build_minutes
database_gib_hours
backup_storage_gib_hours
active_runtime_hours
email_messages
sms_messages
optional premium service units
```

Every event includes:

```text
usage_event_id
organization_id
project_id
resource_id
metric
quantity
unit
window_start
window_end
source
source_revision
observed_at
dedupe_key
```

Usage events are append-only. Corrections are compensating events, not destructive edits.

## 26.2 Plans

Plans are entitlements, not UI labels:

```text
max_projects
max_environments
cpu_limit
memory_limit
storage_limit
database_limit
supabase_projects
preview_environments
backup_retention
restore_priority
build_minutes
support_level
custom_domains
white_label
dedicated_node
ha_profile
```

## 26.3 Billing engine

Lago is the preferred candidate behind the internal billing contract.

Payment collection SHALL be provider-adaptable. The platform can support:

```text
manual invoice
bank transfer reconciliation
card PSP
local PSP
other region-specific processor
```

Lago or any external billing engine cannot suspend/delete resources directly. It emits billing state; platform policy owns enforcement.

---

# 27. COMMUNICATIONS PLATFORM

## 27.1 Messaging abstraction

```text
POST /internal/notifications
channel = email | sms | push | whatsapp | in_app
template
recipient
tenant
priority
idempotency_key
```

## 27.2 Email

Candidate structure:

```text
Auth / Platform Events
        ↓
Notification Gateway
        ├── BillionMail SMTP (self-hosted candidate)
        ├── external SMTP
        └── transactional provider adapter

Campaigns / bulk mail
        ↓
listmonk candidate
        ↓
SMTP transport
```

The platform must monitor:

```text
bounce
complaint
delivery
queue age
provider health
domain/SPF/DKIM/DMARC configuration
```

Hosting customer email is an abuse-sensitive feature and may be disabled by plan/policy.

## 27.3 SMS

Provider interface:

```text
SendOTPTransport
SendTransactionalSMS
SendBulkSMS
GetDeliveryReceipt
GetBalance
HealthCheck
```

Provider transport does not generate or verify authentication codes.

---

# 28. CLIENT PORTAL

The client portal SHALL prioritize outcomes, not infrastructure jargon.

Primary client navigation:

```text
Overview
Projects
Applications
Databases
Storage
Domains
Deployments
Backups
Observability
Usage & Billing
Team & Access
Support
Settings
```

### Dashboard cards may exist only when meaningful

Examples:

```text
Production health
Last successful deployment
Next backup / last restore-tested point
Current monthly usage
Open incident
Certificate expiry warning
Database storage trend
```

Generic decorative cards with no live causal backing are forbidden.

### White-label

Per organization:

```text
logo
brand colors
portal custom domain
support identity
email sender identity where verified
status page branding
legal links
```

---

# 29. OWNERSHIP TRANSFER, EXPORT AND OFFBOARDING

## 29.1 Transfer

Transfer changes authority and billing, not workload identity.

Required checks:

```text
target org exists
target admin accepted
resource plan compatible
outstanding legal hold checked
billing handoff resolved
DNS/domain ownership acknowledged
provider-owned credentials classified
service accounts recalculated
audit receipt generated
```

## 29.2 Export package

Portable export MAY contain:

```text
desired-state manifest
Docker/Compose manifests
OCI digest list and allowed artifact export
environment variable names with secrets redacted
client-owned secret export through explicit secure path
database dump / physical recovery package
object storage manifest/export
DNS record set
domain list
release history
backup metadata
SBOMs
audit subset
support/data exports where contractually included
```

## 29.3 Deletion

Deletion is multi-stage:

```text
request
→ authorization
→ retention/legal check
→ export opportunity
→ tombstone/deletion schedule
→ workload stop
→ credential revocation
→ data purge
→ backup expiry/purge according to policy
→ final deletion receipt
```

---

# 30. SECURITY / THREAT MODEL

## 30.1 Threat classes

```text
cross-tenant data access
stolen admin token
stolen service-account token
malicious dependency/build script
container escape
Docker socket compromise
node impersonation
secret leakage in logs
SSRF into management network
supply-chain poisoned image
DNS takeover/misconfiguration
backup exfiltration
restore poisoning
billing event fraud
webhook replay
OTP abuse/SMS pumping
email abuse/spam
cryptomining resource abuse
privilege escalation through support/admin UI
untrusted customer code
malicious insider
stale/revoked node certificate
```

## 30.2 Mandatory controls

```text
MFA/passkeys for platform administrators
short token lifetimes
tenant-scoped authorization
mTLS node identity
private management network
no public Docker socket
no permanent root-SSH normal operation
OpenBao secret boundary
JIT privileged access
rate limiting
CSRF/PKCE/OIDC best practice through IAM engine
webhook signatures + replay windows
SSRF allow/deny policy
egress controls for sensitive services
rootless build where possible
image admission by digest/signature
seccomp/AppArmor/capability reduction
non-root workload default where compatible
resource quotas
encrypted backups
WAF + abuse controls
tamper-evident audit retention
provider credential rotation
```

## 30.3 Runtime isolation classes

```text
RC1_SHARED_TRUSTED
  DIAL-created/controlled application in hardened container.

RC2_DEDICATED_CONTAINER_NODE
  Client receives dedicated runtime node.

RC3_DEDICATED_VM
  Workload receives dedicated VM boundary.

RC4_MICROVM_UNTRUSTED
  Firecracker-class isolation; required before arbitrary public code hosting.

RC5_DEDICATED_CLUSTER
  k3s/cluster isolation for enterprise/HA workloads.
```

---

# 31. FAILURE, DEGRADATION AND RECOVERY MODEL

| Failure | Required behavior |
|---|---|
| Control API restart | accepted durable operations resume or reconcile; no duplicate side effects |
| Temporal unavailable | new durable ops pause; running workloads continue |
| NATS unavailable | canonical state remains valid; projections catch up after recovery |
| Node unreachable | mark stale/unreachable; do not fabricate success; optionally reschedule eligible stateless workload |
| Registry unavailable | existing workloads continue; new deployments wait/fail explicitly |
| OpenBao unavailable | existing injected secrets continue until lease rules require renewal; new secret-dependent ops pause |
| DNS provider failure | existing DNS continues; changes remain pending |
| ACME failure | preserve currently valid cert; alert before expiry |
| Build failure | production unchanged |
| Security scan rejection | artifact not admitted |
| Deployment unhealthy | automatic/manual rollback according to policy |
| DB backup failure | workload continues; alert escalates by backup SLO |
| Restore failure | original source protected; do not switch target |
| Billing provider failure | hosting continues under bounded grace policy; no destructive action |
| Email/SMS provider failure | retry/failover; auth UI explains delayed challenge without bypass |
| Monitoring backend failure | workloads continue; health confidence marked degraded |
| Control DB loss | restore from verified backup before authoritative mutations resume |
| Tenant suspension | traffic/workload policy follows plan; data retained; credentials constrained |
| Abuse detection | quarantine/suspend via explicit policy; preserve evidence |
| Status-page host failure | separate failure domain should preserve incident communication |

Every failure contract SHALL define timeout, retry, idempotency, compensation, escalation, owner/client feedback and stale-state handling.

---

# 32. PERFORMANCE AND CAPACITY MODEL

All figures below are **pre-certification design targets**, not production SLA claims.

## 32.1 Control plane

Target characteristics:

```text
ordinary read API p95: sub-second
command acceptance: sub-second to low seconds
live state projection: seconds, not minutes
node heartbeat: configurable, nominal tens of seconds
scheduler decision: deterministic and bounded
no control API request waits for a full application build
```

## 32.2 Capacity admission

A node advertises:

```text
cpu architecture
logical cores
allocatable CPU
RAM
allocatable RAM
disk capacity/free/IO class
network class
runtime version
labels/region
supported runtime classes
GPU if any
security profile
```

Scheduler reserves against allocatable capacity rather than raw hardware.

## 32.3 Quota behavior

Resource creation is rejected before side effects if it cannot satisfy:

```text
tenant entitlement
node capacity
required isolation class
region constraint
storage availability
architecture compatibility
policy
```

---

# 33. GITOPS / DESIRED-STATE MODEL

The platform keeps an authoritative normalized desired-state representation and supports Git export/import.

Example:

```yaml
apiVersion: dial.hosting/v1
kind: Application
metadata:
  organization: acme
  project: inventory
  environment: production
  name: api
spec:
  source:
    provider: github
    repository: acme/inventory
    revision: main
  build:
    type: dockerfile
    context: .
  runtime:
    class: RC1_SHARED_TRUSTED
    cpu: "1"
    memory: 1Gi
    replicas: 1
  ingress:
    hosts:
      - api.inventory.example
    tls: automatic
  health:
    type: http
    path: /health
    timeout: 3s
  rollout:
    strategy: rolling
    autoRollback: true
```

The system computes:

```text
desired state
vs
last admitted revision
vs
actual runtime state
```

Drift is visible and reconcilable.

UI changes become normalized desired-state revisions. Git-backed representation must not become an alternate hidden authority.

---

# 34. SCHEDULING AND PLACEMENT

Hard filters first:

```text
runtime class supported
CPU architecture match
tenant isolation
region
required labels
minimum free RAM/storage
node ready/qualified
plan constraints
anti-affinity/affinity
```

Then deterministic ranking:

```text
capacity headroom
data locality
client affinity
cost class
failure-domain spread
cache locality
```

The ranking algorithm SHALL be versioned and golden-vector tested.

---

# 35. SERVICE CATALOG

V1 catalog:

```text
Static Web App
Node/React App
Python App
Go App
Dockerfile App
Docker Compose App
PostgreSQL
Supabase
Valkey
S3 Bucket
```

Optional templates after core:

```text
n8n
Umami
Flagsmith
Chatwoot integration
listmonk
project-specific approved services
```

Catalog entries contain:

```text
template revision
images/digests
ports
volumes
secret requirements
resource defaults
health probes
backup adapter
upgrade contract
license notes
security notes
```

No floating `latest` template in production.

---

# 36. RESEARCH COVERAGE MANIFEST

## 36.1 Current tool disposition

| Capability | Candidate | Disposition | Outstanding qualification |
|---|---|---|---|
| platform IAM | ZITADEL | strong candidate | self-host version, SMS transport, backup/upgrade, resource footprint |
| app BaaS | Supabase | adopt | version pinning, managed template, upgrade/restore |
| durable workflows | Temporal | strong candidate | footprint, HA later, workflow coding standard |
| event fabric | NATS JetStream | strong candidate | retention, replay, auth topology |
| secrets | OpenBao | strong candidate | seal/recovery, HA, audit devices |
| registry | Harbor | strong candidate | footprint, scanner, backup |
| builder | BuildKit rootless | adopt candidate | kernel/network limitations, cache design |
| scanner | Trivy | adopt candidate | policy/severity model, false-positive workflow |
| signing | Cosign/Sigstore | adopt candidate | key management/provenance mode |
| ingress | Traefik | adopt candidate | config driver, HA path |
| WAF | CrowdSec AppSec | candidate | fail mode, performance, false-positive handling |
| DNS | PowerDNS | candidate | authoritative topology, DNSSEC, secondary DNS |
| private network | NetBird | candidate | self-host HA, policy, recovery |
| billing | Lago | candidate | exact licensing/features, local payment integration |
| object storage | SeaweedFS | research candidate | operational benchmark, recovery/repair |
| observability | OTel + Grafana family/VictoriaMetrics | candidate | memory/disk footprint |
| status | OpenStatus | candidate | deploy outside primary failure domain |
| support | Chatwoot | optional | SSO/tenant mapping, resource footprint |
| analytics | Umami | optional | tenant model, embed API |
| feature flags | Flagsmith | optional | tenancy/licensing footprint |
| SMTP | BillionMail | optional candidate | deliverability, security, abuse, backup |
| campaigns | listmonk | optional candidate | tenant isolation strategy |
| Postgres HA | CloudNativePG | deferred | requires k3s |
| microVM | Firecracker | deferred | requires stronger scheduler/network/storage integration |

## 36.2 Build-vs-adopt law

Build custom code only for the platform-specific control plane:

```text
tenant/project/resource domain model
desired-state model
resource controllers
node protocol
scheduler
policy/entitlement composition
client portal
evidence/certification
tool adapters
```

Adopt hardened subsystems for:

```text
identity cryptography
database engine
secret engine
workflow persistence
message/event transport
container registry
build engine
WAF rules
telemetry protocols
billing calculations
support desk
```

---

# 37. IMPLEMENTATION WORKSTREAMS

## WS-A — Canon, schema and policy
DU-001..008

## WS-B — Fleet and runtime
DU-009..015

## WS-C — Build and supply chain
DU-016..025

## WS-D — Edge and networking
DU-026..030

## WS-E — Data services
DU-031..040

## WS-F — Observability and incidents
DU-041..044

## WS-G — Commercial plane
DU-045..052

## WS-H — Client experience
DU-053..064

## WS-I — Security/operations/automation
DU-065..069, 077..080

## WS-J — Deployment profiles
DU-070..075

Parallel work is permitted only after dependencies and shared contracts are frozen.

---

# 38. ATOMIC IMPLEMENTATION PACKET CONTRACT

Every DU packet SHALL contain:

```yaml
packet_id:
development_unit:
source_requirements:
product_truth_bindings:
dependencies:
authority_subjects:
files_to_create:
files_to_modify:
symbols:
migrations:
apis:
events:
state_machines:
runtime_callers:
external_providers:
failure_contracts:
security_contracts:
tests:
mutations:
runtime_evidence:
owner_surface:
rollback:
falsified_by:
completion_state:
```

Completion states:

```text
PLANNED
CONTRACTED
IMPLEMENTED_UNVERIFIED
VERIFIED_REPOSITORY
RUNTIME_QUALIFIED
PRODUCTION_QUALIFIED
OWNER_ACCEPTED
BLOCKED_EXTERNAL
SUPERSEDED
```

No packet may jump directly from `PLANNED` to `PRODUCTION_QUALIFIED`.

---

# 39. VERIFICATION AND EVIDENCE PLAN

## 39.1 Evidence classes

```text
STATIC
TYPECHECK
COMPILE
UNIT
PROPERTY
CONTRACT
INTEGRATION
MIGRATION
REACHABILITY
PERSISTENCE_RESTART
FAILURE_INJECTION
MUTATION
SECURITY
LOAD
RUNTIME
EXTERNAL_PROVIDER
RESTORE
OWNER_ACCEPTANCE
```

## 39.2 Critical end-to-end certifications

### E2E-01 Client onboarding
organization → admin → MFA → project → plan → first app.

### E2E-02 Application deployment
Git push → build → scan → sign → registry → deploy → route → healthy.

### E2E-03 Failed release
new release fails health → rollback → prior release healthy → client sees truthful state.

### E2E-04 Supabase
provision → create user → Google/email/SMS path as configured → DB/API/Storage → backup → restore clone → verify.

### E2E-05 Secret rotation
rotate DB/provider secret → dependent service reconciles → old secret revoked.

### E2E-06 Node loss
runtime node disappears → state marked unreachable → stateless eligible recovery path / explicit degraded state.

### E2E-07 Backup disaster
destroy disposable test DB → restore from retained point → application semantic checks.

### E2E-08 Billing
usage event → aggregation → entitlement/price → invoice → no double charge on replay.

### E2E-09 Tenant isolation
client A attempts every client B identifier/route/log/backup/secret path → all fail.

### E2E-10 Ownership transfer
client A → client B authority handoff without workload redeploy.

### E2E-11 Offboarding/export
export → validate artifacts → revoke access → retention → delete.

### E2E-12 Hermes
Hermes service identity can read approved health and execute approved deployment action, but cannot read secrets, create admins or bypass policy.

---

# 40. COUNTEREXAMPLE / MUTATION PLAN

At least one verifier SHALL fail for each intentional break:

```text
remove tenant filter from log query
bypass policy middleware
disconnect deployment controller from API
replace real health probe with constant success
delete rollback target lookup
permit mutable image tag in production
remove image signature verification
return secret values from list endpoint
replay usage event twice
reuse expired node certificate
disconnect backup restore verification
remove project ownership check
delete domain DNS verification
turn client status into static fixture
remove Supabase Auth health probe
break OpenBao revocation
allow suspended tenant to deploy
allow untrusted PR to read production secrets
drop organization_id from a tenant table
silently switch billing owner without transfer workflow
```

If critical mutations survive, certification fails.

---

# 41. FORENSIC GATE MODEL

This project inherits all sixteen FFDRM gates.

| Gate | Requirement for this platform | Current state |
|---|---|---|
| F0 OWNER_INTENT | mission, scope, exclusions, authority locked | PARTIAL_PASS |
| F1 DEVELOPMENT_UNITS | all material capabilities mapped | DRAFT_COMPLETE |
| F2 FEATURE_COVERAGE | features ↔ surfaces ↔ DUs ↔ proof | DRAFT_COMPLETE |
| F3 AUTHORITY | identity/policy/execution/credential owner per action | DRAFT_COMPLETE |
| F4 STATE | canonical state + persistence/restart/deletion | DRAFT_COMPLETE |
| F5 CAUSAL_PATHS | production chains for all critical outcomes | PARTIAL |
| F6 RESEARCH_TOOLING | exact tools, licenses, security, versions qualified | OPEN |
| F7 ARCHITECTURE | no duplicate authority; contracts coherent | DRAFT_COMPLETE |
| F8 FAILURE_RECOVERY | timeout/retry/idempotency/recovery | DRAFT_COMPLETE |
| F9 SECURITY | trust/secret/identity/isolation model | DRAFT_COMPLETE |
| F10 VERIFICATION_EVIDENCE | tests/evidence predefined | DRAFT_COMPLETE |
| F11 ADVERSARIAL_FORENSICS | repository implementation attacked | NOT_STARTED |
| F12 SYMBIOTIC_LOOP | applicable to Hermes adapter only; deterministic authority preserved | SPECIFIED |
| F13 REACHABILITY | production wiring proved | NOT_STARTED |
| F14 ANTI_GAP_MUTATION | mutations executed and failing correctly | NOT_STARTED |
| F15 CERTIFICATE | all prior gates current and bound to SHA | BLOCKED |

`FORENSIC_BUILD_READY` remains false.

---

# 42. BUILD-READY GATES

The additional PRD-DDP gates are:

```text
Gate 0  baseline known
Gate 1  Product Truth complete
Gate 2  DU graph complete
Gate 3  feature graph complete
Gate 4  Screen Registry complete
Gate 5  bidirectional Screen × Feature proof
Gate 6  research ready
Gate 7  architecture ready
Gate 8  failure/recovery ready
Gate 9  implementation ready
Gate 10 verification ready
Gate 11 closure ready
Gate 12 operations ready
```

Before `BUILD_READY=true`, the project must additionally have:

- repository and baseline SHA;
- exact tool/version/license/admission manifest;
- measured target-node resource profiles;
- environment certification;
- credentials/provider test environments;
- source of truth hashes;
- atomic packets for critical path;
- CI enforcing pack consistency;
- security/admission policy tests;
- backup/restore test environment;
- client-portal design packets;
- explicit commercial/legal operational policies;
- deployment and rollback runbooks.

---

# 43. REPOSITORY STRUCTURE

Proposed:

```text
/apps
  /portal
  /operator-console
/services
  /api
  /scheduler
  /resource-controller
  /usage-meter
  /audit
  /notification-gateway
  /provider-gateway
/agents
  /node-agent
  /build-agent
/internal
  /domain
  /policy
  /workflows
  /events
  /providers
  /runtime
  /evidence
/contracts
  /openapi
  /events
  /node-rpc
  /schemas
/templates
  /applications
  /databases
  /supabase
  /services
/deploy
  /bootstrap
  /single-node
  /split-plane
  /k3s
/development-pack
/docs
/tests
  /unit
  /integration
  /contract
  /reachability
  /mutation
  /security
  /e2e
  /runtime
  /recovery
```

---

# 44. RELEASE MODEL

A release receipt MUST include:

```yaml
release_id:
git_repository:
git_sha:
build_id:
image_digest:
sbom_digest:
scan_result_revision:
signature:
desired_state_revision:
policy_revision:
secret_reference_versions:
migration_revision:
runtime_driver:
target_environment:
deployed_nodes:
health_evidence:
deployment_started_at:
deployment_completed_at:
rollback_target:
```

A release is reproducible only from immutable artifacts and recorded configuration references.

---

# 45. UPGRADE MODEL

Platform components and managed templates have independent channels:

```text
platform control plane
node agent
Traefik
ZITADEL
OpenBao
Temporal
NATS
Harbor
Supabase template
PostgreSQL image
observability stack
optional services
```

Upgrade flow:

```text
research/security review
→ compatibility matrix
→ backup
→ test environment
→ canary
→ runtime evidence
→ staged rollout
→ rollback window
→ final admission
```

Automatic floating upgrades are forbidden for stateful critical services.

---

# 46. CLIENT SERVICE TIERS

These are architecture shapes, not locked prices.

## Managed Basic
- shared trusted runtime
- application + managed Postgres
- automatic TLS
- daily backup policy
- standard logs/metrics
- fixed resource allowance

## Managed Business
- staging + production
- managed Supabase option
- increased limits
- richer retention
- preview environments
- priority restores/support
- status/analytics options

## Dedicated
- dedicated runtime node/VM
- client-specific capacity
- custom backup/RPO policy
- optional HA/k3s profile when certified
- custom network and security policy

The plan engine must express capabilities as entitlements rather than hard-coded UI tiers.

---

# 47. OPERATIONAL / COMMERCIAL GOVERNANCE

Before paying-client production, define:

```text
Acceptable Use Policy
Privacy Policy
Data Processing terms
Backup/restore commitments
SLA/maintenance policy
Incident communication policy
Abuse/spam policy
Domain ownership policy
Email/SMS acceptable use
Data retention/deletion policy
Client export/handover policy
Support response tiers
Payment/grace/suspension policy
Security disclosure process
Subprocessor/provider register
```

No plan may promise an SLA unsupported by measured runtime evidence.

---

# 48. BLOCKERS REGISTER — REV 1

```yaml
- BLK-001: repository not created/bound
- BLK-002: commercial product name not owner-locked
- BLK-003: Go vs alternative control-plane implementation not benchmarked/locked
- BLK-004: exact ZITADEL self-host version and SMS-provider strategy unqualified
- BLK-005: exact Supabase version/template and upgrade path unqualified
- BLK-006: Temporal/NATS footprint not measured on target hosting node
- BLK-007: OpenBao seal/recovery/HA strategy not environment-certified
- BLK-008: Harbor footprint and backup path not measured
- BLK-009: object-storage implementation not selected after benchmark
- BLK-010: observability retention/resource budget not measured
- BLK-011: BillionMail production deliverability/abuse posture not qualified
- BLK-012: local/regional SMS provider adapters not selected/tested
- BLK-013: payment providers not selected
- BLK-014: DNS authoritative topology/secondary DNS not selected
- BLK-015: target first production server topology not pinned
- BLK-016: backup offsite target not selected
- BLK-017: client portal design authority/quality packets not produced
- BLK-018: atomic implementation packets not generated
- BLK-019: runtime/recovery/security test environment absent
- BLK-020: no live production evidence or owner acceptance
```

---

# 49. PREDEVELOPMENT CERTIFICATE — CURRENT

```json
{
  "schema_version": 1,
  "certificate_id": "dial-hosting-platform-predevelopment-r1",
  "project_identity": "dial-hosting-platform",
  "project_kind": "MULTI_TENANT_SELF_HOSTED_PAAS",
  "standard_id": "DIAL_FABLE_FORENSIC_PREDEVELOPMENT_STANDARD",
  "status": "NOT_FORENSIC_BUILD_READY",
  "reason": [
    "repository baseline is not bound",
    "tool/version qualification is incomplete",
    "implementation packets are not yet repository-bound",
    "environment certification does not exist",
    "runtime/recovery evidence does not exist"
  ],
  "runtime_qualification": {
    "separate_from_predevelopment_readiness": true,
    "status": "NOT_STARTED"
  },
  "owner_acceptance": "NOT_STARTED"
}
```

This status is intentionally conservative and must not be manually promoted.

---

# 50. IMPLEMENTATION ORDER

## Phase A — Predevelopment closure
1. Create/bind repository.
2. Decompose this consolidated blueprint into canonical pack artifacts.
3. Qualify exact versions/licences/resources for critical dependencies.
4. Lock control-plane language and contracts.
5. Produce atomic packets for DU-001..024.
6. Produce client-portal design packets.
7. Run FFDRM gates F0-F10.
8. Issue `FORENSIC_BUILD_READY` only if gates actually pass.

## Phase B — Minimal production PaaS
Implement through:

```text
IAM
tenancy
API
audit
workflow/event
node agent
scheduler
Docker runtime
build/registry/admission
release/deploy/health/rollback
domains/TLS
PostgreSQL
secrets
backup/restore
observability
client portal
```

Certify single-node profile.

## Phase C — Supabase + commercial plane
Add:

```text
managed Supabase
object storage
usage ledger
plans/quotas
billing
email/SMS gateway
support
status pages
ownership transfer/export
```

## Phase D — Client-hosting hardening
Add:

```text
dedicated client nodes
stronger WAF/abuse automation
advanced DR
white label
service catalog
JIT console
security-center UX
```

## Phase E — Scale only when measured
Potentially:

```text
k3s
CloudNativePG
multi-region
Firecracker
automated failover
```

---

# 51. DEFINITION OF COMPLETE

The hosting platform is not complete when:

```text
the dashboard renders
containers start
CI is green
a Supabase Compose file exists
a backup command succeeds
a login page exists
a billing engine is installed
a deployment endpoint returns 200
```

Repository completion requires:

```text
requirements mapped
DUs closed
production callers proven
authority enforced
state durable
failures handled
mutations fail correctly
security gates pass
Screen × Feature parity passes
recovery evidence exists
```

Runtime completion separately requires:

```text
real nodes
real builds
real deployments
real domains/TLS
real database/Supabase
real backups and tested restores
real observability
real provider delivery
real tenant isolation
real rollback
measured capacity
```

Commercial production separately requires:

```text
owner acceptance
support/runbooks
security posture
billing correctness
client export/offboarding
legal/operational policies
incident/status process
```

---

# 52. SOURCE / REFERENCE REGISTER — 2026-09-23

Primary official references checked during blueprint preparation:

```text
ZITADEL
https://zitadel.com/docs
https://zitadel.com/docs/guides/manage/console/organizations-overview
https://zitadel.com/docs/guides/integrate/login/hosted-login

Supabase
https://supabase.com/docs/guides/self-hosting
https://supabase.com/docs/guides/self-hosting/docker
https://supabase.com/docs/guides/self-hosting/self-hosted-phone-mfa
https://supabase.com/docs/guides/self-hosting/self-hosted-oauth

Dokploy patterns
https://docs.dokploy.com/docs/core/deployment-options
https://docs.dokploy.com/docs/core/remote-servers/build-server
https://docs.dokploy.com/docs/core/applications/preview-deployments

Coolify patterns
https://coolify.io/docs/api/overview
https://coolify.io/docs/api/permissions
https://coolify.io/docs/core/infrastructure/servers/build-servers

OpenBao
https://openbao.org/docs/what-is-openbao/
https://openbao.org/docs/concepts/lease/
https://openbao.org/docs/audit/

Harbor
https://goharbor.io/docs/edge/administration/robot-accounts/

Temporal
https://docs.temporal.io/

OpenTelemetry
https://opentelemetry.io/docs/collector/quick-start/

CloudNativePG
https://cloudnative-pg.io/documentation/

PowerDNS
https://doc.powerdns.com/authoritative/http-api/index.html

CrowdSec
https://docs.crowdsec.net/docs/appsec/quickstart/traefik/

NetBird
https://docs.netbird.io/

Trivy
https://trivy.dev/

Firecracker
https://firecracker-microvm.github.io/

Chatwoot
https://www.chatwoot.com/help-center

OpenStatus
https://www.openstatus.dev/docs/

Umami
https://docs.umami.is/

Flagsmith
https://docs.flagsmith.com/

listmonk
https://listmonk.app/docs/
```

All tool choices remain subject to exact-version, license, supply-chain, resource, security and operational admission before `FORENSIC_BUILD_READY`.

---

# 53. FINAL CANONICAL RULE

> The platform SHALL behave as a deterministic managed application cloud, not as a collection of dashboards around Docker.

> Identity proves who is acting. Policy decides whether the action is allowed. Canonical desired state defines what should exist. Durable workflows coordinate long-running changes. Typed node agents execute bounded operations. Runtime observation proves what actually exists. Reconciliation closes the loop. Audit/evidence makes every material outcome attributable and falsifiable.

> No subordinate tool — ZITADEL, Supabase, Temporal, NATS, OpenBao, Harbor, Traefik, a billing engine, an AI agent, or a deployment runtime — may silently become product authority outside its bounded responsibility.

> `DESIRED ≠ ADMITTED ≠ DEPLOYED ≠ RUNNING ≠ SERVING ≠ HEALTHY ≠ PRODUCTION_QUALIFIED`.

> No normal material development should begin until the repository-bound pack passes the Fable forensic preparation gates and receives a current `FORENSIC_BUILD_READY` certificate.

---

**END — DIAL-HOSTING-PLATFORM-DDP-R1**
