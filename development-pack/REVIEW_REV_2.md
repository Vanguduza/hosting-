# Architecture review and Rev 2 corrections

Date: 2026-09-23. Repository target: `Vanguduza/hosting-` (the accessible repository; the named `Vanguduza/hosting` did not exist at review time).

## Findings and decisions

| Priority | Finding | Correction / executable gate |
|---|---|---|
| P0 | Eighty development units, many heavy stateful services, and an 8 GB control node are listed without measured placement or failure domains. | Placement is an inventory input. Require per-node measured idle/peak RAM, CPU, disk IOPS and restore bandwidth; deny admission if reserve, isolation, or recovery target fails. Do not assume the entire catalog fits on Netcup. |
| P0 | The plan requires `BUILD_READY` before material development but also makes version qualification and runtime proof prerequisites, creating a circular gate. | Separate *repository admission* (safe to develop), *build ready* (contracts, exact versions and CI), *runtime qualified*, and *commercial production*. Source work can proceed while readiness remains false. |
| P0 | `Docker Compose` is a trusted, privileged configuration input and shared container isolation cannot securely accept arbitrary client code. | Accept only operator-controlled code on shared nodes; allow outside client code only on a certified dedicated VM or stronger isolation. Never accept tenant-supplied Compose with privileged, host networking, host paths, or daemon socket access. |
| P0 | Project IAM and application IAM are separate in prose, but a shared administrative credential could bridge them. | Distinct issuers or distinct OIDC audiences, databases, network identities, secret namespaces, and operators. Supabase Studio needs a separate gate and must not inherit platform operator credentials. |
| P0 | Backup policy does not spell out consistent multi-component restore for Supabase. | Restore a coherent checkpoint containing PostgreSQL state, object bytes, secret/key versions, migration and image digests. Verify app semantics on an isolated target before certifying a recovery point. |
| P1 | Deploy and billing events may be emitted before canonical DB commit or replayed twice. | Use a transactional outbox and durable idempotency keys; consumption is at least once and side effects must be deduplicated. Record actor, policy revision and immutable release digest in the same transaction as intent. |
| P1 | GitHub webhook and PR previews can inject untrusted source into privileged build paths. | Verify signatures; separate workers, credentials, caches and network egress; untrusted PR builds receive no production secrets and cannot publish admitted images. |
| P1 | Domain onboarding is vulnerable to DNS rebinding and tenant takeovers. | Verify ownership token before route/certificate creation, recheck conflicts and authoritative DNS at activation and renewal, reserve hostnames atomically. |
| P1 | Deletion and transfer need time-delayed, revocable operations with legal-hold checks. | Persist request, approvals, freeze interval, export receipt, credential rotation and audit evidence; no direct cascade deletion endpoint. |
| P1 | Tool names are selected without pinned releases, license audit, update/restore plan or measured compatibility. | Maintain per-version admission evidence, image digest, license, dependency, migration/rollback strategy and runtime budget before service enablement. |
| P2 | OpenStatus outside the failure domain, offsite backup, secondary DNS, payment and SMS providers are unspecified. | These remain explicit deployment and commercial gates, never hidden success defaults. |

## Revised deployment topology

Control: IAM → policy/API → PostgreSQL desired state + audit/outbox → durable workflow.
Execution: build workers → signed immutable registry → mTLS node agents → isolated runtime networks.
Evidence: runtime probes → observed state → reconciliation → client readback. Backup/restore and incident status must cross failure domains.

Every stateful service has a distinct backup and recovery receipt. Placement is declarative per node and service; control-plane workload cannot quietly consume Van's reserved Oracle A1 capacity or the recovery-only Oracle node.

## Admission rules

1. Reject a deployment without an immutable digest, signed admission receipt, actor, tenant, environment, policy version, quota approval and live placement.
2. A successful container start never sets `HEALTHY`: route and application probes must pass.
3. A restore job never sets `RESTORE_VERIFIED` without a semantic query against an isolated restored target.
4. Disallow managed Supabase launch until each project's upstream stack version, Auth configuration, object backend, backup coherence and upgrade/restore procedures are certified.
5. Refuse customer code on a shared node until an isolation review proves it safe. Dedicated VM is the default outside-code boundary.
6. Do not publish a plan, invoice, uptime promise or client-facing success state before corresponding live evidence exists.

## Current evidence

Repository code and static tests are evidence for tenant scope, authentication boundaries, schema and pack consistency only. No Docker engine or production nodes were available in this session. All runtime/commercial certificates remain false.
