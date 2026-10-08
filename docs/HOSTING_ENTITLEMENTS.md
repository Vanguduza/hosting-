# Hosting plan assignments

Migration 027 adds hosting-local, protected operator assignments. The tenant API
cannot purchase, assign, renew or edit a plan. No prices, discounts, invoices,
payment collection or automatic product activation are inferred from these
records. Readback identifies this authority as `OPERATOR_ASSIGNED`. The separate
[Partner publisher adapter](PARTNER_AUTHORITY.md) now consumes intent-bound
commercial/admin approvals and requires the current local plan version. Its live
upstream publisher and commercial records remain uninstalled.

## Import and launch enforcement

Use the protected operator database connection described in
[reservation quotas](RESERVATION_QUOTAS.md). Keep credentials in private files.
Create an owner-only JSON file, replacing these example UUIDs, references, limits
and validity period with the approved tenant policy:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "organization_id": "22222222-2222-4222-8222-222222222222",
  "plan_ref": "plan://hosting-standard-v1",
  "evidence_ref": "entitlement://private-agreement-123",
  "features": ["release", "postgres", "valkey", "storage", "domain", "domain_registration", "build"],
  "cpu_milli_limit": 4000,
  "memory_mb_limit": 8192,
  "project_limit": 5,
  "application_limit": 10,
  "domain_limit": 10,
  "registration_limit": 5,
  "valid_from": "2026-10-07T00:00:00Z",
  "valid_until": "2026-11-07T00:00:00Z"
}
```

```sh
chmod 600 /private/tenant-plan.json
python3 tools/set_entitlement.py --operator operator-id assign \
  --file /private/tenant-plan.json --confirm assign_entitlement
```

Assignments require exact typed fields, unique supported features and explicit
timezone-aware validity dates. Activation requires a currently valid period. CPU
and memory ceilings are positive signed 64-bit integers; count limits range from
zero to 100,000. Evidence references identify private records and cannot contain
credentials or personal contact details. Import refuses symlinks, named pipes,
oversized files, duplicate JSON keys and files accessible to other users.

The transaction records an immutable version, updates the reservation quota,
activates the version and writes a hash-chain audit fact and durable outbox entry.
A downgrade cannot fall below existing counts or open reservations. Assignment
UUID replay must match every original field and operator identity. Historical
replay returns `current: false` and never reactivates an old policy. Renewal uses
a new UUID and validity period. Direct activation of older revisions is rejected.

Migration defaults `require_assigned` to false to preserve existing installations
while plans are imported. **This compatibility mode is unsuitable for production
acceptance.** Assign every existing organization, then enable required assignments:

```sh
python3 tools/set_entitlement.py --operator operator-id enable \
  --evidence-ref entitlement://launch-plan-review \
  --confirm require_entitlements
```

Enablement checks every tenant has a valid assignment and bounded quota, records
immutable evidence and tenant audit/outbox facts, and is one-way. Identical retry
is harmless; different replay evidence is rejected. New tenants have read access
but cannot create resources until assigned. These records are included in control
backups and PITR. Restoring an earlier backup restores its policy; recheck required
mode before reopening admission.

Run `python3 tools/entitlement_health.py` with protected operator credentials
from the monitoring scheduler. It reports missing/expired assignments and quotas
that exceed their plan, and exits 2 for policy gaps or compatibility mode.
`ENFORCED` describes these policy checks; it is not a production certificate.

## Admission and execution

Database triggers enforce project, application, connected-domain and registration
counts. Connected domains require `domain`; registrar requests and purchase
processing require `domain_registration`. Registrations count while requested,
quoted, approved, processing or fulfilled. Cancelled and definitively failed
requests release a slot; fulfilled purchases remain counted. These counts never
reserve a name at a registrar.

New releases, PostgreSQL, Valkey, storage and GitHub build deliveries require
their feature. The plan caps combined open CPU/memory reservations across releases
and services. Raising a separate reservation quota cannot enlarge the plan ceiling;
lowering it can impose a stricter limit. Denial rolls back placement counters,
resources, jobs, intervals and audit facts. Existing idempotent receipts and tenant
readback remain available after expiry.

All provisioning/build workers recheck policy while claiming work. Policy and
tenant locks serialize execution-start authorization with plan changes. An
unavailable feature or expired/missing required assignment holds the queue with
`last_error=entitlement_unavailable`, defers its next check by 60 seconds and
preserves operation identity, reserved capacity and retry count. Renewal or feature
restoration resumes normal claims. Reclaimed expired leases also wait without
consuming attempts. Exhausted-lease recovery, health checks and cleanup continue
through their existing reconciliation paths.

Authorization takes effect at a committed claim. A later plan change does not
cancel an in-flight operation; its receipt may complete. Plans neither delete
tenant data nor evict existing services. Resource cancellation, export/offboarding
and commercial renewal orchestration remain separate work. Held capacity is not
automatically released.

Manual registrar fulfillment rechecks the plan when entering `PROCESSING`, after
exact owner approval. Payment evidence, quote expiry and operation identity checks
still apply. Reconciliation of an already started purchase remains available after
expiry; the tool makes no registrar call or payment itself.

## Tenant readback and verification

Human members, including viewers, can read
`GET /v1/organizations/{organization_id}/entitlements`. Machine identities cannot
use this organization route. Readback exposes current policy, features, validity,
limits, required-mode flag and counts with `ACTIVE`, `EXPIRED` or `UNCONFIGURED`
status. Private evidence and operator identities are omitted. CPU/memory use decimal
strings to retain 64-bit precision. The portal clears stale status on failures and
explains renewal holds. CLI readback:

```sh
python3 tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt entitlements TENANT_UUID
```

Disposable database tests cover immutable history, replay, authority, HTTP conflicts,
concurrent admission, atomic rollback, expiry, every worker hold/resume, registrar
processing and one-way required mode. Browser tests cover active/expired plans and
unavailable readback. Live commercial authority, production service qualification
and estate acceptance remain unqualified.
