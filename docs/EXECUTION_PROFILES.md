# Reviewed execution profiles

Migration 030 adds an immutable, tenant-scoped registry of operator-reviewed
Partner template, runtime, estate and compatibility evidence. The registry binds
one exact admitted image digest and supported setup to measured node configurations.
It supplies the profile stage of a HostingIntent observation; importing or matching
a profile does not certify the platform, provision resources or grant commercial
approval. Independent [Partner approval](PARTNER_AUTHORITY.md), [scoped secret availability](PARTNER_SECRETS.md),
backup evidence and mutation-time admission remain separate requirements.

There are no actual estate qualification records installed in this repository.
Only disposable test fixtures exercise imports. The operator must review real
upstream template qualification metadata and hosting runtime/estate/compatibility
evidence before importing a live profile. Evidence references are opaque labels;
this adapter trusts the protected operator's attestation and does not fetch or
cryptographically verify external documents at those references.

## Review and import

Use the exact [execution profile v1 schema](../contracts/execution-profile-v1.schema.json)
in an owned, mode-0600 regular JSON file of at most 64 KiB. Unknown fields, duplicate
keys, symlinks, public file permissions, noninteger ceilings and unsupported profiles
are rejected. Root and packaged schemas must match byte for byte.

All 18 fields are required: `schema_version`, immutable `id`, `organization_id`,
`template_id`, `template_version`, `environment_profile`, `runtime_class`,
`release_artifact_ref`, `database_profile`, `storage_profile`, `backup_profile`,
`observability_profile`, `resource_ceiling`, `node_bindings`, `enabled`,
`valid_from`, `valid_until` and `qualification_refs`.

The template ID/version and environment identify the effective profile within
one tenant. The remaining setup fields bind the exact requested Docker HTTP image
digest, database/storage choices, encrypted off-host backup profile and health
observation profile. Current support is `none`/`postgres-private-v1` and
`none`/`garage-development-v1`; Garage is restricted to development. Managed
Supabase, redundant S3, other runtimes and production Garage are not enabled by
this registry. Runtime compatibility is distinct from live product qualification.

`resource_ceiling` uses strict integer `cpu_milli` (50–32000) and `memory_mb`
(64–32768). Both requested intent values must fit. Profile validity requires an
explicit ISO timezone, at most six fractional digits, an end after the start and
an elapsed span of at most 90 days. New versions can be future-dated or expired;
the newest version then blocks until valid or renewed, with no fallback.

`qualification_refs` requires four separately typed provenance labels:
`template-proof://...`, `runtime-proof://...`, `estate-proof://...` and
`compatibility-proof://...`. The reviewer checks the upstream template metadata,
admitted artifact, exact runtime/estate and upgrade/rollback compatibility
outside this importer. Stateful compatibility evidence must cover the relevant
schema/data upgrade and recovery policy. No credentials, raw business documents
or secret values belong in the JSON.

Each of 1–32 unique `node_bindings` contains `node_id` and
`configuration_sha256`. Obtain a current fingerprint with protected credentials:

```sh
python tools/set_execution_profile.py --operator <protected-operator-name> \
  node-binding <node-uuid>
```

The fingerprint binds registered node UUID, private endpoint, server name, public
IPv4, measured CPU/memory and latest audited lifecycle revision. Changing
identity, capacity or quarantine/re-enrollment history invalidates it. Heartbeat
refresh and changing reservations do not change the fingerprint. Obtaining one
is inventory readback, not a qualification grant or fresh network probe.

After completing the independent review, import the private file:

```sh
python tools/set_execution_profile.py --operator <protected-operator-name> \
  import --profile-file /private/reviewed-execution-profile.json
```

The tool uses protected operator database configuration and verifies the migration
ledger. Its transaction validates the exact typed payload, an existing hosting
artifact admission and **every** bound node's current fingerprint, enabled state,
registered ingress address, measured capacity sufficient for the profile ceiling
and heartbeat no older than five minutes or in the future. Node rows are locked
in UUID order during import to keep the checked configuration consistent.

These checks read registered inventory; actual private mTLS measurement,
public route/health, source/supply-chain qualification and independent recovery
proofs must still be established by their existing tools and reviewed evidence.
Profile eligibility checks physical measured capacity, not free reservation
headroom. Existing plan/quota, scheduler and reservation guards remain required
at resource mutation time.

## Version and withdrawal semantics

Versions are append-only and tenant scoped. Effective ordering follows serialized
imports. A new UUID replaces the prior version for the same template ID/version
and environment, even when the new version is disabled, future-dated, expired,
incompatible or its node evidence later becomes unavailable. Older versions
never fill a gap in the newest version's evidence.

To withdraw, import a new version with `enabled=false`. Withdrawal can be recorded
even after the artifact or node evidence is unavailable; it retains the typed
original review context without granting eligibility. To re-enable, import a new
UUID with current reviewed evidence and measured bindings. Replaying an old UUID
returns its historical acknowledgement and whether it is current; it never
reactivates a superseded or withdrawn version. Changed content or operator for
an existing UUID is rejected. Concurrent duplicate imports commit one review,
one hash-chain audit fact and one outbox event atomically.

Private profile tables have no API privileges or policies; forced RLS also
applies. Private node fingerprint/eligibility and base evidence helpers cannot be
called by the API role. Protected operator tools reject service-role credentials.
Triggers reject updates/deletions even by the operator. Keep this history in the
existing control database backup and WAL/PITR workflows.

## Read current compatibility

Human tenant owners/admins can GET
`/v1/organizations/{org}/applications/{app}/intents/{intent_id}/profile`, or use:

```sh
python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intent-profile <tenant-uuid> \
  <application-uuid> <request-uuid>
```

The API is read-only for this workflow. Neither portal humans nor machine
publishers can import profiles over HTTP. Viewers, machines, other tenants and
wrong application/intent bindings receive 404. Readback includes tenant/app/intent
and intent hash, check time, state, profile version/hash and validity times. It
excludes qualification references, reviewer identity, node lists, fingerprints,
private endpoints and estate details.

| State | Meaning |
| --- | --- |
| `UNCONFIGURED` | No profile exists for this tenant, template ID/version and environment |
| `DISABLED` | The newest profile was withdrawn |
| `NOT_YET_VALID` | The newest profile's validity window has not started |
| `EXPIRED` | The newest profile's review expired |
| `PROFILE_MISMATCH` | Image/runtime/data/storage/backup/observation setup differs from intent |
| `ARTIFACT_UNADMITTED` | The requested digest no longer has hosting admission |
| `BUDGET_EXCEEDED` | Requested CPU or memory exceeds the reviewed ceiling |
| `NO_ELIGIBLE_NODE` | No bound node currently has matching, fresh enabled configuration/capacity |
| `PLACEMENT_MISMATCH` | The requested artifact is serving on a node outside the currently eligible review |
| `MATCHED` | Desired setup and a current eligible reviewed node match at check time |

Matching describes the reviewed desired setup. If the requested artifact is
already serving, its node must be one of the eligible bound nodes. A desired
artifact that is not yet serving can have a matched profile; runtime placement
and release health remain separate stages and cannot borrow another image's
health. Nothing reserves capacity or promises future eligibility.

The portal shows a **latest setup check** beside the current Partner approval and
the immutable historical intent observation. Failed or malformed readback,
changed intent hashes and tenant/application/intent selection changes clear old
status. A current match does not rewrite historical evaluations. Recheck records
a new observation in one database statement snapshot shared with commercial,
plan, administrator, artifact, runtime and resource evidence. Only `MATCHED` can
mark the profile stage matched. All observations still remain `NOT_QUALIFIED`,
with no transformations and no resource mutations.

## Verification and remaining work

`tests.test_execution_profiles` covers exact typed contracts, validity/unsupported
profiles, provenance labels, private files, CLI routing and observer behavior.
`tests.test_execution_profile_integration` runs on its own disposable local
PostgreSQL database and covers tenant/role isolation, redaction, immutable/private
history, audit rollback, concurrent retries, latest-only withdrawal/expiry,
node identity/capacity/lifecycle drift, heartbeat freshness, requested budget,
artifact admission, placement, Unicode fingerprints and read-only HTTP access.
It also proves that commercial/profile matches remain independent of full
qualification. Portal unit and browser checks exercise unavailable/borrowed
status, withdrawal and selection clearing.

Live review metadata, measured estate qualification, independent secret and backup
resolution, automatic execution and production acceptance remain unfinished.
The manifest's readiness and owner-acceptance flags remain false.
