# Durable Partner HostingIntent intake and observations

Migration 028 adds immutable desired-state records and immutable reconciliation
receipts for existing applications. Human organization owners and administrators
can submit the same typed [HostingIntent v1](../contracts/hosting-intent-v1.schema.json)
used by the [read-only preflight](PARTNER_PREFLIGHT.md). The API and preflight share
one validator; pack checks require the packaged schema to match the canonical file.

This is the durable intake and observation part of the controller. Recording or
rechecking an intent does **not** create projects, applications, releases, data
services, domain registrations, credentials or capacity reservations. The
[trusted publisher adapter](PARTNER_AUTHORITY.md) can resolve commercial and
administrator assertions at observation time; it grants no administrator access.
There is no automatic execution worker for intents yet. Every receipt is
`NOT_QUALIFIED`, with `resource_mutations_performed=false` and no transformations.
Database constraints reject receipts that claim qualification or transformations.

## Submit and inspect

Install `services/api/requirements.txt`. Prepare an owner-only JSON file containing
all 20 required contract fields, an existing project UUID and the existing
application's environment. Use opaque references; never put secret values,
identity documents or payment credentials into the intent. The authenticated
human's database membership authorizes intake; `requested_by`, partner/account,
commercial and administrator references cannot authorize it.

```sh
python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intent-submit <tenant-uuid> <application-uuid> \
  --intent-file /private/hosting-intent.json

python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intents <tenant-uuid> <application-uuid>

python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intent <tenant-uuid> <application-uuid> <request-uuid>

python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intent-reconcile <tenant-uuid> <application-uuid> \
  <request-uuid> --idempotency-key <evaluation-uuid>
```

TLS verification, refused redirects, bounded responses and owner-only token files
use the existing CLI boundary. The intent file must be an owned regular file,
without symlinks or group/world permissions, at most 64 KiB. Duplicate JSON keys,
unknown fields, mutable tags, ambiguous numeric budgets and plaintext secret
values are rejected. Both the database and API validate typed payloads. Database
binding rules reject a project or environment that differs from the application.

The corresponding API routes, documented in `/openapi.json`, are:

| Method | Application route suffix | Result |
| --- | --- | --- |
| POST | `/intents` | Exact `{"intent": {...}}`; 201 on first record, 200 on matching replay |
| GET | `/intents` | Up to 50 newest requests, each with its latest receipt |
| GET | `/intents/{intent_id}` | One request plus up to 20 newest receipts |
| POST | `/intents/{intent_id}/reconcile` | Exact `{"idempotency_key": "<uuid>"}`; 201 on a new observation, 200 on its replay |

POST intake/reconciliation requires JSON, one Content-Length and a body of at
most 64 KiB; transfer-encoded and duplicate-key requests are refused. Viewers,
machine identities and other tenants cannot read or insert intent history.
Readback excludes partner/account/commercial/admin/requester/secret-reference
values and the submitting identity. The canonical hash still binds all fields.

## Retry and history semantics

`request_id` is the tenant-scoped immutable intake key. Matching content and
application returns the existing intent with its latest recorded receipt.
Changed content or another application using that key returns 409. To revise
desired state, submit a new request UUID; old content cannot be overwritten.

Reconciliation keys are tenant scoped and bound to one intent. A matching retry
returns the **original historical observation**, even if hosting state changed
since then. Reusing that key for another intent returns 409. Use a new key to
observe again. The CLI generates and prints a new key when omitted; retain it
for retry. Concurrent duplicate submissions and rechecks produce one committed
fact. Each receipt has a database revision for history ordering, an observation
timestamp, the original request hash and `hosting-readback-v1` controller version.

Recording the parent, initial receipt, both hash-chain audit records and both
outbox events happens in one transaction. A failed evaluation leaves no parent
or partial audit/outbox history. Rechecks atomically record one new receipt and
one audit/outbox fact. Database triggers forbid updates and deletion even by
the protected operator. Preserve this history through the existing full control
database backup and WAL/PITR procedures; migration 028 travels with the ledger.

## What an observation establishes

The checked tenant/app/intent evidence function reads one database statement
snapshot. It compares the requested project, environment and immutable artifact;
artifact admission; the active serving release and recently observed enabled
node; domain ownership; release-bound fresh public health; active traffic;
requested PostgreSQL/storage presence and placement; hosting plan features and
budget headroom; and actual open application reservations. Health older than
three minutes, node observations older than five minutes, future observations,
another release/artifact/environment, or ownership proof newer than health cannot
produce a healthy requested-release stage.

The budget includes **all open application reservations**, including overlapping
old/staged releases and cache/data services. It is allocated capacity, not
measured consumption or an invoice. Headroom includes other applications in the
organization and uses the smaller plan/quota ceiling. A matched observation does
not reserve that headroom or guarantee it will still be available on execution.

Profile compatibility here describes implemented development resources, not a
qualified estate. `postgres-private-v1` observes private PostgreSQL; Garage is
limited to the development environment. Managed Supabase and redundant S3 remain
blocked. Without a registered publisher and fresh exact-intent approval,
partner/commercial/admin bindings remain blocked. The [reviewed profile registry](EXECUTION_PROFILES.md) can match the profile
stage when an exact current protected review and measured node bindings exist.
The [scoped secret resolver](PARTNER_SECRETS.md) can match secret availability when
every requested reference has a current reviewed binding and fresh exact-version
OpenBao check. Live template/estate and secret-authority reviews, and independent
backup/restore receipts remain required; recording reviews or observing commercial,
profile, secret, health and resource matches does not certify the platform.
Future orchestration must install these authorities and recheck policy/capacity
before any resource mutation; this intake cannot bypass them.

Owners and administrators can inspect latest receipts and request a recheck in
the portal's **Hosting requests** panel. The panel labels recorded observation
times, clears tenant/application selection changes and failed/malformed readback,
and never interprets request text as HTML. An acknowledged recheck rotates its
retry key; an interrupted request retains its key for a safe retry. The panel
does not submit technical JSON or display private authority references.

## Verification and remaining work

`python -m unittest tests.test_partner_intent_integration -v` uses its own
disposable local database when TEST_* fixture DSNs are configured. It covers
immutability, RLS, actor spoofing, binding, canonical hashes, duplicate concurrency,
historical replay, audit/outbox rollback, allocation accounting, HTTP limits and
public response schemas. Pure evaluator and browser tests cover wrong/stale
evidence, unavailable readback and authority boundaries.

Automatic multi-resource execution, live upstream authority installation and profile review,
backup receipt integration and production acceptance remain unfinished. These
tests do not promote readiness or qualification flags.
