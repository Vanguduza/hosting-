# Trusted Partner approval receipts

Migration 029 implements the hosting side of the Partner commercial and
administrator binding boundary. A protected hosting operator registers one
publisher identity per tenant. That publisher submits an **existing business
platform decision** bound to an exact immutable HostingIntent. Hosting validates
its scope and freshness and observes current local plan and administrator
membership. It does not make commercial decisions, grant membership, charge an
account, purchase a domain or provision infrastructure.

The upstream reference is the Partner Business Platform Rev 1 canon in
`Vanguduza/dial-business-group`,
`docs/dial/final-audit/29_PARTNER_PLATFORM/DIAL_PARTNER_BUSINESS_PLATFORM_REV1_CANONICAL.md`,
Git blob `dd4b605439eda72e2dfb7b17f282a892777eb513`, inspected 2026-10-08.
Its typed intent and infrastructure handoff require business approval outside
hosting. The factory is specified there; a working upstream decision publisher
was not found. This adapter establishes an executable hosting interface, not a
claim that the business platform or its commercial truth has been implemented.

## Register a publisher

Use [the exact source schema](../contracts/partner-authority-source-v1.schema.json)
in an owned, mode-0600, regular JSON file of at most 64 KiB. Supply a fresh UUID,
the tenant UUID, purpose `partner-commercial-bindings-v1`, a short operator label,
the exact HTTPS issuer, machine client ID and subject, an `enabled` boolean,
`max_validity_seconds` between 30 and 3600, and an opaque `authority://` evidence
reference. No credentials belong in this file.

```sh
python tools/partner_authority_source.py --operator <protected-operator-name> \
  --source-file /private/partner-publisher.json
```

The tool uses the protected database configuration shared by operator tools and
verifies the migration ledger. API/worker credentials cannot register publishers.
Provision the machine client in the actual configured OIDC issuer separately;
registration creates no provider accounts or credentials. Its signed access token
must have the **exact service audience** accepted by hosting, the registered
`client_id`, `sub` and verified `iss`. Human tokens cannot publish decisions.
An existing release service account grant does not authorize this route.

Source versions are immutable and audited. The newest serialized version is
effective. To change or disable a publisher, import a new UUID with the changed
configuration. Any source version replacement invalidates prior authorizations,
even when the principal stays the same. Re-enabling requires a new decision.
Replaying an old source UUID never makes it effective again. Use protected
credential custody: source registration is a trust decision, not a request that
the human client portal can make.

## Publish a decision

The [exact receipt schema](../contracts/partner-authority-receipt-v1.schema.json)
contains 13 fields: schema version, purpose, immutable receipt UUID, source version
UUID, exact intent SHA-256, positive signed-64-bit sequence, `AUTHORIZE` or `REVOKE`,
local hosting entitlement version UUID, administrator bindings, issuance time,
expiry and opaque `partner-proof://` evidence reference. The publisher resolves
partner, business account, commercial entitlement and administrator references
from its own canonical records. Authorization asserts that **all 20 fields of the
hashed HostingIntent** have that decision's business approval.

For `AUTHORIZE`, bind the currently active local hosting plan version and exactly
the requested `tenant_admin_refs`. Each mapping is `{"ref": "<opaque-reference>",
"actor_sub": "<existing-human-subject>"}`. Subjects must already be tenant owners
or administrators. Duplicate references, extra/missing references and viewers
are rejected. Hosting never adds or upgrades these memberships. The hosting plan
remains a distinct local infrastructure entitlement, with its existing feature,
count and capacity enforcement.

Use explicit ISO timestamps with a timezone and at most six fractional digits.
Issuance cannot be in the future or older than the registered maximum validity.
Expiry must be later than the current check and within that maximum of issuance.
No plaintext secrets, raw tokens, payment details or arbitrary business documents
are accepted. Evidence references are opaque provenance labels: hosting trusts
the registered authenticated publisher's assertion and does not fetch or verify
a document at those references. TLS and the signed identity protect transmission;
the receipt is not a portable detached signature.

```sh
python tools/publish_partner_authority.py --url https://control.example:443 \
  --token-file /private/partner-machine.jwt --org <tenant-uuid> \
  --app <application-uuid> --intent-id <request-uuid> \
  --receipt-file /private/partner-decision.json
```

The JSON and token files must be private owned regular files. The publisher
helper verifies TLS, refuses redirects and bounds responses. POST to
`/v1/organizations/{org}/applications/{app}/intents/{intent_id}/authority` requires
exact `{"receipt": {...}}`, one Content-Length, JSON and at most 64 KiB. The body
cannot override the verified token identity. Unknown publishers, wrong tenant or
application, missing intent and human callers receive 404. Invalid JSON/contract
returns 400; conflicting intent hash, plan/admin bindings, source version,
sequence or expiry returns 409. Database errors remain redacted.

A new committed receipt returns 201 with `id`, `state=RECORDED`, `sequence` as a
decimal **string**, and `replayed=false`. The database stores its canonical UTF-8
payload hash, checks bindings, and commits one hash-chain audit and outbox event
atomically. Private source and receipt tables have no API table privileges;
bounded functions enforce verified context. API roles cannot call the private
base evidence or administrator-resolution helpers. History cannot be edited or
deleted even by the protected operator.

## Revocation and retry

Sequences increase per tenant and intent across source versions; gaps are allowed.
The latest recorded sequence is the only candidate. An expired or invalid newest
receipt never falls back to an older approval. A `REVOKE` has null plan and expiry
and empty administrator bindings. It remains effective until a new higher
`AUTHORIZE` passes all checks. Revocation is recorded even if the plan or
administrator memberships have already become unavailable.

The receipt UUID is a tenant-scoped idempotency key. An identical retry returns
200 and its original acknowledgement, including after expiry, revocation or a
source version change with the same authenticated principal. It **never activates
old approval**. Changed content, another application/intent or a replaced
principal cannot reuse that UUID. Disabled publishers cannot replay or publish.
Concurrent duplicate calls record one fact. Source registration/publication,
receipt UUID, intent and audit locks use that order to serialize changes without
conflicting with intent observation locks.

## Read current status and record an observation

Human owners/admins can GET the same `/authority` route, or use:

```sh
python tools/hosting_cli.py --base-url https://control.example:443 \
  --token-file /private/control.jwt intent-authority <tenant-uuid> \
  <application-uuid> <request-uuid>
```

Readback exposes tenant/app/intent binding, observation time, state, public
version/receipt IDs, decimal sequence and validity times. It excludes publisher
principals, business/account/commercial/admin references and private proofs.
Viewers and machines cannot read it or read intent history. The portal's Hosting
requests panel shows the latest approval check separately from its historical
intent observation and clears failed, malformed and obsolete selections.

| State | Meaning |
| --- | --- |
| `UNCONFIGURED` | No trusted publisher is registered |
| `SOURCE_DISABLED` | The latest publisher configuration is disabled |
| `AWAITING_RECEIPT` | No publisher receipt is recorded |
| `REVOKED` | Latest decision is a revocation |
| `SOURCE_CHANGED` | Approval is bound to an older publisher version |
| `EXPIRED` | Approval is expired or its issuance is in the future |
| `PLAN_UNAVAILABLE` | No active local plan is assigned |
| `PLAN_CHANGED` | Current local plan differs from the approved version |
| `ADMIN_UNBOUND` | A bound administrator is no longer a tenant owner/admin |
| `ACTIVE` | Approval passes these checks at the recorded observation time |

A fresh human intent recheck reads the source, receipt, plan, memberships and
hosting runtime evidence in one statement snapshot. Only `ACTIVE` can mark the
commercial and administrator stages `MATCHED`. Historical evaluations do not
change when the current approval changes. The separate [reviewed profile registry](EXECUTION_PROFILES.md) can now match
exact supported setup and measured node bindings. Live profile review, Partner
live [secret-authority review](PARTNER_SECRETS.md) and independent backup/restore integration remain required;
all intent receipts still have `NOT_QUALIFIED`, no transformations and no resource
mutations. Any future execution must revalidate all authority and capacity at
mutation time; an observation does not reserve permission or capacity.

## Verification and installation boundary

`tests.test_partner_authority` checks typed contracts, private files, client route
construction and evaluator behavior. `tests.test_partner_authority_integration`
uses a separate disposable local PostgreSQL database to check publisher purpose
and tenant isolation, source replacement/disable serialization, retries and
sequence races, immutable/private tables, audit rollback, Unicode hashes,
expiry/revocation, current plan/admin changes, strict HTTP intake and redaction.
Portal unit/browser tests check malformed/unavailable/borrowed status and clearing.

No actual tenant publisher has been configured or upstream factory installed.
Live OIDC, canonical commercial records, upstream issuance/renewal and revocation
operations, qualified profiles, backups, automatic execution and production
acceptance still need completion. Readiness flags remain false.
