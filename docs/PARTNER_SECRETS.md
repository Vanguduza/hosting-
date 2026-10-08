# Scoped Partner secret references

Migration 031 adds operator-reviewed bindings for the private `secret_refs` in a
recorded HostingIntent. Each exact reference is scoped to an organization and
application. The protected checker reads its pinned OpenBao KV v2 version, verifies
the requested key is a nonempty string, and records only availability. Values and
value hashes never enter PostgreSQL, audit/outbox, public readback or stdout.

This resolves availability before orchestration. It does not deliver values to an
application, create runtime resources, register commercial authority or certify
production. Overall intent evaluations remain `NOT_QUALIFIED`, with no resource
mutations or transformations. Independent backup receipts and actual execution
still need implementation and installation.

## Trust boundary and namespace

The protected hosting operator reviews the upstream authority to use the secret
and imports an immutable binding. `authorization_ref` is opaque review provenance,
not a fetched or cryptographically verified document. A protected database owner
can attest availability directly; the normal tool performs the actual TLS read.
Neither arbitrary reference text nor a successful OpenBao read grants tenant or
commercial authority. Existing owners/admins may read redacted status; API, worker,
hook, admitter and buildworker roles cannot import, inspect private mappings or
record checks, even with spoofed operator settings. Machine publishers cannot
use the readback endpoint. All writes use protected database credentials.

References are never interpreted as OpenBao paths. The only supported path is:

```text
<mount>/data/partner-applications/<organization UUID>/<application UUID>/<resource UUID>?version=<KV version>
```

It is separate from managed-service `resources/<UUID>` credentials. All UUIDs are
canonicalized before path construction. The exact reference's `#revision` must
equal the pinned KV version. The configured HTTPS authority and mount must match
the binding exactly; the checker never connects to an address supplied by a tenant
or constructs a client from imported address text. It refuses redirects, validates
TLS using the configured CA, bounds responses and rejects duplicate JSON fields.
Missing, deleted, destroyed or different versions, missing/invalid keys and
authentication or network errors yield `UNAVAILABLE` without storing remote errors.

Provision separate AppRoles: a private provisioning role can create/update exact
application paths; the checker needs only read on the reviewed application paths.
For one application, a policy can use the following scope (replace UUIDs with real
values; narrow the final wildcard to resource UUIDs when feasible):

```hcl
path "dial/data/partner-applications/<organization UUID>/<application UUID>/*" {
  capabilities = ["read"]
}
```

The existing managed-service runtime role needs no access to this namespace.
Configure `BAO_ADDR`, `BAO_CA_FILE`, `BAO_ROLE_ID_FILE`, `BAO_SECRET_ID_FILE` and
optionally `BAO_KV_MOUNT` for the checker. OpenBao initialization, unseal, audit,
production access controls and independent recovery remain installation steps
described in [the secret runbook](SECRETS.md). No real authority is configured by
the repository or disposable tests.

## Provision, import and check

1. Confirm the application belongs to the organization, upstream secret authority
   is reviewed, and the chosen resource UUID is dedicated to this application.
2. Using the provisioning AppRole, send a private JSON object on stdin to:

   ```sh
   python tools/secret_control.py <resource UUID> --cas 0 \
     --partner-organization <organization UUID> --partner-application <application UUID>
   ```

   The command has no hosting database authority: OpenBao ACLs must constrain its
   scope. Rotation uses the current version as `--cas`. CAS detects competing
   writes. The command prints only resource UUID, new version and `STORED`.
   A new version requires a new reference revision and new binding; existing
   intents retain their pinned old revision until it is withdrawn or destroyed.
3. Prepare an owner-only regular JSON file using the exact fourteen-field
   [binding schema](../contracts/partner-secret-binding-v1.schema.json):
   `schema_version`, `id`, `organization_id`, `application_id`, `secret_ref`,
   `bao_address`, `bao_mount`, `resource_id`, `kv_version`, `value_key`, `enabled`,
   `valid_from`, `valid_until`, `authorization_ref`. Use a new binding UUID,
   explicit timezones and a validity window no longer than 90 elapsed days.
   `value_key` uses lowercase letters, digits and underscores; it is not a path.
   The file contains private references and mapping metadata, never plaintext.
4. With protected database credentials and a reviewed operator identity:

   ```sh
   python tools/partner_secret_control.py --operator <operator> import --binding-file <private file>
   python tools/partner_secret_control.py --operator <operator> check <binding UUID> --check-id <fresh UUID>
   ```

   The importer checks the actual database role and application/organization
   binding. Check IDs are optional, with a fresh UUID generated by default. A
   failed availability check records `UNAVAILABLE`, prints a minimal receipt and
   exits nonzero. Retry with the same ID returns the original historical result
   without probing or extending freshness. Use a fresh ID to perform a new read.

Imports, checks and their audit/outbox records commit atomically. Immutable
versions order by serialized database revision. Concurrent duplicate IDs produce
one fact; conflicting content or operator identity is rejected. Import and check
serialize on the exact tenant/application/reference. A bounded network read holds
that lock; a queued withdrawal becomes current after the check commits and blocks
readback immediately. Keep checker invocations separate from user request paths.

## Readback, expiry and withdrawal

`GET /v1/organizations/{org}/applications/{app}/intents/{intent}/secrets` and
`hosting_cli.py intent-secrets <org> <app> <intent>` return an exact-intent summary:
scope IDs and intent hash, observation time, state, requested/matched counts, and
the oldest successful check and limiting expiry when all references match. The
portal shows current availability separately from historical evaluations. It
rejects borrowed, incomplete, expired or malformed readback and clears old checks
on selection/session changes. There is no browser write, probe or secret upload.

Only the newest binding for each exact scoped reference is considered. States are
`NOT_REQUESTED`, `UNCONFIGURED`, `BINDING_DISABLED`, `NOT_YET_VALID`, `EXPIRED`,
`CHECK_REQUIRED`, `CHECK_FAILED` or `MATCHED`. All requested references must have
enabled, currently valid bindings and newest `AVAILABLE` checks less than five
minutes old. A newer failed check always overrides a prior success. Expiry is the
earliest binding expiry or check time plus five minutes. Partial matches withhold
success timestamps. No reference names, keys, paths, resource IDs, operator names,
authority configuration, values or hashes appear in the summary.

Run checks at an operator-managed interval shorter than five minutes before
rechecking an intent; an installed scheduler is not supplied by this continuation.
The TTL is bounded observation freshness, not continuous verification: deletion or
an OpenBao outage after a read may take until the next check/expiry to appear.
Future execution must read the pinned version again immediately before delivery
and recheck authority, binding, policy and placement. Cached availability must not
authorize delivery or reactivation.

To withdraw, import a new binding version with `enabled: false` for the same exact
reference. Disabled imports require no working OpenBao connection. Old retries do
not reactivate it. To restore, import a new enabled version and run a fresh check;
checks from an old binding never carry forward. Database-supplied timestamps prevent
caller backdating or future-dating from extending freshness. Preserve both tables,
the migration ledger and audit/outbox with control backups; preserve OpenBao data,
unseal material and credential custody using the independent recovery workflow.

## Verification

`tests.test_partner_secrets` checks contract, private-file, pinned-path/version and
fail-closed evaluator boundaries. `tests.test_partner_secret_integration` uses its
own disposable PostgreSQL database for isolation, redaction, immutable/private
history, latest-only withdrawal, failures, expiry, all-reference scope, concurrency,
rollback, timestamp enforcement and read-only HTTP. The real TLS OpenBao fixture
exercises scoped ACLs, cross-tenant/application denial, CAS, pinned versions and
deleted/destroyed version refusal. Portal client/browser checks cover unavailable,
malformed and withdrawn status, exact selection, session clearing and mobile layout.
These tests establish software behavior using disposable credentials, not a live
Partner secret-authority review or production estate qualification.
