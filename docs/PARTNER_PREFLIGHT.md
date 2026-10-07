# Typed Partner HostingIntent preflight

[The integration contract](PARTNER_PLATFORM_INTEGRATION.md) now has an executable
[v1 JSON Schema](../contracts/hosting-intent-v1.schema.json) and
`tools/partner_preflight.py`. All 20 fields are required. Unknown fields,
duplicate JSON keys, mutable image tags, ambiguous resource numbers, invalid
hostnames and plaintext secret values are rejected before any API access.
References remain references; the tool does not resolve or authorize them.

Install the API contract-check dependencies, then run:

```sh
python -m pip install -r services/api/requirements-contracts.txt
python tools/partner_preflight.py /private/hosting-intent.json \
  --organization <canonical-tenant-uuid> --application <application-uuid>
```

Add `--base-url https://control.example:443 --token-file /private/control.jwt`
for authenticated readback. The token file must be owner-only. TLS remains
verified, redirects are refused and responses are bounded by the existing CLI.
Every remote request is GET; the tool never provisions, registers a domain,
issues credentials or charges a customer.

The receipt contains the request ID, canonical intent SHA-256, explicit stage
states and an empty transformations list. It excludes secret/admin/entitlement
reference values. Remote readback checks the application inside the requested
tenant/project/environment, active serving artifact, fresh release-bound health,
domain ownership proof and actual PostgreSQL/storage presence. A missing resource
field is an error, not proof that no resource exists. A healthy older release,
another artifact, stale health or a different environment cannot satisfy intent.

`postgres-private-v1` describes the existing private PostgreSQL development
resource. `garage-development-v1` is limited to development. Supabase and
redundant S3 profiles are explicitly unqualified. `secret://namespace/key#revision`
is a typed reference syntax awaiting an authoritative resolver; it does not map
to arbitrary OpenBao paths or grant secret access.

The overall receipt remains `NOT_QUALIFIED`: canonical partner/commercial/admin
bindings, profile qualification, independent backup receipts and complete resource
budget evidence are missing. Exit 1 means valid but unqualified; exit 2 means
invalid input or failed readback. No exit path claims production success.

This is the intake/readback boundary for later orchestration. It does not implement
the durable HostingIntent controller, canonical entitlement registry, profile
registry or multi-resource reconciliation described in the integration contract.
