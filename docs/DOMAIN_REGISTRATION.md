# Domain registration requests and manual fulfillment

The development control API, owner portal and CLI implement an audited manual
registration workflow for `.com` and `.co.zw`. This is separate from application
DNS ownership proof. Requests and quote approval do not contact a registrar,
reserve a name, charge funds or establish a production domain certificate.

## Owner workflow

1. Obtain a support-issued `registrant://` profile reference. Support verifies
   the customer's real identity, eligibility and ownership documents privately
   with the selected registrar. The platform stores an opaque reference only;
   it currently has no document intake or identity-verification service.
2. In `/portal`, select an organization as its owner and request a root name
   such as `example.com` or `example.co.zw`. `.com` accepts terms of one to five
   years; the initial `.co.zw` workflow accepts one year. Keep the same
   idempotency key after a lost response. A changed specification requires a
   new key. The portal retains these keys within the connected session.
3. Support obtains current eligibility, availability, fees and terms from
   OpenSRS for `.com` or the selected ZISPA member for `.co.zw`, retains its
   evidence privately, and issues a quote. A quote is not a reservation.
4. Review the exact domain, registrant reference, registration term, registrar,
   currency, initial total, **one-year renewal price**, expiry and terms. The
   initial total covers the requested registration term. Prices are integer
   minor units, with two decimal places for USD, ZAR and ZWG. Renewal pricing is
   disclosure only; no renewal or automatic billing is enabled.
5. Explicitly approve the displayed quote. The request must include its UUID
   and server-generated SHA-256. A replacement quote invalidates earlier
   approval. The immutable historical quote and consent remain recorded.
6. Refresh to observe support processing and its retained fulfillment receipt.
   Owners may cancel `REQUESTED`, `QUOTED` or `APPROVED` requests. Cancellation
   cannot stop an operation already in `PROCESSING`. Any payment settlement,
   refund or dispute is handled under the quoted manual support policy; these
   endpoints do not move money.

Owner-only API routes:

| Method | Route under `/v1/organizations/{organization_id}` | Body |
| --- | --- | --- |
| GET | `/domain-registrations` | Latest 25 requests with current quotes |
| POST | `/domain-registrations` | `idempotency_key`, `hostname`, `term_years`, `registrant_ref` |
| POST | `/domain-registrations/{id}/approve` | `quote_id`, `quote_sha256`, `confirm: approve_registration_quote` |
| POST | `/domain-registrations/{id}/cancel` | `confirm: cancel_registration` |

The corresponding `tools/hosting_cli.py` commands are `registrations`,
`registration-request`, `registration-approve` and `registration-cancel`.
Request creation accepts `--idempotency-key`. Exact JSON schemas are published
at `/openapi.json`. Other human roles and machine identities cannot use these
routes. Tenant selection changes, failed quote readback and disconnect clear
the portal's displayed terms and approval checkbox.

## Protected operator workflow

Run `tools/registration_operator.py` using the existing protected database
configuration (`DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD_FILE`). Runtime
service roles, including `hosting_api`, cannot perform operator fulfillment.
Restrict operator credentials and the execution host to trusted support staff.
The operator identity is an asserted audit label under those credentials;
this tool does not implement separate operator OIDC or MFA.

All references below are opaque keys into private evidence storage, not URLs
containing personal information. Replace shell variables with the actual
request, quote and operation UUIDs. Keep quote and operation UUIDs stable when
reconciling a lost local response. Keep quoted legal terms in an owner-only
regular UTF-8 file, at most 4,000 UTF-8 bytes, and do not include private identity
documents or credentials in those customer-visible terms.

```bash
python3 tools/registration_operator.py "$REGISTRATION_ORG" "$REGISTRATION_REQUEST" \
  --operator support-operator quote \
  --quote-id "$REGISTRATION_QUOTE" --registrar 'Selected ZISPA member' \
  --amount-minor 2000 --renewal-minor 1500 --currency USD \
  --expires-at "$QUOTE_EXPIRY_UTC" --terms-file /private/registration-terms.txt \
  --provider-quote-ref quote://retained-provider-evidence

python3 tools/registration_operator.py "$REGISTRATION_ORG" "$REGISTRATION_REQUEST" \
  --operator support-operator start --quote-id "$REGISTRATION_QUOTE" \
  --payment-ref payment://verified-quote-bound-evidence \
  --operation-id "$REGISTRATION_OPERATION"

python3 tools/registration_operator.py "$REGISTRATION_ORG" "$REGISTRATION_REQUEST" \
  --operator support-operator complete --operation-id "$REGISTRATION_OPERATION" \
  --provider-order-ref order://retained-registrar-order \
  --receipt-sha256 "$REGISTRAR_RECEIPT_SHA256"
```

The amounts above illustrate the command syntax, not registrar pricing. Quotes
must expire within seven days. Before `start`, inspect the retained quote and
payment evidence, verify the payment covers that exact quote and registrant,
and confirm current registrar availability and eligibility. `start` requires
current owner consent and an unexpired quote, locks the request, and commits
`PROCESSING` before support submits the registrar order externally. Execute it
as its own CLI invocation; do not hold an uncommitted database transaction while
making a purchase. A quote cannot be replaced after processing begins.

There is **no automatic registrar call or retry**. If the registrar response or
operator process is lost, leave the operation in `PROCESSING`. Reconcile the
same operation against the registrar and retained evidence before any further
submission. Matching local retries return receipts; they do not prove whether
an external purchase occurred. Support must not treat `replayed: true` as
permission to submit another registrar order.

Record `complete` only after verifying the retained authoritative receipt and
its SHA-256. The status is `FULFILLMENT_RECORDED`: it records the trusted
operator's assertion, not independent live registrar readback or DNS/TLS
qualification. Use the existing application domain-proof and release lifecycle
to connect the name after verifying delegation and ownership.

For a definitive registrar failure **without a purchase**, retain its evidence
and use `fail --operation-id ... --evidence-ref failure://... --confirm
registrar_failed_without_purchase`. This releases internal name exclusion for a
new request. Never use failure to clear an unknown or timed-out purchase.

## Database authority and remaining work

Migration 026 adds owner-only forced row policies, composite tenant/request/quote
foreign keys, immutable quotes and consent history, and transactional audit and
event-outbox facts. API credentials may insert original request columns and call
the guarded consent function; they cannot write quote prices or fulfillment
states. Row locks serialize consent, cancellation and processing. A unique index
prevents simultaneous approved/processing/fulfilled purchases of the same name
within this platform. It cannot reserve a name at a registrar.

Production requires contracted registrar accounts, a chosen ZISPA member,
private registrant/evidence storage and support/payment policy. Automated
availability, registrar ordering and authoritative readback, refund integration,
expiry monitoring, renewal notices, explicit auto-renew consent, transfers,
registrant changes and production failure qualification remain open. No readiness
or owner-acceptance flag is promoted by this development workflow.
