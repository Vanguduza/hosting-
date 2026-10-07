# Zimbabwe launch configuration and domain registration

Recommendation recorded 2026-10-07. These are proposed provider choices, not
provisioned accounts, purchased domains or placement certificates.

## Initial infrastructure

Use the existing Netcup 8 GB machine as a control-plane candidate only after
measurement and recovery admission. If a new provider is needed, Hetzner Cloud
in Europe is a cost-oriented candidate. Keep workload/data nodes separate, and
compare latency from Zimbabwean fixed/mobile networks with a South African
provider before selecting production placement. Do not place the whole product
catalog on the control machine. Choose initial workload capacity from measured
CPU, RAM, disk and restore bandwidth, rather than tenant counts alone.

Use a dedicated ZITADEL OIDC project for platform customers and machine identities,
with separate human/service audiences. The blueprint's candidate is ZITADEL;
hosting applications retain their own IAM. Install and qualify the issuer before
replacing the development portal's token connection flow.

Use a private Harbor registry with scoped robot accounts and an isolated build
host. Send encrypted Restic backups and WAL to a different provider/failure domain
(for example, a separately contracted S3-compatible storage provider). Keep
recovery keys and external health/status infrastructure outside the primary host.
Restore drills and external probes, rather than account creation, admit production.

## Domains

Support two independent customer journeys: connect an existing domain, or purchase
and manage a new registration. The existing API/portal implements ownership proof
and application routing for the former. It does not purchase or renew domains.

| Namespace | Recommended registration route | Required next input |
| --- | --- | --- |
| `.com` | OpenSRS reseller account and documented API integration | Reseller approval, price/renewal catalogue, sandbox/production credentials, customer/payment policy |
| `.co.zw` | A ZISPA member registrar | Selected member, reseller agreement, documented submission/API process, registrant/document requirements and service terms |

[ZISPA's published registry guidance](https://www.zispa.org.zw/) states that `.co.zw`
registrations go through members, including local ISPs and web-related organisations.
It requires accurate real-owner details and an individual ID or company incorporation
document. Its applications are vetted; availability is not equivalent to eligibility
or completed registration. The published guidance does not establish a registrar API.
Start with an audited operator fulfillment process if the selected member cannot
offer one, then automate only its documented interface.

[OpenSRS](https://opensrs.com/domains/) advertises a white-label reseller program,
`.com` coverage, API integration and branded end-user notices. Its availability,
prices, account eligibility, payment funding and API behavior must be confirmed in
the reseller account. Do not assume it covers `.co.zw`.

Domain registration authority must retain the customer's ownership. Keep identity
documents in private access-controlled storage and refer to them by opaque IDs;
never put them in browser receipts, audit payloads, Git or registrar diagnostics.

## Required implementation before selling registrations

1. Persist tenant-scoped registration intent and registrar-backed availability/quote
   receipts. Distinguish quotes from a domain reservation or purchase.
2. Obtain explicit approval of the exact name, registrant, term, currency, initial
   price, renewal price and terms. Bind payment/entitlement evidence to that quote.
3. Queue a durable provider operation with a stable request ID. After timeout,
   reconcile the provider's order before retrying; do not blindly repeat a purchase.
4. Record authoritative registrar readback, nameserver delegation and registrant
   verification. Only then mark registration completed. DNS existence alone is
   neither availability evidence nor registration/ownership evidence.
5. Manage expiry, renewal notifications, explicit auto-renew consent, failed payment,
   transfer locks/auth codes and registrant changes. Keep hosting cancellation
   separate from domain expiry/deletion and preserve export/transfer access.
6. Connect the acquired name through the existing DNS ownership and TLS lifecycle.
   Qualify `.com` and `.co.zw` independently against each registrar's failure paths.

Provider accounts, domain purchases and automatic billing are not configured in
this repository. Registration remains an implementation/qualification item; the
development portal must not present a DNS proof request as a registrar purchase.
