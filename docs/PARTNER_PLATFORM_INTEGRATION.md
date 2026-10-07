# DIAL Partner Platform Integration Contract

**Status:** SPECIFIED — no runtime qualification implied

**Date:** 2026-10-04

**Consumer:** DIAL Partner Business Platform / Partner App Factory in `Vanguduza/dial-business-group`

**Provider:** DIAL Self-Hosted Client Cloud in this repository

## Purpose

This contract defines how DIAL-built supplier/service-provider applications consume the hosting platform without making the hosting control plane a commerce or business-domain authority.

The Partner App Factory creates configuration-first partner applications from qualified templates and shared DIAL capabilities. This repository receives a typed hosting desired-state request and owns only the infrastructure lifecycle.

## Authority boundary

The hosting platform owns:

- tenant / organization / project / environment isolation;
- desired infrastructure state;
- build, artifact admission, release and deployment;
- runtime placement and resource budgets;
- domains, DNS intent and TLS lifecycle;
- managed PostgreSQL / Supabase / storage where enabled;
- secret references and runtime secret delivery;
- backup / restore;
- observability and hosting health evidence;
- hosting quotas, usage and hosting billing;
- project transfer/export/offboarding.

The hosting platform does **not** own:

- supplier/provider commercial consent;
- partner contracts or marketplace eligibility;
- product/service catalog truth;
- seller offer, price, stock or service availability authority;
- order, booking or job authority;
- DIAL pricing/margin authority;
- payment, ledger or settlement authority;
- delivery/dispatch business authority;
- promotions/marketing authority;
- partner quality/compliance authority outside hosting-specific controls.

## HostingIntent

The Partner App Factory SHALL request infrastructure through a typed intent comparable to:

```yaml
schema_version:
partner_id:
dial_business_account_id:
project_id:
template_id:
template_version:
environment_profile:
runtime_class:
domain_intent:
database_profile:
storage_profile:
backup_profile:
observability_profile:
resource_budget:
release_artifact_ref:
secret_refs:
tenant_admin_refs:
commercial_entitlement_ref:
requested_by:
request_id:
```

The control plane MAY reject or transform a request only according to deterministic hosting policy, quotas, security, placement, compatibility and admission rules. Any transformation must be visible in resulting desired state and receipts.

## Required receipts

A successful partner-app provisioning path shall eventually produce evidence for:

```text
intent accepted
→ tenant/project/environment created
→ immutable release admitted
→ runtime placed
→ route/domain/TLS active
→ database/storage provisioned where requested
→ backups configured
→ observability active
→ health evidence bound to release/environment
→ hosting readback available
```

A configured template, successful build or started container alone does not prove that a partner platform is LIVE or commercially activated.

## Partner template handling

This repository hosts/deploys template-derived applications but does not own the template business semantics.

A template release passed to hosting must be immutable/versioned and already carry its Partner App Factory qualification metadata. Hosting performs its own supply-chain/runtime admission independently.

Template upgrades must preserve rollback and compatibility evidence. Stateful upgrades require backup/restore protection according to hosting policy.

## Commercial package boundary

The DIAL business layer may offer discounted setup, subsidized development, free introductory periods or hosting bundles. Hosting consumes only the resulting entitlement/plan state.

Exact discounts, free-month offers, commercial eligibility or partner acquisition rules SHALL NOT be hard-coded into deployment controllers.

## Security

Partner applications remain tenant-scoped workloads.

- platform IAM and hosted-app IAM remain separate;
- partner app secrets are references, not plaintext source configuration;
- browser/platform connector credentials belong to the Partner Integration Fabric or appropriate secret namespace, not ordinary app configuration;
- partner apps cannot receive host-level privileges by template choice;
- untrusted/custom partner code follows the repository's isolation gates;
- cross-tenant access fails closed.

## Failure semantics

Hosting failure must not mutate DIAL commercial/domain truth.

Examples:

- deployment failure does not deactivate a partner contract;
- DNS/TLS failure does not change catalog ownership;
- backup failure does not rewrite order state;
- hosting suspension does not settle or refund money automatically;
- application health loss is reported upstream as hosting/integration degradation for the relevant business workflow to handle.

## Cross-repository invariant

> DIAL business canon determines **what** partner capability is commercially and operationally authorized. The hosting control plane determines **how** an admitted partner application is provisioned and operated. Neither repository may silently assume the other's authority.

Current hosting certification flags remain authoritative; this specification does not promote `BUILD_READY`, `RUNTIME_QUALIFIED` or `PRODUCTION_QUALIFIED`.
