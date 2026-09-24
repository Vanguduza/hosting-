# Application service grants

The API accepts machine access tokens from the configured OIDC issuer with a separate `OIDC_SERVICE_AUDIENCE`. The issuer must authenticate confidential machine clients, assign an immutable `client_id` and `sub`, and ensure that a human token cannot obtain the service audience. The JWT must have a single string audience, the expected issuer, a valid signature, `exp`, `iat`, `sub`, and `client_id`. Configure this audience separately from `OIDC_AUDIENCE`; API startup fails if they match. The API does not create IdP clients or mint their credentials.

An organization owner registers the exact `client_id` and `sub` from an IdP issued machine token for one existing application:

```http
POST /v1/organizations/{org}/service-accounts
Content-Type: application/json

{"application_id":"<canonical UUID>","client_id":"<issuer client_id>","actor_sub":"<issuer sub>"}
```

The operator CLI exposes `service-grant`, `service-accounts`, and `service-revoke`. A `(organization, client_id, sub)` pair has one immutable grant, so a revoked client must be provisioned with a new issuer identity to receive access again. The owner revokes a grant with `POST /v1/organizations/{org}/service-accounts/revoke` and `{"id":"<grant UUID>","confirm":"revoke_service_account"}`. A revocation serializes with an in-flight release request and blocks the next request, even if its JWT remains valid. Creation and revocation write tenant audit events.

The machine token can call only `GET` and `POST /v1/organizations/{org}/applications/{app}/releases` for its bound application (plus authenticated `/ready`). It may queue a digest that has already passed artifact admission; domain ownership, traffic state, placement, capacity and idempotency checks still apply. It cannot register domains, alter traffic, create resources, roll back, inspect projects or manage team membership. Service tokens do not inherit a human membership with the same `sub`; database row policies also enforce the application boundary. Releases and their jobs retain the machine `sub` and the audit event.

This is a bounded client integration; the API does not provision IdP clients or publish a public package. Production still requires a certified issuer configuration, credential lifecycle and live end-to-end deployment proof. Apply migration `015_service_accounts.sql` with the protected migration role before starting the updated API on an existing database.
An installable Python release client and its token provider contract are in [sdk/python](../sdk/python/README.md).
