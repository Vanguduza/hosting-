# Organization team membership

The hosting API authenticates users against one configured OIDC issuer and audience. A trusted operator bootstraps the first owner with a verified issuer `sub`. The API's team flow does not create accounts at the identity provider; an invitee signs in with their existing OIDC account and accepts a capability token. Hosting membership, rather than a mutable JWT role claim, authorizes every organization operation.

## Owner actions

An owner creates an invitation at `POST /v1/organizations/{org}/team/invitations` with:

```json
{"idempotency_key":"<UUID>","role":"viewer","expires_hours":24,"confirm":"invite_viewer"}
```

For an admin invitation use `"role":"admin"` and `"confirm":"invite_admin"`. The response returns a cryptographically random token **once**. Deliver it to the intended person over an independently verified private channel. It is a bearer capability: possession permits any account at the configured OIDC issuer to claim the role until it expires, is revoked, or is used. The control database stores only SHA-256 of the token. An exact idempotency replay returns metadata without the original token; a changed replay fails. Tokens expire after 1–72 hours. The API does not send mail or SMS.

`GET` on the same path lists up to 100 recent invitations without token hashes. `POST /v1/organizations/{org}/team/invitations/revoke` with `{"invitation_id":"<UUID>"}` revokes an unused invitation. `GET /v1/organizations/{org}/team/members` lists actor subjects and roles. `POST /v1/organizations/{org}/team/members/remove` with `{"actor_sub":"<verified OIDC sub>","confirm":"remove_member"}` removes an admin or viewer. Owners cannot remove themselves or another owner here. Owner transfer is a distinct high-risk workflow that is **not** implemented by this API.

An invitee sends `POST /v1/team/invitations/accept` with `{"token":"<token>"}` and a valid platform OIDC bearer token. Acceptance binds the invitation once to the JWT `sub`; exact replay by the same still-active member returns `replayed=true`. A revoked, expired, used-by-another, or formerly accepted membership cannot be claimed again. Every successful creation, acceptance, revocation and member removal writes an audit event in the same database transaction. Membership removal takes effect on the next API request even if a JWT has not expired.

Apply `007_team.sql` after prior migrations using the protected migration role. Its three `SECURITY DEFINER` functions are owned by that role; the migration owner must have permission to bypass the FORCE RLS membership table. Function execution is granted only to `hosting_api`, and direct membership INSERT/DELETE is not. On existing control volumes, apply the migration explicitly before starting the new API; Docker entrypoint migrations run only for a fresh database.

The operator must protect invitation transport, the OIDC issuer and the API TLS gateway. Self-service owner transfer, identity-provider enrollment, MFA/step-up enforcement, and email invitation delivery remain production gates. Application service grants are described in [SERVICE_ACCOUNTS.md](SERVICE_ACCOUNTS.md).
