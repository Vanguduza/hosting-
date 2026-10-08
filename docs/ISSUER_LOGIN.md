# Issuer sign-in and session renewal

The owner portal now supports a configured public OIDC client using authorization
code flow with PKCE S256. The issuer handles login, password recovery, OTP, social
providers and MFA. The platform validates signed identity/access tokens and keeps
tenant permissions in canonical PostgreSQL membership and service-grant policies.
No issuer account or production authentication qualification is created by this
implementation.

## Configuration

The existing `OIDC_ISSUER`, `OIDC_JWKS_URL`, `OIDC_AUDIENCE` and
`OIDC_SERVICE_AUDIENCE` remain required API settings. Configure these additional
non-secret settings in the control deployment's private `.env`:

| Setting | Meaning |
| --- | --- |
| `OIDC_LOGIN_CLIENT_ID` | Dedicated public portal client ID; distinct from both API audiences |
| `OIDC_AUTHORIZATION_URL` | Exact HTTPS authorization endpoint on the issuer origin |
| `OIDC_TOKEN_URL` | Exact HTTPS token endpoint on the issuer origin |
| `OIDC_LOGIN_REDIRECT_URI` | Exact public URL `https://your-control-host/portal`, registered with the issuer |
| `OIDC_LOGIN_SCOPES` | Space-separated scopes including `openid`, the required API audience scope, and optionally `offline_access` |

Enable authorization code flow, mandatory PKCE S256, and token endpoint
authentication method `none` for this public client. Configure **JWT access
tokens** signed with RS256 or ES256. No client secret is accepted. Copy the
issuer/endpoints from verified issuer metadata; this implementation pins them
in operator configuration and does not follow token-endpoint redirects.
The JWKS client retains verified TLS, a five-second network timeout and bounded
key-set caching. Token exchange uses inherited verified HTTPS/proxy settings.

For ZITADEL, use its hosted-login public client and configure a dedicated project
audience for the control API. Its documented
[`urn:zitadel:iam:org:project:id:{projectid}:aud` scope](https://zitadel.com/docs/apis/openidoauth/scopes)
requests that project audience; replace `{projectid}` with the actual API project
ID. Include it in `OIDC_LOGIN_SCOPES`. `offline_access` requests refresh tokens
in code flow when allowed by the issuer. If scopes are omitted, the default is
`openid offline_access`; deployments still need their actual API audience scope.
See [ZITADEL hosted login](https://zitadel.com/docs/guides/integrate/login/hosted-login)
for provider-side setup. Never infer hosting owner/admin roles from issuer
organization metadata or template claims.

Access-token `aud` may be the human API audience, a singleton array containing
it, or an array containing it and the **explicitly configured portal client**.
Mixed human/machine audiences, unrelated resource audiences and duplicates are
rejected. Machine authorization remains separate. ID-token audience is the
portal client; multiple ID audiences require the correct `azp`. Issuer,
signature, expiry, subject, nonce and any supplied `at_hash` must validate.

Leaving all four login settings empty disables issuer sign-in and retains the
manual human-token development connection. Partial/invalid configuration refuses
startup. Callback URLs require HTTPS, except an exact loopback HTTP URL for a
local development browser. No callback query, fragment or alternative path is
accepted. Keep public TLS ingress and its edge request limits in front of the
loopback-bound API before remote use.

## Browser/session behavior

The browser generates a random state, nonce and PKCE verifier using Web Crypto.
Only the pending transaction is retained in **this tab's sessionStorage**, for
at most ten minutes. It contains no access, ID or refresh token. It is preserved
through the issuer redirect, then consumed once before code exchange. The callback
must match the stored state, exact callback URL and unchanged public configuration;
an issuer parameter must match when present. Errors, duplicate parameters,
fragments, expired transactions and replays fail closed.

The portal strips callback parameters from browser history immediately. The API
logs request paths without queries so authorization codes/state do not enter its
access log. Configure upstream ingress logging to exclude callback queries too;
the application cannot control another server's access log.

`POST /v1/auth/exchange` sends the code, verifier and nonce to the fixed issuer.
Signed access/ID tokens must identify the same human. The API returns only a
bounded access token, optional refresh token, subject and effective expiry;
ID tokens and issuer diagnostics are omitted. Both exchange and refresh require
JSON and an `Origin` matching the configured callback origin. They accept no
cookies or browser-selected issuer, client or redirect destination.

Tokens remain in JavaScript memory. Refresh is serialized, begins shortly before
expiry and preserves the subject. It validates any returned ID token; a refresh
ID token may omit nonce, but a supplied nonce must match the original transaction.
Rotated refresh tokens replace the old credential in memory. Requests check
session freshness before sending a bearer token, and tab visibility changes
check delayed timers. Failed/uncertain renewal clears authentication and tenant
data and requires a new sign-in; refresh credentials are not blindly retried.

Disconnect aborts pending exchanges/renewals and clears tokens, timers, pending
transactions and displayed tenant data. A late response cannot reconnect it.
Page exit clears the local workspace, preserving only a pending transaction when
the page is deliberately navigating to its issuer. Reloaded pages sign in again.
Disconnect is local: issuer-wide SSO logout and refresh-token revocation are not
implemented here. Use the issuer's account/session controls for those operations.

## API and verification

Public routes are `GET /v1/auth/config`, `POST /v1/auth/exchange` and
`POST /v1/auth/refresh`; their exact schemas are in `/openapi.json`. All tenant
routes continue to require validated bearer tokens and database authorization.

Run:

```sh
python -m unittest tests.test_oidc_login tests.test_auth tests.test_openapi -v
node --test tests/test_login_client.mjs tests/test_portal_client.mjs
node tests/login_browser.mjs
node tests/portal_browser.mjs
```

The browser proofs use intercepted issuer/API contracts. Python proofs use real
signed JWTs, HTTP routes and rejected origin/nonce/audience/subject/hash cases.
Actual issuer version, login/recovery/MFA/social-provider flows, public ingress,
key rotation and production session/logout behavior still require live
configuration and qualification. Step-up protection for sensitive hosting changes
and the complete commercial workspace remain open; readiness flags stay false.
