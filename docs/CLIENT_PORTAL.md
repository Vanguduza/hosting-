# Client workspace portal

The implemented development portal is served at `GET /portal` by the control API.
The API Docker image copies its static files with the existing `hosting_api`
package; no frontend dependency installation or separate server is needed.

Connect using a **human** OIDC token for the configured control API audience.
The issuer remains responsible for login and token renewal. Application-scoped
machine tokens cannot list organizations and cannot use this workspace. The
portal uses same-origin API requests with bearer authentication, no cookies,
no redirects and no browser persistence. Disconnect aborts in-flight requests,
removes the token, clears the rendered tenant data and resets forms and retry
keys. A 401 clears authentication and requests reconnection.

## Implemented workflow

- Select an organization, project and application from authenticated readback.
- Read reservation ceilings, allocated CPU/RAM, current release health and
  observation time, recent outage episodes, release history, traffic state,
  registered domain and private PostgreSQL, Valkey and development S3 state.
- Owners and admins can create projects and applications, request domain TXT
  proof, check the proof, provision private data services and queue admitted
  immutable releases. Viewers see readback only. API authorization and database
  row policies remain authoritative for every action.
- Show the actual operation receipt, including queued state and resource IDs.
  Provisioning and public release verification continue through the existing
  durable workers. Refresh reads their latest state. Missing or failed readback
  is displayed as unavailable; it cannot retain an earlier green observation.

Release and resource requests keep the same idempotency key for the same
application, route and specification throughout the connected session, including
after a transport failure. A changed specification gets another key. Keys clear
on disconnect/page exit. After a network interruption, refresh readback before
resubmitting project, application or domain creation: those existing API routes
do not accept idempotency keys. The portal never automatically retries writes.

## Browser boundaries

Only four exact asset paths are served. Unknown paths cannot access files from
the package. Assets have `Cache-Control: no-store`, MIME sniffing protection,
no-referrer policy and a content policy restricting scripts, styles and API
connections to the same origin while denying embedding. API data is inserted
with `textContent`, never interpreted as HTML. Tokens appear only in outbound
authorization headers. Error text is bounded and excludes transport diagnostics.

## Qualification

This completes a development client workspace against implemented contracts.
It does not implement the complete commercial portal in the blueprint.
Issuer login/refresh integration, independent HTTPS access installation,
commercial plans/billing, tenant notifications, ownership transfer/export,
destructive offboarding, audit/team administration screens and production
browser/estate qualification remain open. Neither this UI nor a successful
readback changes `BUILD_READY`, `RUNTIME_QUALIFIED`, `PRODUCTION_QUALIFIED` or
owner acceptance.

Run `python3 -m unittest tests.test_portal -v` and
`node --test tests/test_portal_client.mjs`. CI also runs
`node tests/portal_browser.mjs` with a pinned Playwright installation against
intercepted API contracts, including mobile layout and actual form submissions.
These cover asset/browser boundaries,
request origins, token handling, stale-session rejection, bounded readback,
401 handling, role affordances and tenant/application-scoped retry keys.
