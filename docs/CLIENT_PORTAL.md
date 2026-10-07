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
- Read tenant audit history in pages of up to 100 committed events. The API
  checks hash integrity; the client additionally checks ascending IDs, page
  cursor progression and predecessor continuity. Browser-unsafe integer cursors
  are refused rather than rounded. The operator CLI remains available for the
  full signed-64-bit cursor range. This readback does not replace off-host audit
  anchors or independently signed recovery evidence.
- Owners can list team members, create/revoke one-time invitations, remove an
  admin or viewer, and create/revoke application-bound machine release grants.
  Owner removal and ownership transfer are excluded. Invitations have no email
  delivery; the owner shares the one-time capability through a verified private
  channel. An authenticated user can accept an invitation even before they have
  any organization membership.
- Owners and admins can queue a new deployment of an eligible previous release.
  The rollback route repeats the existing admission and placement checks. An
  explicit new-release request rotates that route's retry key when redeploying
  the same specification is intentional.

Release and resource requests keep the same idempotency key for the same
application, route and specification throughout the connected session, including
after a transport failure. A changed specification gets another key. Keys clear
on disconnect/page exit. After a network interruption, refresh readback before
resubmitting project, application or domain creation: those existing API routes
do not accept idempotency keys. The portal never automatically retries writes.
Invitation creation also retains its retry key. Starting a new invitation request
deliberately creates a different key; it does not revoke earlier invitations.
If the first response is lost, a matching retry returns metadata without a token.
Revoke that invitation and start another to obtain a new usable capability.
Machine grant creation has no idempotency key; inspect its readback after a
transport interruption before trying another creation.

## Browser boundaries

Only four exact asset paths are served. Unknown paths cannot access files from
the package. Assets have `Cache-Control: no-store`, MIME sniffing protection,
no-referrer policy and a content policy restricting scripts, styles and API
connections to the same origin while denying embedding. API data is inserted
with `textContent`, never interpreted as HTML. Tokens appear only in outbound
authorization headers. Error text is bounded and excludes transport diagnostics.
Invitation capabilities are shown in a separate private panel and redacted from
the generic receipt. Selection changes clear that panel, pending form values and
the previous selection's receipt. A role refresh that removes owner access also
clears the private invitation panel. Disconnect clears all access and audit data.
Unauthorized responses end the session even when their body is malformed or
body cancellation stalls; stream errors never expose transport diagnostics.

## Qualification

This completes a development client workspace against implemented contracts.
It does not implement the complete commercial portal in the blueprint.
Issuer login/refresh integration, independent HTTPS access installation,
commercial plans/billing, tenant notifications, ownership transfer/export,
destructive offboarding, MFA/step-up and production
browser/estate qualification remain open. Neither this UI nor a successful
readback changes `BUILD_READY`, `RUNTIME_QUALIFIED`, `PRODUCTION_QUALIFIED` or
owner acceptance.

Run `python3 -m unittest tests.test_portal -v` and
`node --test tests/test_portal_client.mjs`. CI also runs
`node tests/portal_browser.mjs` with a pinned Playwright installation against
intercepted API contracts, including mobile layout and actual form submissions.
These cover asset/browser boundaries,
request origins, token handling, stale-session rejection, bounded readback,
401 handling, role affordances, tenant/application-scoped retry keys, audit
pagination, private invitation handling, membership/grant operations and rollback.
