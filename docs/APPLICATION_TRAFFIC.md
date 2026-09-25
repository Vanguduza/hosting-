# Reversible application traffic suspension

The organization owner can request suspension with
`POST /v1/organizations/{org}/applications/{app}/traffic` and a JSON body such as
`{"action":"suspend","reason":"Abuse investigation 123","confirm":"suspend_application"}`.
The API returns `SUSPENDING` (202). Poll `GET .../traffic` until the state is
`SUSPENDED`; only then has the worker received a node route-removal receipt and
verified that the labeled active application container is stopped.
The worker retries a failed route operation and exposes its error category in
`traffic_last_error`. An application without an active release reaches
`SUSPENDED` without a node operation. The stopped application container,
running managed data services, backups and capacity reservations are retained.
The worker rechecks suspended routes and container state every minute; a
failed recheck is visible in `traffic_last_error` and retried sooner.
New releases and rollbacks are blocked during suspension; outstanding releases must finish before suspension
can be requested.

To resume, the owner sends `{"action":"resume","reason":"Review complete",
"confirm":"resume_application"}`. The worker rechecks domain TXT ownership,
the registered public IP and the HTTPS release receipt before committing
`ACTIVE`. Failed proof removes the route and stops the application again;
the state remains `RESUMING` for retry. If node cleanup cannot be proven, the
error remains visible and requires operator intervention. An owner may inspect
the persistent, append-only request reasons in
`hosting.application_traffic_events`; both intent and completed transitions
are recorded in the audit chain. A 202 response is an accepted intent, not a
claim that traffic already changed.

This traffic control covers the selected application's ingress and active
container. It does not revoke stored secrets, stop managed data services,
remove a malicious image or quarantine the node. The broader abuse policy and
automated detection remain
unqualified; operators must handle those separately before commercial use.
