# Reversible application traffic suspension

The organization owner can request suspension with `POST
/v1/organizations/{org}/applications/{app}/traffic` and a JSON body such as
`{"action":"suspend","reason":"Abuse investigation 123","confirm":"suspend_application"}`.
The API returns `SUSPENDING` (202). Poll `GET .../traffic` until the state is
`SUSPENDED`; only then has the worker received a node route-removal receipt.
The worker retries a failed route operation and exposes its error category in
`traffic_last_error`. An application without an active release reaches
`SUSPENDED` without a node operation. Existing containers, database resources,
backups and capacity reservations are retained. New releases and rollbacks are
blocked during suspension; outstanding releases must finish before suspension
can be requested.

To resume, the owner sends `{"action":"resume","reason":"Review complete",
"confirm":"resume_application"}`. The worker rechecks domain TXT ownership,
the registered public IP and the HTTPS release receipt before committing
`ACTIVE`. Failed proof leaves the route removed and the state `RESUMING` for
retry. An owner may inspect the persistent, append-only request reasons in
`hosting.application_traffic_events`; both intent and completed transitions
are recorded in the audit chain. A 202 response is an accepted intent, not a
claim that traffic already changed.

This traffic control covers the application ingress route only. It does not
stop a running container, revoke its secrets or outbound network access, or
quarantine a node. The broader abuse policy and automated detection remain
unqualified; operators must handle those separately before commercial use.
