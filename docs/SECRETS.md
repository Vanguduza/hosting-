# OpenBao secret authority

The control and node roles use a TLS verified OpenBao KV v2 mount named `dial`.
The operator supplies an OpenBao origin, trusted CA, and owner-only AppRole
role-ID and secret-ID files to the worker. Do not use a root token for the
runtime role. The role must have only create/read/update on
`dial/data/resources/*`; the operator provisioning role manages policies,
AppRoles, mounts and rotation separately. Enable an OpenBao audit device
before accepting production secrets.

Configure `BAO_ADDR`, `BAO_CA_FILE`, `BAO_ROLE_ID_FILE`, `BAO_SECRET_ID_FILE`,
and optionally `BAO_KV_MOUNT`. The worker authenticates for each operation,
reads an exact KV revision over TLS, and sends it to the selected node over
the existing private mTLS channel. Node receipts contain only resource ID,
revision and state. The agent stores revisioned files with mode 0600 under
`NODE_SECRETS_DIR` (0700). A changed payload under the same revision is
rejected. The HTTP API and control database must store paths and revisions,
never values.

For an operator-managed resource, write a JSON object on standard input to
`python tools/secret_control.py <resource-uuid> --cas 0`. Rotate with the
current revision as `--cas`; OpenBao rejects concurrent writers. Do not pass
secret values in command arguments or shell history. The command prints only
the resource ID and new revision.

This is the credential transport, not a deployed production OpenBao cluster.
The production cluster requires an encrypted Raft storage and off-host backup
plan, operator-controlled initialization/unseal, TLS identity, audit device,
restricted network and tested recovery. Node-local copies must be included
in host compromise and credential-rotation procedures. The disposable CI
OpenBao dev server is isolated to CI and is never a deployment profile.
