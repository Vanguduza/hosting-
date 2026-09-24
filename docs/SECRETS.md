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
An Integrated Storage Raft deployment can use `tools/openbao_backup.py` for
TLS-verified snapshots to an encrypted off-host Restic repository. Configure
the owner-only files in `deploy/control/openbao-backup.env.example`. The backup
token needs `read` on `sys/health`, `dial/data/resources/<probe UUID>` and
`sys/storage/raft/snapshot`; provision the KV v2 canary under that resource
path and put its canonical JSON SHA256 in the protected probe file, for example
`{"path":"dial/data/resources/<UUID>","sha256":"<64 lowercase hex>"}`.
Install the daily snapshot timer with `deploy/control/install-openbao-backup.sh`.
An operator restores a snapshot to a **separate initialized, unsealed disposable
Raft authority** with distinct TLS origin and cluster ID. Create a disposable
identity entity named `dial-disposable-restore` whose metadata has a fresh
unpredictable `nonce` of at least 32 characters. Run
`openbao_backup.py restore-to-disposable <full snapshot ID> --target <https origin>
--target-ca <owner-only CA file> --target-token-file <owner-only disposable root token file>
--marker <nonce>`. This overwrites the disposable authority using the Raft
`snapshot-force` endpoint, because its new seal keys differ from the source.
Unseal the disposable authority with the **original source's** separately held
unseal material, then run `openbao_backup.py confirm <full snapshot ID>
--target <https origin> --target-ca <owner-only CA file>`. Confirm reads the
restored canary at the snapshotted KV revision with the source token and only
then records `RESTORE_VERIFIED`. Rotate/delete the disposable credentials and
destroy this test authority after the drill. The Restic password, repository
access, original unseal material, TLS configuration and plugins need separate
protected recovery copies; this workflow does not store unseal keys. The
production cluster still requires operator-controlled initialization/unseal,
TLS identity, audit device, restricted network, HA and a tested cross-host
recovery drill. Node-local copies must be included
in host compromise and credential-rotation procedures. The disposable CI
OpenBao dev server is isolated to CI and is never a deployment profile.
