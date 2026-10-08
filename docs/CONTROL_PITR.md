# Control PostgreSQL WAL archive and point-in-time recovery

`tools/control_wal.py` runs a dedicated `pg_receivewal --synchronous` stream using the `dial_control_wal` physical replication slot. Completed, immutable segments are encrypted to an independently configured off-host Restic repository. Each segment gets an owner-only receipt only after an isolated restore matches its SHA-256; a changed local segment or missing remote snapshot fails closed. The latest completed local segment is kept for stream resumption. The stream uses a protected PostgreSQL replication credential, not the control API role. The slot must be provisioned before taking a new physical base backup. Monitor both the slot and the disk used by `pg_wal` and the receiver spool; a stalled receiver can retain WAL on the primary.

On the selected backup host, install PostgreSQL 17 client utilities, Restic and Docker. Initialize an encrypted off-host Restic repository, configure protected PostgreSQL replication access, then create `/etc/dial-hosting/control-wal.env` from `deploy/control/control-wal.env.example` as root mode 0600. The spool and evidence directories must be local protected directories. Run `sh deploy/control/install-control-wal.sh` to install the persistent receiver, minute upload, five-minute health check and hourly segment switch. An alarm handler must supervise failed services and disk capacity from another failure domain. Do not reuse the control database server's local disk as the only repository.

The hourly switch bounds the time a low-traffic WAL segment stays only in the receiver spool; the minute upload runs after a segment closes. These are scheduling bounds, not a guaranteed one-hour disaster RPO: replication or off-host outages increase lag and require alerting. A committed transaction still in the current partial segment has no verified off-host receipt. Operators must measure actual end-to-end lag and capacity before selecting a production RPO or retention period.

After a verified physical base snapshot, the protected receipt records the PostgreSQL system identifier. For a recovery drill, provide the base receipt directory, WAL receipts, encrypted Restic access, and a JSON file of a read-only SQL probe and exact expected result. The source PostgreSQL server and WAL spool are not needed for the restore. Set `CONTROL_WAL_SYSTEM_ID` to the base receipt's `system_id`, and invoke:

```bash
python3 tools/control_wal.py pitr \
  --base-evidence /private/control-physical-evidence \
  --base-snapshot FULL_RESTIC_ID \
  --target '2026-10-01T00:00:00+00:00' \
  --probe-file /private/probe.json
```

The probe file is `{"sql":"SELECT ...","expected":"exact single row"}` and must be owner-only. The operation checks the base archive digest and PostgreSQL 17 manifest, restores every WAL snapshot with matching system-identity receipts into a disposable Docker volume, starts a network-isolated database, waits for recovery to pause at the target, and runs the probe inside a read-only transaction. It writes a `PITR_VERIFIED` receipt only after all checks pass. The restore target must follow the base backup. Operator keys, repository retention, cross-host credential recovery, application-level consistency, and an actual estate drill remain qualification gates.

The disposable CI proof streams through a physical slot, snapshots real WAL and a base backup to Restic, removes the local spool, then proves that an earlier committed row is present at the selected target while a later row is absent. This is a control PostgreSQL path; managed client PostgreSQL instances require their own WAL transport and restore qualification.
