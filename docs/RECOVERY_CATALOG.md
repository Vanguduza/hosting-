# Encrypted disaster recovery catalog

`tools/recovery_catalog.py` runs on each backup operator host. It compares the required node resource UUIDs to the **actual labeled Docker containers and volumes**, checks the newest owner-only restore receipts and their freshness, confirms each full snapshot ID and resource tag in its configured encrypted Restic repository, and publishes a small catalog into a **separate encrypted off-host Restic repository**. It then restores that catalog from Restic and checks its entries against the source repositories. A failed step prevents `CATALOG_PUBLISHED`. The hourly `inspect-latest` path can also run on an independent recovery host with the same configuration and repository access, without the original Docker daemon or receipt files.

This is a recovery **index**, not a substitute for any individual backup or restore. Each source receipt must already say `RESTORE_VERIFIED`. The catalog records the named intended recovery failure domain, but only a real restore to that domain proves it. The backup encryption passwords, repository credentials, OpenBao unseal material, database credentials, canary definitions and container images must be available separately for recovery. Retain the catalog snapshot and referenced data snapshots together; a Restic retention job that removes either causes the health check to fail.

## Configure one source host

Install the relevant backup timers first. Create and initialize a different remote Restic repository for the catalog, and provision its owner-only password file. Create `/etc/dial-hosting/recovery-catalog.json`, root-owned mode 0600, with entries for every backup class located on this host. Example for a control host (replace paths, remote endpoints and failure domains):

```json
{
  "version": 1,
  "catalog_id": "control-one",
  "host_id": "control-host-one",
  "failure_domain": "primary-dc",
  "recovery_failure_domain": "recovery-dc",
  "catalog_repository": "sftp:catalog-backup:/encrypted/control-catalog",
  "catalog_password_file": "/etc/dial-hosting/catalog-restic-password",
  "classes": [
    {"kind": "control", "evidence_dir": "/var/lib/dial-hosting/control-backup/evidence",
     "repository": "sftp:db-backup:/encrypted/control-logical",
     "password_file": "/etc/dial-hosting/control-restic-password",
     "max_age_hours": 36, "required_instances": []},
    {"kind": "control-physical", "evidence_dir": "/var/lib/dial-hosting/control-physical-backup/control-physical-evidence",
     "repository": "sftp:db-backup:/encrypted/control-physical",
     "password_file": "/etc/dial-hosting/control-physical-restic-password",
     "max_age_hours": 36, "required_instances": []}
  ]
}
```

Valid kinds are `control`, `control-physical`, `openbao`, `postgres`, `postgres-physical`, `valkey` and `storage`. A node class must list **every expected instance UUID** in `required_instances`, including stopped containers. Update that list as part of provisioning or decommissioning; an omitted live instance or a missing required instance makes publication fail. An authority class uses `[]`. A host with no resources of a particular kind omits that class. Use one catalog ID and configuration per source host; run it independently on each backup operator host. The catalog does not merge or certify estate-wide coverage across hosts.

Set backend credential variables in root-owned mode-0600 `/etc/dial-hosting/recovery-catalog.env` using `deploy/recovery/recovery-catalog.env.example`. Restic password files are separate regular mode-0600 files owned by the operator. Run `sh deploy/recovery/install-catalog.sh` as root on the operator host. Its daily timer publishes after the ordinary overnight backup window; its hourly timer checks the latest off-host catalog and every referenced source snapshot. Review failed systemd units and the `CATALOG_PUBLISHED`/`CATALOG_INSPECTED` records. Freshness remains bounded by each class's `max_age_hours`; an older catalog cannot turn stale data green.

For a recovery-host inspection, install `backup_health.py` and `recovery_catalog.py`, copy the protected JSON configuration and Restic access credentials, then run:

```sh
python3 tools/recovery_catalog.py /etc/dial-hosting/recovery-catalog.json inspect-latest
python3 tools/recovery_catalog.py /etc/dial-hosting/recovery-catalog.json inspect FULL_64_CHARACTER_CATALOG_SNAPSHOT_ID
```

On the recovery host the `evidence_dir` paths can be absent; inspection uses the encrypted catalog and checks the source repositories directly. The output identifies each backup class, resource UUID, full Restic snapshot ID and receipt/archive SHA256 for the relevant restore tool. Use those exact snapshot IDs with the corresponding runbook, on the isolated restore target. This check proves remote availability and provenance tags; it does not download and revalidate every referenced archive on each hourly run. The existing isolated restore drills verify the archives at creation time.

The repository restriction rejects local paths by default. `--allow-local-repositories` exists for disposable CI only; it cannot establish off-host disaster recovery. A failure domain name in JSON is an operator declaration and must be confirmed against real placement. `sftp:` URLs and other repository identifiers may include sensitive location information, so the catalog stores only a SHA256 of each source repository string. Credentials never appear in the published catalog.
