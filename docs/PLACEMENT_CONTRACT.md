# Placement contract

No service is silently assigned to Netcup, Oracle A1, a VEKL micro VM or the recovery VM.

Every placement decision must record `node_id`, `failure_domain`, `isolation_class`, `cpu_limit`, `memory_limit`, `disk_limit`, `disk_iops_budget`, `backup_target`, `restore_target`, `network_policy`, `reserved_capacity` and `evidence_at`. The scheduler must deny admission when measured free capacity minus reservations cannot contain peak demand. A restore target may never share the only copy of the backup it is intended to recover.

Oracle `oracle-admin` is recovery-only. Oracle A1 reserves VAN priority. Netcup's initial 8 GB does not imply room for every stateful control component. Dedicated client VMs and managed Supabase projects are placed only after a measured qualification run, with separate data and application IAM.

The placement decision remains open by owner request; no runtime topology is claimed or provisioned here.
