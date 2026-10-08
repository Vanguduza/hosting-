#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the managed PostgreSQL node' >&2
  exit 1
fi
for command in restic docker python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
config=/etc/dial-hosting/postgres-wal.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only managed WAL configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/backup/wal-evidence
install -d -o root -g root -m 0755 /opt/dial-hosting
for tool in postgres_wal.py control_wal.py postgres_physical_backup.py postgres_backup.py \
            control_physical_backup.py control_backup.py; do
  install -o root -g root -m 0755 "$repo_root/tools/$tool" "/opt/dial-hosting/$tool"
done
for unit in dial-postgres-wal@.service dial-postgres-wal-reconcile.service \
            dial-postgres-wal-reconcile.timer dial-postgres-wal-archive.service \
            dial-postgres-wal-archive.timer dial-postgres-wal-health.service \
            dial-postgres-wal-health.timer dial-postgres-wal-switch.service \
            dial-postgres-wal-switch.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-postgres-wal-reconcile.timer dial-postgres-wal-archive.timer \
  dial-postgres-wal-health.timer dial-postgres-wal-switch.timer
systemctl start dial-postgres-wal-reconcile.service
systemctl --no-pager list-timers dial-postgres-wal-reconcile.timer dial-postgres-wal-archive.timer \
  dial-postgres-wal-health.timer dial-postgres-wal-switch.timer
