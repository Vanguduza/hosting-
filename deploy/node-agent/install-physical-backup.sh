#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the managed PostgreSQL node' >&2
  exit 1
fi
for command in restic docker python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling physical backups" >&2
    exit 1
  fi
done
config=/etc/dial-hosting/postgres-physical-backup.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only physical backup configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/backup/physical-evidence
install -d -o root -g root -m 0755 /opt/dial-hosting
install -o root -g root -m 0755 "$repo_root/tools/postgres_physical_backup.py" /opt/dial-hosting/postgres_physical_backup.py
install -o root -g root -m 0755 "$repo_root/tools/postgres_backup.py" /opt/dial-hosting/postgres_backup.py
install -o root -g root -m 0755 "$repo_root/tools/backup_health.py" /opt/dial-hosting/backup_health.py
for unit in dial-postgres-physical-backup.service dial-postgres-physical-backup.timer \
            dial-postgres-physical-backup-health.service dial-postgres-physical-backup-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-postgres-physical-backup.timer dial-postgres-physical-backup-health.timer
systemctl --no-pager list-timers dial-postgres-physical-backup.timer dial-postgres-physical-backup-health.timer
