#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on a qualified PostgreSQL runtime node' >&2
  exit 1
fi
if ! command -v restic >/dev/null 2>&1 || ! command -v docker >/dev/null 2>&1; then
  echo 'Install Docker Engine and Restic before enabling client backups' >&2
  exit 1
fi
config=/etc/dial-hosting/postgres-backup.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only PostgreSQL backup configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/backup
install -d -o root -g root -m 0700 /var/lib/dial-hosting/backup/tmp
install -d -o root -g root -m 0755 /opt/dial-hosting
install -o root -g root -m 0755 "$repo_root/tools/postgres_backup.py" /opt/dial-hosting/postgres_backup.py
install -o root -g root -m 0644 "$script_dir/dial-postgres-backup.service" /etc/systemd/system/
install -o root -g root -m 0644 "$script_dir/dial-postgres-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dial-postgres-backup.timer
systemctl --no-pager list-timers dial-postgres-backup.timer
