#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on a qualified Valkey runtime node' >&2
  exit 1
fi
for command in docker restic python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling Valkey backups" >&2
    exit 1
  fi
done
config=/etc/dial-hosting/valkey-backup.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only Valkey backup configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/valkey-backup/evidence
install -d -o root -g root -m 0700 /var/lib/dial-hosting/valkey-backup/tmp
install -d -o root -g root -m 0700 /etc/dial-hosting/valkey-probes
install -d -o root -g root -m 0755 /opt/dial-hosting/node-agent/node_agent
install -o root -g root -m 0644 "$repo_root"/agents/node-agent/node_agent/*.py /opt/dial-hosting/node-agent/node_agent/
install -o root -g root -m 0755 "$repo_root/tools/postgres_backup.py" /opt/dial-hosting/postgres_backup.py
install -o root -g root -m 0755 "$repo_root/tools/storage_backup.py" /opt/dial-hosting/storage_backup.py
install -o root -g root -m 0755 "$repo_root/tools/valkey_backup.py" /opt/dial-hosting/valkey_backup.py
install -o root -g root -m 0755 "$repo_root/tools/backup_health.py" /opt/dial-hosting/backup_health.py
install -o root -g root -m 0644 "$script_dir/dial-valkey-backup.service" /etc/systemd/system/
install -o root -g root -m 0644 "$script_dir/dial-valkey-backup.timer" /etc/systemd/system/
install -o root -g root -m 0644 "$script_dir/dial-backup-health@.service" /etc/systemd/system/
install -o root -g root -m 0644 "$script_dir/dial-backup-health@.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dial-valkey-backup.timer
systemctl enable --now dial-backup-health@valkey.timer
systemctl --no-pager list-timers dial-valkey-backup.timer
