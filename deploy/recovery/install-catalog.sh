#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the backup operator host' >&2
  exit 1
fi
for command in python3 restic flock; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling the recovery catalog" >&2
    exit 1
  fi
done
for config in /etc/dial-hosting/recovery-catalog.json /etc/dial-hosting/recovery-catalog.env; do
  if [ ! -f "$config" ] || [ -L "$config" ] || [ "$(stat -c %u:%a "$config")" != 0:600 ]; then
    echo "Provide a root-owned, mode-0600 regular file: $config" >&2
    exit 1
  fi
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0755 /opt/dial-hosting
install -d -o root -g root -m 0700 /var/lib/dial-hosting/recovery-catalog
install -o root -g root -m 0755 "$repo_root/tools/backup_health.py" /opt/dial-hosting/backup_health.py
install -o root -g root -m 0755 "$repo_root/tools/recovery_catalog.py" /opt/dial-hosting/recovery_catalog.py
python3 /opt/dial-hosting/recovery_catalog.py /etc/dial-hosting/recovery-catalog.json validate
for unit in dial-recovery-catalog.service dial-recovery-catalog.timer \
            dial-recovery-catalog-health.service dial-recovery-catalog-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-recovery-catalog.timer dial-recovery-catalog-health.timer
systemctl --no-pager list-timers dial-recovery-catalog.timer dial-recovery-catalog-health.timer
