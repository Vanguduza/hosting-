#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the qualified OpenBao backup operator host' >&2
  exit 1
fi
for command in restic python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling OpenBao backups" >&2
    exit 1
  fi
done
config=/etc/dial-hosting/openbao-backup.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only OpenBao backup configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/openbao-backup/evidence
install -d -o root -g root -m 0755 /opt/dial-hosting
install -o root -g root -m 0755 "$repo_root/tools/openbao_backup.py" /opt/dial-hosting/openbao_backup.py
for unit in dial-openbao-backup.service dial-openbao-backup.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-openbao-backup.timer
systemctl --no-pager list-timers dial-openbao-backup.timer
