#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run on the alert receiver as root' >&2
  exit 1
fi
for command in python3 restic systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
config=/etc/dial-alert-receiver/backup.json
environment=/etc/dial-alert-receiver/restic.env
if [ -L "$environment" ] || [ ! -f "$environment" ] || \
   [ "$(stat -c %a "$environment")" != 600 ] || [ "$(stat -c %u "$environment")" != 0 ]; then
  echo 'Provide root-owned mode-0600 Restic backend environment first' >&2
  exit 1
fi
install -d -o root -g root -m 0700 /var/lib/dial-alert-receiver/evidence \
  /var/lib/dial-alert-receiver/tmp
python3 - "$repo_root/tools" "$config" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from alert_receiver_backup import configuration
configuration(sys.argv[2])
PY
install -o root -g root -m 0644 "$repo_root/tools/alert_receiver_backup.py" \
  /opt/dial-hosting/alert-receiver/alert_receiver_backup.py
for unit in dial-alert-backup.service dial-alert-backup.timer \
            dial-alert-backup-health.service dial-alert-backup-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-alert-backup.timer dial-alert-backup-health.timer
systemctl --no-pager list-timers dial-alert-backup.timer dial-alert-backup-health.timer
