#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run on the operator monitor as root' >&2
  exit 1
fi
for command in python3 restic systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
environment=/etc/dial-hosting/monitor-restic.env
if [ -L "$environment" ] || [ ! -f "$environment" ] || \
   [ "$(stat -c %a "$environment")" != 600 ] || [ "$(stat -c %u "$environment")" != 0 ]; then
  echo 'Provide root-owned mode-0600 Restic backend environment first' >&2
  exit 1
fi
install -d -o root -g root -m 0700 /var/lib/dial-hosting-monitor/evidence \
  /var/lib/dial-hosting-monitor/tmp
python3 - "$repo_root/tools" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from alert_receiver_backup import configuration
config = configuration('/etc/dial-hosting/monitor-backup.json')
if config['kind'] != 'monitor':
    raise RuntimeError('Monitor recovery profile required')
PY
target=/opt/dial-hosting/release-health-check/tools
install -o root -g root -m 0644 "$repo_root/tools/alert_receiver_backup.py" \
  "$target/alert_receiver_backup.py"
for unit in dial-monitor-backup.service dial-monitor-backup.timer \
            dial-monitor-backup-health.service dial-monitor-backup-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-monitor-backup.timer dial-monitor-backup-health.timer
systemctl --no-pager list-timers dial-monitor-backup.timer dial-monitor-backup-health.timer
