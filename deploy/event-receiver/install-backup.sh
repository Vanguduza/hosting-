#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run on the event receiver as root' >&2
  exit 1
fi
for command in python3 restic systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
environment=/etc/dial-event-receiver/restic.env
if [ -L "$environment" ] || [ ! -f "$environment" ] || \
   [ "$(stat -c %a "$environment")" != 600 ] || [ "$(stat -c %u "$environment")" != 0 ]; then
  echo 'Provide root-owned mode-0600 Restic backend environment first' >&2
  exit 1
fi
install -d -o root -g root -m 0700 /var/lib/dial-event-receiver/evidence \
  /var/lib/dial-event-receiver/tmp
python3 - "$repo_root/tools" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from alert_receiver_backup import configuration
config = configuration('/etc/dial-event-receiver/backup.json')
if config['kind'] != 'event':
    raise RuntimeError('Event recovery profile required')
PY
install -o root -g root -m 0644 "$repo_root/tools/alert_receiver_backup.py" \
  /opt/dial-hosting/event-receiver/alert_receiver_backup.py
for unit in dial-event-backup.service dial-event-backup.timer \
            dial-event-backup-health.service dial-event-backup-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-event-backup.timer dial-event-backup-health.timer
systemctl --no-pager list-timers dial-event-backup.timer dial-event-backup-health.timer
