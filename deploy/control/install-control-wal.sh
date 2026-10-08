#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the qualified control backup host' >&2
  exit 1
fi
for command in restic pg_receivewal psql docker python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
config=/etc/dial-hosting/control-wal.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only WAL configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/control-wal/spool
install -d -o root -g root -m 0700 /var/lib/dial-hosting/control-wal/evidence
install -d -o root -g root -m 0755 /opt/dial-hosting
for tool in control_wal.py control_physical_backup.py control_backup.py; do
  install -o root -g root -m 0755 "$repo_root/tools/$tool" "/opt/dial-hosting/$tool"
done
for unit in dial-control-wal-stream.service dial-control-wal-archive.service \
            dial-control-wal-archive.timer dial-control-wal-health.service \
            dial-control-wal-health.timer dial-control-wal-switch.service \
            dial-control-wal-switch.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-control-wal-stream.service dial-control-wal-archive.timer \
  dial-control-wal-health.timer dial-control-wal-switch.timer
systemctl --no-pager list-timers dial-control-wal-archive.timer dial-control-wal-health.timer \
  dial-control-wal-switch.timer
