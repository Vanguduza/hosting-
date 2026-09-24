#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on a qualified Garage storage node' >&2
  exit 1
fi
for command in docker restic python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling storage backups" >&2
    exit 1
  fi
done
config=/etc/dial-hosting/storage-backup.env
if [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ]; then
  echo 'Provide owner-only Garage backup configuration first' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0700 /var/lib/dial-hosting/storage-backup/evidence
install -d -o root -g root -m 0700 /var/lib/dial-hosting/storage-backup/tmp
install -d -o root -g root -m 0700 /etc/dial-hosting/storage-probes
install -d -o root -g root -m 0755 /opt/dial-hosting
install -d -o root -g root -m 0755 /opt/dial-hosting/node-agent/node_agent
install -o root -g root -m 0644 "$repo_root"/agents/node-agent/node_agent/*.py /opt/dial-hosting/node-agent/node_agent/
python3 -m venv /opt/dial-hosting/storage-backup
/opt/dial-hosting/storage-backup/bin/python -m pip install --disable-pip-version-check 'boto3==1.43.101'
install -o root -g root -m 0755 "$repo_root/tools/storage_backup.py" /opt/dial-hosting/storage_backup.py
install -o root -g root -m 0755 "$repo_root/tools/postgres_backup.py" /opt/dial-hosting/postgres_backup.py
install -o root -g root -m 0644 "$script_dir/dial-storage-backup.service" /etc/systemd/system/
install -o root -g root -m 0644 "$script_dir/dial-storage-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dial-storage-backup.timer
systemctl --no-pager list-timers dial-storage-backup.timer
