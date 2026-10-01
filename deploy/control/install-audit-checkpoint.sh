#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the qualified audit checkpoint publisher' >&2
  exit 1
fi
for command in python3 restic systemctl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling audit checkpoints" >&2
    exit 1
  fi
done
for config in /etc/dial-hosting/audit-checkpoint.env /etc/dial-hosting/audit-checkpoint.json; do
  if [ -L "$config" ] || [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ] || \
     [ "$(stat -c %u "$config")" != 0 ]; then
    echo 'Provide root-owned mode-0600 audit configuration first' >&2
    exit 1
  fi
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
target=/opt/dial-hosting/audit-checkpoint
install -d -o root -g root -m 0755 "$target/tools" "$target/services/api/hosting_api" "$target/services/api/schema"
install -d -o root -g root -m 0700 /var/cache/dial-hosting/audit-checkpoint
python3 -m venv "$target/venv"
"$target/venv/bin/python" -m pip install --disable-pip-version-check \
  --requirement "$repo_root/services/api/requirements.txt"
for tool in audit_checkpoint.py recovery_catalog.py backup_health.py; do
  install -o root -g root -m 0755 "$repo_root/tools/$tool" "$target/tools/$tool"
done
for source in "$repo_root"/services/api/hosting_api/*.py; do
  install -o root -g root -m 0644 "$source" "$target/services/api/hosting_api/"
done
for source in "$repo_root"/services/api/schema/*.sql; do
  install -o root -g root -m 0644 "$source" "$target/services/api/schema/"
done
for unit in dial-audit-checkpoint.service dial-audit-checkpoint.timer \
            dial-audit-checkpoint-health.service dial-audit-checkpoint-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-audit-checkpoint.timer dial-audit-checkpoint-health.timer
systemctl --no-pager list-timers dial-audit-checkpoint.timer dial-audit-checkpoint-health.timer
