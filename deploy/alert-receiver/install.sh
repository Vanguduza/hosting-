#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run on the isolated alert receiver as root' >&2
  exit 1
fi
for command in python3 systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
python3 - "$repo_root/services" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from alert_receiver import config_file
config_file('/etc/dial-alert-receiver/config.json')
PY
install -d -o root -g root -m 0755 /opt/dial-hosting/alert-receiver
install -o root -g root -m 0644 "$repo_root/services/alert_receiver.py" \
  /opt/dial-hosting/alert-receiver/alert_receiver.py
for unit in dial-alert-receiver.service dial-alert-mail.service dial-alert-mail.timer \
            dial-alert-receiver-health.service dial-alert-receiver-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-alert-receiver.service dial-alert-mail.timer \
  dial-alert-receiver-health.timer
systemctl --no-pager status dial-alert-receiver.service
