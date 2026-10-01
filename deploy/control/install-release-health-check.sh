#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the supervised release health monitor' >&2
  exit 1
fi
for command in python3 systemctl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Install $command before enabling release health monitoring" >&2
    exit 1
  fi
done
config=/etc/dial-hosting/release-health-check.env
if [ -L "$config" ] || [ ! -f "$config" ] || [ "$(stat -c %a "$config")" != 600 ] || \
   [ "$(stat -c %u "$config")" != 0 ]; then
  echo 'Provide root-owned mode-0600 release health configuration first' >&2
  exit 1
fi
alert_config=/etc/dial-hosting/monitor-alert.env
if [ -L "$alert_config" ] || [ ! -f "$alert_config" ] || \
   [ "$(stat -c %a "$alert_config")" != 600 ] || [ "$(stat -c %u "$alert_config")" != 0 ]; then
  echo 'Provide root-owned mode-0600 monitor alert configuration first' >&2
  exit 1
fi
if ! grep -Eq '^ALERT_RECEIVER_URL=https://[^[:space:]]+' "$alert_config" || \
   ! grep -Eq '^ALERT_SIGNING_KEY_FILE=/[^[:space:]]+' "$alert_config"; then
  echo 'Configure an HTTPS alert receiver and absolute signing key file' >&2
  exit 1
fi
alert_key=$(sed -n 's/^ALERT_SIGNING_KEY_FILE=//p' "$alert_config")
if [ -L "$alert_key" ] || [ ! -f "$alert_key" ] || \
   [ "$(stat -c %a "$alert_key")" != 600 ] || [ "$(stat -c %u "$alert_key")" != 0 ] || \
   [ "$(stat -c %s "$alert_key")" -lt 32 ] || [ "$(stat -c %s "$alert_key")" -gt 4096 ]; then
  echo 'Provide a root-owned private 32-4096 byte alert signing key' >&2
  exit 1
fi
for variable in MIN_ACTIVE_APPLICATIONS MAX_AGE_SECONDS MIN_ENABLED_NODES NODE_MAX_AGE_SECONDS \
                EVENT_MAX_AGE_SECONDS EVENT_MAX_PENDING; do
  if ! grep -Eq "^$variable=[0-9]+$" "$config"; then
    echo "Set numeric $variable before enabling health timers" >&2
    exit 1
  fi
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
target=/opt/dial-hosting/release-health-check
install -d -o root -g root -m 0755 "$target/tools" "$target/services/api/hosting_api" "$target/services/api/schema"
python3 -m venv "$target/venv"
"$target/venv/bin/python" -m pip install --disable-pip-version-check \
  --requirement "$repo_root/services/api/requirements.txt"
install -o root -g root -m 0755 "$repo_root/tools/release_health_check.py" "$target/tools/"
install -o root -g root -m 0755 "$repo_root/tools/node_health_check.py" "$target/tools/"
install -o root -g root -m 0755 "$repo_root/tools/event_health.py" "$target/tools/"
install -o root -g root -m 0755 "$repo_root/tools/external_public_health.py" "$target/tools/"
install -o root -g root -m 0755 "$repo_root/tools/operator_alerts.py" "$target/tools/"
for source in "$repo_root"/services/api/hosting_api/*.py; do
  install -o root -g root -m 0644 "$source" "$target/services/api/hosting_api/"
done
for source in "$repo_root"/services/api/schema/*.sql; do
  install -o root -g root -m 0644 "$source" "$target/services/api/schema/"
done
for unit in dial-release-health-check.service dial-release-health-check.timer \
            dial-node-health-check.service dial-node-health-check.timer \
            dial-event-outbox-health.service dial-event-outbox-health.timer \
            dial-external-public-health.service dial-external-public-health.timer \
            dial-operator-alert-dispatch.service dial-operator-alert-dispatch.timer \
            dial-operator-alert-health.service dial-operator-alert-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-release-health-check.timer dial-node-health-check.timer \
  dial-event-outbox-health.timer
systemctl enable --now dial-external-public-health.timer dial-operator-alert-dispatch.timer \
  dial-operator-alert-health.timer
systemctl --no-pager list-timers dial-release-health-check.timer dial-node-health-check.timer \
  dial-event-outbox-health.timer dial-external-public-health.timer \
  dial-operator-alert-dispatch.timer dial-operator-alert-health.timer
