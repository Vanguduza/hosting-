#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run on the isolated event receiver as root' >&2
  exit 1
fi
for command in python3 systemctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Install $command first" >&2; exit 1; }
done
config=/etc/dial-event-receiver/receiver.env
key=/etc/dial-event-receiver/signing-key
for file in "$config" "$key"; do
  if [ -L "$file" ] || [ ! -f "$file" ] || [ "$(stat -c %a "$file")" != 600 ] || \
     [ "$(stat -c %u "$file")" != 0 ]; then
    echo 'Provide root-owned mode-0600 event receiver configuration and key' >&2
    exit 1
  fi
done
if [ "$(stat -c %s "$key")" -lt 32 ] || [ "$(stat -c %s "$key")" -gt 4096 ] || \
   ! grep -Eq '^EVENT_RECEIVER_MIN_EVENTS=[0-9]+$' "$config"; then
  echo 'Set a valid signing key and event floor' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
install -d -o root -g root -m 0755 /opt/dial-hosting/event-receiver
install -o root -g root -m 0644 "$repo_root/services/event_receiver.py" \
  /opt/dial-hosting/event-receiver/event_receiver.py
for unit in dial-event-receiver.service dial-event-receiver-health.service \
            dial-event-receiver-health.timer; do
  install -o root -g root -m 0644 "$script_dir/$unit" /etc/systemd/system/
done
systemctl daemon-reload
systemctl enable --now dial-event-receiver.service dial-event-receiver-health.timer
systemctl --no-pager status dial-event-receiver.service
