#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the selected private runtime node' >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! getent group docker >/dev/null; then
  echo 'Docker Engine and its group must be installed and qualified first' >&2
  exit 1
fi
if [ ! -f /etc/dial-hosting/node-agent.env ]; then
  echo 'Supply root-only /etc/dial-hosting/node-agent.env and mTLS certificates first' >&2
  exit 1
fi
if [ "$(stat -c %a /etc/dial-hosting/node-agent.env)" != 600 ]; then
  echo 'node-agent.env must be mode 0600' >&2
  exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
if ! id dial-node >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/dial-hosting/node-agent --shell /usr/sbin/nologin --groups docker dial-node
else
  usermod -aG docker dial-node
fi
install -d -o dial-node -g dial-node -m 0700 /var/lib/dial-hosting/node-agent
install -d -o root -g root -m 0755 /opt/dial-hosting/node-agent
cp -R "$repo_root/agents/node-agent/node_agent" /opt/dial-hosting/node-agent/
chown -R root:root /opt/dial-hosting/node-agent
find /opt/dial-hosting/node-agent -type d -exec chmod 0755 '{}' +
find /opt/dial-hosting/node-agent -type f -exec chmod 0644 '{}' +
install -o root -g root -m 0644 "$script_dir/dial-node-agent.service" /etc/systemd/system/dial-node-agent.service
systemctl daemon-reload
systemctl enable --now dial-node-agent.service
systemctl --no-pager --full status dial-node-agent.service
