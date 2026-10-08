#!/bin/sh
# Install on the selected public ingress node after installing the node agent.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root on the selected ingress node' >&2
  exit 1
fi
if [ -z "${DIAL_ACME_EMAIL:-}" ] || [ -z "${DIAL_INGRESS_IMAGE:-}" ]; then
  echo 'Set DIAL_ACME_EMAIL and digest-pinned DIAL_INGRESS_IMAGE' >&2
  exit 1
fi
case "$DIAL_INGRESS_IMAGE" in
  *@sha256:*) ;;
  *) echo 'Ingress image must be immutable digest-pinned' >&2; exit 1 ;;
esac
if [ ! -f /var/lib/dial-hosting/node-agent/state.sqlite3 ]; then
  echo 'Install the node agent first' >&2
  exit 1
fi
install -d -o dial-node -g dial-node -m 0700 /var/lib/dial-hosting/node-agent/routes
install -d -o root -g root -m 0700 /var/lib/dial-hosting/ingress
if [ ! -e /var/lib/dial-hosting/ingress/acme.json ]; then
  install -o root -g root -m 0600 /dev/null /var/lib/dial-hosting/ingress/acme.json
fi
docker network inspect dial-runtime >/dev/null 2>&1 || docker network create --driver bridge dial-runtime >/dev/null
if docker container inspect dial-ingress >/dev/null 2>&1; then
  echo 'Existing ingress requires explicit operator replacement; preserving certificates' >&2
  exit 1
fi
docker pull "$DIAL_INGRESS_IMAGE"
docker run -d --name dial-ingress --restart unless-stopped --network dial-runtime \
  --read-only --security-opt no-new-privileges --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --pids-limit 256 --memory 512m --cpus 1 --tmpfs /tmp:rw,nosuid,noexec,size=32m \
  -p 80:80 -p 443:443 \
  -v /var/lib/dial-hosting/node-agent/routes:/etc/traefik/dynamic:ro \
  -v /var/lib/dial-hosting/ingress:/data \
  "$DIAL_INGRESS_IMAGE" \
  --api=false --providers.docker=false \
  --providers.file.directory=/etc/traefik/dynamic --providers.file.watch=true \
  --entrypoints.web.address=:80 --entrypoints.websecure.address=:443 \
  --entrypoints.web.http.redirections.entrypoint.to=websecure \
  --certificatesresolvers.acme.acme.email="$DIAL_ACME_EMAIL" \
  --certificatesresolvers.acme.acme.storage=/data/acme.json \
  --certificatesresolvers.acme.acme.httpchallenge.entrypoint=web
