#!/usr/bin/env bash
# Disposable GitHub Actions profile: proves fresh startup and upgrade refusal.
set -Eeuo pipefail
if [[ "${CI:-}" != "true" || -e deploy/control/.secrets ]]; then
  echo 'This test requires a clean CI checkout' >&2
  exit 1
fi

export OIDC_ISSUER=https://issuer.example.org
export OIDC_AUDIENCE=dial-hosting-ci
export OIDC_SERVICE_AUDIENCE=dial-hosting-service-ci
export OIDC_JWKS_URL=https://issuer.example.org/jwks
export COMPOSE_PROJECT_NAME="dial-hosting-ci-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
secrets=deploy/control/.secrets
mkdir -m 700 "$secrets"
for name in pg_admin pg_api pg_worker pg_admitter pg_hook pg_buildworker github_webhook; do
  openssl rand -hex 32 > "$secrets/$name"
  # Compose bind-mounts local files without remapping uid/mode. The host
  # directory is private; each container receives only its assigned files.
  chmod 644 "$secrets/$name"
done
compose=(docker compose -f deploy/control/compose.yaml)
cleanup() {
  "${compose[@]}" down --volumes --remove-orphans || true
  rm -rf -- "$secrets"
}
trap cleanup EXIT
trap '"${compose[@]}" logs --no-color --tail=80 db migrate api github-webhook || true' ERR

"${compose[@]}" up --build -d db migrate api github-webhook
for i in {1..30}; do
  if curl --fail --silent http://127.0.0.1:8080/live >/dev/null; then break; fi
  sleep 2
done
curl --fail --silent http://127.0.0.1:8080/live >/dev/null
test "$("${compose[@]}" exec -T db psql -U postgres -d hosting -At \
  -c 'SELECT count(*) FROM hosting.schema_migrations')" = 19
"${compose[@]}" exec -T db psql -U postgres -d hosting -v ON_ERROR_STOP=1 \
  -c "UPDATE hosting.schema_migrations SET sha256=repeat('0',64) WHERE version=19" >/dev/null

# A formerly successful migration container must not let a restarted API serve
# against drifted history. Force a new service container without touching data.
"${compose[@]}" stop api github-webhook
"${compose[@]}" up -d --no-deps --force-recreate api github-webhook
for i in {1..30}; do
  api_id="$("${compose[@]}" ps -a -q api)"
  hook_id="$("${compose[@]}" ps -a -q github-webhook)"
  if [[ -n "$api_id" && -n "$hook_id" ]] &&
    [[ "$(docker inspect --format '{{.RestartCount}}' "$api_id")" -ge 1 ]] &&
    [[ "$(docker inspect --format '{{.RestartCount}}' "$hook_id")" -ge 1 ]]; then break; fi
  sleep 2
done
[[ "$(docker inspect --format '{{.RestartCount}}' "$api_id")" -ge 1 ]]
[[ "$(docker inspect --format '{{.RestartCount}}' "$hook_id")" -ge 1 ]]
if curl --fail --silent --max-time 2 http://127.0.0.1:8080/live >/dev/null; then
  echo 'API served requests with drifted control schema' >&2
  exit 1
fi
if "${compose[@]}" run --rm migrate; then
  echo 'Migrator accepted a modified applied migration' >&2
  exit 1
fi
echo 'Fresh Compose startup and drift refusal: PASS'
