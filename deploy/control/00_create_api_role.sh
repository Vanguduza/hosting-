#!/bin/bash
set -Eeuo pipefail
api_password="$(cat /run/secrets/pg_api)"
worker_password="$(cat /run/secrets/pg_worker)"
admitter_password="$(cat /run/secrets/pg_admitter)"
if [ "${#api_password}" -lt 32 ] || [ "${#worker_password}" -lt 32 ] || [ "${#admitter_password}" -lt 32 ]; then
  echo 'API, worker and admission database passwords must have at least 32 characters' >&2
  exit 1
fi
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 --set api_password="$api_password" --set worker_password="$worker_password" --set admitter_password="$admitter_password" <<'SQL'
SELECT format('CREATE ROLE hosting_api LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'api_password') \gexec
SELECT format('CREATE ROLE hosting_worker LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'worker_password') \gexec
SELECT format('CREATE ROLE hosting_admitter LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'admitter_password') \gexec
SQL
