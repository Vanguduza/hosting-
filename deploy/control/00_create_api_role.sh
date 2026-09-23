#!/bin/bash
set -Eeuo pipefail
api_password="$(cat /run/secrets/pg_api)"
if [ "${#api_password}" -lt 32 ]; then
  echo 'The API database password must have at least 32 characters' >&2
  exit 1
fi
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 --set api_password="$api_password" <<'SQL'
SELECT format('CREATE ROLE hosting_api LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'api_password') \gexec
SQL
