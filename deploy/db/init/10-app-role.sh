#!/bin/sh
# =============================================================================
# Create the role the application connects as. Run by the postgres image on
# first start (mounted at /docker-entrypoint-initdb.d), and safe to run again:
#
#   docker compose --env-file deploy/.env exec -T db \
#     /docker-entrypoint-initdb.d/10-app-role.sh
#
# which is how a database initialised before this script existed gets the role,
# and how its password is changed after editing AIVS_DB_APP_PASSWORD.
#
# WHY A SECOND ROLE. The image's POSTGRES_USER is a superuser and owns every
# table the migrations create. Either can drop or disable the append-only
# triggers on audit_log and submission_transitions, so an application connected
# as it held the means to rewrite the evidence the product exists to keep --
# and that is how the shipped stack ran until this script existed. The
# application role is a plain login: no superuser, no CREATEDB, no CREATEROLE,
# not a member of the owner. It is granted its table privileges by the
# migration step (aivs_server.db.grants), which refuses a role that is any of
# those things, so a misconfiguration fails the migration rather than passing
# silently.
#
# This script only creates the login. It grants nothing on tables: they do not
# exist yet on first start, and the grants belong with the schema they cover.
# =============================================================================
set -eu

: "${AIVS_DB_APP_USER:?AIVS_DB_APP_USER is required}"
: "${AIVS_DB_APP_PASSWORD:?AIVS_DB_APP_PASSWORD is required}"

if [ "${AIVS_DB_APP_USER}" = "${POSTGRES_USER}" ]; then
    echo "refusing: AIVS_DB_APP_USER must not be the owner role (${POSTGRES_USER})" >&2
    exit 1
fi

# Re-run with `exec`, the entrypoint's exported PGPASSWORD is absent; the
# socket requires the password (scram-sha-256 for local connections too).
export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD}}"

# The password reaches psql through its environment (\getenv), never its
# argument list, and the session turns statement logging off first: the server
# runs with log_statement=ddl, and ALTER ROLE ... PASSWORD is DDL, so the
# plaintext would otherwise be written to a log that is forwarded off the host.
psql -v ON_ERROR_STOP=1 --no-psqlrc --no-password \
     --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
     -v app_user="${AIVS_DB_APP_USER}" -v db_name="${POSTGRES_DB}" <<'SQL'
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET log_min_error_statement = 'panic';
\getenv app_password AIVS_DB_APP_PASSWORD

SELECT format('CREATE ROLE %I LOGIN', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

ALTER ROLE :"app_user" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
SQL
