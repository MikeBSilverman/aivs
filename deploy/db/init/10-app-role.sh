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
# THE MEMBER LOGIN (Phase P). A second plain login, AIVS_DB_MEMBER_USER, which
# member organisations' requests run on. Created here the same way, and never
# granted the staff role: the migration step refuses a member login that is,
# or can act as, the staff one, because one SET ROLE would undo the split.
#
# This script only creates the logins. It grants nothing on tables: they do not
# exist yet on first start, and the grants belong with the schema they cover.
# =============================================================================
set -eu

: "${AIVS_DB_APP_USER:?AIVS_DB_APP_USER is required}"
: "${AIVS_DB_APP_PASSWORD:?AIVS_DB_APP_PASSWORD is required}"
: "${AIVS_DB_MEMBER_USER:?AIVS_DB_MEMBER_USER is required}"
: "${AIVS_DB_MEMBER_PASSWORD:?AIVS_DB_MEMBER_PASSWORD is required}"

for login in "${AIVS_DB_APP_USER}" "${AIVS_DB_MEMBER_USER}"; do
    if [ "${login}" = "${POSTGRES_USER}" ]; then
        echo "refusing: ${login} must not be the owner role (${POSTGRES_USER})" >&2
        exit 1
    fi
done
if [ "${AIVS_DB_APP_USER}" = "${AIVS_DB_MEMBER_USER}" ]; then
    echo "refusing: AIVS_DB_MEMBER_USER must differ from AIVS_DB_APP_USER" >&2
    exit 1
fi

# Re-run with `exec`, the entrypoint's exported PGPASSWORD is absent; the
# socket requires the password (scram-sha-256 for local connections too).
export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD}}"

# create_login NAME: create or update the plain login NAME, with the password
# in LOGIN_PASSWORD.
#
# The password reaches psql through its environment (\getenv), never its
# argument list, and the session turns statement logging off first: the server
# runs with log_statement=ddl, and ALTER ROLE ... PASSWORD is DDL, so the
# plaintext would otherwise be written to a log that is forwarded off the host.
create_login() {
    psql -v ON_ERROR_STOP=1 --no-psqlrc --no-password \
         --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
         -v app_user="$1" -v db_name="${POSTGRES_DB}" <<'SQL'
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET log_min_error_statement = 'panic';
\getenv app_password LOGIN_PASSWORD

SELECT format('CREATE ROLE %I LOGIN', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

ALTER ROLE :"app_user" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS PASSWORD :'app_password';
GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
SQL
}

# Exported, not prefixed to the call: POSIX sh does not promise that an
# assignment before a function call reaches the commands the function runs.
export LOGIN_PASSWORD="${AIVS_DB_APP_PASSWORD}"
create_login "${AIVS_DB_APP_USER}"
export LOGIN_PASSWORD="${AIVS_DB_MEMBER_PASSWORD}"
create_login "${AIVS_DB_MEMBER_USER}"
unset LOGIN_PASSWORD
