#!/bin/sh
# First start only (docker-entrypoint-initdb.d): the SOC's own role, owner of the idps database
# (so it may create the tables its migrations need) but not a superuser, so a compromised SOC
# can't read server files or run programs through PostgreSQL.
set -eu
psql -v ON_ERROR_STOP=1 -v pw="$SOC_DB_PASSWORD" --username "$POSTGRES_USER" --dbname postgres <<'SQL'
CREATE ROLE idps LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'pw';
ALTER DATABASE idps OWNER TO idps;
SQL
