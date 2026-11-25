#!/bin/sh
# Lab SOC database (PostgreSQL 16). Runs in soc-net's network namespace, so it listens only on
# the SOC's loopback (127.0.0.1:5432) and netguard.sh drops anything else. The SOC's password is
# made here on the first start and written to a volume only this container (read-write) and the
# SOC (read-only) mount: nobody types it and it is never in lab/.env, compose or the image.
# The SOC logs in as "idps", an ordinary role that owns the idps database (soc/db-init.sh), not
# as the superuser.
set -eu
umask 077
SECRET=/run/idps-db/password
if [ ! -s "$SECRET" ]; then
  if [ -s "$PGDATA/PG_VERSION" ]; then
    # A new password would not match the one the existing database was made with.
    echo "soc-db: the database exists but its password file is gone (volume soc_db_secret);" \
         "restore the volume or remove soc_pg too and restore the SOC from a backup" >&2
    exit 1
  fi
  # 32 random characters from [A-Za-z0-9] (safe in a URL without escaping).
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 >"$SECRET.tmp"
  mv "$SECRET.tmp" "$SECRET"
fi
# Owned by root, 0600: the SOC runs as root without CAP_DAC_OVERRIDE, so only root can read it.
chown 0:0 "$SECRET"
chmod 0600 "$SECRET"
# Only used by initdb on the very first start. The superuser gets a random password nobody keeps
# (it is reachable only through the local socket inside this container); db-init.sh creates the
# SOC's role with the password in $SECRET.
SOC_DB_PASSWORD=$(cat "$SECRET")
POSTGRES_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
export SOC_DB_PASSWORD POSTGRES_PASSWORD
exec docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1 -c password_encryption=scram-sha-256
