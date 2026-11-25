#!/bin/sh
# Lab SOC: TLS certificate, secrets, admin user and sensor token on first start, then the API.
# Fails closed. Two volumes:
#   /var/lib/idps-soc  SOC only: database, JWT secret, TLS private keys
#   /run/idps-soc      shared with the sensor (read-only there): ca.pem and sensor_token
set -eu
umask 077
DATA=/var/lib/idps-soc
SHARED=/run/idps-soc

case "${LAB_SOC_ADMIN_PASSWORD:-}" in
  "") echo "soc: LAB_SOC_ADMIN_PASSWORD is not set; copy lab/.env.example to lab/.env" >&2; exit 1 ;;
  change-me*) echo "soc: set your own LAB_SOC_ADMIN_PASSWORD in lab/.env" >&2; exit 1 ;;
esac

# A private CA for the lab, and a server certificate for the SOC's lab address and localhost
# (the dashboard reaches it through the published port 127.0.0.1:8443).
# The CA key signs once and is deleted; when the certificate is due to expire (within 30 days)
# the whole set is made again, and the sensor picks up the new ca.pem on its next start.
if [ ! -s "$DATA/server.pem" ] || ! openssl x509 -checkend 2592000 -noout -in "$DATA/server.pem" >/dev/null; then
  openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 \
    -subj "/CN=IDPS lab CA" -keyout "$DATA/ca.key" -out "$DATA/ca.pem"
  openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -subj "/CN=soc.lab" -keyout "$DATA/server.key" -out "$DATA/server.csr"
  printf 'subjectAltName=IP:10.10.3.10,IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' \
    > "$DATA/server.ext"
  openssl x509 -req -in "$DATA/server.csr" -CA "$DATA/ca.pem" -CAkey "$DATA/ca.key" \
    -CAcreateserial -days 365 -extfile "$DATA/server.ext" -out "$DATA/server.pem"
  rm -f "$DATA/server.csr" "$DATA/server.ext" "$DATA/ca.key" "$DATA/ca.srl"
fi
install -m 0644 "$DATA/ca.pem" "$SHARED/ca.pem"  # a certificate: public, readable by all

if [ ! -s "$DATA/jwt_secret" ]; then
  python -c "import secrets; print(secrets.token_urlsafe(48))" > "$DATA/jwt_secret.tmp"
  mv "$DATA/jwt_secret.tmp" "$DATA/jwt_secret"
fi
IDPS_SOC_JWT_SECRET=$(cat "$DATA/jwt_secret")
export IDPS_SOC_JWT_SECRET
SQLITE_URL="sqlite:///$DATA/soc.db"
MOVED="$DATA/soc.db.moved-to-postgres"
case "${LAB_SOC_DATABASE:-postgres}" in
  sqlite)
    if [ -e "$MOVED" ] && [ ! -e "$DATA/soc.db" ]; then
      echo "soc: warning: this SOC's history is in PostgreSQL ($MOVED was moved there);" \
           "LAB_SOC_DATABASE=sqlite starts an empty SQLite database" >&2
    fi
    IDPS_SOC_DATABASE_URL=$SQLITE_URL ;;
  postgres)
    # soc-db makes the password on its first start (lab/soc/db-start.sh). Never printed.
    if [ ! -s /run/idps-db/password ]; then
      echo "soc: no database password in /run/idps-db; is soc-db running?" >&2; exit 1
    fi
    IDPS_SOC_DATABASE_URL="postgresql+psycopg://idps:$(cat /run/idps-db/password)@127.0.0.1:5432/idps" ;;
  *)
    echo "soc: LAB_SOC_DATABASE must be postgres or sqlite" >&2; exit 1 ;;
esac
export IDPS_SOC_DATABASE_URL

# One-time move of an older lab SOC's SQLite data into PostgreSQL: a portable backup of soc.db,
# restored into the empty database. Each stage leaves a mark, so a start that was interrupted
# carries on where it stopped instead of failing:
#   $DATA/move.backup    names the finished, verified backup (reused, not made again)
#   $DATA/move.restored  the restore committed; only the rename of soc.db is left
# The backup stays in the volume (0600) as the way back; soc.db is renamed, never deleted.
if [ "${LAB_SOC_DATABASE:-postgres}" = postgres ] && [ -s "$DATA/soc.db" ]; then
  # Never overwrite the copy kept from an earlier move.
  if [ -e "$MOVED" ]; then MOVED="$MOVED-$(date -u +%Y%m%dT%H%M%SZ)"; fi
  if [ ! -e "$DATA/move.restored" ]; then
    echo "soc: moving $DATA/soc.db into PostgreSQL (one time)" >&2
    if [ -s "$DATA/move.backup" ] && [ -s "$(cat "$DATA/move.backup")" ]; then
      MOVE=$(cat "$DATA/move.backup")
      echo "soc: reusing the backup made by an earlier start: $MOVE" >&2
    else
      rm -f "$DATA"/*.body.tmp  # left by a backup that was killed
      MOVE="$DATA/sqlite-to-postgres-$(date -u +%Y%m%dT%H%M%SZ).jsonl.gz"
      python -m soc.api db upgrade --database-url "$SQLITE_URL"
      python -m soc.api backup --database-url "$SQLITE_URL" "$MOVE"
      printf '%s\n' "$MOVE" > "$DATA/move.backup"
    fi
    if ! python -m soc.api restore "$MOVE"; then
      echo "soc: the move did not happen and soc.db is untouched. If PostgreSQL already holds" \
           "this SOC's data, rename $DATA/soc.db yourself; otherwise see the error above" >&2
      exit 1
    fi
    : > "$DATA/move.restored"
  fi
  for side in -wal -shm; do  # SQLite's side files belong with the database they came from
    if [ -e "$DATA/soc.db$side" ]; then mv "$DATA/soc.db$side" "$MOVED$side"; fi
  done
  mv "$DATA/soc.db" "$MOVED"
  rm -f "$DATA/move.restored" "$DATA/move.backup"
  echo "soc: moved into PostgreSQL. Kept: $MOVED and the backup" \
       "$(ls -1t "$DATA"/sqlite-to-postgres-*.jsonl.gz 2>/dev/null | head -1)" >&2
fi
# Data retention runs hourly in the SOC (alerts 180 days, audit 365 by default; 0 = forever):
# set LAB_ALERT_RETENTION_DAYS / LAB_AUDIT_RETENTION_DAYS in lab/.env to change it.

python /opt/idps/lab/soc/bootstrap.py "$SHARED/sensor_token"
# The admin password is only needed for the first start; keep it out of the server's environment.
# (It still shows in `docker inspect`; it is a lab-only password. Changing it in lab/.env later
# has no effect: change it in the dashboard's Admin page instead.)
unset LAB_SOC_ADMIN_PASSWORD

# One process, two listeners (soc/api/serve.py): 8443 for the dashboard (and, unless mutual TLS
# is required, sensors), 8444 for sensors only, with a client certificate signed by the sensor CA
# that bootstrap.py made. One process because the live alert feed is an in-process broadcaster.
# LAB_SOC_SENSOR_MTLS=false lets sensors use 8443 with their token alone again.
IDPS_SOC_SENSOR_MTLS_REQUIRED="${LAB_SOC_SENSOR_MTLS:-true}"
export IDPS_SOC_SENSOR_MTLS_REQUIRED
exec python -m soc.api.serve --host 0.0.0.0 --port 8443 --ws-max-size 65536 \
  --ssl-keyfile "$DATA/server.key" --ssl-certfile "$DATA/server.pem" \
  --sensor-port 8444 --sensor-ca "$DATA/sensor-ca.pem"
