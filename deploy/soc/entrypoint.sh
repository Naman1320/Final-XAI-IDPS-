#!/bin/sh
# idps-soc entrypoint: secrets come from files (compose secrets), never from the image or the
# environment of `docker inspect`. `serve` (the default) starts the API; any other command runs
# with the same environment (python -m soc.api ..., used by install.sh).
set -eu
SECRETS="${IDPS_SECRETS_DIR:-/run/secrets}"
PKI="${IDPS_PKI_DIR:-/var/lib/idps-pki}"

read_secret() { # read_secret NAME: the file's first line; fail closed when missing or empty
  [ -s "$SECRETS/$1" ] || { echo "idps-soc: secret file $SECRETS/$1 is missing or empty" >&2; exit 1; }
  head -n 1 "$SECRETS/$1"
}

IDPS_SOC_JWT_SECRET=$(read_secret jwt_secret)
IDPS_SOC_MFA_KEY=$(read_secret mfa_key)
DB_PASSWORD=$(read_secret db_password)
case "$DB_PASSWORD" in
  *[!A-Za-z0-9._~-]*) echo "idps-soc: the database password may only use letters, digits and ._~-" >&2; exit 1 ;;
esac
IDPS_SOC_DATABASE_URL="postgresql+psycopg://${IDPS_DB_USER:-idps}:${DB_PASSWORD}@${IDPS_DB_HOST:-db}:5432/${IDPS_DB_NAME:-idps}"
unset DB_PASSWORD
export IDPS_SOC_JWT_SECRET IDPS_SOC_MFA_KEY IDPS_SOC_DATABASE_URL

if [ "${1:-serve}" = serve ]; then
  # Sensor port: always TLS with a required client certificate. Its certificate and the CA that
  # signs the sensors' certificates come from install.sh (idps-init-pki) in $PKI.
  for f in server.key server.pem sensor-ca.pem; do
    [ -s "$PKI/$f" ] || { echo "idps-soc: $PKI/$f is missing; run install.sh (it makes the certificates)" >&2; exit 1; }
  done
  export IDPS_SOC_SENSOR_MTLS_REQUIRED="${IDPS_SOC_SENSOR_MTLS_REQUIRED:-true}"
  # The main port is plain HTTP and is reachable only by the proxy (it is not published). Only the
  # proxy's address (compose gives it a fixed one: IDPS_FORWARDED_ALLOW_IPS) may set
  # X-Forwarded-For; the default trusts nobody but localhost.
  set -- python -m soc.api.serve --host 0.0.0.0 --port 8000 --ws-max-size 65536 \
    --proxy-headers --forwarded-allow-ips "${IDPS_FORWARDED_ALLOW_IPS:-127.0.0.1}" \
    --sensor-port 8444 --sensor-ca "$PKI/sensor-ca.pem" \
    --sensor-ssl-keyfile "$PKI/server.key" --sensor-ssl-certfile "$PKI/server.pem"
fi

# Compose starts this container as root so the secret files (0600, owned by whoever ran
# install.sh) can be read whatever their owner; the service itself always runs as uid 10001.
if [ "$(id -u)" = 0 ]; then
  exec setpriv --reuid 10001 --regid 10001 --clear-groups "$@"
fi
exec "$@"
