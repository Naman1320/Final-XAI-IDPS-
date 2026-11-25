#!/bin/sh
# idps-renew-sensor NAME: a new client certificate (and key) for an enrolled sensor, as a tar
# stream on stdout (install.sh renew-sensor puts it into the sensor's bundle). The token is kept.
set -eu
umask 077
NAME="$1"
CA="${IDPS_CAKEYS_DIR:-/var/lib/idps-cakeys}"
case "$NAME" in
  ""|*[!A-Za-z0-9._-]*) echo "sensor names may only use letters, digits and ._-" >&2; exit 2 ;;
esac
# only an existing sensor that has not been revoked gets a certificate
python - "$NAME" <<'PY' || { echo "no such sensor, or it is revoked: $NAME" >&2; exit 1; }
import sys

from sqlalchemy import select

from soc.api.__main__ import _session
from soc.api.models import SensorToken

with _session() as db:
    row = db.scalar(select(SensorToken).where(SensorToken.name == sys.argv[1]))
    sys.exit(0 if row is not None and not row.revoked else 1)
PY
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
python -m soc.api sensor-cert "$NAME" --ca-dir "$CA" --out-dir "$W" >&2
mv "$W/$NAME.pem" "$W/client.pem"
mv "$W/$NAME.key" "$W/client.key"
cp "$CA/server-ca.pem" "$W/ca.pem"
tar -C "$W" -cf - client.pem client.key ca.pem
