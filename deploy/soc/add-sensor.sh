#!/bin/sh
# idps-add-sensor NAME: create the sensor's token and client certificate and write them as a tar
# stream on stdout (install.sh unpacks it into deploy/sensors/NAME/). Nothing secret is printed
# anywhere else; the files exist only in this container's /tmp.
set -eu
umask 077
NAME="$1"
CA="${IDPS_CAKEYS_DIR:-/var/lib/idps-cakeys}"
case "$NAME" in
  ""|*[!A-Za-z0-9._-]*) echo "sensor names may only use letters, digits and ._-" >&2; exit 2 ;;
esac
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# create-sensor prints the token as its last line; keep it out of the log.
python -m soc.api create-sensor "$NAME" 2>&1 >"$W/out" | head -c 300 >&2 || true
[ -s "$W/out" ] || { echo "could not create the sensor $NAME (does it exist already?)" >&2; exit 1; }
tail -n 1 "$W/out" | tr -d '\n' > "$W/token"
rm -f "$W/out"
[ -s "$W/token" ] || { echo "no token was made" >&2; exit 1; }
python -m soc.api sensor-cert "$NAME" --ca-dir "$CA" --out-dir "$W" >&2
mv "$W/$NAME.pem" "$W/client.pem"
mv "$W/$NAME.key" "$W/client.key"
cp "$CA/server-ca.pem" "$W/ca.pem"
tar -C "$W" -cf - token client.pem client.key ca.pem
