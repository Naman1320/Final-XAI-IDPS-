#!/bin/sh
# idps-init-pki SAN...: make (once) the sensor CA and the sensor port's server certificate.
# CA private keys live in $IDPS_CAKEYS_DIR (mounted only into the soc-admin service); the running
# SOC gets the certificates and the server key in $IDPS_PKI_DIR (read-only). Safe to repeat:
# existing keys are kept; the server certificate is re-issued only when its names change or it
# nears expiry. Prints "written" when anything changed (install.sh then restarts the SOC).
set -eu
umask 077
PKI="${IDPS_PKI_DIR:-/var/lib/idps-pki}"
CA="${IDPS_CAKEYS_DIR:-/var/lib/idps-cakeys}"
[ "$#" -gt 0 ] || { echo "usage: idps-init-pki NAME_OR_IP..." >&2; exit 2; }
if [ ! -s "$CA/sensor-ca.key" ]; then
  python -m soc.api sensor-ca --out-dir "$CA"
  echo "written: sensor CA"
fi
# the sensor CA certificate (public) is what the SOC trusts for client certificates
if ! cmp -s "$CA/sensor-ca.pem" "$PKI/sensor-ca.pem" 2>/dev/null; then
  cp "$CA/sensor-ca.pem" "$PKI/sensor-ca.pem.tmp" && mv "$PKI/sensor-ca.pem.tmp" "$PKI/sensor-ca.pem"
  echo "written: sensor-ca.pem"
fi
args=""
for s in "$@"; do args="$args --san $s"; done
# shellcheck disable=SC2086  # the names are validated by install.sh and hold no spaces
out=$(python -m soc.api server-cert --dir "$PKI" --ca-dir "$CA" $args)
echo "$out"
case "$out" in *"is current"*) ;; *) echo "written: server certificate" ;; esac
