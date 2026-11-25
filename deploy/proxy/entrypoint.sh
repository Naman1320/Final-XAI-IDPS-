#!/bin/sh
# IDPS_TLS_MODE=internal (Caddy's own CA; default) or domain (Let's Encrypt); IDPS_SITE is the
# host name or address the dashboard is served on; IDPS_REDIR_PORT is ":N" when the public HTTPS
# port is not 443 (empty otherwise).
set -eu
case "${IDPS_TLS_MODE:-internal}" in
  internal|domain) ;;
  *) echo "idps-proxy: IDPS_TLS_MODE must be internal or domain" >&2; exit 1 ;;
esac
[ -n "${IDPS_SITE:-}" ] || { echo "idps-proxy: IDPS_SITE is not set" >&2; exit 1; }
exec caddy run --config "/etc/caddy/Caddyfile.${IDPS_TLS_MODE:-internal}" --adapter caddyfile
