#!/bin/sh
# Network namespace of the lab SOC (soc joins it with network_mode: service:soc-net and has no
# capabilities, so nothing inside the SOC can change this). Fails closed like lab/netns/setup.sh.
#
# - No default route: the SOC reaches nothing outside 10.10.3.0/24.
# - Inbound: only TCP 8443 (the dashboard through the published 127.0.0.1 port; sensors too when
#   mutual TLS is off) and TCP 8444 from the sensor's address 10.10.3.2 (the mutual-TLS sensor port).
# - Outbound: only replies, by default. The SOC never opens a connection, so it can't reach the
#   lab, the Docker host or the internet even if it were compromised.
# - Optional additional sensors (SOC_EXTRA_SENSOR_ADDRS, from LAB_SOC_EXTRA_SENSOR_ADDRS in lab/.env,
#   blank by default): TCP 8444 (never 8443) also from those mgmt_net addresses, e.g. the cloud
#   collector at 10.10.3.3 (lab/cloud/README.md). The lab sensor's rule is always there. An entry
#   must be a host address 10.10.3.2 to 10.10.3.254 other than the SOC, at most 4; anything else
#   is ignored and logged, so a typo leaves the port closed, never opens it wider.
# - Optional exception (SOC_EGRESS_HOSTS, from LAB_SOC_EGRESS_HOSTS in lab/.env): HTTPS (TCP 443)
#   to the public IPv4 addresses those host names resolve to, e.g. api.abuseipdb.com for IP
#   reputation or hooks.slack.com for Slack. Each address gets its own /32 route through the
#   Docker gateway (still no default route); private and reserved answers are refused. Names are
#   looked up again every 2 minutes and an address stays allowed for an hour after it was last
#   seen, so rotating CDN answers keep working and stale ones age out.
#   Accepted risks (see lab/README.md): the rule is per address, so other sites on the same CDN
#   addresses are reachable too, and a compromised SOC could send data out through them; DNS
#   queries already reach the internet through Docker's resolver.
# - Optional exception for email (SOC_EGRESS_SMTP_HOST and SOC_EGRESS_SMTP_PORT, from LAB_SMTP_HOST
#   and LAB_SMTP_PORT in lab/.env, so the SOC can reach exactly the mail server it is configured
#   for): that one port (25, 465 or 587) to the public addresses of that one host, in its own set,
#   refreshed the same way. Nothing else changes: HTTPS stays limited to SOC_EGRESS_HOSTS.
set -eu
set -f            # no globbing of SOC_EGRESS_HOSTS
trap 'exit 0' TERM INT

GW=""
REFRESH_SECONDS=120
RETRY_SECONDS=30
KEEP=1h           # an address stays allowed this long after it was last resolved
MAX_PER_HOST=32

public_ipv4() {  # $1 is a dotted IPv4 address; true unless private, shared, loopback or reserved
  case "$1" in
    0.*|10.*|127.*|169.254.*|192.168.*|192.0.0.*|192.0.2.*|198.18.*|198.19.*|198.51.100.*|203.0.113.*) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
    22[4-9].*|2[3-5][0-9].*) return 1 ;;
  esac
  return 0
}

valid_host() {  # a DNS name: letters, digits, dots, hyphens; no empty label; no label edge hyphen
  [ "${#1}" -le 253 ] || return 1
  case "$1" in
    ""|*[!A-Za-z0-9.-]*|.*|*.|*..*|-*|*-|*.-*|*-.*) return 1 ;;
  esac
  return 0
}

resolve() {  # dotted-quad A records of $1 (two lookups, to catch rotating answers), capped
  { getent ahostsv4 "$1" || true; getent ahostsv4 "$1" || true; } \
    | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1}' | sort -u | head -n "$MAX_PER_HOST"
}

allowed_now() {  # addresses currently in set $1 (default egress4)
  nft list set inet socguard "${1:-egress4}" | sed -n '/elements/,$p' \
    | grep -oE '([0-9]+\.){3}[0-9]+' | sort -u || true
}

refresh() {  # the HTTPS set (egress4) from $HOSTS
  refresh_set egress4 HTTPS "$HOSTS"
}

refresh_set() {  # $1 set, $2 label for the log, $3 host names. Returns 1, changing nothing, when
  # no host gave a public address or nft/ip failed.
  set_name=$1; label=$2; set_hosts=$3
  found=""
  for h in $set_hosts; do
    got=""
    for a in $(resolve "$h"); do
      if public_ipv4 "$a"; then got="$got $a"; else
        echo "soc-net: ignoring non-public address $a for $h" >&2; fi
    done
    [ -n "$got" ] || echo "soc-net: no public address for $h this time (its earlier ones stay until they expire)" >&2
    found="$found$got"
  done
  found=$(printf '%s\n' $found | sort -u)  # two names may share addresses (CDNs)
  [ -n "$found" ] || return 1
  # Routes first, then the set: a failure leaves the rule as it was.
  for a in $found; do ip route replace "$a/32" via "$GW" proto 99 || return 1; done
  elems=""
  for a in $found; do elems="$elems${elems:+, }$a timeout $KEEP"; done
  printf 'add element inet socguard %s { %s }\n' "$set_name" "$elems" | nft -f - || return 1
  # Drop the routes of addresses that have expired from every set (routes are shared).
  keep=$(allowed_now "$set_name")
  [ -z "${SMTP_HOST:-}" ] || [ "$set_name" = egress_smtp4 ] \
    || keep=$(printf '%s\n%s\n' "$keep" "$(allowed_now egress_smtp4)" | sort -u)
  [ "$set_name" = egress4 ] || keep=$(printf '%s\n%s\n' "$keep" "$(allowed_now egress4)" | sort -u)
  for r in $(ip -4 route show proto 99 | awk '{print $1}'); do
    printf '%s\n' "$keep" | grep -qxF "$r" || ip route del "$r/32" via "$GW" proto 99 || true
  done
  now="$(allowed_now "$set_name" | tr '\n' ' ')"
  eval "last=\${LAST_$set_name:-}"
  if [ "$now" != "$last" ]; then  # log changes only
    echo "soc-net: $label allowed to $set_hosts ($now)" >&2
    eval "LAST_$set_name=\$now"
  fi
}

refresh_all() {  # every configured set; 1 only if all of them failed (one working is enough to
  # leave the fast start-up retries; the others are retried on the normal schedule)
  ok=0; tried=0
  if [ -n "$HOSTS" ]; then tried=1; if refresh; then ok=1; else
    echo "soc-net: HTTPS hosts not resolved: $HOSTS" >&2; fi; fi
  if [ -n "${SMTP_HOST:-}" ]; then tried=1
    if refresh_set egress_smtp4 "SMTP port $SMTP_PORT" "$SMTP_HOST"; then ok=1; else
      echo "soc-net: mail server not resolved: $SMTP_HOST" >&2; fi; fi
  [ "$tried" = 0 ] || [ "$ok" = 1 ]
}

MAX_EXTRA_SENSORS=4

sensor_addr_ok() {  # true for a mgmt_net host address a sensor may have: 10.10.3.2 to .254, not the SOC
  case "$1" in
    10.10.3.10) return 1 ;;
    10.10.3.[2-9]|10.10.3.[1-9][0-9]|10.10.3.1[0-9][0-9]|10.10.3.2[0-4][0-9]|10.10.3.25[0-4]) return 0 ;;
  esac
  return 1
}

extra_sensor_addrs() {  # the usable entries of SOC_EXTRA_SENSOR_ADDRS, one per line; the rest are logged
  for a in $(printf '%s' "${SOC_EXTRA_SENSOR_ADDRS:-}" | tr ',' ' '); do
    if sensor_addr_ok "$a"; then printf '%s\n' "$a"; else
      echo "soc-net: ignoring SOC_EXTRA_SENSOR_ADDRS entry '$a' (needs a host address 10.10.3.2-254, not the SOC)" >&2
    fi
  done | sort -u | head -n "$MAX_EXTRA_SENSORS"
}

local_mail_host() {  # true for blank, localhost or a non-public IPv4 literal: nothing to open
  case "$1" in
    ""|localhost|*.localhost) return 0 ;;
    *[!0-9.]*) return 1 ;;  # a name: resolved and checked later
  esac
  ! public_ipv4 "$1"
}

valid_smtp_port() {  # only the mail submission and relay ports
  case "$1" in 25|465|587) return 0 ;; esac
  return 1
}

[ "${NETGUARD_LIB:-}" = 1 ] && return 0 2>/dev/null  # sourced by tests: functions only

# Normalise "a, b,,c" to "a b c"; only separators means none.
set -- $(printf '%s' "${SOC_EGRESS_HOSTS:-}" | tr ',' ' ')
HOSTS="$*"
for h in $HOSTS; do
  valid_host "$h" || { echo "soc-net: bad host name in SOC_EGRESS_HOSTS: $h" >&2; exit 1; }
done
SMTP_HOST=$(printf '%s' "${SOC_EGRESS_SMTP_HOST:-}" | tr -d ' ')
SMTP_PORT=${SOC_EGRESS_SMTP_PORT:-}
if [ -z "$SMTP_PORT" ]; then  # the SOC's own default: 465 for implicit TLS, else 587
  case "${SOC_EGRESS_SMTP_SECURITY:-}" in ssl|SSL) SMTP_PORT=465 ;; *) SMTP_PORT=587 ;; esac
fi
if local_mail_host "$SMTP_HOST"; then
  # A test receiver inside the SOC's own container (lab/README.md): loopback needs no exception.
  [ -z "$SMTP_HOST" ] || echo "soc-net: mail server $SMTP_HOST is local; no SMTP exception" >&2
  SMTP_HOST=""
fi
# The email exception is optional: a value it can't use leaves email blocked, never the SOC down.
if [ -n "$SMTP_HOST" ] && ! valid_host "$SMTP_HOST"; then
  echo "soc-net: LAB_SMTP_HOST is not a plain host name; no SMTP exception, email stays blocked" >&2
  SMTP_HOST=""
fi
if [ -n "$SMTP_HOST" ] && ! valid_smtp_port "$SMTP_PORT"; then
  echo "soc-net: LAB_SMTP_PORT must be 25, 465 or 587 for the SMTP exception; email stays blocked" >&2
  SMTP_HOST=""
fi

EXTRA_SENSORS=$(extra_sensor_addrs)

GW=$(ip -4 route show default | awk '{print $3; exit}')
ip route del default 2>/dev/null || true

nft -f - <<'NFT'
table inet socguard {
  set egress4 { type ipv4_addr; flags timeout; }
  set egress_smtp4 { type ipv4_addr; flags timeout; }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 8443 accept
    ip saddr 10.10.3.2 tcp dport 8444 accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr @egress4 tcp dport 443 accept
  }
}
NFT
for a in $EXTRA_SENSORS; do  # each one is a validated dotted quad
  nft add rule inet socguard input ip saddr "$a" tcp dport 8444 accept
  echo "soc-net: sensor port 8444 also open to $a" >&2
done
if [ -n "$SMTP_HOST" ]; then  # the port is validated above (25, 465 or 587)
  nft add rule inet socguard output ip daddr @egress_smtp4 tcp dport "$SMTP_PORT" accept
fi

if { [ -n "$HOSTS" ] || [ -n "$SMTP_HOST" ]; } && [ -z "$GW" ]; then
  echo "soc-net: no Docker gateway for SOC_EGRESS_HOSTS / SOC_EGRESS_SMTP_HOST" >&2; exit 1
fi
if ip route | grep -q '^default'; then
  echo "soc-net: default route still present, refusing to start" >&2
  exit 1
fi
touch /tmp/ready  # the SOC starts either way; the exception is optional

if [ -z "$HOSTS" ] && [ -z "$SMTP_HOST" ]; then
  while :; do sleep 3600 & wait $!; done
fi
# Until the first success (DNS down at start, say) retry often; what failed stays closed meanwhile.
until refresh_all; do
  echo "soc-net: nothing resolved yet; retrying in ${RETRY_SECONDS}s" >&2
  sleep "$RETRY_SECONDS" & wait $!
done
while :; do
  sleep "$REFRESH_SECONDS" & wait $!
  refresh_all || echo "soc-net: refresh failed; addresses already allowed expire after $KEEP" >&2
  # (a set that failed while another worked has logged its own line above)
done
