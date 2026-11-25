#!/bin/sh
# Prepare an endpoint's network namespace, then idle. Fails closed: if any step
# fails the container exits, /tmp/ready is never written, and the endpoint that
# depends on it never starts.
set -eu
: "${PEER_NET:?}" "${SENSOR_IP:?}" "${GATEWAY_IP:?}"

# No route to the outside world; the other lab subnet only via the sensor.
ip route del default 2>/dev/null || true
ip route replace "$PEER_NET" via "$SENSOR_IP"

nft -f - <<EOF
table inet labguard {
  chain output {
    type filter hook output priority 0; policy accept;
    ip daddr 127.0.0.11 drop comment "no Docker DNS, so no name lookups or DNS tunnelling out"
    ip daddr $GATEWAY_IP drop comment "no access to the Docker VM gateway"
  }
}
EOF

if ip route | grep -q '^default'; then
  echo "netns: default route still present, refusing to start" >&2
  exit 1
fi
touch /tmp/ready
exec sleep infinity
