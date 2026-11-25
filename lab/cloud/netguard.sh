#!/bin/sh
# Network namespace of the emulator (moto joins it with network_mode: service:moto-net and has
# no capabilities, so nothing inside Moto can change this). Same idea as lab/soc/netguard.sh.
# - No default route: the emulator reaches nothing outside cloud_net (10.10.4.0/24).
# - Inbound: only TCP 4566 from cloud_net (the published 127.0.0.1 port arrives from the
#   Docker gateway on that subnet; later the C3 exporter and C4 collector join cloud_net).
# - Outbound: only replies. Moto never needs to open a connection.
# Fails closed: the container only reports healthy once every step worked.
set -eu
trap 'exit 0' TERM INT

ip route del default 2>/dev/null || true

nft -f - <<'NFT'
table inet cloudguard {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ip saddr 10.10.4.0/24 tcp dport 4566 accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
NFT

if ip route | grep -q '^default'; then
  echo "netguard: a default route is still present" >&2
  exit 1
fi
touch /tmp/ready
while :; do sleep 3600 & wait $!; done
