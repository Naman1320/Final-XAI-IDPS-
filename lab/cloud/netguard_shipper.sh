#!/bin/sh
# Network namespace of the flow-log shipper (the shipper joins it with network_mode: service:...
# and has no capabilities, so nothing inside it can change this). Same idea as netguard.sh.
# - No default route: the shipper cannot reach the internet, only cloud_net (10.10.4.0/24).
# - Outbound: TCP 4566 to the emulator (10.10.4.10) and replies, nothing else. So even a bug or a
#   wrong endpoint in the shipper cannot send a packet to real AWS or anywhere else.
# - Inbound: replies only.
# Fails closed: the container only reports healthy once every step worked.
set -eu
trap 'exit 0' TERM INT

ip route del default 2>/dev/null || true

nft -f - <<'NFT'
table inet shipperguard {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr 10.10.4.10 tcp dport 4566 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
NFT

if ip route | grep -q '^default'; then
  echo "shipper netguard: a default route is still present" >&2
  exit 1
fi
touch /tmp/ready
while :; do sleep 3600 & wait $!; done
