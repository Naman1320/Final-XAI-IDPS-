#!/bin/sh
# Network namespace of the cloud collector (docs/cloud-plan.md step C4). The collector joins it
# with network_mode: service:collector-net and has no capabilities, so nothing inside it can
# change this. Same pattern as netguard_shipper.sh, with two legs:
#   eth on cloud_net (10.10.4.0/24)  - the emulated AWS
#   eth on mgmt_net  (10.10.3.0/24)  - the lab SOC's sensor port
# - No default route: nothing outside those two /24 networks is reachable (no internet, no
#   attacker_net, no victim_net).
# - Outbound, and nothing else: TCP 4566 to the emulator (10.10.4.10), TCP 8444 to the SOC
#   (10.10.3.10, the mutual-TLS sensor port; NOT the dashboard port 8443), and replies.
# - Inbound: replies only. Nothing listens in this namespace, and the SOC's and sensor's addresses
#   cannot open a connection to it.
# - No forwarding: ip_forward is 0 (set by compose) and the forward chain drops everything, so the
#   collector is not a bridge between cloud_net and mgmt_net.
# Fails closed: the container reports healthy only once every step worked.
set -eu
trap 'exit 0' TERM INT

ip route del default 2>/dev/null || true

nft -f - <<'NFT'
table inet collectorguard {
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
    ip daddr 10.10.3.10 tcp dport 8444 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
NFT

if ip route | grep -q '^default'; then
  echo "collector netguard: a default route is still present" >&2
  exit 1
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 0 ]; then
  echo "collector netguard: ip_forward is on; refusing to start" >&2
  exit 1
fi
# Exactly the two expected legs (a stray extra network would be an unreviewed route).
legs=$(ip -4 -o route show scope link | awk '{print $1}' | sort | tr '\n' ' ')
if [ "$legs" != "10.10.3.0/24 10.10.4.0/24 " ]; then
  echo "collector netguard: unexpected networks attached: $legs" >&2
  exit 1
fi
touch /tmp/ready
while :; do sleep 3600 & wait $!; done
