#!/bin/sh
# Name the interfaces, load the lab firewall and drop the default route, then idle.
# Fails closed.
set -eu

# Docker doesn't guarantee which network becomes eth0, so find each interface by
# its address and give it a fixed name: lab_attack (10.10.1.2), lab_victim (10.10.2.2),
# lab_mgmt (10.10.3.2, the management network shared only with the lab SOC).
rename() {
  iface=$(ip -4 -o addr show | awk -v ip="$1" '$4 ~ "^"ip"/" {print $2; exit}')
  [ -n "$iface" ] || { echo "sensor: no interface has address $1" >&2; exit 1; }
  if [ "$iface" != "$2" ]; then
    ip link set "$iface" down
    ip link set "$iface" name "$2"
    ip link set "$2" up
  fi
}
rename 10.10.1.2 lab_attack
rename 10.10.2.2 lab_victim
rename 10.10.3.2 lab_mgmt

nft -f /etc/idps-lab/nftables.conf
ip route del default 2>/dev/null || true
if ip route | grep -q '^default'; then
  echo "sensor: default route still present, refusing to start" >&2
  exit 1
fi
touch /tmp/ready
exec sleep infinity
