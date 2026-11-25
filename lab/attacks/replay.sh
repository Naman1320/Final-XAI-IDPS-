#!/bin/sh
# Dataset replay (mixed classes). Runs inside the attacker container only:
#   docker compose cp capture.pcap attacker:/tmp/capture.pcap
#   docker compose exec attacker /attacks/replay.sh /tmp/capture.pcap [mbit_per_s]
# The rate defaults to 10 Mbit/s (optional second argument, or REPLAY_MBPS).
# Every frame is rewritten to the sensor's MAC address, so only the sensor
# receives it; the sensor's firewall then drops it (dataset IPs are not lab IPs).
. "$(dirname "$0")/common.sh"
[ -n "${1:-}" ] || { echo "usage: $0 capture.pcap [mbit_per_s]" >&2; exit 1; }
[ -f "$1" ] || { echo "replay: no such file: $1" >&2; exit 1; }

RATE="${2:-${REPLAY_MBPS:-10}}"
case "$RATE" in ''|*[!0-9.]*|*.*.*|.) echo "replay: rate must be a positive number of Mbit/s, got: $RATE" >&2; exit 1;; esac
[ "$(awk -v r="$RATE" 'BEGIN{print (r > 0)}')" = 1 ] || { echo "replay: rate must be above 0" >&2; exit 1; }

SENSOR_IP=10.10.1.2
IFACE=$(ip -4 -o addr show | awk '/inet 10\.10\.1\.10\//{print $2; exit}')
ping -c 1 -W 1 "$SENSOR_IP" >/dev/null 2>&1 || true   # fills the ARP cache
SENSOR_MAC=$(ip neigh show "$SENSOR_IP" | awk '/lladdr/{print $5; exit}')
[ -n "$IFACE" ] && [ -n "$SENSOR_MAC" ] || { echo "replay: cannot find the sensor on attack_net" >&2; exit 1; }

exec tcpreplay-edit --intf1="$IFACE" --enet-dmac="$SENSOR_MAC" --mbps="$RATE" "$1"
