#!/bin/sh
# Expected class: PortScan
. "$(dirname "$0")/common.sh"
# -n: the lab has no DNS on purpose; -Pn: skip host discovery (the victim is known to be up)
exec nmap -n -Pn -sS -p 1-1024 -T4 "$VICTIM_IP"
