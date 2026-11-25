#!/bin/bash
# Entry point of the lab Suricata sidecar: cap the alert log, then run suricata with the arguments from
# docker-compose.yml. It does NOT use the image's entrypoint: that one chowns folders and drops to the
# `suricata` user, which needs CHOWN, SETUID, SETGID, NET_ADMIN and SYS_NICE. This container keeps
# only NET_RAW (capture) and DAC_READ_SEARCH (read the rules volume, whose folder belongs to
# `suricata`), and runs as root without the rest.
#
# Suricata keeps eve.json open in append mode, so truncating it is safe: it carries on writing at the
# new end, and the sensor's rule forwarder (idps/rules/tail.py) notices the file got smaller and
# starts again from its beginning. Once a minute, a file over EVE_MAX_MB is emptied.
set -eu
EVE=/eve/eve.json
MAX_BYTES=$(( ${EVE_MAX_MB:-32} * 1024 * 1024 ))
(
  while sleep 60; do
    size=$(stat -c %s "$EVE" 2>/dev/null || echo 0)
    if [ "$size" -gt "$MAX_BYTES" ]; then
      echo "run.sh: $EVE is $size bytes (cap $MAX_BYTES), emptying it" >&2
      : > "$EVE"
    fi
  done
) &
exec /usr/bin/suricata "$@"
