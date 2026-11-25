#!/bin/sh
# Give the cloud collector its credentials at the lab SOC (docs/cloud-plan.md step C4), once:
#   lab/cloud/collector_provision.sh
# Makes the sensor token "cloud" and its client certificate INSIDE the running SOC
# (lab/cloud/collector_provision.py, piped in, no image rebuild), and stores them in the Docker
# volume idps-cloud_collector_secrets, owned by the collector's unprivileged user and mounted
# read-only into it. Nothing secret is printed, written into the repo or put in an environment
# variable, `docker inspect` or an image layer. Safe to run again: it keeps what is still good.
# Options (passed on): --force-token replaces the token even if it matches.
# When it added a new CA to the SOC's sensor CA file the SOC must be restarted once (it says so).
set -eu
umask 077   # the temporary archive (0700 folder, 0600 file) is removed on exit
SOC=${IDPS_LAB_SOC_CONTAINER:-idps-soc}
VOLUME=idps-cloud_collector_secrets
HELPER=idps-lab-soc-net:latest   # alpine: only used for tar/chown/test in a throwaway container
here=$(cd "$(dirname "$0")" && pwd)

[ "$(docker inspect -f '{{.State.Health.Status}}' "$SOC" 2>/dev/null)" = healthy ] \
  || { echo "collector_provision: the lab SOC ($SOC) is not running and healthy" >&2; exit 1; }
docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

# What the volume already holds: whether a key exists, and the SHA-256 of the token file (the hash
# is what the SOC stores; the token itself never leaves the volume or the tar pipe).
has() { docker run --rm --network none -v "$VOLUME:/s:ro" --entrypoint test "$HELPER" -s "/s/$1"; }
have_key=0
if has client.key && has client.pem; then have_key=1; fi
token_sha=""
if has sensor_token; then
  token_sha=$(docker run --rm --network none -v "$VOLUME:/s:ro" --entrypoint sha256sum "$HELPER" /s/sensor_token | cut -d' ' -f1)
fi

archive=$(mktemp -d "${TMPDIR:-/tmp}/collector-provision.XXXXXX") || exit 1
trap 'rm -rf "$archive"' EXIT      # on any exit, including an error under set -e
trap 'exit 1' INT TERM             # a signal ends the script (and so runs the EXIT trap)
docker exec -i "$SOC" python - --token-sha256 "$token_sha" --have-key "$have_key" "$@" \
  < "$here/collector_provision.py" > "$archive/creds.tar"
# Unpack into the volume as the collector's user (65534); keys and the token are 0600 from the tar.
docker run --rm --network none -i -v "$VOLUME:/s" --entrypoint sh "$HELPER" -c \
  'tar x -C /s -f - && chown -R 65534:65534 /s && chmod 0755 /s' < "$archive/creds.tar"
echo "collector_provision: credentials are in volume $VOLUME (not shown)"
