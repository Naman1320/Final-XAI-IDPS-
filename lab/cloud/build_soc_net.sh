#!/bin/sh
# Rebuild the lab SOC's netns image with the current lab/soc/netguard.sh, WITHOUT network (C4):
#   lab/cloud/build_soc_net.sh           build (first run keeps the old image as idps-lab-soc-net:pre-c4)
#   lab/cloud/build_soc_net.sh --check   only verify that the image holds the repo's netguard.sh
# The way back: docker tag idps-lab-soc-net:pre-c4 idps-lab-soc-net:latest, then recreate soc-net
# soc-db soc in lab/ (docker compose up -d --no-build --force-recreate soc-net soc-db soc).
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
IMG=idps-lab-soc-net

check() {
  want=$(shasum -a 256 "$repo/lab/soc/netguard.sh" | cut -d' ' -f1)
  have=$(docker run --rm --network none --entrypoint sha256sum "$IMG:latest" /netguard.sh | cut -d' ' -f1)
  [ "$want" = "$have" ] || { echo "build_soc_net: $IMG:latest holds another netguard.sh than lab/soc/netguard.sh" >&2; return 1; }
  echo "build_soc_net: $IMG:latest holds the repo's netguard.sh"
}
[ "${1:-}" = "--check" ] && { check; exit $?; }

if ! docker image inspect "$IMG:pre-c4" >/dev/null 2>&1; then
  docker image inspect "$IMG:latest" >/dev/null 2>&1 || { echo "build_soc_net: no $IMG:latest to start from" >&2; exit 1; }
  docker tag "$IMG:latest" "$IMG:pre-c4"
  echo "build_soc_net: kept the old image as $IMG:pre-c4"
fi
docker build --network none -f "$repo/lab/soc/Dockerfile.net.offline" -t "$IMG:latest" "$repo/lab"
check
