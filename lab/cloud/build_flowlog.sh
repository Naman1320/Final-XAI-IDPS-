#!/bin/sh
# Build the exporter images WITHOUT network (docs/cloud-plan.md step C3), from local layers only:
#   lab/cloud/build_flowlog.sh           build, then verify the baked billing guard
#   lab/cloud/build_flowlog.sh --check   only verify an existing image (no build)
# idps-lab-flowlog (writer and shipper) is a layer on idps-lab-sensor:latest; boto3 comes from the
# wheel cache the emulator build already filled. idps-cloud-shipper-net holds the shipper's
# locked-down network namespace.
# The image holds its OWN copy of lab/cloud/guard.py. If it differs from the repo's file the
# script fails (a stale guard in the image would be a weaker or different guard): rebuild.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)

check_guard() {
  want=$(shasum -a 256 "$repo/lab/cloud/guard.py" | cut -d' ' -f1)
  have=$(docker run --rm --network none --entrypoint sha256sum idps-lab-flowlog:latest \
           /opt/idps/lab/cloud/guard.py | cut -d' ' -f1)
  if [ "$want" != "$have" ]; then
    echo "build_flowlog: the guard.py baked into idps-lab-flowlog differs from lab/cloud/guard.py" >&2
    echo "  repo $want" >&2
    echo "  image $have" >&2
    echo "  rebuild with lab/cloud/build_flowlog.sh" >&2
    return 1
  fi
  echo "build_flowlog: baked guard.py matches lab/cloud/guard.py"
}

if [ "${1:-}" = "--check" ]; then
  check_guard
  exit $?
fi

wheels=${IDPS_MOTO_WHEELS:-$HOME/Library/Caches/idps-lab/wheels-moto}
[ -d "$wheels" ] || { echo "build_flowlog: wheel cache $wheels not found" >&2; exit 1; }
docker build --network none -f "$repo/lab/cloud/Dockerfile.flowlog" -t idps-lab-flowlog:latest \
  --build-context "wheels=$wheels" "$repo"
docker build --network none -f "$repo/lab/cloud/Dockerfile.shipper-net" \
  -t idps-cloud-shipper-net:latest "$repo/lab/cloud"
check_guard
