#!/bin/sh
# Build the collector images WITHOUT network (docs/cloud-plan.md step C4), from local layers only:
#   lab/cloud/build_collector.sh           build, then verify what was baked
#   lab/cloud/build_collector.sh --check   only verify the existing image (no build)
# idps-lab-collector  = layer on idps-lab-flowlog:latest (run lab/cloud/build_flowlog.sh first if
#                       that image is missing) with the code, the billing guard, the signed cloud
#                       model and the model-signing public key.
# idps-cloud-collector-net holds the collector's locked-down network namespace.
# Run it again after models/cloud_xgboost.joblib changes (retrained and re-signed): the model's
# SHA-256 is part of the image, and the check fails while the image holds another one.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
model=$repo/models/cloud_xgboost.joblib
pub=$repo/lab/keys/model-signing.pub
IMG=idps-lab-collector:latest

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
in_image() { docker run --rm --network none --entrypoint sha256sum "$IMG" "$1" | cut -d' ' -f1; }

check() {
  bad=0
  for pair in "23csu441_1_23csu294_2_23csu095/idps/cloud/collector.py:/opt/idps/idps/cloud/collector.py" \
              "23csu441_1_23csu294_2_23csu095/idps/cloud/__main__.py:/opt/idps/idps/cloud/__main__.py" \
              "lab/cloud/guard.py:/opt/idps/lab/cloud/guard.py" \
              "models/cloud_xgboost.joblib:/opt/idps/cloud-model/cloud_xgboost.joblib" \
              "models/cloud_xgboost.joblib.sig:/opt/idps/cloud-model/cloud_xgboost.joblib.sig" \
              "models/cloud_xgboost.joblib.sha256:/opt/idps/cloud-model/cloud_xgboost.joblib.sha256" \
              "lab/keys/model-signing.pub:/opt/idps/cloud-keys/model-signing.pub"; do
    want=$(sha "$repo/${pair%%:*}")
    have=$(in_image "${pair#*:}")
    if [ "$want" != "$have" ]; then
      echo "build_collector: ${pair%%:*} in $IMG differs from the repo's (repo $want, image $have)" >&2
      bad=1
    fi
  done
  [ "$bad" = 0 ] || { echo "  rebuild with lab/cloud/build_collector.sh" >&2; return 1; }
  # The real test: the image's own copy of the model loads with the image's own public key
  # (signature, digest, feature layout), exactly as the collector will do it.
  docker run --rm --network none --entrypoint python "$IMG" -c "
from idps.cloud.collector import load_cloud_bundle
b = load_cloud_bundle('/opt/idps/cloud-model/cloud_xgboost.joblib', '/opt/idps/cloud-keys/model-signing.pub')
print('build_collector: baked model verified (signature ok),', len(b.features), 'features')" >&2
  echo "build_collector: baked guard.py, model, signature and public key match the repo"
}

if [ "${1:-}" = "--check" ]; then
  check
  exit $?
fi

for f in "$model" "$model.sha256" "$model.sig" "$pub"; do
  [ -f "$f" ] || { echo "build_collector: $f not found (train and sign the cloud model first)" >&2; exit 1; }
done
docker image inspect idps-lab-flowlog:latest >/dev/null 2>&1 \
  || { echo "build_collector: idps-lab-flowlog:latest is missing; run lab/cloud/build_flowlog.sh first" >&2; exit 1; }
docker image inspect idps-lab-soc-net:latest >/dev/null 2>&1 \
  || { echo "build_collector: idps-lab-soc-net:latest is missing (the lab's netns image)" >&2; exit 1; }
docker build --network none -f "$repo/lab/cloud/Dockerfile.collector" -t "$IMG" \
  --build-arg "MODEL_SHA256=$(sha "$model")" "$repo"
docker build --network none -f "$repo/lab/cloud/Dockerfile.collector-net" \
  -t idps-cloud-collector-net:latest "$repo/lab/cloud"
check
