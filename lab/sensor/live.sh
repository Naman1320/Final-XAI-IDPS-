#!/bin/sh
# python -m idps.live, sending alerts to the lab SOC when it has published a sensor token.
# Usage: docker compose exec sensor live.sh --interface lab_attack --model models/friday_xgboost.joblib
# Without the SOC (no token file yet) alerts go to data/processed/live_alerts.jsonl as before.
set -eu
SHARED=/run/idps-soc
if [ -s "$SHARED/sensor_token" ] && [ -s "$SHARED/ca.pem" ]; then
  IDPS_SOC_SENSOR_TOKEN=$(cat "$SHARED/sensor_token")
  export IDPS_SOC_SENSOR_TOKEN
  export IDPS_SOC_CA_FILE="$SHARED/ca.pem"
  if [ -s "$SHARED/sensor.pem" ] && [ -s "$SHARED/sensor.key" ]; then
    # Mutual TLS: the SOC's sensor port, with this sensor's certificate (lab/soc/bootstrap.py).
    export IDPS_SOC_URL="${IDPS_SOC_URL:-https://10.10.3.10:8444}"
    export IDPS_SOC_CLIENT_CERT="$SHARED/sensor.pem" IDPS_SOC_CLIENT_KEY="$SHARED/sensor.key"
  else
    export IDPS_SOC_URL="${IDPS_SOC_URL:-https://10.10.3.10:8443}"
  fi
else
  echo "live.sh: no lab SOC token in $SHARED; alerts go to a file" >&2
fi
# Rule-triggered blocks (IDPS_RULES_BLOCK_SIDS) never act on a source inside the protected network.
export IDPS_RULES_PROTECTED_NETS="${IDPS_RULES_PROTECTED_NETS:-10.10.2.0/24}"
# Signed models (idps.detect.signing): with the lab's public key in the image (lab/keys/), the
# sensor refuses a model without a valid signature from it.
if [ -s /opt/idps/keys/model-signing.pub ]; then
  export IDPS_MODEL_PUBLIC_KEY="${IDPS_MODEL_PUBLIC_KEY:-/opt/idps/keys/model-signing.pub}"
fi
exec python -m idps.live "$@"
