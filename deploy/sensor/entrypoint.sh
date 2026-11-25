#!/bin/sh
# idps-sensor: starts python -m idps.live with the enrolment bundle from /enrol (read-only mount):
#   token, client.pem, client.key, ca.pem (+ model-signing.pub optional), and the model from /models.
# IDPS_SOC_URL, IDPS_INTERFACE and IDPS_MODEL_FILE come from the environment (deploy/.env.sensor).
set -eu
E=/enrol
for f in token client.pem client.key ca.pem; do
  [ -s "$E/$f" ] || { echo "idps-sensor: $E/$f is missing (the enrolment bundle from 'install.sh add-sensor')" >&2; exit 1; }
done
: "${IDPS_SOC_URL:?IDPS_SOC_URL is not set}"
: "${IDPS_INTERFACE:?IDPS_INTERFACE is not set}"
: "${IDPS_MODEL_FILE:?IDPS_MODEL_FILE is not set}"
case "$IDPS_SOC_URL" in https://*) ;; *) echo "idps-sensor: IDPS_SOC_URL must be https://" >&2; exit 1 ;; esac
case "$IDPS_MODEL_FILE" in */*|"") echo "idps-sensor: IDPS_MODEL_FILE is a file name inside /models" >&2; exit 1 ;; esac
[ -s "/models/$IDPS_MODEL_FILE" ] || { echo "idps-sensor: /models/$IDPS_MODEL_FILE is missing" >&2; exit 1; }
IDPS_SOC_SENSOR_TOKEN=$(head -n 1 "$E/token" | tr -d '\r\n')
export IDPS_SOC_SENSOR_TOKEN
export IDPS_SOC_CA_FILE="$E/ca.pem" IDPS_SOC_CLIENT_CERT="$E/client.pem" IDPS_SOC_CLIENT_KEY="$E/client.key"
# Signed models: with a public key, the sensor refuses a model without a valid signature.
if [ -s "$E/model-signing.pub" ]; then
  export IDPS_MODEL_PUBLIC_KEY="$E/model-signing.pub"
fi
# State (the unsent-alert outbox, local alert file) goes to the writable volume.
export IDPS_LIVE_OUTBOX_FILE="${IDPS_LIVE_OUTBOX_FILE:-/var/lib/idps-sensor/live_outbox.json}"
export IDPS_LIVE_ALERTS_FILE="${IDPS_LIVE_ALERTS_FILE:-/var/lib/idps-sensor/live_alerts.jsonl}"
exec python -m idps.live --interface "$IDPS_INTERFACE" --model "/models/$IDPS_MODEL_FILE"
