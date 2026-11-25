#!/bin/sh
# Start (or stop) the cloud collector, live against the emulated AWS and the lab SOC (C4).
#   lab/cloud/start_collector.sh          start
#   lab/cloud/start_collector.sh stop     stop collector and collector-net (volumes stay)
# Needs: the lab running (lab/docker-compose.yml, incl. the SOC), the emulator with its bucket
# (docker compose -f lab/cloud/docker-compose.yml up -d; lab/cloud/tf.sh apply), the exporter
# (flowlog-writer + flowlog-shipper) to have something to read, lab/cloud/build_collector.sh
# once, LAB_SOC_EXTRA_SENSOR_ADDRS=10.10.3.3 in lab/.env (so the SOC's firewall accepts the
# collector on 8444; then recreate soc-net soc-db soc), and lab/cloud/collector_provision.sh once.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
compose="docker compose -f $repo/lab/cloud/docker-compose.yml --profile collector"

if [ "${1:-start}" = stop ]; then
  $compose stop collector collector-net
  exit 0
fi

fail() { echo "start_collector: $*" >&2; exit 1; }
for c in idps-soc idps-soc-net idps-sensor; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || fail "$c is not running (start the lab)"
done
# The SOC's firewall must already accept the collector (netguard.sh logs "also open to").
docker logs idps-soc-net 2>&1 | grep -q "sensor port 8444 also open to 10.10.3.3" \
  || fail "the SOC does not accept 10.10.3.3 on 8444: set LAB_SOC_EXTRA_SENSOR_ADDRS=10.10.3.3 in lab/.env and run (in lab/) docker compose up -d --no-build --force-recreate soc-net soc-db soc"
[ "$(docker inspect -f '{{.State.Health.Status}}' idps-cloud-moto 2>/dev/null)" = healthy ] || fail "the emulator is not up (docker compose -f lab/cloud/docker-compose.yml up -d)"
docker image inspect idps-lab-collector:latest >/dev/null 2>&1 || fail "no collector image: run lab/cloud/build_collector.sh"
"$repo/lab/cloud/build_collector.sh" --check >/dev/null || fail "the collector image is stale: run lab/cloud/build_collector.sh"
docker volume inspect idps-cloud_collector_secrets >/dev/null 2>&1 || fail "no credentials yet: run lab/cloud/collector_provision.sh"

# The SOC's own bootstrap rewrites its sensor CA file when it re-issues the lab sensor's certificate
# (a new data volume, a replaced lab token, or 30 days before that certificate expires) and so drops
# the cloud CA. Check it (public certificates only, by fingerprint) before starting.
set +e
facts=$(docker exec -i idps-soc python - --check < "$repo/lab/cloud/collector_provision.py" 2>/dev/null)
rc=$?
set -e
printf '%s\n' "$facts" | while IFS='=' read -r k v; do
  case "$k" in client_cert_days_left|cloud_ca_days_left)
    [ "$v" -ge 30 ] 2>/dev/null || echo "start_collector: WARNING the collector's ${k%_days_left} expires in $v days: run lab/cloud/collector_provision.sh (re-issues it)" >&2 ;;
  esac
done
case "$rc" in
  0) ;;
  3) echo "start_collector: the SOC's sensor CA file no longer trusts the cloud CA (the SOC's bootstrap rewrote it); re-issuing now" >&2
     "$repo/lab/cloud/collector_provision.sh"
     fail "the SOC reads that file only at start: run 'docker restart idps-soc', wait until it is healthy, then run this again" ;;
  4) fail "the cloud CA was added to the SOC's sensor CA file after the SOC started: run 'docker restart idps-soc', wait until it is healthy, then run this again" ;;
  *) fail "could not check the SOC's sensor CA file (exit $rc)" ;;
esac

if [ "${LAB_CLOUD_DRY_RUN:-false}" = true ]; then
  nacl=""
else
  nacl=$("$repo/lab/cloud/tf.sh" output -raw target_nacl_id 2>/dev/null | tail -n 1) || nacl=""
  case "$nacl" in
    acl-[0-9a-f]*) ;;
    *) fail "cannot read the emulated network ACL id (lab/cloud/tf.sh output target_nacl_id): has 'lab/cloud/tf.sh apply' run?" ;;
  esac
fi
LAB_CLOUD_NACL_ID=$nacl $compose up -d --no-build collector-net collector
echo "start_collector: started; logs: docker logs -f idps-collector"
