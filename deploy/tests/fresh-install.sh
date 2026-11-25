#!/bin/bash
# Fresh-machine check: copy the working tree (tracked + new, not ignored files) into an empty
# directory, run install.sh there and check that the dashboard works. Uses only the Compose
# project idps-pkg-fresh and removes it (with its volumes) at the end. Needs docker, curl, python3.
#   deploy/tests/fresh-install.sh
set -eu
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PROJECT=idps-pkg-fresh
HTTP=18080; HTTPS=18443; SENSOR=18444
WORK=$(mktemp -d "${TMPDIR:-/tmp}/idps-fresh.XXXXXX")
SRC="$WORK/src"
PASS=0; FAIL=0
SHA=$(git -C "$REPO" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] || SHA="$SHA-dirty"   # the copy has uncommitted changes
export IDPS_GIT_SHA="${IDPS_GIT_SHA:-$SHA}"
# The database image under a tag that is not on this machine: install.sh must pull it (a fresh
# machine has no postgres image). The shared postgres:16-alpine image is never touched.
DBIMG=postgres:16.4-alpine
export IDPS_DB_IMAGE="$DBIMG"
if docker image inspect "$DBIMG" >/dev/null 2>&1; then echo "$DBIMG is already present: remove it yourself (docker rmi $DBIMG) to prove the pull"; exit 2; fi

ok() { PASS=$((PASS + 1)); echo "PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL  $*"; }
check() { # check DESCRIPTION COMMAND...
  d=$1; shift
  if "$@" >"$WORK/check.out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/      /' "$WORK/check.out" | head -8; fi
}

cleanup() {
  echo "--- tearing down $PROJECT (containers, network, volumes)"
  if [ -f "$SRC/deploy/.env" ]; then
    sh "$SRC/deploy/install.sh" uninstall --delete-data --yes >/dev/null 2>&1 || true
  fi
  # belt and braces, this project only
  docker compose -p "$PROJECT" down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$PROJECT-sensor" --profile tools down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker rmi "$DBIMG" >/dev/null 2>&1 || true   # the image this script pulled (a different tag from the lab's)
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$SRC"
(cd "$REPO" && git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done 2>/dev/null) > "$WORK/files.list" || true
(cd "$REPO" && tar --null -T "$WORK/files.list" -cf -) | tar -xf - -C "$SRC"
# a fresh machine has no git history, no secrets and no generated deploy state
rm -rf "$SRC/deploy/secrets" "$SRC/deploy/.env" "$SRC/deploy/sensors"
echo "--- fresh copy: $SRC ($(wc -c < "$WORK/files.list" | tr -d ' ') bytes of file names)"

echo "--- install.sh soc"
sh "$SRC/deploy/install.sh" soc --host localhost --http-port $HTTP --https-port $HTTPS \
  --sensor-port $SENSOR --project $PROJECT --build 2>&1 | tee "$WORK/install.log" | tail -40
ENVF="$SRC/deploy/.env"
[ -f "$ENVF" ] || { bad "install.sh produced no deploy/.env"; exit 1; }
dc() { docker compose --env-file "$ENVF" -f "$SRC/deploy/compose/soc.yml" -p "$PROJECT" "$@"; }

echo "--- checks"
check "deploy/.env is mode 0600" test "$(stat -f %Lp "$ENVF" 2>/dev/null || stat -c %a "$ENVF")" = 600
for s in db_password jwt_secret mfa_key admin_password; do
  check "secrets/$s exists, mode 0600" test "$(stat -f %Lp "$SRC/deploy/secrets/$s" 2>/dev/null || stat -c %a "$SRC/deploy/secrets/$s")" = 600
done
leak=0
for s in db_password jwt_secret mfa_key admin_password; do
  if grep -qF -f "$SRC/deploy/secrets/$s" "$WORK/install.log"; then leak=1; fi
done
check "no secret value appears in install.sh output" test "$leak" = 0
check "install.sh pulled the database image $DBIMG (it was not on this machine)" sh -c "grep -q 'pulling $DBIMG' '$WORK/install.log' && docker image inspect $DBIMG >/dev/null"

CID=$(dc ps -q proxy)
docker cp "$CID:/data/caddy/pki/authorities/local/root.crt" "$WORK/caddy-root.crt" >/dev/null 2>&1 || true
CA="$WORK/caddy-root.crt"
if [ -s "$CA" ]; then ok "Caddy root CA extracted from the proxy container"; CURL="curl -sS --cacert $CA"; PYCA="$CA"
else bad "could not extract Caddy's root CA (falling back to curl -k)"; CURL="curl -sSk"; PYCA=""; fi
BASE="https://localhost:$HTTPS"

check "https dashboard index is served (certificate verified against Caddy's root)" sh -c "$CURL $BASE/ | grep -q '<div id=\"root\">'"
check "SPA fallback: /alerts/123 serves index.html" sh -c "$CURL $BASE/alerts/123 | grep -q '<div id=\"root\">'"
check "a built asset is served with a long cache lifetime" sh -c "
  a=\$($CURL $BASE/ | grep -o '/assets/index-[A-Za-z0-9_-]*\.js' | head -1); [ -n \"\$a\" ] &&
  $CURL -D - -o /dev/null $BASE\$a | grep -i 'cache-control' | grep -q immutable"
HDR="$WORK/headers.txt"
$CURL -D "$HDR" -o /dev/null "$BASE/" || true
check "X-Frame-Options DENY" grep -qi '^x-frame-options: DENY' "$HDR"
check "CSP has frame-ancestors 'none' and default-src 'self'" sh -c "grep -i '^content-security-policy' '$HDR' | grep -q \"frame-ancestors 'none'\" && grep -i '^content-security-policy' '$HDR' | grep -q \"default-src 'self'\""
check "no HSTS for a non-domain (tls internal) site" sh -c "! grep -qi '^strict-transport-security' '$HDR'"
check "http redirects to https with the right port" sh -c "curl -sS -D - -o /dev/null http://localhost:$HTTP/anything | tr -d '\r' | grep -i '^location: https://localhost:$HTTPS/anything'"
check "/api/health through the proxy is ok" python3 -I "$HERE/api_check.py" health --base "$BASE" ${PYCA:+--cafile "$PYCA"}
check "the SOC main port 8000 is not published (docker's port table)" sh -c "! docker port $(dc ps -q soc) | grep -q '^8000/'"
check "only the proxy's fixed address may set X-Forwarded-For (soc env = proxy IP; proxy has that address)" sh -c "
  ip=\$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(dc ps -q proxy));
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' $(dc ps -q soc) | grep -qx \"IDPS_FORWARDED_ALLOW_IPS=\$ip\" && [ \"\$ip\" != '*' ]"
check "the running soc container has no CA private key (cakeys volume is soc-admin only)" sh -c "! docker exec $(dc ps -q soc) sh -c 'ls /var/lib/idps-cakeys 2>/dev/null | grep -q .' 2>/dev/null"
soc_proc_ok() {
  st=$(docker exec "$(dc ps -q soc)" cat /proc/1/status) || return 1
  echo "$st" | grep -Eq '^Uid:[[:space:]]+10001[[:space:]]+10001' && echo "$st" | grep -Eq '^CapEff:[[:space:]]+0+$'
}
check "the API process (pid 1 of soc) runs as uid 10001 with no capabilities" soc_proc_ok
check "only 8444 is published by the soc service, and the db publishes nothing" sh -c "
  [ \"\$(docker port $(dc ps -q soc) | cut -d/ -f1 | sort -u)\" = 8444 ] && [ -z \"\$(docker port $(dc ps -q db))\" ]"
check "login with the generated admin password demands MFA enrolment (mfa=enrol, no token)" \
  python3 -I "$HERE/api_check.py" login-state --base "$BASE" ${PYCA:+--cafile "$PYCA"} --password-file "$SRC/deploy/secrets/admin_password"

SURL="https://localhost:$SENSOR"
# the sensor port's certificate is signed by the SOC's own server CA, which the bundle carries
sh "$SRC/deploy/install.sh" add-sensor test1 > "$WORK/add.log" 2>&1 && ok "install.sh add-sensor test1" || { bad "install.sh add-sensor test1"; cat "$WORK/add.log"; }
B="$SRC/deploy/sensors/test1"
for f in token client.pem client.key ca.pem sensor.env; do check "bundle has $f" test -s "$B/$f"; done
check "bundle token and client.key are mode 0600, directory 0700" sh -c "
  m() { stat -f %Lp \"\$1\" 2>/dev/null || stat -c %a \"\$1\"; }
  [ \"\$(m $B/token)\" = 600 ] && [ \"\$(m $B/client.key)\" = 600 ] && [ \"\$(m $B)\" = 700 ]"
check "sensor.env names the SOC sensor URL" grep -qx "IDPS_SOC_URL=$SURL" "$B/sensor.env"
check "sensor port refuses a client without a certificate" python3 -I "$HERE/api_check.py" sensor-nocert --sensor-url "$SURL" --cafile "$B/ca.pem"
check "sensor port accepts an alert with the client certificate and token" python3 -I "$HERE/api_check.py" sensor-post --sensor-url "$SURL" --cafile "$B/ca.pem" --bundle "$B" --count 1
check "the sensor token alone is refused on the dashboard port (mutual TLS is required)" python3 -I "$HERE/api_check.py" sensor-on-main --base "$BASE" ${PYCA:+--cafile "$PYCA"} --bundle "$B"
fp() { # fingerprints of everything that must survive a second run
  { cat "$SRC/deploy/secrets/db_password" "$SRC/deploy/secrets/jwt_secret" "$SRC/deploy/secrets/mfa_key" "$SRC/deploy/secrets/admin_password"
    docker run --rm --network none -v "${PROJECT}_pki:/p:ro" --entrypoint sh "idps-soc:$(sed -n 's/^IDPS_TAG=//p' "$ENVF")" -c 'cat /p/sensor-ca.pem /p/server-ca.pem /p/server.pem'
  } | cksum
}
FP1=$(fp)
sh "$SRC/deploy/install.sh" soc --image-tag "$(sed -n 's/^IDPS_TAG=//p' "$ENVF")" > "$WORK/install2.log" 2>&1 && ok "second 'install.sh soc' run succeeds" || { bad "second install.sh soc run failed"; tail -5 "$WORK/install2.log"; }
FP2=$(fp)
[ "$FP1" = "$FP2" ] && ok "idempotent: db_password, jwt_secret, mfa_key, admin_password, sensor CA, server CA and server certificate unchanged" || bad "a second run changed secrets or certificates"
check "the admin user was not re-created (no second admin_password written)" sh -c "! grep -q 'generated password' '$WORK/install2.log'"
check "after the second run the test1 bundle still posts alerts" python3 -I "$HERE/api_check.py" sensor-post --sensor-url "$SURL" --cafile "$B/ca.pem" --bundle "$B" --count 2 --offset 100
check "install.sh status runs" sh "$SRC/deploy/install.sh" status

echo "--- sensor image (no capture here: the real image is run once without host networking)"
printf 'not a model' > "$WORK/m.joblib"
# the sensor image is big: IDPS_FRESH_SENSOR_TAG=<tag> uses an image that is already built
if [ -n "${IDPS_FRESH_SENSOR_TAG:-}" ]; then SENSOR_IMG_ARGS="--image-tag $IDPS_FRESH_SENSOR_TAG"; else SENSOR_IMG_ARGS="--build"; fi
sh "$SRC/deploy/install.sh" sensor --bundle "$B" --interface lo --model "$WORK/m.joblib" --project "$PROJECT-sensor" $SENSOR_IMG_ARGS --no-start > "$WORK/sensor-install.log" 2>&1 \
  && ok "install.sh sensor --build --no-start" || { bad "install.sh sensor failed"; tail -8 "$WORK/sensor-install.log"; }
STAG=$(sed -n 's/^IDPS_TAG=//p' "$SRC/deploy/.env.sensor")
check "sensor compose has no DAC_READ_SEARCH and mounts the bundle volume read-only" sh -c "
  docker compose --env-file $SRC/deploy/.env.sensor -f $SRC/deploy/compose/sensor.yml -p $PROJECT-sensor config | grep -q DAC_ && exit 1; exit 0"
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --security-opt no-new-privileges:true \
  -v "$PROJECT-sensor_sensor_enrol:/enrol:ro" -v "$SRC/deploy/sensor-data/models:/models:ro" \
  -e IDPS_SOC_URL="https://localhost:$SENSOR" -e IDPS_INTERFACE=lo -e IDPS_MODEL_FILE=m.joblib \
  "idps-sensor:$STAG" > "$WORK/sensor-run.log" 2>&1 || true
check "the sensor entrypoint read the bundle (volume) and reached the model with only NET_ADMIN/NET_RAW" sh -c "grep -q 'cannot load the model /models/m.joblib' '$WORK/sensor-run.log' && ! grep -q '/enrol/.* is missing' '$WORK/sensor-run.log'"
check "the sensor image is CPU-only: no nvidia-* packages" sh -c "! docker run --rm --entrypoint sh idps-sensor:$STAG -c 'pip list 2>/dev/null | grep -i nvidia' | grep -q ."

echo "--- result: $PASS passed, $FAIL failed"
[ -s "$CA" ] || echo "note: curl -k was used (root CA could not be extracted)"
[ "$FAIL" = 0 ]
