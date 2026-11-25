#!/bin/bash
# Upgrade, restore, failed-upgrade and rollback checks, 0.1.0 -> the working tree's version.
# Uses only the Compose project idps-pkg-upgrade and removes it (with its volumes) at the end.
# Needs docker, git, curl, python3.
#
# WHAT THIS PROVES AND WHAT IT DOES NOT. Commit 6767ebb (0.1.0) has no Dockerfiles or deploy/
# folder, so the "0.1.0" images are a hybrid: 6767ebb's application code (git archive; the git
# repository is not touched) built with the new Dockerfiles and VERSION=0.1.0, plus three files
# taken from the new tree because the packaging needs them (soc/api/serve.py without TLS,
# create-user --password-file, the server-cert command: soc/api/serve.py, soc/api/__main__.py,
# soc/api/pki.py). Models and migrations are 0.1.0's. It is NOT a byte-for-byte earlier release.
# 0.1.0 and 0.2.0 have the same schema revision (0002_mfa_oidc: no migration in step 12), so the
# script puts the database back to revision 0001_initial (alembic downgrade, with the SOC
# stopped) before upgrading: the upgrade then really applies migration 0002.
#   deploy/tests/upgrade.sh
set -eu
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OLD_COMMIT=6767ebb
PROJECT=idps-pkg-upgrade
HTTP=19080; HTTPS=19443; SENSOR=19444
WORK=$(mktemp -d "${TMPDIR:-/tmp}/idps-upgrade.XXXXXX")
OLD="$WORK/old"; NEW="$WORK/new"
PASS=0; FAIL=0
SHA=$(git -C "$REPO" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] || SHA="$SHA-dirty"
export IDPS_GIT_SHA="${IDPS_GIT_SHA:-$SHA}"

ok() { PASS=$((PASS + 1)); echo "PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL  $*"; }
check() { d=$1; shift; if "$@" >"$WORK/check.out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/      /' "$WORK/check.out" | head -8; fi; }

cleanup() {
  echo "--- tearing down $PROJECT (containers, network, volumes)"
  for d in "$NEW" "$OLD"; do
    if [ -f "$d/deploy/.env" ]; then sh "$d/deploy/install.sh" uninstall --delete-data --yes >/dev/null 2>&1 || true; break; fi
  done
  docker compose -p "$PROJECT" --profile tools down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker rmi idps-soc:0.0.0-broken idps-proxy:0.0.0-broken idps-soc:0.0.9 idps-proxy:0.0.9 idps-soc:0.0.8-nostart idps-proxy:0.0.8-nostart >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OLD" "$NEW"
echo "--- exporting $OLD_COMMIT and the working tree"
(cd "$REPO" && git archive "$OLD_COMMIT") | tar -xf - -C "$OLD"
(cd "$REPO" && git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done 2>/dev/null) > "$WORK/files.list" || true
(cd "$REPO" && tar --null -T "$WORK/files.list" -cf -) | tar -xf - -C "$NEW"
rm -rf "$NEW/deploy/secrets" "$NEW/deploy/.env" "$NEW/deploy/sensors"
[ ! -e "$OLD/deploy" ] || { echo "unexpected: $OLD_COMMIT already has deploy/"; exit 1; }
cp -R "$NEW/deploy" "$OLD/deploy"
for f in soc/api/serve.py soc/api/__main__.py soc/api/pki.py; do cp "$NEW/$f" "$OLD/$f"; done
OLD_VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$OLD/pyproject.toml" | head -1)
NEW_VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$NEW/pyproject.toml" | head -1)
echo "--- old version $OLD_VER (hybrid, see the header), new version $NEW_VER"
[ "$OLD_VER" = 0.1.0 ] || { echo "the old tree is not 0.1.0"; exit 1; }

echo "--- install $OLD_VER (install.sh soc --build from the old tree)"
sh "$OLD/deploy/install.sh" soc --host localhost --http-port $HTTP --https-port $HTTPS \
  --sensor-port $SENSOR --project $PROJECT --build 2>&1 | tail -6
ENVF="$OLD/deploy/.env"; TREE="$OLD"
dc() { docker compose --env-file "$ENVF" -f "$TREE/deploy/compose/soc.yml" -p "$PROJECT" "$@"; }
check "installed version is $OLD_VER (container image tag and .env)" sh -c "
  [ \"\$(docker inspect -f '{{.Config.Image}}' $(dc ps -q soc))\" = idps-soc:$OLD_VER ] && grep -qx IDPS_TAG=$OLD_VER $ENVF"

CA="$WORK/caddy-root.crt"
docker cp "$(dc ps -q proxy):/data/caddy/pki/authorities/local/root.crt" "$CA" >/dev/null
BASE="https://localhost:$HTTPS"; SURL="https://localhost:$SENSOR"
API="$HERE/api_check.py"
AP="$WORK/analyst_pw"; od -An -v -tx1 -N18 /dev/urandom | tr -d ' \n' > "$AP"
snap_analyst() { python3 -I "$API" snapshot --user analyst1 --base "$BASE" --cafile "$CA" --password-file "$AP" "$@"; }

echo "--- data on $OLD_VER: sensor, 7 alerts, an analyst, a case"
sh "$OLD/deploy/install.sh" add-sensor up1 >/dev/null
B="$OLD/deploy/sensors/up1"
check "7 alerts ingested through the sensor port (token + client certificate)" python3 -I "$API" sensor-post --sensor-url "$SURL" --cafile "$B/ca.pem" --bundle "$B" --count 7
dc run --rm -T soc-admin sh -c 'umask 077; cat > /tmp/pw && python -m soc.api create-user analyst1 --role analyst --password-file /tmp/pw' < "$AP" >/dev/null 2>&1 || { echo "cannot create analyst1"; exit 1; }
BEFORE=$(snap_analyst --create-case "before upgrade")
echo "before upgrade: $BEFORE"
[ "$BEFORE" = "alerts=7 cases=1" ] && ok "counts before the upgrade are alerts=7 cases=1" || bad "unexpected counts before the upgrade: $BEFORE"

echo "--- put the database back to revision 0001_initial (SOC stopped) so the upgrade has a migration to apply"
dc stop soc proxy >/dev/null 2>&1
dc run --rm -T soc-admin python -c "
import os
from alembic import command
from soc.api import migrate
from soc.api.db import make_engine
e = make_engine(os.environ['IDPS_SOC_DATABASE_URL'])
with e.begin() as c:
    command.downgrade(migrate.alembic_config(c), '0001_initial')
" >/dev/null 2>&1 || { echo "downgrade failed"; exit 1; }
has_mfa_cols() { dc run --rm -T soc-admin python -c "
import os
import sqlalchemy as sa
from soc.api.db import make_engine
print('mfa_enabled' in {c['name'] for c in sa.inspect(make_engine(os.environ['IDPS_SOC_DATABASE_URL'])).get_columns('users')})
" 2>/dev/null; }
CUR=$(dc run --rm -T soc-admin python -m soc.api db current 2>/dev/null | tail -1)
[ "$CUR" = 0001_initial ] && ok "database is at 0001_initial" || bad "database revision is $CUR, not 0001_initial"
[ "$(has_mfa_cols | tail -1)" = False ] && ok "users has no mfa_enabled column before the upgrade" || bad "users still has the MFA columns"

echo "--- install.sh upgrade --build (new tree, state carried over)"
cp -R "$OLD/deploy/secrets" "$NEW/deploy/secrets"; cp -R "$OLD/deploy/sensors" "$NEW/deploy/sensors"
cp "$OLD/deploy/.env" "$NEW/deploy/.env"; cp "$OLD/deploy/caddy-root.crt" "$NEW/deploy/" 2>/dev/null || true
sh "$NEW/deploy/install.sh" upgrade --build 2>&1 | tee "$WORK/upgrade.log" | tail -12
ENVF="$NEW/deploy/.env"; TREE="$NEW"
INST="sh $NEW/deploy/install.sh"

echo "--- checks after the upgrade"
check "IDPS_TAG is now $NEW_VER and IDPS_PREVIOUS_TAG is $OLD_VER-previous" sh -c "grep -qx IDPS_TAG=$NEW_VER $ENVF && grep -qx IDPS_PREVIOUS_TAG=$OLD_VER-previous $ENVF"
check "the running soc and proxy containers use images idps-soc/idps-proxy:$NEW_VER" sh -c "
  [ \"\$(docker inspect -f '{{.Config.Image}}' $(dc ps -q soc))\" = idps-soc:$NEW_VER ] &&
  [ \"\$(docker inspect -f '{{.Config.Image}}' $(dc ps -q proxy))\" = idps-proxy:$NEW_VER ]"
check "the old images are kept as idps-soc/idps-proxy:$OLD_VER-previous" sh -c "docker image inspect idps-soc:$OLD_VER-previous idps-proxy:$OLD_VER-previous >/dev/null"
check "the new image's OCI version label is $NEW_VER" sh -c "[ \"\$(docker image inspect -f '{{index .Config.Labels \"org.opencontainers.image.version\"}}' idps-soc:$NEW_VER)\" = $NEW_VER ]"
AFTER=$(snap_analyst)
echo "after upgrade: $AFTER"
[ "$AFTER" = "alerts=7 cases=1" ] && ok "alert and case counts unchanged (alerts=7 cases=1); the analyst's login still works" || bad "counts changed: $AFTER"
check "database is at head (python -m soc.api db check)" dc run --rm -T soc-admin python -m soc.api db check
[ "$(has_mfa_cols | tail -1)" = True ] && ok "migration 0002 was applied: users now has the MFA columns" || bad "the MFA columns are missing after the upgrade"
check "upgrade printed 'db current' (the revision)" grep -q "Database revision" "$WORK/upgrade.log"
BK=$(docker run --rm --entrypoint sh -v "${PROJECT}_backups:/b:ro" "idps-soc:$NEW_VER" -c 'ls -1 /b' | grep "^pre-upgrade-$OLD_VER-to-$NEW_VER-.*\.jsonl\.gz$" | head -1 || true)
[ -n "$BK" ] && ok "backup file exists in the backups volume: $BK" || bad "no backup file in the backups volume"
check "the backup was taken at revision 0001_initial (before the migration)" sh -c "docker run --rm --entrypoint sh -v ${PROJECT}_backups:/b:ro idps-soc:$NEW_VER -c 'zcat /b/$BK | head -c 600' | grep -q 0001_initial"
check "an old enrolment bundle (0.1.0 era) still works: alert accepted on the sensor port" python3 -I "$API" sensor-post --sensor-url "$SURL" --cafile "$B/ca.pem" --bundle "$B" --count 1 --offset 50
check "the dashboard still serves index.html through the same Caddy certificate" sh -c "curl -sS --cacert $CA $BASE/ | grep -q '<div id=\"root\">'"
SNAP=8   # 7 + the alert just posted

echo "--- admin MFA on the new version, then restore (secrets and certificates kept)"
dc run --rm -T soc-admin sh -c 'umask 077; python -m soc.api mfa-enrol admin --secret-file /tmp/s >&2 && cat /tmp/s' > "$WORK/totp" 2>/dev/null || { echo "mfa-enrol failed"; exit 1; }
PW="$NEW/deploy/secrets/admin_password"
snap_admin() { python3 -I "$API" snapshot --base "$BASE" --cafile "$CA" --password-file "$PW" --totp-file "$WORK/totp" "$@"; }
A1=$(snap_admin)
[ "$A1" = "alerts=$SNAP cases=1" ] && ok "admin signs in with the password and a TOTP code after the upgrade ($A1)" || bad "admin snapshot: $A1"
dc run --rm -T soc-admin python -m soc.api backup /var/lib/idps-backups/post-upgrade.jsonl.gz >/dev/null 2>&1 && ok "manual backup post-upgrade.jsonl.gz" || bad "manual backup failed"
A2=$(snap_admin --create-case "made after the backup")
[ "$A2" = "alerts=$SNAP cases=2" ] && ok "a case made after the backup exists (cases=2)" || bad "unexpected: $A2"
SECRETS_BEFORE=$(cat "$NEW"/deploy/secrets/* | cksum)
$INST restore post-upgrade.jsonl.gz --yes > "$WORK/restore1.log" 2>&1 && ok "install.sh restore post-upgrade.jsonl.gz --yes" || { bad "restore failed"; tail -15 "$WORK/restore1.log"; }
A3=$(snap_admin)
echo "after restore: $A3"
[ "$A3" = "alerts=$SNAP cases=1" ] && ok "restore brought the database back to the backup (cases=2 -> cases=1); admin login with MFA still works" || bad "after restore: $A3"
check "secrets were kept by the restore" sh -c "[ \"$SECRETS_BEFORE\" = \"\$(cat $NEW/deploy/secrets/* | cksum)\" ]"
check "the database is at head after the restore" dc run --rm -T soc-admin python -m soc.api db check
check "a safety copy pre-restore-*.jsonl.gz of the replaced database exists" sh -c "docker run --rm --entrypoint sh -v ${PROJECT}_backups:/b:ro idps-soc:$NEW_VER -c 'ls /b' | grep -q '^pre-restore-'"
check "an enrolment bundle still works after the restore (certificates kept)" python3 -I "$API" sensor-post --sensor-url "$SURL" --cafile "$B/ca.pem" --bundle "$B" --count 1 --offset 60
SNAP=9
docker run --rm --entrypoint sh -v "${PROJECT}_backups:/b:ro" "idps-soc:$NEW_VER" -c "cat /b/$BK" > "$WORK/pre-upgrade.jsonl.gz"
$INST restore "$WORK/pre-upgrade.jsonl.gz" --yes > "$WORK/restore2.log" 2>&1 && ok "install.sh restore HOST_PATH (the pre-upgrade backup, revision 0001_initial)" || { bad "restore of the pre-upgrade backup failed"; tail -15 "$WORK/restore2.log"; }
R2=$(snap_analyst)
[ "$R2" = "alerts=7 cases=1" ] && ok "the pre-upgrade backup restored: alerts=7 cases=1 (migrated to head at start-up)" || bad "after the second restore: $R2"
check "database is at head after restoring the old backup" dc run --rm -T soc-admin python -m soc.api db check
check "a restored pre-MFA admin has to enrol again (login says mfa=enrol)" python3 -I "$API" login-state --base "$BASE" --cafile "$CA" --password-file "$PW"
check "restore refuses a missing backup and changes nothing" sh -c "! $INST restore does-not-exist.jsonl.gz --yes"
check "restore refuses a damaged file before touching the database" sh -c "head -c 100 $WORK/pre-upgrade.jsonl.gz > $WORK/bad.jsonl.gz; ! $INST restore $WORK/bad.jsonl.gz --yes && [ \"\$(python3 -I $API snapshot --user analyst1 --base $BASE --cafile $CA --password-file $AP)\" = 'alerts=7 cases=1' ]"

echo "--- a failed upgrade rolls back"
printf 'FROM idps-soc:%s\nENTRYPOINT ["sh","-c","echo broken image >&2; exit 1"]\n' "$NEW_VER" | docker build -q -t idps-soc:0.0.0-broken - >/dev/null
docker tag "idps-proxy:$NEW_VER" idps-proxy:0.0.0-broken
IDPS_HEALTH_TIMEOUT=45 $INST upgrade --image-tag 0.0.0-broken > "$WORK/failed.log" 2>&1 && bad "the broken upgrade reported success" || ok "the broken upgrade exits non-zero"
grep -E "FAILED|rolled back" "$WORK/failed.log" | sed 's/^/      /'
check "IDPS_TAG is back to $NEW_VER" grep -qx "IDPS_TAG=$NEW_VER" "$ENVF"
check "soc is healthy again on the old image" sh -c "[ \"\$(docker inspect -f '{{.Config.Image}} {{.State.Health.Status}}' $(dc ps -q soc))\" = 'idps-soc:$NEW_VER healthy' ]"
check "the failed upgrade's backup exists" sh -c "docker run --rm --entrypoint sh -v ${PROJECT}_backups:/b:ro idps-soc:$NEW_VER -c 'ls /b' | grep -q '^pre-upgrade-$NEW_VER-to-0.0.0-broken-'"
F1=$(snap_analyst)
[ "$F1" = "alerts=7 cases=1" ] && ok "data intact after the failed upgrade (alerts=7 cases=1)" || bad "after the failed upgrade: $F1"
check "the dashboard answers through the proxy" sh -c "curl -sS --cacert $CA $BASE/ | grep -q '<div id=\"root\">'"
echo "--- install.sh rollback"
$INST rollback > "$WORK/rollback.log" 2>&1 && ok "install.sh rollback" || { bad "rollback failed"; tail -8 "$WORK/rollback.log"; }
check "rollback switched to the saved images ($NEW_VER-previous) and the stack is healthy" sh -c "grep -qx IDPS_TAG=$NEW_VER-previous $ENVF && [ \"\$(docker inspect -f '{{.State.Health.Status}}' $(dc ps -q soc))\" = healthy ]"
R3=$(snap_analyst)
[ "$R3" = "alerts=7 cases=1" ] && ok "data intact after rollback" || bad "after rollback: $R3"
check "a plain re-run of 'install.sh soc' keeps the rolled-back tag (no --image-tag/--build)" sh -c "$INST soc >/dev/null 2>&1 && grep -qx IDPS_TAG=$NEW_VER-previous $ENVF"
check "the stack is still healthy after the re-run" sh -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $(dc ps -q soc))\" = healthy ]"
$INST soc --image-tag "$NEW_VER" >/dev/null 2>&1 && grep -qx "IDPS_TAG=$NEW_VER" "$ENVF" && ok "an explicit --image-tag still wins ($NEW_VER)" || bad "install.sh soc --image-tag $NEW_VER did not switch"
check "a caller's IDPS_TAG/IDPS_SITE in the environment do not override deploy/.env" sh -c "IDPS_TAG=0.0.0-broken IDPS_SITE=evil $INST soc >/dev/null 2>&1 && grep -qx IDPS_TAG=$NEW_VER $ENVF && grep -qx IDPS_SITE=localhost $ENVF && [ \"\$(docker inspect -f '{{.Config.Image}}' $(dc ps -q soc))\" = idps-soc:$NEW_VER ]"

echo "--- rollback after a migration is refused; a previous version that will not start is undone"
printf 'FROM idps-soc:%s\nUSER root\nRUN rm -f /opt/venv/lib/python3.12/site-packages/soc/api/migrations/versions/0002_mfa_oidc.py\nUSER 10001:10001\n' "$NEW_VER" | docker build -q -t idps-soc:0.0.9 - >/dev/null
docker tag "idps-proxy:$NEW_VER" idps-proxy:0.0.9
printf 'FROM idps-soc:%s\nCMD ["no-such-command"]\n' "$NEW_VER" | docker build -q -t idps-soc:0.0.8-nostart - >/dev/null
docker tag "idps-proxy:$NEW_VER" idps-proxy:0.0.8-nostart
set_prev() { sed "s/^IDPS_PREVIOUS_TAG=.*/IDPS_PREVIOUS_TAG=$1/" "$ENVF" > "$ENVF.t" && chmod 600 "$ENVF.t" && mv "$ENVF.t" "$ENVF"; }
set_prev 0.0.9
$INST rollback > "$WORK/rb-refused.log" 2>&1 && bad "rollback to a version that does not know the schema succeeded" || ok "rollback is refused when the previous image does not know the database revision (migration 0002 ran)"
check "the refusal says so and points at 'restore'" sh -c "grep -q 'does not know the database' $WORK/rb-refused.log && grep -q 'install.sh restore' $WORK/rb-refused.log"
check "after the refusal the SOC still runs healthy on $NEW_VER" sh -c "grep -qx IDPS_TAG=$NEW_VER $ENVF && [ \"\$(docker inspect -f '{{.Config.Image}} {{.State.Health.Status}}' $(dc ps -q soc))\" = 'idps-soc:$NEW_VER healthy' ]"
set_prev 0.0.8-nostart
IDPS_HEALTH_TIMEOUT=45 $INST rollback > "$WORK/rb-fail.log" 2>&1 && bad "rollback to an image that cannot start succeeded" || ok "rollback to a previous image that knows the schema but cannot start exits non-zero"
check "...and switches back to $NEW_VER: tag restored and soc healthy" sh -c "grep -qx IDPS_TAG=$NEW_VER $ENVF && grep -q 'switching back' $WORK/rb-fail.log && [ \"\$(docker inspect -f '{{.Config.Image}} {{.State.Health.Status}}' $(dc ps -q soc))\" = 'idps-soc:$NEW_VER healthy' ]"
R4=$(snap_analyst)
[ "$R4" = "alerts=7 cases=1" ] && ok "data intact after the refused and failed rollbacks" || bad "after the rollback tests: $R4"

echo "--- renew-sensor"
B2="$NEW/deploy/sensors/up1"   # the state copied into the new tree
TOK1=$(cksum < "$B2/token"); CRT1=$(cksum < "$B2/client.pem")
$INST renew-sensor up1 > "$WORK/renew.log" 2>&1 && ok "install.sh renew-sensor up1" || { bad "renew-sensor failed"; tail -5 "$WORK/renew.log"; }
[ "$TOK1" = "$(cksum < "$B2/token")" ] && [ "$CRT1" != "$(cksum < "$B2/client.pem")" ] && ok "same token, new client certificate" || bad "renew did not keep the token / change the certificate"
check "the renewed bundle posts alerts on the sensor port" python3 -I "$API" sensor-post --sensor-url "$SURL" --cafile "$B2/ca.pem" --bundle "$B2" --count 1 --offset 70
check "the bundle directory is still 0700, key and token 0600" sh -c "m() { stat -f %Lp \"\$1\" 2>/dev/null || stat -c %a \"\$1\"; }; [ \"\$(m $B2)\" = 700 ] && [ \"\$(m $B2/client.key)\" = 600 ] && [ \"\$(m $B2/token)\" = 600 ]"
check "renew-sensor refuses a sensor that does not exist" sh -c "mkdir -p $NEW/deploy/sensors/ghost && ! $INST renew-sensor ghost && [ ! -e $NEW/deploy/sensors/ghost/client.pem ]"
check "install.sh status runs" sh "$NEW/deploy/install.sh" status

echo "--- result: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
