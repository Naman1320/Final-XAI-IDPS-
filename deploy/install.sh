#!/bin/sh
# IDPS installer. See docs/deploy.md.
#
#   install.sh soc [--domain NAME | --host IP_OR_NAME] [--http-port N] [--https-port N]
#                  [--sensor-port N] [--project NAME] [--build | --image-tag TAG]
#   install.sh add-sensor NAME
#   install.sh renew-sensor NAME
#   install.sh sensor --bundle DIR --interface IFACE --model FILE [--public-key FILE]
#                     [--build | --image-tag TAG] [--project NAME] [--no-start]
#   install.sh upgrade [--build | --image-tag TAG]
#   install.sh rollback
#   install.sh restore BACKUP [--yes]
#   install.sh status
#   install.sh uninstall [--keep-data | --delete-data] [--yes]
#
# Secrets are written to files (mode 0600) under deploy/secrets and are never printed.
set -eu
umask 077
# The caller's environment must not override deploy/.env (compose gives the shell precedence).
# IDPS_DB_IMAGE is the one deliberate input; IDPS_GIT_SHA and IDPS_HEALTH_TIMEOUT only tune the script.
DB_IMAGE_ARG="${IDPS_DB_IMAGE:-}"
unset IDPS_DB_IMAGE IDPS_TAG IDPS_PREVIOUS_TAG IDPS_PROJECT IDPS_SITE IDPS_TLS_MODE IDPS_HTTP_PORT \
  IDPS_HTTPS_PORT IDPS_REDIR_PORT IDPS_SENSOR_PORT IDPS_PUBLIC_URL IDPS_SENSOR_BIND IDPS_SUBNET \
  IDPS_IP_RANGE IDPS_PROXY_IP IDPS_SENSOR_PROJECT IDPS_SOC_URL IDPS_INTERFACE IDPS_MODEL_FILE

DEPLOY_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(dirname "$DEPLOY_DIR")
ENV_FILE="$DEPLOY_DIR/.env"
SENSOR_ENV_FILE="$DEPLOY_DIR/.env.sensor"
SECRETS_DIR="$DEPLOY_DIR/secrets"
SENSORS_DIR="$DEPLOY_DIR/sensors"
SENSOR_DATA="$DEPLOY_DIR/sensor-data"
SOC_COMPOSE="$DEPLOY_DIR/compose/soc.yml"
SENSOR_COMPOSE="$DEPLOY_DIR/compose/sensor.yml"
MIN_COMPOSE="2.24"
HEALTH_TIMEOUT="${IDPS_HEALTH_TIMEOUT:-240}"

die() { echo "install.sh: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

# --- helpers ------------------------------------------------------------------------------------

valid_port() {
  case "$1" in ""|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_host() { # a host name or IPv4 address: letters, digits, dots and hyphens
  case "$1" in ""|*[!A-Za-z0-9.-]*|.*|-*) return 1 ;; esac
  [ "${#1}" -le 253 ]
}

valid_name() { # sensor and project names
  case "$1" in ""|*[!A-Za-z0-9._-]*|.*|-*) return 1 ;; esac
  [ "${#1}" -le 64 ]
}

valid_tag() {
  case "$1" in ""|*[!A-Za-z0-9._-]*|.*|-*) return 1 ;; esac
  [ "${#1}" -le 128 ]
}

version_ge() { # version_ge A B: A >= B (dotted numbers)
  a1=${1%%.*}; r=${1#*.}; a2=${r%%.*}
  b1=${2%%.*}; r=${2#*.}; b2=${r%%.*}
  [ "$a1" -gt "$b1" ] || { [ "$a1" -eq "$b1" ] && [ "$a2" -ge "$b2" ]; }
}

check_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is not installed (https://docs.docker.com/engine/install/)"
  docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running, and are you allowed to use it?)"
  cv=$(docker compose version --short 2>/dev/null) || die "the Docker Compose plugin is missing (docker compose version fails)"
  cv=${cv#v}
  version_ge "$cv" "$MIN_COMPOSE" || die "Docker Compose $cv is too old: $MIN_COMPOSE or newer is needed"
}

project_version() {
  v=$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' "$REPO_DIR/pyproject.toml" | head -n 1)
  [ -n "$v" ] || die "cannot read the version from pyproject.toml"
  echo "$v"
}

git_sha() {
  if [ -n "${IDPS_GIT_SHA:-}" ]; then echo "$IDPS_GIT_SHA"; return; fi
  s=$(git -C "$REPO_DIR" rev-parse --short=7 HEAD 2>/dev/null) || { echo unknown; return; }
  # uncommitted changes: the image is not exactly that commit
  if [ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ]; then s="$s-dirty"; fi
  echo "$s"
}

# env_get FILE KEY: a value from a KEY=VALUE file (never sourced, so a bad file cannot run code)
env_get() {
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | head -n 1
}

write_env() { # write_env FILE KEY=VALUE...: replaces the file atomically, mode 0600
  f=$1; shift
  tmp="$f.tmp.$$"
  : > "$tmp"
  for kv in "$@"; do printf '%s\n' "$kv" >> "$tmp"; done
  chmod 600 "$tmp"
  mv "$tmp" "$f"
}

random_hex() { # random_hex BYTES: from the kernel's CSPRNG
  od -An -v -tx1 -N "$1" /dev/urandom | tr -d ' \n'
}

env_set() { # env_set KEY VALUE: change or add one line of deploy/.env (each step checked)
  tmp="$ENV_FILE.tmp.$$"
  if grep -q "^$1=" "$ENV_FILE"; then
    sed "s|^$1=.*|$1=$2|" "$ENV_FILE" > "$tmp" || { rm -f "$tmp"; die "cannot update $ENV_FILE"; }
  else
    { cat "$ENV_FILE" && printf '%s=%s\n' "$1" "$2"; } > "$tmp" || { rm -f "$tmp"; die "cannot update $ENV_FILE"; }
  fi
  chmod 600 "$tmp" || { rm -f "$tmp"; die "cannot update $ENV_FILE"; }
  mv "$tmp" "$ENV_FILE" || die "cannot update $ENV_FILE"
}

ensure_secret() { # ensure_secret NAME BYTES: create deploy/secrets/NAME unless it exists
  f="$SECRETS_DIR/$1"
  if [ -s "$f" ]; then chmod 600 "$f"; return; fi
  tmp="$f.tmp.$$"
  random_hex "$2" > "$tmp"
  [ -s "$tmp" ] || { rm -f "$tmp"; die "could not generate a secret"; }
  chmod 600 "$tmp"
  mv "$tmp" "$f"
}

dc() { # compose for the SOC stack
  docker compose --env-file "$ENV_FILE" -f "$SOC_COMPOSE" -p "$PROJECT" "$@"
}

dc_tag() { # dc_tag TAG ARGS...: the same, with the images of another tag (the shell wins over --env-file)
  t=$1; shift
  env "IDPS_TAG=$t" docker compose --env-file "$ENV_FILE" -f "$SOC_COMPOSE" -p "$PROJECT" "$@"
}

# check_network: IDPS_SUBNET, IDPS_IP_RANGE and IDPS_PROXY_IP are all unset (the defaults) or all
# set, consistent (the proxy address inside the subnet and outside the range), and the subnet
# overlaps no other Docker network. The check runs in the SOC image (it has python).
check_network() {
  sn=$(env_get "$ENV_FILE" IDPS_SUBNET); rg=$(env_get "$ENV_FILE" IDPS_IP_RANGE); px=$(env_get "$ENV_FILE" IDPS_PROXY_IP)
  if [ -n "$sn$rg$px" ] && { [ -z "$sn" ] || [ -z "$rg" ] || [ -z "$px" ]; }; then
    die "set IDPS_SUBNET, IDPS_IP_RANGE and IDPS_PROXY_IP in $ENV_FILE all together, or none of them (defaults 172.28.77.0/24, 172.28.77.0/25, 172.28.77.200)"
  fi
  : "${sn:=172.28.77.0/24}" "${rg:=172.28.77.0/25}" "${px:=172.28.77.200}"
  others=""
  for net in $(docker network ls --format '{{.Name}}'); do
    [ "$net" != "${PROJECT}_default" ] || continue
    for s in $(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net" 2>/dev/null); do others="$others $s"; done
  done
  # shellcheck disable=SC2086
  docker run --rm --network none --entrypoint python "idps-soc:$TAG" -c '
import ipaddress, sys
sn, rg, px = sys.argv[1:4]
try:
    n, r, p = ipaddress.ip_network(sn), ipaddress.ip_network(rg), ipaddress.ip_address(px)
except ValueError as e:
    sys.exit("IDPS_SUBNET/IDPS_IP_RANGE/IDPS_PROXY_IP are not valid addresses: %s" % e)
if n.version != 4 or not r.subnet_of(n) or p not in n or p in r:
    sys.exit("inconsistent: IDPS_IP_RANGE must lie inside IDPS_SUBNET, and IDPS_PROXY_IP inside the subnet but outside the range")
for o in sys.argv[4:]:
    try:
        if ipaddress.ip_network(o).overlaps(n):
            sys.exit("the subnet %s overlaps an existing Docker network (%s)" % (sn, o))
    except ValueError:
        pass
' "$sn" "$rg" "$px" $others || die "network settings: change IDPS_SUBNET, IDPS_IP_RANGE and IDPS_PROXY_IP in $ENV_FILE (docs/deploy.md, \"Ports\") and run install.sh soc again"
}

ensure_db_image() { # the database image is the one image not built here: pull it when it is missing
  img=$(env_get "$ENV_FILE" IDPS_DB_IMAGE); : "${img:=postgres:16-alpine}"
  if ! image_exists "$img"; then
    info "pulling $img (not found locally; offline hosts: docker load it first)"
    docker pull "$img" || die "cannot pull $img"
  fi
}

load_project() {
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found: run 'install.sh soc' first"
  PROJECT=$(env_get "$ENV_FILE" IDPS_PROJECT)
  valid_name "$PROJECT" || die "IDPS_PROJECT in $ENV_FILE is not valid"
}

image_exists() { docker image inspect "$1" >/dev/null 2>&1; }

build_image() { # build_image NAME DOCKERFILE: idps-NAME:<version> and :<version>-<sha7>
  name=$1; dockerfile=$2
  ver=$(project_version); sha=$(git_sha)
  info "building idps-$name:$ver (revision $sha)"
  set -- -t "idps-$name:$ver"
  [ "$sha" = unknown ] || set -- "$@" -t "idps-$name:$ver-$sha"
  docker build -f "$DEPLOY_DIR/docker/$dockerfile" --build-arg "VERSION=$ver" \
    --build-arg "GIT_SHA=$sha" "$@" "$REPO_DIR"
}

# resolve_tag KIND IMAGE...: sets TAG from --build / --image-tag / the project version, and
# checks the images exist locally (nothing is pulled: the images are built here or loaded).
resolve_tag() {
  kind=$1; shift
  if [ "$BUILD" = 1 ] && [ -n "$IMAGE_TAG" ]; then die "--build and --image-tag cannot be used together"; fi
  if [ "$BUILD" = 1 ]; then
    TAG=$(project_version)
    for n in "$@"; do build_image "$n" "$n.Dockerfile"; done
  elif [ -n "$IMAGE_TAG" ]; then
    valid_tag "$IMAGE_TAG" || die "bad --image-tag"
    TAG=$IMAGE_TAG
  else
    TAG=$(project_version)
    # a plain re-run of `install.sh soc` must not undo a rollback or an --image-tag: keep the tag
    if [ "${KEEP_TAG:-0}" = 1 ] && [ -n "$(env_get "$ENV_FILE" IDPS_TAG)" ]; then TAG=$(env_get "$ENV_FILE" IDPS_TAG); fi
  fi
  valid_tag "$TAG" || die "the image tag '$TAG' is not valid (letters, digits, . _ -; no '+')"
  for n in "$@"; do
    image_exists "idps-$n:$TAG" || die "image idps-$n:$TAG not found: use --build (or load the image first) [$kind]"
  done
}

# health_wait SERVICE: 0 when healthy/running, 1 on failure (prints the state and the log tail)
health_wait() {
  svc=$1; waited=0; restarts=0
  info "waiting for $svc to be healthy"
  while :; do
    cid=$(dc ps -q "$svc" 2>/dev/null | head -n 1)
    st=none
    [ -z "$cid" ] || st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo none)
    case "$st" in
      healthy|running) return 0 ;;
      exited|dead) break ;;
      restarting) restarts=$((restarts + 1)); [ "$restarts" -lt 6 ] || break ;;
    esac
    if [ "$waited" -ge "$HEALTH_TIMEOUT" ]; then break; fi
    sleep 3; waited=$((waited + 3))
  done
  echo "install.sh: $svc did not become healthy (state: $st). Last log lines:" >&2
  dc logs --tail 30 "$svc" >&2 || true
  return 1
}

wait_healthy() { health_wait "$1" || exit 1; }

# --- soc ----------------------------------------------------------------------------------------

cmd_soc() {
  DOMAIN=""; HOST=""; HTTP_PORT=""; HTTPS_PORT=""; SENSOR_PORT=""; PROJECT_ARG=""
  BUILD=0; IMAGE_TAG=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) [ $# -ge 2 ] || usage; DOMAIN=$2; shift 2 ;;
      --host) [ $# -ge 2 ] || usage; HOST=$2; shift 2 ;;
      --http-port) [ $# -ge 2 ] || usage; HTTP_PORT=$2; shift 2 ;;
      --https-port) [ $# -ge 2 ] || usage; HTTPS_PORT=$2; shift 2 ;;
      --sensor-port) [ $# -ge 2 ] || usage; SENSOR_PORT=$2; shift 2 ;;
      --project) [ $# -ge 2 ] || usage; PROJECT_ARG=$2; shift 2 ;;
      --build) BUILD=1; shift ;;
      --image-tag) [ $# -ge 2 ] || usage; IMAGE_TAG=$2; shift 2 ;;
      *) echo "unknown option: $1" >&2; usage ;;
    esac
  done
  [ -z "$DOMAIN" ] || [ -z "$HOST" ] || die "use --domain or --host, not both"

  # Values: the options, else what a previous run wrote, else the defaults.
  old_site=$(env_get "$ENV_FILE" IDPS_SITE); old_mode=$(env_get "$ENV_FILE" IDPS_TLS_MODE)
  if [ -n "$DOMAIN" ]; then MODE=domain; SITE=$DOMAIN
  elif [ -n "$HOST" ]; then MODE=internal; SITE=$HOST
  elif [ -n "$old_site" ]; then MODE=${old_mode:-internal}; SITE=$old_site
  else MODE=internal; SITE=localhost; fi
  [ -n "$HTTP_PORT" ] || HTTP_PORT=$(env_get "$ENV_FILE" IDPS_HTTP_PORT)
  [ -n "$HTTPS_PORT" ] || HTTPS_PORT=$(env_get "$ENV_FILE" IDPS_HTTPS_PORT)
  [ -n "$SENSOR_PORT" ] || SENSOR_PORT=$(env_get "$ENV_FILE" IDPS_SENSOR_PORT)
  [ -n "$PROJECT_ARG" ] || PROJECT_ARG=$(env_get "$ENV_FILE" IDPS_PROJECT)
  : "${HTTP_PORT:=80}" "${HTTPS_PORT:=443}" "${SENSOR_PORT:=8444}" "${PROJECT_ARG:=idps}"
  PROJECT=$PROJECT_ARG

  valid_host "$SITE" || die "not a valid host name or address: $SITE"
  valid_port "$HTTP_PORT" || die "bad --http-port"
  valid_port "$HTTPS_PORT" || die "bad --https-port"
  valid_port "$SENSOR_PORT" || die "bad --sensor-port"
  valid_name "$PROJECT" || die "bad --project (letters, digits, . _ -)"
  if [ "$MODE" = domain ]; then
    [ "$HTTP_PORT" = 80 ] && [ "$HTTPS_PORT" = 443 ] \
      || die "--domain (Let's Encrypt) needs the standard ports 80 and 443; use --host for other ports"
    case "$SITE" in *[!0-9.]*) ;; *) die "--domain needs a host name, not an IP address (use --host)" ;; esac
  fi
  REDIR_PORT=""
  PUBLIC="https://$SITE"
  if [ "$HTTPS_PORT" != 443 ]; then REDIR_PORT=":$HTTPS_PORT"; PUBLIC="https://$SITE:$HTTPS_PORT"; fi

  check_docker
  # Secrets lost but the database still there: a new password or MFA key would not match it.
  if docker volume inspect "${PROJECT}_pgdata" >/dev/null 2>&1; then
    for s in db_password mfa_key; do
      [ -s "$SECRETS_DIR/$s" ] || die "the database volume ${PROJECT}_pgdata exists but $SECRETS_DIR/$s is missing: restore deploy/secrets from your backup (a new secret would not match the data)"
    done
  fi
  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
  ensure_secret db_password 32
  ensure_secret jwt_secret 48
  ensure_secret mfa_key 48

  KEEP_TAG=1
  resolve_tag soc soc proxy
  KEEP_TAG=0
  bind=$(env_get "$ENV_FILE" IDPS_SENSOR_BIND)   # optional, set by hand: the sensor port's bind address
  set -- "IDPS_PROJECT=$PROJECT" "IDPS_TAG=$TAG" "IDPS_SITE=$SITE" "IDPS_TLS_MODE=$MODE" \
    "IDPS_HTTP_PORT=$HTTP_PORT" "IDPS_HTTPS_PORT=$HTTPS_PORT" "IDPS_REDIR_PORT=$REDIR_PORT" \
    "IDPS_SENSOR_PORT=$SENSOR_PORT" "IDPS_PUBLIC_URL=$PUBLIC"
  [ -z "$bind" ] || set -- "$@" "IDPS_SENSOR_BIND=$bind"
  # kept across runs: the proxy's fixed address (the SOC trusts X-Forwarded-For from it only), the
  # network, the previous tag (rollback) and an optional database image
  for k in IDPS_SUBNET IDPS_IP_RANGE IDPS_PROXY_IP IDPS_PREVIOUS_TAG IDPS_DB_IMAGE; do
    v=$(env_get "$ENV_FILE" "$k")
    if [ "$k" = IDPS_DB_IMAGE ] && [ -n "$DB_IMAGE_ARG" ]; then v=$DB_IMAGE_ARG; fi
    [ -z "$v" ] || set -- "$@" "$k=$v"
  done
  write_env "$ENV_FILE" "$@"

  ensure_db_image
  check_network
  info "starting the database"
  dc up -d --pull never db
  wait_healthy db

  info "sensor CA and the server certificate of port $SENSOR_PORT (names: $SITE localhost 127.0.0.1)"
  soc_was_up=$(dc ps -q soc 2>/dev/null | head -n 1)
  pki_out=$(dc run --rm -T --no-deps soc-admin idps-init-pki "$SITE" localhost 127.0.0.1) || die "could not make the certificates"
  echo "$pki_out"

  info "starting the SOC (database migrations run at start-up)"
  dc up -d --pull never
  case "$pki_out" in
    *written:*) # a running SOC reads its certificates only at start-up
      if [ -n "$soc_was_up" ]; then info "new certificates: restarting the SOC"; dc restart soc; fi ;;
  esac
  wait_healthy soc
  wait_healthy proxy

  admin_file="$SECRETS_DIR/admin_password"
  admin_new=0
  if [ ! -s "$admin_file" ]; then
    tmp="$admin_file.tmp.$$"
    random_hex 18 > "$tmp"; chmod 600 "$tmp"
    # The password goes in on stdin and through a file on the container's tmpfs /tmp: never on a
    # command line, never on the container's disk.
    if out=$(dc run --rm -T soc-admin sh -c 'umask 077; cat > /tmp/pw && python -m soc.api create-user admin --role admin --password-file /tmp/pw; rc=$?; rm -f /tmp/pw; exit $rc' < "$tmp" 2>&1); then
      mv "$tmp" "$admin_file" || die "cannot write $admin_file"; admin_new=1
    else
      rm -f "$tmp"
      case "$out" in
        *"already exists"*)
          echo "install.sh: note: the user 'admin' exists already; its password is not changed" >&2 ;;
        *) echo "$out" | tail -5 >&2; die "could not create the admin user" ;;
      esac
    fi
  fi

  caddy_note=""
  if [ "$MODE" = internal ]; then
    # Caddy makes its local CA when it loads the configuration; give it a moment.
    n=0
    while [ "$n" -lt 20 ]; do
      if dc cp proxy:/data/caddy/pki/authorities/local/root.crt "$DEPLOY_DIR/caddy-root.crt" >/dev/null 2>&1; then
        chmod 644 "$DEPLOY_DIR/caddy-root.crt"; caddy_note=1; break
      fi
      sleep 1; n=$((n + 1))
    done
  fi

  echo
  echo "IDPS SOC is running ($PROJECT, images idps-soc:$TAG and idps-proxy:$TAG)."
  echo "  Dashboard:        $PUBLIC/"
  echo "  Sensor port:      $SITE:$SENSOR_PORT (mutual TLS)"
  if [ "$admin_new" = 1 ]; then
    echo "  Admin user:       admin; the generated password is in $admin_file (mode 0600)"
    echo "                    The admin must set up two-factor sign-in (an authenticator app) at the first login."
  elif [ -s "$admin_file" ]; then
    echo "  Admin password:   $admin_file (from an earlier run)"
  fi
  if [ "$MODE" = internal ]; then
    echo
    echo "  The certificate is signed by Caddy's own CA. Browsers warn until you trust its root:"
    if [ -n "$caddy_note" ]; then
      echo "    root certificate (public): $DEPLOY_DIR/caddy-root.crt"
    fi
    echo "    docker compose --env-file $ENV_FILE -f $SOC_COMPOSE -p $PROJECT cp proxy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt"
    echo "    macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt"
    echo "    Debian/Ubuntu:  sudo cp caddy-root.crt /usr/local/share/ca-certificates/idps-caddy.crt && sudo update-ca-certificates"
    echo "    Windows:  certutil -addstore -f ROOT caddy-root.crt   (or import it in the browser)"
  fi
  echo
  echo "Next: install.sh add-sensor NAME   (on this host), then install.sh sensor ... on the sensor host."
}

# --- add-sensor ---------------------------------------------------------------------------------

cmd_add_sensor() {
  [ $# -eq 1 ] || usage
  NAME=$1
  valid_name "$NAME" || die "sensor names may only use letters, digits, . _ -"
  load_project
  check_docker
  dest="$SENSORS_DIR/$NAME"
  [ ! -e "$dest" ] || die "$dest exists already (remove it, and revoke the old token in the dashboard, to enrol again)"
  mkdir -p "$SENSORS_DIR"; chmod 700 "$SENSORS_DIR"
  work=$(mktemp -d "$SENSORS_DIR/.new.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  trap 'exit 130' INT TERM
  dc run --rm -T soc-admin idps-add-sensor "$NAME" > "$work/bundle.tar" || die "could not create the sensor $NAME"
  mkdir "$work/out"
  tar -xf "$work/bundle.tar" -C "$work/out"
  rm -f "$work/bundle.tar"
  for f in token client.pem client.key ca.pem; do [ -s "$work/out/$f" ] || die "the bundle is missing $f"; done
  host=$(env_get "$ENV_FILE" IDPS_SITE); port=$(env_get "$ENV_FILE" IDPS_SENSOR_PORT)
  printf 'IDPS_SOC_URL=https://%s:%s\nIDPS_SENSOR_NAME=%s\n' "$host" "$port" "$NAME" > "$work/out/sensor.env"
  chmod 600 "$work/out/token" "$work/out/client.key"
  chmod 644 "$work/out/client.pem" "$work/out/ca.pem" "$work/out/sensor.env"
  chmod 700 "$work/out"
  mv "$work/out" "$dest"
  rm -rf "$work"; trap - EXIT INT TERM
  echo "Enrolment bundle for sensor $NAME: $dest (token and client.key are mode 0600)"
  echo "  SOC sensor URL: https://$host:$port"
  case "$host" in localhost|127.*) echo "  note: the SOC address is $host; sensors on other machines cannot reach it. Re-run 'install.sh soc --host <address>' first." ;; esac
  echo "Copy the directory to the sensor host over a secure channel (scp), then there:"
  echo "  install.sh sensor --bundle $NAME --interface IFACE --model models/MODEL.joblib"
}

cmd_renew_sensor() {
  [ $# -eq 1 ] || usage
  NAME=$1
  valid_name "$NAME" || die "sensor names may only use letters, digits, . _ -"
  load_project
  check_docker
  dest="$SENSORS_DIR/$NAME"
  [ -d "$dest" ] || die "$dest not found: this host has no bundle for $NAME (use add-sensor)"
  work=$(mktemp -d "$SENSORS_DIR/.renew.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  trap 'exit 130' INT TERM
  # idps-renew-sensor refuses a name that is not an existing, non-revoked sensor
  dc run --rm -T soc-admin idps-renew-sensor "$NAME" > "$work/bundle.tar" || die "could not issue a new certificate for $NAME"
  mkdir "$work/new" "$work/tar"
  tar -xf "$work/bundle.tar" -C "$work/tar"
  for f in client.pem client.key ca.pem; do [ -s "$work/tar/$f" ] || die "the new bundle is missing $f"; done
  # the whole bundle (the token stays) is staged and swapped in one step
  cp -p "$dest"/* "$work/new/" || die "cannot copy the bundle"
  for f in client.pem client.key ca.pem; do cp "$work/tar/$f" "$work/new/$f"; done
  chmod 600 "$work/new/client.key" "$work/new/token"; chmod 644 "$work/new/client.pem" "$work/new/ca.pem"
  chmod 700 "$work/new"
  mv "$dest" "$work/old" || die "cannot replace $dest"
  mv "$work/new" "$dest" || { mv "$work/old" "$dest"; die "cannot replace $dest (the old bundle is back)"; }
  echo "New client certificate for $NAME written to $dest (the token is unchanged)."
  echo "Copy client.pem and client.key to the sensor host, run 'install.sh sensor ...' again there"
  echo "(or re-load the bundle) and restart the sensor."
}

# --- sensor -------------------------------------------------------------------------------------

cmd_sensor() {
  BUNDLE=""; IFACE=""; MODEL=""; PUBKEY=""; PROJECT=idps-sensor; BUILD=0; IMAGE_TAG=""; START=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --bundle) [ $# -ge 2 ] || usage; BUNDLE=$2; shift 2 ;;
      --interface) [ $# -ge 2 ] || usage; IFACE=$2; shift 2 ;;
      --model) [ $# -ge 2 ] || usage; MODEL=$2; shift 2 ;;
      --public-key) [ $# -ge 2 ] || usage; PUBKEY=$2; shift 2 ;;
      --project) [ $# -ge 2 ] || usage; PROJECT=$2; shift 2 ;;
      --build) BUILD=1; shift ;;
      --image-tag) [ $# -ge 2 ] || usage; IMAGE_TAG=$2; shift 2 ;;
      --no-start) START=0; shift ;;
      *) echo "unknown option: $1" >&2; usage ;;
    esac
  done
  [ -n "$BUNDLE" ] && [ -n "$IFACE" ] && [ -n "$MODEL" ] || usage
  [ -d "$BUNDLE" ] || die "bundle directory not found: $BUNDLE"
  for f in token client.pem client.key ca.pem sensor.env; do [ -s "$BUNDLE/$f" ] || die "the bundle is missing $f"; done
  [ -f "$MODEL" ] || die "model file not found: $MODEL"
  [ -z "$PUBKEY" ] || [ -f "$PUBKEY" ] || die "public key file not found: $PUBKEY"
  valid_name "$PROJECT" || die "bad --project"
  case "$IFACE" in ""|*[!A-Za-z0-9._:@-]*) die "bad interface name" ;; esac
  soc_url=$(env_get "$BUNDLE/sensor.env" IDPS_SOC_URL)
  case "$soc_url" in https://*) ;; *) die "sensor.env has no https:// IDPS_SOC_URL" ;; esac
  case "$soc_url" in *[!A-Za-z0-9.:/-]*) die "sensor.env: IDPS_SOC_URL has unexpected characters" ;; esac
  model_name=$(basename "$MODEL")
  valid_name "$model_name" || die "the model file name may only use letters, digits, . _ -"

  check_docker
  resolve_tag sensor sensor
  info "copying the model into $SENSOR_DATA/models"
  mkdir -p "$SENSOR_DATA/models"
  chmod 755 "$SENSOR_DATA" "$SENSOR_DATA/models"   # nothing secret here: root in the container reads it without extra capabilities
  cp "$MODEL" "$SENSOR_DATA/models/$model_name"
  for ext in .sha256 .sig .drift.json; do
    if [ -f "$MODEL$ext" ]; then cp "$MODEL$ext" "$SENSOR_DATA/models/$model_name$ext"; fi
  done
  chmod 644 "$SENSOR_DATA/models/"*

  # The bundle (token, client key) goes into a Docker volume, written by a container as root, so
  # the sensor needs no capability to read files owned by another user (and no host copy exists
  # besides your bundle directory).
  info "loading the enrolment bundle into the volume ${PROJECT}_sensor_enrol"
  stage=$(mktemp -d "${TMPDIR:-/tmp}/idps-enrol.XXXXXX")
  trap 'rm -rf "$stage"' EXIT
  trap 'exit 130' INT TERM
  for f in token client.key; do cp "$BUNDLE/$f" "$stage/$f"; chmod 600 "$stage/$f"; done
  for f in client.pem ca.pem; do cp "$BUNDLE/$f" "$stage/$f"; chmod 644 "$stage/$f"; done
  if [ -n "$PUBKEY" ]; then
    cp "$PUBKEY" "$stage/model-signing.pub"; chmod 644 "$stage/model-signing.pub"
    set -- token client.key client.pem ca.pem model-signing.pub
  else
    echo "warning: no --public-key: the sensor will not check model signatures" >&2
    set -- token client.key client.pem ca.pem
  fi
  write_env "$SENSOR_ENV_FILE" "IDPS_SENSOR_PROJECT=$PROJECT" "IDPS_TAG=$TAG" \
    "IDPS_SOC_URL=$soc_url" "IDPS_INTERFACE=$IFACE" "IDPS_MODEL_FILE=$model_name"
  sdc() { docker compose --env-file "$SENSOR_ENV_FILE" -f "$SENSOR_COMPOSE" -p "$PROJECT" "$@"; }
  # a running sensor reads the bundle and the model at start-up and would lose them under it:
  # stop it, load, and recreate it below
  sdc stop sensor >/dev/null 2>&1 || true
  # replace the old bundle completely (a removed public key must not linger)
  sdc run --rm -T --no-deps --entrypoint sh sensor-load -c 'rm -rf /enrol/* /enrol/.[!.]* 2>/dev/null; true' </dev/null >/dev/null 2>&1 || true
  COPYFILE_DISABLE=1 tar -C "$stage" -cf - "$@" | sdc run --rm -T --no-deps sensor-load || die "could not load the bundle into the volume"
  rm -rf "$stage"; trap - EXIT INT TERM

  docker compose --env-file "$SENSOR_ENV_FILE" -f "$SENSOR_COMPOSE" -p "$PROJECT" config -q \
    || die "the sensor compose file does not validate"
  if [ "$START" = 0 ]; then
    echo "Wrote $SENSOR_ENV_FILE, $SENSOR_DATA/models and the volume ${PROJECT}_sensor_enrol (not started: --no-start)."
    return
  fi
  info "starting the sensor (host network, capturing on $IFACE)"
  docker compose --env-file "$SENSOR_ENV_FILE" -f "$SENSOR_COMPOSE" -p "$PROJECT" up -d --pull never --force-recreate sensor
  echo "Sensor started. Logs: docker compose --env-file $SENSOR_ENV_FILE -f $SENSOR_COMPOSE -p $PROJECT logs -f"
}

# --- upgrade, rollback, restore ---------------------------------------------------------------

# switch_to TAG: point the stack at TAG's images; 0 when soc and proxy come up healthy
switch_to() {
  env_set IDPS_TAG "$1"
  ok=0
  # soc first, on its own: compose's own wait for a dependency has no time limit
  dc up -d --pull never --no-deps soc || ok=1
  if [ "$ok" = 0 ]; then health_wait soc || ok=1; fi
  if [ "$ok" = 0 ]; then dc up -d --pull never || ok=1; fi
  if [ "$ok" = 0 ]; then health_wait proxy || ok=1; fi
  return "$ok"
}

cmd_upgrade() {
  BUILD=0; IMAGE_TAG=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --build) BUILD=1; shift ;;
      --image-tag) [ $# -ge 2 ] || usage; IMAGE_TAG=$2; shift 2 ;;
      *) echo "unknown option: $1" >&2; usage ;;
    esac
  done
  load_project
  check_docker
  old_tag=$(env_get "$ENV_FILE" IDPS_TAG)
  # Keep the images that run now under a tag that a new build cannot overwrite (a rebuild of the
  # same version would): they are the way back.
  prev_tag="$old_tag-previous"
  for n in soc proxy; do
    image_exists "idps-$n:$old_tag" || die "the current image idps-$n:$old_tag is missing: cannot upgrade safely (no way back)"
    docker tag "idps-$n:$old_tag" "idps-$n:$prev_tag" || die "cannot tag idps-$n:$prev_tag"
  done
  resolve_tag soc soc proxy
  [ "$TAG" != "$old_tag" ] || echo "note: the tag is unchanged ($TAG): the containers are recreated only if the image differs"

  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  backup="pre-upgrade-$old_tag-to-$TAG-$stamp.jsonl.gz"
  info "backing up the database first (volume ${PROJECT}_backups: $backup)"
  ensure_db_image
  dc up -d --pull never db
  wait_healthy db
  # Made by the version that is running now, whatever IDPS_TAG's image has become.
  dc_tag "$prev_tag" run --rm -T soc-admin python -m soc.api backup "/var/lib/idps-backups/$backup" \
    || die "the backup failed: nothing was changed"

  env_set IDPS_PREVIOUS_TAG "$prev_tag"
  info "switching $old_tag -> $TAG (migrations run at start-up)"
  if ! switch_to "$TAG"; then
    echo "install.sh: the new version ($TAG) did not start: going back to the old images" >&2
    back=$old_tag
    # a rebuild of the same version replaced the old tag: use the saved one
    if [ "$(docker image inspect -f '{{.Id}}' "idps-soc:$old_tag")" != "$(docker image inspect -f '{{.Id}}' "idps-soc:$prev_tag")" ]; then back=$prev_tag; fi
    if switch_to "$back"; then
      echo "install.sh: rolled back to $back; the data is as it was unless a migration ran." >&2
    else
      echo "install.sh: the old version does not start either (a migration may have run already)." >&2
      echo "  Restore the pre-upgrade backup: install.sh restore $backup" >&2
    fi
    echo "install.sh: upgrade to $TAG FAILED. Backup taken before it: $backup (volume ${PROJECT}_backups)" >&2
    exit 1
  fi
  echo "Database revision:"
  dc run --rm -T soc-admin python -m soc.api db current
  dc run --rm -T soc-admin python -m soc.api db check
  echo "Upgraded to $TAG. Backup: volume ${PROJECT}_backups, file $backup"
  echo "To go back: install.sh rollback (if the new version changed the schema, then install.sh restore $backup)"
}

cmd_rollback() {
  [ $# -eq 0 ] || usage
  load_project
  check_docker
  cur=$(env_get "$ENV_FILE" IDPS_TAG); prev=$(env_get "$ENV_FILE" IDPS_PREVIOUS_TAG)
  [ -n "$prev" ] || die "no previous version is recorded (install.sh upgrade records it)"
  for n in soc proxy; do image_exists "idps-$n:$prev" || die "image idps-$n:$prev not found"; done
  # Does the previous version know the database's schema revision? After an upgrade that ran a
  # migration it does not, and starting it would only stop a healthy SOC.
  dc up -d --pull never db
  wait_healthy db
  rev=$(dc run --rm -T soc-admin python -m soc.api db current 2>/dev/null | tail -n 1)
  [ -n "$rev" ] || die "cannot read the database revision: not rolling back"
  if ! dc_tag "$prev" run --rm -T soc-admin python -c 'import sys
from soc.api import migrate
sys.exit(0 if migrate.known_revision(sys.argv[1]) else 1)' "$rev" >/dev/null 2>&1; then
    echo "install.sh: the previous version ($prev) does not know the database's schema revision ($rev):" >&2
    echo "  the upgrade changed the schema. Nothing was changed; the SOC keeps running on $cur." >&2
    echo "  To go back, restore the backup made before the upgrade: install.sh restore pre-upgrade-<...>.jsonl.gz" >&2
    echo "  (list them: docker run --rm -v ${PROJECT}_backups:/b --entrypoint ls idps-soc:$cur /b)" >&2
    exit 1
  fi
  info "rolling back $cur -> $prev"
  if switch_to "$prev"; then
    echo "Rolled back to $prev."
  else
    echo "install.sh: the previous version did not start: switching back to $cur" >&2
    if switch_to "$cur"; then
      echo "install.sh: running on $cur again. Rollback failed; see the log above." >&2
    else
      echo "install.sh: $cur does not start either: check the logs (install.sh status)" >&2
    fi
    exit 1
  fi
}

# restore BACKUP: a file name inside the backups volume, or a path on this host. Keeps the secrets
# and the certificates; replaces the database (a new, empty pgdata volume) with the backup's.
cmd_restore() {
  YES=0; SRC=""; SAFETY=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) YES=1; shift ;;
      --no-safety-copy) SAFETY=0; shift ;;
      -*) echo "unknown option: $1" >&2; usage ;;
      *) [ -z "$SRC" ] || usage; SRC=$1; shift ;;
    esac
  done
  [ -n "$SRC" ] || usage
  load_project
  check_docker
  ensure_db_image
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  if [ -f "$SRC" ]; then
    name="imported-$stamp.jsonl.gz"
    info "copying $SRC into the backups volume as $name"
    dc up -d --pull never db
    wait_healthy db
    dc run --rm -T soc-admin sh -c "umask 077; cat > /var/lib/idps-backups/$name" < "$SRC" || die "could not copy the backup into the volume"
  else
    valid_name "$SRC" || die "BACKUP is a file on this host or a file name in the backups volume"
    name=$SRC
    dc up -d --pull never db
    wait_healthy db
    dc run --rm -T soc-admin sh -c "test -s /var/lib/idps-backups/$name" || die "$name is not in the backups volume ${PROJECT}_backups"
  fi
  if [ "$YES" != 1 ]; then
    printf 'REPLACE the database of project %s with %s? All data since the backup is lost. [y/N] ' "$PROJECT" "$name"
    read -r answer || answer=n
    case "$answer" in y|Y|yes|YES) ;; *) echo "cancelled"; exit 1 ;; esac
  fi
  info "checking the backup file"
  # Checked before anything is deleted: the file is restored into a scratch SQLite database. That
  # proves it is a complete, undamaged backup (checksum, format, a schema revision this version
  # knows); it does not prove which SOC made it or that its secrets match this install.
  dc run --rm -T soc-admin sh -c "python -m soc.api restore --database-url sqlite:////tmp/verify.db /var/lib/idps-backups/$name" >/dev/null \
    || die "the backup file cannot be restored (damaged, incomplete, or a schema this version does not know): nothing was changed"
  # no alert may arrive between the safety copy and the wipe
  info "stopping the SOC"
  dc stop soc proxy
  restore_abort() { echo "install.sh: $*" >&2; echo "install.sh: starting the SOC again; nothing was changed" >&2; dc up -d --pull never >/dev/null 2>&1 || true; exit 1; }
  if [ "$SAFETY" = 1 ]; then
    info "safety copy of the current database (pre-restore-$stamp.jsonl.gz)"
    dc run --rm -T soc-admin python -m soc.api backup "/var/lib/idps-backups/pre-restore-$stamp.jsonl.gz" \
      || restore_abort "the current database could not be backed up; refusing to delete it (use --no-safety-copy to replace it anyway)"
  else
    echo "warning: --no-safety-copy: the current database is not backed up" >&2
  fi
  info "replacing the database volume ${PROJECT}_pgdata"
  dc stop db
  dc rm -f db >/dev/null
  docker volume rm "${PROJECT}_pgdata" >/dev/null || die "cannot remove the volume ${PROJECT}_pgdata"
  dc up -d --pull never db
  wait_healthy db
  # the restore brings an empty database to the backup's revision, then loads the rows
  dc run --rm -T soc-admin python -m soc.api restore "/var/lib/idps-backups/$name" || die "the restore failed (the safety copy is pre-restore-$stamp.jsonl.gz in the backups volume)"
  info "starting the SOC (migrations bring the schema to the current head)"
  dc up -d --pull never
  wait_healthy soc
  wait_healthy proxy
  dc run --rm -T soc-admin python -m soc.api db current
  dc run --rm -T soc-admin python -m soc.api db check
  echo "Restored $name. Secrets and certificates were kept; sensors keep working."
}

# --- status / uninstall -------------------------------------------------------------------------

cmd_status() {
  load_project
  check_docker
  echo "project: $PROJECT   images tag: $(env_get "$ENV_FILE" IDPS_TAG)   dashboard: $(env_get "$ENV_FILE" IDPS_PUBLIC_URL)/"
  dc ps
  for svc in db soc proxy; do
    cid=$(dc ps -q "$svc" 2>/dev/null | head -n 1)
    [ -z "$cid" ] || echo "$svc: $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
  done
}

# sensor_down [--volumes]: the sensor project of this host (compose project in .env.sensor)
sensor_down() {
  sp=$(env_get "$SENSOR_ENV_FILE" IDPS_SENSOR_PROJECT)
  valid_name "$sp" || die "IDPS_SENSOR_PROJECT in $SENSOR_ENV_FILE is not valid"
  docker compose --env-file "$SENSOR_ENV_FILE" -f "$SENSOR_COMPOSE" -p "$sp" --profile tools down "$@" --remove-orphans
}

cmd_uninstall() {
  YES=0; DELETE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --keep-data) DELETE=0; shift ;;   # the default, accepted for clarity
      --delete-data) DELETE=1; shift ;;
      --yes) YES=1; shift ;;
      *) echo "unknown option: $1" >&2; usage ;;
    esac
  done
  HAVE_SOC=0; HAVE_SENSOR=0
  [ ! -f "$ENV_FILE" ] || HAVE_SOC=1
  [ ! -f "$SENSOR_ENV_FILE" ] || HAVE_SENSOR=1
  [ "$HAVE_SOC$HAVE_SENSOR" != 00 ] || die "nothing to uninstall: neither $ENV_FILE nor $SENSOR_ENV_FILE exists"
  [ "$HAVE_SOC" = 0 ] || load_project
  check_docker
  what=""
  [ "$HAVE_SOC" = 0 ] || what="the SOC (project $PROJECT)"
  [ "$HAVE_SENSOR" = 0 ] || what="${what:+$what and }the sensor on this host"
  if [ "$DELETE" = 1 ]; then
    msg="Remove $what AND DELETE its data: database, certificates, backups, secrets, .env files, soc.env, sensor bundles, sensor-data/ and the sensor's volumes?"
  else
    msg="Remove the containers and network of $what? (data volumes, secrets and .env files are kept)"
  fi
  if [ "$YES" != 1 ]; then
    printf '%s [y/N] ' "$msg"
    read -r answer || answer=n
    case "$answer" in y|Y|yes|YES) ;; *) echo "cancelled"; exit 1 ;; esac
  fi
  if [ "$DELETE" = 1 ]; then
    if [ "$HAVE_SOC" = 1 ]; then
      dc --profile tools down --volumes --remove-orphans
      rm -rf "$SECRETS_DIR" "$SENSORS_DIR" "$ENV_FILE" "$DEPLOY_DIR/soc.env" "$DEPLOY_DIR/caddy-root.crt"
    fi
    if [ "$HAVE_SENSOR" = 1 ]; then
      sensor_down --volumes || true
      rm -rf "$SENSOR_DATA" "$SENSOR_ENV_FILE" "$DEPLOY_DIR/sensor.extra.env"
    fi
    echo "Removed $what, with their data."
  else
    [ "$HAVE_SOC" = 0 ] || dc --profile tools down --remove-orphans
    [ "$HAVE_SENSOR" = 0 ] || sensor_down
    echo "Removed the containers of $what. Data kept (volumes, secrets, .env files)."
    [ "$HAVE_SOC" = 0 ] || echo "Install the SOC again with: install.sh soc   (the image tag is kept: $(env_get "$ENV_FILE" IDPS_TAG))"
  fi
}

# --- main ---------------------------------------------------------------------------------------

[ $# -ge 1 ] || usage
cmd=$1; shift
case "$cmd" in
  soc) cmd_soc "$@" ;;
  add-sensor) cmd_add_sensor "$@" ;;
  sensor) cmd_sensor "$@" ;;
  upgrade) cmd_upgrade "$@" ;;
  rollback) cmd_rollback "$@" ;;
  restore) cmd_restore "$@" ;;
  renew-sensor) cmd_renew_sensor "$@" ;;
  status) cmd_status "$@" ;;
  uninstall) cmd_uninstall "$@" ;;
  -h|--help|help) usage 0 ;;
  *) echo "unknown command: $cmd" >&2; usage ;;
esac
