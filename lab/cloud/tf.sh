#!/usr/bin/env bash
# Run Terraform against the emulated AWS only (docs/cloud-plan.md step C1).
#   lab/cloud/tf.sh init | validate | plan | apply | destroy | output | show | state | providers
# infra/ is copied into a work folder outside the repo, with lab/cloud/terraform/emulator_override.tf
# added, so infra/ stays the real design and its state never mixes with the emulator's.
# The billing guard runs first, every time; if it refuses, Terraform never starts.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=${IDPS_CLOUD_TF_DIR:-$HOME/Library/Caches/idps-lab/cloud-tf}
marker=.idps-cloud-tf   # written into the work folder; rsync --delete runs only where it exists

cmd=${1:-plan}; shift || true
# Only these subcommands, and no flags that could point Terraform at another folder, state or
# variable file (e.g. -chdir=../infra would write emulator resources into the real state).
case "$cmd" in
  init|validate|plan|apply|destroy|output|show|state|providers|refresh|fmt|graph|version) ;;
  *) echo "tf.sh: subcommand '$cmd' is not allowed" >&2; exit 2 ;;
esac
for arg in "$@"; do
  case "$arg" in
    -chdir*|-state*|-backup*|-var-file*|-backend-config*|-plugin-dir*)
      echo "tf.sh: option '$arg' is not allowed" >&2; exit 2 ;;
  esac
done

# shellcheck source=env.sh
source "$repo/lab/cloud/env.sh"
"$repo/.venv/bin/python" "$repo/lab/cloud/guard.py" >&2

tf=${TERRAFORM:-$(command -v terraform || echo "$HOME/.local/bin/terraform")}
[ -x "$tf" ] || { echo "terraform is not installed (looked for $tf)" >&2; exit 1; }

# The work folder must be new, empty, or one this script made: rsync --delete below would
# otherwise wipe whatever folder IDPS_CLOUD_TF_DIR points at.
if [ -e "$work" ] && [ ! -f "$work/$marker" ] && [ -n "$(ls -A "$work" 2>/dev/null)" ]; then
  echo "tf.sh: $work is not empty and was not made by tf.sh; refusing to sync into it" >&2
  exit 1
fi
mkdir -p "$work"
touch "$work/$marker"
# Fresh copy of the design each run; keep only the work folder's own state and provider cache.
# No variable files are copied (*.tfvars, *.tfvars.json): real values never reach the emulator.
rsync -a --delete \
  --exclude "/$marker" \
  --exclude '.terraform/' --exclude '.terraform.lock.hcl' \
  --exclude 'terraform.tfstate*' --exclude '*.tfvars' --exclude '*.tfvars.json' \
  --exclude 'budget/' \
  "$repo/infra/" "$work/"
cp "$repo/lab/cloud/terraform/emulator_override.tf" "$work/"
# Moto ignores policy Conditions, so the buckets' TLS-only Deny would block everything: see the file.
cp "$repo/lab/cloud/terraform/secure_bucket_override.tf" "$work/modules/secure_bucket/"
# Values for the emulated run only (documentation range, nobody's real address).
export TF_VAR_admin_cidrs='["203.0.113.25/32"]'

cd "$work"

# Everything except init runs behind the emulator-only proxy (lab/cloud/egress_proxy.py): it
# routes S3 Control's <account>.localhost names to the emulator and refuses any other host and
# every HTTPS tunnel. init is left out because it downloads the provider from the registry.
if [ "$cmd" != init ]; then
  fifo=$(mktemp -u "${TMPDIR:-/tmp}/idps-proxy.XXXXXX"); mkfifo "$fifo"
  "$repo/.venv/bin/python" "$repo/lab/cloud/egress_proxy.py" --port 0 >"$fifo" &
  proxy_pid=$!
  trap 'kill "$proxy_pid" 2>/dev/null; rm -f "$fifo"' EXIT
  proxy_port=""
  read -r proxy_port <"$fifo" || true
  [ -n "$proxy_port" ] || { echo "egress proxy did not start" >&2; exit 1; }
  export HTTP_PROXY=http://127.0.0.1:$proxy_port HTTPS_PROXY=http://127.0.0.1:$proxy_port
  export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY
  unset NO_PROXY no_proxy
fi

"$tf" "$cmd" "$@"
