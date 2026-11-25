#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
export PATH="/opt/homebrew/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:$PATH"

compose=(docker compose -f compose.yml)
"${compose[@]}" up -d gateway
read -r "email?Google email allowed to open this dashboard: "
email=${email:l}
pattern='^[a-z0-9_+.-]+@[a-z0-9.-]+\.[a-z]{2,}$'
if ! [[ "$email" =~ $pattern ]]; then
  echo "Enter a single Google sign-in email address."
  exit 1
fi
echo "Copy your free account's authtoken from https://dashboard.ngrok.com/get-started/your-authtoken"
read -rs "token?ngrok authtoken (hidden): "
echo
[[ -n "$token" ]] || exit 1
echo "Open the HTTPS address shown beside url= on your iPhone. Keep this window open."
echo "Press Control-C to close the tunnel."
printf '%s\n' "$token" "$email" | "${compose[@]}" run --rm --no-deps -T --name idps-iphone-tunnel tunnel
