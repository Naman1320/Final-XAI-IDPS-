#!/bin/bash
# Victim: a web server and nothing else. No SSH key is installed; use SSM Session Manager.
set -euo pipefail

# The instance can boot before its route to the internet works: wait, then retry the install.
for i in $(seq 1 30); do
  if curl -fsS -m 5 -o /dev/null https://checkip.amazonaws.com; then break; fi
  echo "waiting for the network ($i/30)"
  sleep 5
  if [ "$i" -eq 30 ]; then echo "no network after 150 s" >&2; exit 1; fi
done
for n in 1 2 3 4 5; do
  if dnf install -y nginx; then break; fi
  if [ "$n" -eq 5 ]; then exit 1; fi
  sleep 10
done

systemctl enable --now nginx
echo "idps-fyp victim" > /usr/share/nginx/html/index.html
