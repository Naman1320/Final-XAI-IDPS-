#!/bin/sh
# Lab-only credentials come from the environment, never from the image.
# Routes and firewall rules are set by the victim-net container, whose network
# namespace this container shares.
set -e
if [ -z "${LAB_VICTIM_PASSWORD:-}" ]; then
  echo "victim: LAB_VICTIM_PASSWORD is not set; copy lab/.env.example to lab/.env" >&2
  exit 1
fi
case "$LAB_VICTIM_PASSWORD" in
  *"
"*) echo "victim: LAB_VICTIM_PASSWORD must be a single line" >&2; exit 1 ;;
esac
printf 'labuser:%s\n' "$LAB_VICTIM_PASSWORD" | chpasswd

# Fresh SSH host keys for every container, instead of keys baked into the image.
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A >/dev/null
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
/usr/sbin/sshd
exec nginx -g 'daemon off;'
