#!/bin/sh
# Fills LAB_SMTP_PASSWORD and LAB_SMTP_TO in lab/.env. The password is read without echo and is
# never printed. Run it from anywhere: sh lab/set-smtp.sh   (then delete this file if you like)
set -eu
ENV_FILE="$(cd "$(dirname "$0")" && pwd)/.env"
[ -f "$ENV_FILE" ] || { echo "no $ENV_FILE" >&2; exit 1; }
printf 'Gmail App Password (16 letters; typing is hidden): '
stty -echo; IFS= read -r PW; stty echo; echo
PW=$(printf '%s' "$PW" | tr -d ' ')
[ "${#PW}" -eq 16 ] || { echo "that is ${#PW} characters, not 16: nothing changed" >&2; exit 1; }
printf 'Send alerts to (email, several separated by commas): '
IFS= read -r TO
TO=$(printf '%s' "$TO" | tr -d ' ')
case "$TO" in *@*) ;; *) echo "that is not an email address: nothing changed" >&2; exit 1 ;; esac
PW="$PW" TO="$TO" python3 - "$ENV_FILE" <<'PY'
import os, sys
path = sys.argv[1]
lines = open(path).read().splitlines()
vals = {"LAB_SMTP_PASSWORD": os.environ["PW"], "LAB_SMTP_TO": os.environ["TO"]}
out, seen = [], set()
for line in lines:
    key = line.split("=", 1)[0].strip()
    if key in vals:
        out.append(f"{key}={vals[key]}"); seen.add(key)
    else:
        out.append(line)
out += [f"{k}={v}" for k, v in vals.items() if k not in seen]
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(out) + "\n")
os.replace(tmp, path)
PY
echo "Saved. Tell Claude: done"
