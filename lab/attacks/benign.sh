#!/bin/bash
# Normal traffic for the false-positive test: one busy user working against the lab victims for
# DURATION seconds (default 3600) with random think times. No attack tools, no scans.
#
#   docker compose exec -e LAB_VICTIM_PASSWORD attacker /attacks/benign.sh [DURATION]
#
# Activities (one "benign <activity> ..." line each, UTC timestamp first, on stdout):
#   web      a page of 10-50 KB (mostly /benign/*.html, sometimes nginx's default page) with its
#            assets, browser-like: one keep-alive connection, or the page and then the assets on up
#            to 6 parallel connections; sometimes a 404
#   dvwa     DVWA login page and assets, now and then a login, a few pages with their assets, logout
#   download files of 100 KB - 50 MB from the victim's nginx (rate-limited like a real client)
#   ssh      an interactive-looking session: a few commands with pauses, then exit
#   scp      a small file to the victim and back
#   burst    15-40 small requests: an API poller (one keep-alive connection, 2-5 requests a second)
#            or a page with many assets (6 parallel connections)
#   connreq  a script or health check: a few requests, each on a NEW connection
#   ping     3-5 echo requests
#
# Besides the activity lines every request gets a line "benign req ACTIVITY LOCAL_PORT SERVER:PORT
# STATUS SECONDS PATH [expect=404]" (SSH, scp and ping have "-" as the port and the exit code as
# the status). scripts/bench_benign.py matches alerts to these lines by client port, server address
# and time, to report the false-positive rate per activity.
#
# Needs these files in the victim's nginx root (scripts/bench_benign.py creates and removes them;
# by hand see "False-positive test" in docs/live.md): /benign/index.html, page2.html, page3.html,
# /benign/files/f_100k.bin, f_1m.bin, f_10m.bin, f_50m.bin and /benign/assets/a1..a8.{css,js,png}.
# SSH needs LAB_VICTIM_PASSWORD in the environment (the attacker container does not have it by
# default; pass it with `exec -e LAB_VICTIM_PASSWORD`). Without it the ssh and scp activities are
# skipped. Optional BENIGN_SEED makes the choices (which activity, page, file, how many) repeatable;
# the timings still vary. TERM or INT stops everything at once, including the running activity.
. "$(dirname "$0")/common.sh"

DURATION="${1:-${BENIGN_DURATION:-3600}}"
case "$DURATION" in ''|*[!0-9]*) echo "usage: benign.sh [DURATION seconds]" >&2; exit 2 ;; esac
[ "$DURATION" -ge 1 ] || { echo "usage: benign.sh [DURATION seconds]" >&2; exit 2; }
[ -n "$BENIGN_SEED" ] && RANDOM=$BENIGN_SEED

set -m   # every background job gets its own process group, so one kill stops the whole activity
NGINX="http://$VICTIM_IP"
DVWA="http://$DVWA_IP"
WORK=$(mktemp -d)
ACT=""   # pid (= process group) of the activity or sleep that is running now

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s benign %s\n' "$(ts)" "$*"; }
stop_all() {
  [ -n "$ACT" ] && kill -TERM -- "-$ACT" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
on_signal() { stop_all; log "stop (signal)"; exit 0; }
trap on_signal INT TERM HUP
trap 'rm -rf "$WORK"' EXIT

# Random numbers go into the global R (not into $(...)), so a seed really repeats the choices.
rnd() { R=$(( $1 + RANDOM % ($2 - $1 + 1) )); }          # integer in [lo, hi]
pick() { local a=("$@"); R=${a[RANDOM % ${#a[@]}]}; }
pause() { local w; rnd "$1" "$2"; w=$R; rnd 0 9; sleep "$w.$R"; }   # lo..hi seconds
bgsleep() { sleep "$1" & ACT=$!; wait "$ACT"; ACT=""; }  # a sleep that TERM can interrupt
# One activity in a background subshell with its own seed drawn here, so it can be killed at once.
run() { local s=$RANDOM; ( RANDOM=$s; "$@" ) & ACT=$!; wait "$ACT"; ACT=""; }

HAVE_SSH=1
if [ -z "$LAB_VICTIM_PASSWORD" ]; then
  HAVE_SSH=0; log "note: LAB_VICTIM_PASSWORD not set, ssh and scp skipped"
fi
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
          -o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=password)
export SSHPASS="$LAB_VICTIM_PASSWORD"

# ---- requests (curl, logged with the client's port) -------------------------------------------

CURL_OPTS=(-A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
           --compressed)
WFMT='%{local_port}|%{remote_ip}|%{remote_port}|%{http_code}|%{time_total}|%{url_effective}\n'
FARGS=()      # extra curl arguments for req / fetch_many (cookie jar, rate)
REQ_CODE=000

_logreq() {   # $1 activity, $2 optional tag; reads curl -w lines on stdin
  local lp rip rp c t u
  while IFS='|' read -r lp rip rp c t u; do
    [ -n "$u" ] || continue
    printf '%s benign req %s %s %s:%s %s %s /%s%s\n' "$(ts)" "$1" "$lp" "$rip" "$rp" "$c" "$t" \
      "${u#*//*/}" "${2:+ $2}"
  done
}

req() {       # req ACTIVITY OUTFILE TAG curl-args... : one request on its own connection
  local act=$1 out=$2 tag=$3 line; shift 3
  line=$(curl -s -o "$out" -w "$WFMT" --max-time 30 "${CURL_OPTS[@]}" "${FARGS[@]}" "$@")
  printf '%s\n' "$line" | _logreq "$act" "$tag"
  REQ_CODE=$(printf '%s' "$line" | cut -d'|' -f4)
}

fetch_many() {   # fetch_many ACTIVITY seq|parallel URL... : ONE curl call, like a browser
  local act=$1 mode=$2 args=() u; shift 2
  for u in "$@"; do args+=(-o /dev/null "$u"); done
  [ "$mode" = parallel ] && args=(--parallel --parallel-max 6 --parallel-immediate "${args[@]}")
  curl -s -w "$WFMT" --max-time 60 "${CURL_OPTS[@]}" "${FARGS[@]}" "${args[@]}" | _logreq "$act" ""
}

reqraw() {    # reqraw ACTIVITY SERVER:PORT STATUS SECONDS : a non-HTTP session (no client port known)
  printf '%s benign req %s - %s %s %s /\n' "$(ts)" "$1" "$2" "$3" "$4"
}

# ---- activities -------------------------------------------------------------------------------

act_web() {
  local assets=() n i ext page mode
  rnd 1 10
  if [ "$R" = 1 ]; then   # a page that does not exist
    pick missing.html old/index.php favicon.ico notes.txt
    req web /dev/null expect=404 "$NGINX/$R"
    log "web nginx 404 status=$REQ_CODE"; return
  fi
  rnd 3 8; n=$R
  for ((i = 0; i < n; i++)); do
    pick css js png; ext=$R; rnd 1 8; assets+=("$NGINX/benign/assets/a$R.$ext")
  done
  rnd 1 10
  if [ "$R" -le 2 ]; then page="$NGINX/"; else
    pick index.html index.html page2.html page3.html; page="$NGINX/benign/$R"
  fi
  rnd 1 2
  if [ "$R" = 1 ]; then
    mode=keep-alive; fetch_many web seq "$page" "${assets[@]}"
  else
    mode=parallel; fetch_many web seq "$page"; pause 0 0; fetch_many web parallel "${assets[@]}"
  fi
  log "web nginx $mode page=${page#$NGINX} requests=$((n + 1))"
}

# A DVWA page and its css/js/image files (found in the HTML), one browser-like fetch.
dvwa_view() {   # dvwa_view PATH
  local p=$1 dir="" refs ref urls=()
  case "$p" in */*) dir=${p%/*} ;; esac
  req dvwa "$WORK/page.html" "" "$DVWA/$p"
  refs=$(grep -o '\(src\|href\)="[^"#?]*\.\(css\|js\|png\|jpg\|ico\)"' "$WORK/page.html" \
         | sed 's/^[a-z]*="//; s/"$//')
  for ref in $refs; do
    case "$ref" in
      http*) ;;
      /*) urls+=("$DVWA$ref") ;;
      *) urls+=("$DVWA/${dir:+$dir/}$ref") ;;
    esac
  done
  [ "${#urls[@]}" -gt 0 ] || return
  rnd 1 2
  if [ "$R" = 1 ]; then fetch_many dvwa seq "${urls[@]}"; else fetch_many dvwa parallel "${urls[@]}"; fi
}

# DVWA sends logins to setup.php while its database does not exist. Create it (once per run, and
# only then); an existing database is never reset.
dvwa_setup_once() {
  [ ! -e "$WORK/setup_tried" ] || return
  : > "$WORK/setup_tried"
  req dvwa "$WORK/page.html" "" "$DVWA/setup.php"
  local token
  token=$(sed -n "s/.*user_token' value='\([^']*\)'.*/\1/p" "$WORK/page.html" | head -n 1)
  [ -n "$token" ] || { log "dvwa setup: no CSRF token on setup.php"; return; }
  req dvwa /dev/null "" --data-urlencode "create_db=Create / Reset Database" \
      -d "user_token=$token" "$DVWA/setup.php"
  log "dvwa database was missing and has been created (setup.php)"
}

act_dvwa() {
  local token pages=(index.php instructions.php about.php setup.php
        "vulnerabilities/sqli/?id=1&Submit=Submit" vulnerabilities/xss_r/ security.php phpinfo.php)
  FARGS=(-b "$WORK/cj" -c "$WORK/cj"); rm -f "$WORK/cj"
  dvwa_view login.php
  rnd 1 3
  if [ "$R" -gt 1 ]; then log "dvwa login-page"; return; fi
  token=$(sed -n "s/.*user_token' value='\([^']*\)'.*/\1/p" "$WORK/page.html" | head -n 1)
  pause 1 4   # typing the credentials
  req dvwa /dev/null "" -D "$WORK/hdr" \
      -d "username=admin&password=password&Login=Login&user_token=$token" "$DVWA/login.php"
  if grep -qi '^location: *setup.php' "$WORK/hdr" 2>/dev/null; then
    log "dvwa login failed (redirected to setup.php: no database)"
    dvwa_setup_once; return
  fi
  dvwa_view index.php
  if [ "$REQ_CODE" != 200 ]; then log "dvwa login failed (index.php status=$REQ_CODE)"; return; fi
  local visited=0 k i
  rnd 2 4; k=$R
  for ((i = 0; i < k; i++)); do
    pick "${pages[@]}"; dvwa_view "$R"; visited=$((visited + 1)); pause 1 6
  done
  req dvwa /dev/null "" "$DVWA/logout.php"
  log "dvwa login pages=$((visited + 1))"
}

act_download() {
  local f rate
  pick f_100k.bin f_100k.bin f_1m.bin f_1m.bin f_1m.bin f_10m.bin f_10m.bin f_50m.bin; f=$R
  pick 2M 5M 10M 20M; rate=$R
  req download /dev/null "" --max-time 120 --limit-rate "$rate" "$NGINX/benign/files/$f"
  log "download $f limit=$rate status=$REQ_CODE"
}

act_ssh() {
  [ "$HAVE_SSH" = 1 ] || return
  local cmds=("ls -la" "uname -a" "whoami" "df -h" "uptime" "cat /etc/os-release" "ps aux | head"
              "ls /var/www/html" "free -m" "pwd" "date" "id" "head -5 /etc/passwd")
  local n k start rc cmd w
  rnd 2 5; n=$R; start=$SECONDS
  {
    rnd 1 3; sleep "$R"
    for ((k = 0; k < n; k++)); do
      pick "${cmds[@]}"; printf '%s\n' "$R"; rnd 1 8; sleep "$R"
    done
    printf 'exit\n'
  } | timeout 120 sshpass -e ssh -tt "${SSH_OPTS[@]}" "labuser@$VICTIM_IP" >/dev/null 2>&1
  rc=${PIPESTATUS[1]}
  reqraw ssh "$VICTIM_IP:22" "$rc" "$((SECONDS - start))"
  log "ssh session commands=$n seconds=$((SECONDS - start)) exit=$rc"
}

act_scp() {
  [ "$HAVE_SSH" = 1 ] || return
  local kb f rc1 rc2 rc3 t0=$SECONDS name
  rnd 5 200; kb=$R; name="doc_$RANDOM.dat"; f="$WORK/$name"
  head -c $((kb * 1024)) /dev/urandom > "$f"
  timeout 60 sshpass -e scp "${SSH_OPTS[@]}" -q "$f" "labuser@$VICTIM_IP:/tmp/$name" >/dev/null 2>&1
  rc1=$?; reqraw scp "$VICTIM_IP:22" "$rc1" "$((SECONDS - t0))"
  pause 1 3; t0=$SECONDS
  timeout 60 sshpass -e scp "${SSH_OPTS[@]}" -q "labuser@$VICTIM_IP:/tmp/$name" "$f.back" >/dev/null 2>&1
  rc2=$?; reqraw scp "$VICTIM_IP:22" "$rc2" "$((SECONDS - t0))"; t0=$SECONDS
  timeout 30 sshpass -e ssh "${SSH_OPTS[@]}" "labuser@$VICTIM_IP" "rm -f /tmp/$name" >/dev/null 2>&1
  rc3=$?; reqraw scp "$VICTIM_IP:22" "$rc3" "$((SECONDS - t0))"
  rm -f "$f" "$f.back"
  log "scp size_kb=$kb up_exit=$rc1 down_exit=$rc2 cleanup_exit=$rc3"
}

act_burst() {
  local n i rate target urls=() ext
  rnd 15 40; n=$R
  rnd 1 2
  if [ "$R" = 1 ]; then   # an API poller: one keep-alive connection, a few requests a second
    pick "$NGINX/benign/assets/a1.css" "$NGINX/benign/assets/a2.js" "$NGINX/" "$DVWA/login.php"
    target=$R; rnd 2 5; rate=$R
    for ((i = 0; i < n; i++)); do urls+=("$target?_=$i"); done
    FARGS=(--rate "$rate/s")
    fetch_many burst seq "${urls[@]}"
    log "burst poller requests=$n rate=$rate/s target=$target"
  else                    # a page with many assets: up to 6 parallel connections
    for ((i = 0; i < n; i++)); do
      pick css js png; ext=$R; rnd 1 8; urls+=("$NGINX/benign/assets/a$R.$ext?_=$i")
    done
    fetch_many burst parallel "${urls[@]}"
    log "burst assets requests=$n parallel=6"
  fi
}

act_connreq() {   # a script or health check: every request opens a new connection
  local n i target
  rnd 3 8; n=$R
  for ((i = 0; i < n; i++)); do
    pick "$NGINX/" "$NGINX/" "$NGINX/benign/assets/a1.css" "$DVWA/login.php"; target=$R
    req connreq /dev/null "" "$target"
    pause 0 3
  done
  log "connreq requests=$n"
}

act_ping() {
  local t c t0=$SECONDS rc
  pick "$VICTIM_IP" "$DVWA_IP"; t=$R; rnd 3 5; c=$R
  ping -c "$c" -W 2 "$t" >/dev/null 2>&1; rc=$?
  reqraw ping "$t:icmp" "$rc" "$((SECONDS - t0))"
  log "ping $t count=$c exit=$rc"
}

# ---- main loop --------------------------------------------------------------------------------

log "start duration=${DURATION}s victim=$VICTIM_IP dvwa=$DVWA_IP seed=${BENIGN_SEED:-none}"
for f in index.html files/f_100k.bin; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$NGINX/benign/$f")
  [ "$c" = 200 ] || log "note: /benign/$f is missing in the victim's nginx (status $c; see the header)"
done
END=$((SECONDS + DURATION))
while [ "$SECONDS" -lt "$END" ]; do
  rnd 1 100
  if   [ "$R" -le 30 ]; then run act_web
  elif [ "$R" -le 45 ]; then run act_dvwa
  elif [ "$R" -le 57 ]; then run act_download
  elif [ "$R" -le 69 ]; then run act_ssh
  elif [ "$R" -le 75 ]; then run act_scp
  elif [ "$R" -le 85 ]; then run act_burst
  elif [ "$R" -le 92 ]; then run act_connreq
  else run act_ping
  fi
  # think time: usually a few seconds, sometimes a long coffee break
  rnd 1 12
  if [ "$R" = 1 ]; then rnd 15 40; else rnd 1 8; fi
  w=$R; rnd 0 9; bgsleep "$w.$R"
done
log "done"
