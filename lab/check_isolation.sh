#!/bin/sh
# Run on the host after `docker compose up`. Checks the lab is cut off from the
# outside world and that lab traffic goes through the sensor. Sends no attack traffic.
cd "$(dirname "$0")" || exit 1
FAIL=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAIL=1; }
in_c() { c=$1; shift; docker exec "idps-$c" sh -c "$*" >/dev/null 2>&1; }

for c in sensor attacker victim dvwa; do
  if in_c "$c" '(ip route 2>/dev/null || route -n) | grep -qE "^(default|0\.0\.0\.0)"'; then
    fail "$c has a default route"; else pass "$c has no default route"; fi
done

for c in attacker victim; do
  if in_c "$c" 'getent hosts example.com'; then
    fail "$c can resolve internet names"; else pass "$c can't resolve internet names"; fi
done

if in_c attacker 'ping -c1 -W1 10.10.1.1'; then fail "attacker reaches gateway 10.10.1.1"; else pass "attacker can't reach gateway 10.10.1.1"; fi
if in_c attacker 'ping -c1 -W1 10.10.2.1'; then fail "attacker reaches gateway 10.10.2.1 via sensor"; else pass "attacker can't reach gateway 10.10.2.1"; fi
if in_c attacker 'ip route add default via 10.10.1.1'; then
  in_c attacker 'ip route del default'; fail "attacker can change its routes"
else pass "attacker can't change its routes"; fi

if in_c attacker 'ping -c1 -W2 10.10.2.10'; then pass "attacker reaches victim"; else fail "attacker can't reach victim"; fi
if docker exec idps-attacker ip route get 10.10.2.10 | grep -q 'via 10.10.1.2'; then
  pass "attacker -> victim goes via the sensor"; else fail "attacker -> victim does not go via the sensor"; fi

# The lab SOC (mgmt_net): reachable from the sensor only, and it reaches nothing.
if in_c soc-net 'ip route | grep -q "^default"'; then fail "soc has a default route"; else pass "soc has no default route"; fi
for c in attacker victim; do
  if in_c "$c" 'curl -sk --max-time 3 https://10.10.3.10:8443/health || wget -q -T 3 -O- --no-check-certificate https://10.10.3.10:8443/health || ping -c1 -W2 10.10.3.10'; then
    fail "$c reaches the SOC"; else pass "$c can't reach the SOC"; fi
done
# Exit 0 when the SOC gets any answer (even "connection refused"), 1 when its packets go nowhere.
soc_reaches() {
  in_c soc "python -c \"import socket,sys
try: socket.create_connection(('$1', $2), 3)
except ConnectionRefusedError: sys.exit(0)
except OSError: sys.exit(1)\""
}
if soc_reaches 10.10.3.2 22; then fail "soc can open connections to the sensor"; else pass "soc can't open connections to the sensor"; fi
if soc_reaches 10.10.3.1 80; then fail "soc reaches the Docker gateway"; else pass "soc can't reach the Docker gateway"; fi
if soc_reaches 1.1.1.1 443; then fail "soc reaches the internet"; else pass "soc can't reach the internet"; fi
if in_c sensor "python -c \"import ssl,urllib.request; urllib.request.urlopen('https://10.10.3.10:8443/health', context=ssl.create_default_context(cafile='/run/idps-soc/ca.pem'), timeout=3)\""; then
  pass "sensor reaches the SOC over verified TLS"; else fail "sensor can't reach the SOC"; fi

# The cloud collector (docs/cloud-plan.md C4), only when its namespace holder is running.
if docker ps --format '{{.Names}}' | grep -qx idps-collector-net; then
  if in_c collector-net 'ip route | grep -q "^default"'; then fail "collector has a default route"; else pass "collector has no default route"; fi
  if in_c collector-net '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ]'; then pass "collector does not forward (ip_forward 0)"; else fail "collector forwards packets"; fi
  if in_c collector-net 'nft list chain inet collectorguard forward | grep -q "policy drop"'; then pass "collector forward chain drops"; else fail "collector forward chain does not drop"; fi
  # Exit 0 = connected; anything else (refused, unreachable, dropped = timeout) = not reachable.
  col_reaches() { in_c collector-net "nc -w 3 $1 $2 </dev/null"; }
  if col_reaches 10.10.4.10 4566; then pass "collector reaches the emulator 10.10.4.10:4566"; else fail "collector can't reach the emulator"; fi
  if col_reaches 10.10.3.10 8444; then pass "collector reaches the SOC sensor port 10.10.3.10:8444"; else fail "collector can't reach the SOC sensor port"; fi
  for target in "10.10.3.10 8443" "10.10.3.2 22" "10.10.2.10 80" "10.10.1.10 22" "10.10.1.2 22" "1.1.1.1 443"; do
    if col_reaches $target; then fail "collector reaches ${target% *}:${target#* }"; else pass "collector can't reach ${target% *}:${target#* }"; fi
  done
  # Nothing may open a connection to the collector (replies only): from the sensor and the SOC.
  # Exit 0 when something answers (even "connection refused"), 1 when the packets go nowhere.
  reaches_collector() {
    in_c "$1" "python -c \"import socket,sys
try: socket.create_connection(('10.10.3.3', 8444), 3)
except ConnectionRefusedError: sys.exit(0)
except OSError: sys.exit(1)\""
  }
  if reaches_collector sensor; then fail "sensor can open connections to the collector"; else pass "sensor can't open connections to the collector"; fi
  if reaches_collector soc; then fail "soc can open connections to the collector"; else pass "soc can't open connections to the collector"; fi
  for c in attacker victim; do
    if in_c "$c" 'ping -c1 -W2 10.10.3.3 || ping -c1 -W2 10.10.4.30'; then fail "$c reaches the collector"; else pass "$c can't reach the collector"; fi
  done
fi

[ "$FAIL" = 0 ] && echo "All isolation checks passed." || { echo "Some checks FAILED: don't run attacks."; exit 1; }
