# Shared lab addresses. Run attacks ONLY against these lab hosts.
VICTIM_IP="${VICTIM_IP:-10.10.2.10}"
DVWA_IP="${DVWA_IP:-10.10.2.11}"

# Each target must be exactly one of the lab hosts (not the sensor or a gateway).
for ip in "$VICTIM_IP" "$DVWA_IP"; do
  case "$ip" in
    10.10.2.10|10.10.2.11) ;;
    *) echo "Refusing: $ip is not a lab target (allowed: 10.10.2.10, 10.10.2.11)" >&2; exit 1 ;;
  esac
done

# Only run inside the lab attacker container, never on the host machine.
if ! ip -4 addr show 2>/dev/null | grep -q 'inet 10\.10\.1\.10/'; then
  echo "Refusing: run this inside the lab attacker container (docker compose exec attacker ...)" >&2
  exit 1
fi
