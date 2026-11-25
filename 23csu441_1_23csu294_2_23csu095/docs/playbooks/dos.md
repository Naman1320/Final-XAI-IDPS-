# Playbook: denial of service (DoS / DDoS)

**What it is.** Traffic meant to exhaust a service: floods of packets or requests (Hulk, DDoS),
or slow attacks that hold connections open (slowloris, Slowhttptest). DDoS comes from many sources.

**MITRE ATT&CK:** T1498 Network Denial of Service, T1499 Endpoint Denial of Service (Impact).

**Confirm it**
- Very high packets or bytes per second toward one service, or many long-lived connections
  sending data very slowly (slow attacks: long duration, tiny packets, long gaps).
- Check the target's health: response times, error rates, connection counts.

**Contain**
- For one or a few sources, block them (short TTL first) and watch whether the load drops.
- For a distributed attack, per-IP blocking doesn't scale: use rate limiting, connection
  limits and upstream filtering (hosting provider or DDoS protection service).

**Fix**
- Web servers: set request header/body timeouts and per-IP connection limits (mitigates slow
  attacks); put a reverse proxy or CDN in front.
- Make sure monitoring alerts on service health, not only on the IDPS.
