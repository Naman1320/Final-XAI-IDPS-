# Playbook: port scan

**What it is.** One source contacts many ports or hosts in a short time to find open services.
Often the first step before an attack, but also done by monitoring tools and internet-wide scanners.

**MITRE ATT&CK:** T1046 Network Service Discovery (Discovery), T1595 Active Scanning (Reconnaissance).

**Confirm it**
- Many distinct destination ports or hosts from one source in minutes; mostly SYN-only or
  very short flows with few bytes, often answered by RST.
- Check whether the source is a known scanner you run yourself (vulnerability scanner,
  monitoring); if so, mark the alert as a false positive and add it to the allowlist.

**Contain**
- A scan alone is low severity. Block the source only if it keeps scanning or is followed by
  other alerts (brute force, web attacks) from the same address.
- Check what the scan could see: which ports answered on the targets.

**Fix**
- Close or firewall services that don't need to be reachable; expose management ports
  (SSH, RDP, databases) only on internal networks or a VPN.
- Watch the same source for follow-up activity over the next hours.
