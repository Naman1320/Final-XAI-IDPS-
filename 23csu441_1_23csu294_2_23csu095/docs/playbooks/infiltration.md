# Playbook: infiltration

**What it is.** An attacker who already has a foothold inside (for example through a malicious
download or document) exploring the internal network from a compromised host.

**MITRE ATT&CK:** T1204 User Execution (Execution), T1046 Network Service Discovery, T1021 Remote Services (Lateral Movement).

**Confirm it**
- An internal host scanning or connecting to other internal hosts it doesn't normally talk to.
- Check that host for recently run programs, downloads and new accounts.

**Contain**
- Isolate the internal host at once; it should be treated as compromised.

**Fix**
- Investigate and rebuild the host; reset credentials that were used on it.
- Segment the network so workstations can't reach servers they don't need.
- User awareness training for downloads and attachments.
