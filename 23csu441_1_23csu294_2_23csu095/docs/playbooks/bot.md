# Playbook: botnet traffic

**What it is.** An infected machine talking to a command-and-control (C2) server, taking orders
or sending data, often on a regular schedule.

**MITRE ATT&CK:** T1071 Application Layer Protocol (Command and Control), T1571 Non-Standard Port.

**Confirm it**
- Repeated connections from an **internal** host to the same external address at regular
  intervals, sometimes on unusual ports (e.g. 8080).
- The internal host is the problem here, not just the remote address.

**Contain**
- Block the remote C2 address, and isolate the internal host from the network.

**Fix**
- Investigate and clean or rebuild the infected host; find how it was infected.
- Check other hosts for connections to the same remote address.
- Restrict outbound traffic to what is needed (egress filtering).
