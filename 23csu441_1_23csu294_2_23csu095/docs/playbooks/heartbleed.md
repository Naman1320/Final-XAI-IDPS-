# Playbook: Heartbleed (CVE-2014-0160)

**What it is.** Exploitation of a bug in old OpenSSL versions that lets a remote client read
server memory, which can include private keys, passwords and session data.

**MITRE ATT&CK:** T1190 Exploit Public-Facing Application, T1040 Network Sniffing (data exposure).

**Confirm it**
- TLS connections with malformed heartbeat messages and unusually large responses from the
  server. Check the server's OpenSSL version: affected are 1.0.1 to 1.0.1f.

**Contain**
- Block the source, and take the vulnerable service offline or patch it immediately.

**Fix**
- Upgrade OpenSSL, then **replace the server's certificate and private key** (assume they
  leaked), invalidate sessions and ask users to change passwords.
- Track software versions so known-vulnerable libraries are found before attackers do.
