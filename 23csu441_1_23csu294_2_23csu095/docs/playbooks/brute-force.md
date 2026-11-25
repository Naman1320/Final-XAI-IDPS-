# Playbook: password brute force (FTP / SSH)

**What it is.** Repeated login attempts with many passwords (FTP-Patator, SSH-Patator) to guess
an account's credentials.

**MITRE ATT&CK:** T1110 Brute Force (Credential Access), T1110.001 Password Guessing.

**Confirm it**
- Many short connections from one source to port 21 or 22 in a short time, similar sizes and timing.
- Check the target's authentication logs for failed logins, and especially any **successful**
  login from the same source: that means an account may be compromised.

**Contain**
- Block the source IP. If any login succeeded, disable or reset that account at once and
  investigate what the session did.

**Fix**
- SSH: disable password login (keys only), disable root login, use fail2ban or similar.
- Replace FTP with SFTP; never expose FTP to untrusted networks.
- Enforce strong passwords and, where possible, multi-factor authentication.
