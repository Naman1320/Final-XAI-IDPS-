# Playbook: web application attacks (brute force, XSS, SQL injection)

**What it is.** Requests crafted to abuse a web application: guessing logins, injecting script
(cross-site scripting, XSS) or injecting database queries (SQL injection).

**MITRE ATT&CK:** T1190 Exploit Public-Facing Application (Initial Access), T1110 Brute Force.

**Confirm it**
- Check the web server and application logs for the source's requests: unusual parameters,
  script tags or SQL syntax in inputs, many login attempts, error responses (HTTP 500s).
- For SQL injection, check whether any request returned unusual amounts of data.

**Contain**
- Block the source IP. If data may have been read or changed, treat it as an incident:
  preserve logs and open a case.

**Fix**
- Use parameterised queries everywhere (prevents SQL injection); validate input and encode
  output (prevents XSS); add a Content-Security-Policy.
- Rate-limit and lock out repeated failed logins; consider a web application firewall.
- Keep the application and its libraries patched.
