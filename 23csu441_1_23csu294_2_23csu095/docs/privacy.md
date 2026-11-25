# Privacy

What the SOC does with personal data, why, for how long, and what an admin does when someone asks
for their data to be erased. This describes the software's behaviour and is **not legal advice**:
what the law requires of you depends on who you are and where you operate; have it checked.

## What is processed

Network monitoring sees who talks to whom, and an IP address can identify a person (a home
connection, a laptop). The SOC stores:

| Data | Where | Why |
|---|---|---|
| Source and destination IP addresses and ports, protocol and timing of the flows that raised an alert; the sensor that saw them | `alerts` | Detect and investigate attacks |
| Flow statistics and the model's explanation | `alerts.features`, `alerts.explanation` | Judge and retrain the detector; explain a detection |
| Addresses the SOC blocked, or would have blocked in a dry run, with a reason | `blocks`, `would_blocks`, `actions` | Respond to attacks, keep a record of what was done |
| Analyst accounts: login name, password hash, MFA and single sign-on details | `users` | Operate the SOC |
| Who did what | `audit_log` | Accountability |
| Who looked at which address (as a one-way fingerprint) | `access_log` | Accountability for personal-data reads |
| Cases, case notes, assistant conversations | `cases`, `case_notes`, `assistant_conversations` | Incident response; notes and chats can quote addresses |
| Sensor reports (allowlists, health) | `sensor_status`, `model_versions` | Operate the sensors |

The purposes are network security monitoring and incident response. Nothing is used for marketing
or sold. `GET /privacy/notice` publishes this summary, with the retention settings actually in force
and the contacts you configure, to anyone without signing in; link to it from wherever you tell
people their traffic is monitored.

## Who receives it

Only what you configure, and the notice names the channels (never their addresses): `email`, `slack`,
`webhook`, `syslog` (a SIEM) and AbuseIPDB (a source address is sent only when an analyst asks for
its reputation, and only if it is public), and, when the assistant is on, the language-model service
that answers it (the conversation, which can contain addresses, is sent there). The weekly PDF
report lists source addresses; it is downloadable by any signed-in user and, if you turn it on,
emailed (`REPORT_MASK_IPS` hides the last octet).

## Retention

Automatic deletion runs in the background every hour (docs/soc.md "Retention"). `0` means not
deleted automatically.

| Data | Setting | Default |
|---|---|---|
| Alerts | `ALERT_RETENTION_DAYS` | 180 days |
| ... but judged alerts that carry features (training rows) | `ALERT_RETENTION_KEEP_LABELLED` | kept (set false to apply the limit to them too) |
| Audit entries | `AUDIT_RETENTION_DAYS` | 365 days |
| Access log | `ACCESS_LOG_RETENTION_DAYS` | 365 days |
| Assistant conversations | `ASSISTANT_RETENTION_DAYS` | 90 days after the last message |
| Closed cases and notes | `CLOSED_CASE_RETENTION_DAYS` | kept |
| Would-block records | `WOULD_BLOCK_RETENTION_DAYS` | 7 days |
| Blocks and actions | none | **kept until erased on request** |
| Erasure records | none | kept (they hold no address) |

Decide these deliberately: the defaults keep blocks and judged alerts for as long as the SOC runs.
The notice states the values you set, so it stays true when you change them.

## Rights and how a request is handled

A person can ask what you hold about them (access), to correct it, to have it erased, to complain to
the grievance officer, and to nominate someone to act for them. The notice says who to write to
(`PRIVACY_CONTACT_EMAIL`, `PRIVACY_GRIEVANCE_OFFICER`). The software helps with two of these:

### Access: "what do you hold about my address?"

1. Check the request really comes from whoever uses the address (the SOC cannot do this).
2. `GET /alerts?ip=203.0.113.7`, `GET /blocks?ip=...`, `GET /blocks/would?ip=...` show the alerts and
   blocks. These searches are access-logged under your name.
3. `POST /admin/privacy/erase/preview {"ip": ...}` also counts, per table and field, every place the
   address appears, including free text in notes, audit entries and assistant conversations.
4. Free text can mention an address in places the searches do not cover; the preview is the complete
   list.

### Erasure

1. Verify the request, and decide whether it must be granted (see "Framing" below). Erasure cannot be
   undone, except from a backup.
2. `POST /admin/privacy/erase/preview {"ip": "203.0.113.7"}`. Read `counts`, `warnings` and
   `manual_review`. A single address only: a CIDR is refused (422), erase each address.
3. `POST /admin/privacy/erase {"ip": "203.0.113.7", "reason": "request of the data principal, ref 123"}`.
   The reason (1 to 500 characters) is kept in the erasure record; it must not contain the address (it is
   refused if it does), so refer to the ticket, not the address.
   Erasure is refused (409) while the address has an **active block** (the sensor's firewall rule would
   stay and the SOC could no longer lift it): unblock it first, or send `"force": true` (audited). It
   is also refused (409, "an assistant reply is in progress; try again in a minute") while **any**
   assistant conversation has a reply running (at most `ASSISTANT_MAX_CONCURRENT` of them, for a
   minute or two each): a reply stores its conversation when it finishes and its new message may quote
   the address. A reply that crashed counts as finished after 10 minutes, so it blocks erasure for at
   most that long. On PostgreSQL the erasure also locks the conversations table against new replies
   until it commits (they wait a few seconds, they are not refused). The preview lists both as warnings, and `active_blocks` (a count) says how many
   active blocks it found.
4. In one transaction it:
   - deletes the alerts whose source or destination is the address (a case left without alerts stays;
     other addresses' blocks that came from those alerts lose the link);
   - deletes the address's blocks and would-blocks;
   - cancels open (pending or confirmed) actions that name it, so no sensor is handed an action with an
     erased address (confirmed ones become `failed`, pending ones `rejected`);
   - replaces the address with `[erased]` in: other alerts' explanation, rule, class and model-version
     text; block and would-block reasons; action params, result and reason; case titles and notes;
     assistant conversation messages and titles (an assistant "thinking" block that mentions it is
     dropped, because the model API signs it and it cannot be edited; `redacted_thinking` blocks are
     encrypted and keep their content, which the SOC cannot read or edit); audit entry targets and details;
     model version names; sensor status (an allowlist entry that is exactly the address is removed);
     earlier erasure reasons;
   - forgets it in the in-memory reputation, location and notification de-duplication caches.
   Matching is by token and in every spelling: `10.0.0.1` does not touch `10.0.0.10`; IPv6 compressed
   (any zero run), with or without leading zeros, in capitals, and IPv4-mapped forms
   (`::ffff:10.0.0.1`, `::ffff:a00:1`), all count as the address, and a trailing `.443` is treated as a
   port as tcpdump writes it (`10.0.0.1.443`, `2001:db8::1.443`). Not matched: NAT64
   (`64:ff9b::a00:1`) and other embeddings, and zero-padded IPv4 (`010.000.000.001`), which is not
   a valid address spelling.
   Mechanics: a read-only scan finds what mentions the address (no write lock, however long it
   takes), then a write phase takes the lock and first looks again for anything written since: every
   table except alerts is scanned again, alerts only above the newest id the first scan saw. Each
   candidate row is then read again (locked, on PostgreSQL) and rewritten from its current content, and
   the by-address deletes of alerts and blocks are repeated last. So a pending block, an audit entry
   or a note written while the scan ran is caught. Erasure is still a point in time: new traffic
   after it creates new rows.
   A tcpdump-style `10.0.0.1.443` and an IPv6 address with its port written without brackets
   (`2001:db8::1:443`) are read as address and port; that can over-redact a different, longer
   address, which is the safe direction. The assistant now writes IPv6 endpoints as `[addr]:port`.
5. Check the answer: `counts` equals what the preview said if nothing changed in between (a sensor
   ingesting, an analyst writing a note: later rows are caught too, so the numbers can then be higher). A second preview reports zero.
   One narrow gap remains on PostgreSQL: another alert that mentions the address only in its text
   (not as its source or destination) and commits during the erasure's last moments can be missed;
   alerts from or to the address are always deleted. The second preview shows any such leftover;
   erase again to remove it. `GET
   /admin/privacy/erasures` lists what was done (who, when, why, a fingerprint, counts; never the
   address) and the audit entry is `privacy_erase`.
6. Tell the requester what was and was not erased (next section).

`manual_review` lists account names (`users.username`) and sensor names (`sensor_tokens.name`) that
contain the address as text. Those are keys chosen by admins and are not rewritten; rename them by
hand.

### Looking up who accessed an address

`GET /admin/privacy/access-log?ip=203.0.113.7` returns who looked at that address and when (filters:
`username`, `action`, `since`, `until`). The log stores no address: each row has `subject_fp`, an
HMAC-SHA256 of the normalised address under a key derived from `IDPS_SOC_MFA_KEY` (or the JWT secret),
and the server fingerprints the address in your question. Without the key a database dump cannot be
turned back into addresses. A fingerprint is **pseudonymous, not anonymous**: with the key anyone can
compute it for a candidate address, and IPv4 has only 2^32 of them, so treat the key (and a dump
together with it) as personal data. The same holds for `erasure_records.subject_fp`, which is kept on
purpose so you can answer "was this address erased, when and by whom" (`GET
/admin/privacy/erasures?ip=`) without keeping the address. The log is kept (`ACCESS_LOG_RETENTION_DAYS`) even after an erasure, as the
record of who looked; it holds nothing that identifies the address on its own. Changing the key breaks
the match with older rows. Logged: an alert's detail, searches of alerts, blocks and would-blocks by
address, an alert's reputation, a case and its alerts' addresses, the assistant's read tools
(`search_alerts`, `get_alert`, `top_attackers`, `list_blocks`, `get_case`: the addresses returned), the
training export through the API, report downloads (the addresses the PDF prints in full; none when
`REPORT_MASK_IPS` is on) and erasure previews. **Not logged**: the unfiltered alert, block, case and
action lists, metrics, topology, the live feed and sensor status; they show many addresses at once. The offline `export_feedback` command reads the database directly and is not logged:
treat database access as privileged. If the log cannot be written the request fails (500): a read is
never served unlogged.

## Performance

Preview and erasure scan every free-text and JSON column that can mention an address; the work is
reading the table once, so it grows with the data and is bound by disk reads. Measured on a laptop
with 1,000,000 alerts (about 1 KB of explanation each, 1 GB) and 20,000 audit entries:

| Database | Preview (read-only scan) | Erasure (scan + writes) | Write phase alone (the only time writers wait) |
|---|---|---|---|
| SQLite (file, WAL) | 9.2 s | about 9.3 s | 0.01 s |
| PostgreSQL 16 (Docker on the same laptop) | 15.0 s | about 15.1 s | 0.04 s |

(302 rows affected in the test; the earlier single-transaction design held SQLite's write lock for
the whole 19 s scan and made ingest and the access-logged reads fail while it ran.) Expect minutes on
tens of millions of rows and do it off peak. Ingest and reads continue during the scan.

The write phase is not constant: it re-scans the small tables and deletes the address's own alerts,
so it grows with how many it has. For an address with 50,000 alerts of its own (SQLite, the same
1M-alert database) the scan took 9.2 s and the write phase, the only time writers wait, 1.0 s. An
address with millions of alerts blocks writers for correspondingly longer.

## What erasure cannot reach

- **Copies already sent**: alert emails, Slack and webhook messages, syslog/SIEM events and weekly
  report emails or downloads live in other systems. Ask their owners; the SOC cannot recall them.
- **Backups** (`python -m soc.api backup`, database dumps, volume snapshots) still contain the data
  until they are deleted or age out. Restoring one brings the address back: after a restore, repeat
  the erasures listed in `GET /admin/privacy/erasures` (keep the list of addresses somewhere you can
  protect; the SOC does not keep them, by design).
- **AbuseIPDB**, which already received the address if an analyst looked up its reputation; the
  request has to go to them.
- **The sensors**: their allowlists, blocklists, firewall rules and outbox are theirs. An erased block
  is gone from the SOC's records but a sensor that applied it still has the firewall rule (the preview
  warns about active blocks). A sensor re-reports its allowlist every 30 seconds, so an allowlist entry
  you erased returns unless you remove it in the sensor's configuration. `IDPS_SOC_BLOCK_ALLOWLIST`
  is configuration, not data, and is not touched.
- **The language-model service** that received an assistant conversation, and anything the analyst
  copied elsewhere (tickets, chat).
- **Queued notifications** that were already waiting to be sent when the erasure ran.
- **Open actions**: a pending action is rejected and a confirmed one is marked failed, but a confirmed
  action the sensor had already fetched may have been applied; the sensor's own record is its own.
- **Assistant replies that start after the erasure** and are asked about the address again: that is
  new data (and goes in the access log).
- **Web server logs**: the address filter of `GET /alerts?ip=...` and the like is in the query string,
  which uvicorn and the reverse proxy (Caddy) may write to their access logs. The SOC does not
  control those; rotate or scrub them.
- **New data**: the sensors keep reporting. If the address keeps attacking, new alerts appear; erasure
  is a point in time.
- **Account and sensor names** (see `manual_review`), and addresses in the SOC's own logs and your
  reverse proxy's access logs.

## Framing under India's DPDP Act, 2023

This is a factual summary of how the software maps onto the Act, not legal advice; check the current
text of the Act and the Rules made under it, and your own situation, with a lawyer.

- **Data fiduciary.** Whoever decides the purpose and means of processing (the organisation running
  the SOC) is the data fiduciary and carries the duties; whoever hosts or operates it for them is
  at most a data processor. The notice's controller fields are for the fiduciary.
- **Consent or another ground.** Consent is the main ground, but the Act also allows processing for
  "certain legitimate uses" without it, and exempts some processing for preventing or investigating
  offences and for security. Network security monitoring is usually argued under those; whether that
  holds for your use (for example, who is monitored, what is kept, for how long, and whether data
  is used for something else such as retraining) is a legal judgement. The software can help you stay
  within the narrow reading: it collects flow metadata, not content; it keeps limits you can set and
  state; and it can erase on request.
- **Notice.** The fiduciary must tell people what it processes, why, how to exercise their rights
  and how to complain. `GET /privacy/notice` is that text, generated from the real settings.
- **Accuracy, limits and safeguards.** Keep data only as long as the purpose needs (the retention
  settings; note that blocks and judged alerts are kept by default), and protect it (MFA for admins,
  signed models, mutual TLS for sensors, the access log).
- **Rights.** Access, correction and erasure, grievance redressal and nomination map to the
  sections above. Erasure may legitimately be declined or limited where retention is needed (for an
  ongoing investigation, or a legal duty); record that decision and tell the requester.
- **Breach and records.** The access log, audit log and erasure records are the evidence of what
  was done and by whom.

Configure `PRIVACY_CONTROLLER_NAME`, `PRIVACY_CONTACT_EMAIL` and `PRIVACY_GRIEVANCE_OFFICER` before
you publish the notice; until then they read as unset.
