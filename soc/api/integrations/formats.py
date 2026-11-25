"""What gets sent: the small event record and the message each channel builds from it.

Messages carry only what an on-call person needs: class, severity, source or rule signature,
addresses, sensor and a link. Never the features or the explanation. Text that an attacker can
influence (the class and the rule signature come from traffic and rule files) is cleaned and
escaped for the place it lands: Slack mrkdwn, HTML email, CEF.
"""

from __future__ import annotations

import html
import socket
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from importlib import metadata

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_UNSAFE = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TEST_TEXT = "IDPS SOC test message: this is not an alert. Nothing needs doing."


def idps_version() -> str:
    try:
        return metadata.version("idps")
    except metadata.PackageNotFoundError:
        return "0"


def clean(value: object, limit: int = 200) -> str:
    """Plain one-line text: control, format and direction characters dropped, whitespace
    collapsed, cut to `limit` characters."""
    text = "".join(c if not c.isspace() else " " for c in str(value)
                   if unicodedata.category(c) not in _UNSAFE or c.isspace())
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class Event:
    """A new alert (kind "alert") or a block event (kind "block") headed for the channels."""

    kind: str
    at: datetime
    sensor: str
    severity: str | None = None  # alerts only
    predicted_class: str = ""
    source: str = "ml"  # "ml" or "rule"
    alert_id: int | None = None
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: int | None = None
    sid: int | None = None
    signature: str | None = None
    category: str | None = None
    count: int = 1
    block_event: str | None = None  # "blocked" / "unblocked" / "would_block"
    reason: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity or "", 0)

    def dedupe_key(self) -> tuple | None:
        if self.kind != "alert":
            return None
        if self.source == "rule":
            return ("rule", self.sid, self.src_ip, self.dst_ip, self.dst_port)
        return ("ml", self.predicted_class, self.src_ip)


@dataclass(frozen=True)
class Digest:
    """One summary standing for `count` messages held back by the rate limit."""

    count: int  # all events held back: alerts and blocks
    by_severity: dict[str, int] = field(default_factory=dict)  # alerts only
    top_classes: list[tuple[str, int]] = field(default_factory=list)  # alerts only
    blocks: int = 0  # block events among them (syslog only)


@dataclass(frozen=True)
class TestNotice:
    __test__ = False  # not a pytest class

    at: datetime


Item = Event | Digest | TestNotice


def event_from_alert(alert, sensor_name: str) -> Event:
    rule = alert.rule if alert.source == "rule" and alert.rule else None
    return Event(
        kind="alert", at=alert.received_at, sensor=sensor_name, severity=alert.severity.value,
        predicted_class=alert.predicted_class, source="rule" if rule else "ml",
        alert_id=alert.id, src_ip=alert.src_ip, src_port=alert.src_port, dst_ip=alert.dst_ip,
        dst_port=alert.dst_port, protocol=alert.protocol,
        sid=rule.get("sid") if rule else None, signature=rule.get("signature") if rule else None,
        category=rule.get("category") if rule else None, count=rule.get("count", 1) if rule else 1)


def alert_url(public_url: str | None, alert_id: int | None) -> str | None:
    if not public_url or alert_id is None:
        return None
    return f"{public_url}/alerts/{alert_id}"


def iso(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _addr(ip: str, port: int | None) -> str:
    ip = clean(ip, 45)
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def headline(item: Event) -> str:
    """One line: severity, what, from where."""
    if item.kind == "block":
        return f"IP {item.block_event or 'block'}: {clean(item.src_ip, 45)}"
    what = clean(item.signature, 120) if item.signature else clean(item.predicted_class, 64)
    return f"{(item.severity or '').upper()} alert: {what}"


# --- generic webhook ----------------------------------------------------------------------

def webhook_payload(item: Item, public_url: str | None) -> dict:
    if isinstance(item, TestNotice):
        return {"type": "idps.test", "version": 1, "test": True, "message": TEST_TEXT,
                "at": iso(item.at)}
    if isinstance(item, Digest):
        return {"type": "idps.digest", "version": 1, "more": item.count,
                "blocks": item.blocks, "by_severity": item.by_severity,
                "top_classes": [{"class": c, "count": n} for c, n in item.top_classes]}
    rule = ({"sid": item.sid, "signature": clean(item.signature), "category":
             clean(item.category, 100) if item.category else None, "count": item.count}
            if item.source == "rule" else None)
    return {"type": "idps.alert", "version": 1, "id": item.alert_id, "severity": item.severity,
            "class": clean(item.predicted_class, 64), "source": item.source, "rule": rule,
            "src": {"ip": item.src_ip, "port": item.src_port},
            "dst": {"ip": item.dst_ip, "port": item.dst_port}, "protocol": item.protocol,
            "sensor": clean(item.sensor, 64), "at": iso(item.at),
            "url": alert_url(public_url, item.alert_id)}


# --- Slack ----------------------------------------------------------------------------------

def slack_code(value: object, limit: int = 200) -> str:
    """Attacker-influenced text as an inline code span: `&`, `<` and `>` escaped (so no
    <!channel>, <@user> or <https://evil|label> links), and no backtick to break out of it."""
    text = clean(value, limit).replace("`", "'")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"`{text}`" if text else "`-`"


def slack_escape(value: object, limit: int = 200) -> str:
    text = clean(value, limit)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(item: Item, public_url: str | None) -> dict:
    if isinstance(item, TestNotice):
        return {"text": TEST_TEXT, "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "IDPS SOC test message"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": TEST_TEXT}}]}
    if isinstance(item, Digest):
        sev = ", ".join(f"{n} {slack_escape(s)}" for s, n in item.by_severity.items())
        classes = ", ".join(f"{slack_code(c, 64)} x{n}" for c, n in item.top_classes)
        text = f"...and {item.count} more (held back by the rate limit)"
        body = f"*{text}*\n{sev}" + (f"\nMostly: {classes}" if classes else "")
        return {"text": text, "blocks": [{"type": "section",
                                           "text": {"type": "mrkdwn", "text": body}}]}
    # plain_text: Slack interprets no markup there; angle brackets are swapped anyway.
    title = clean(headline(item), 150).replace("<", "\u2039").replace(">", "\u203a")
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{slack_escape(item.severity or '-')}"},
        {"type": "mrkdwn", "text": f"*Source*\n{'rule (Suricata)' if item.source == 'rule' else 'model (ml)'}"},
        {"type": "mrkdwn", "text": f"*Class*\n{slack_code(item.predicted_class, 64)}"},
        {"type": "mrkdwn", "text": f"*Sensor*\n{slack_code(item.sensor, 64)}"},
        {"type": "mrkdwn", "text":
         f"*From to*\n{slack_code(_addr(item.src_ip, item.src_port))} → "
         f"{slack_code(_addr(item.dst_ip, item.dst_port))}"},
    ]
    if item.source == "rule":
        sig = f"{slack_code(item.signature)}" + (f" (sid {int(item.sid)})" if item.sid else "")
        fields.append({"type": "mrkdwn", "text": f"*Rule*\n{sig}"})
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": title}},
              {"type": "section", "fields": fields}]
    url = alert_url(public_url, item.alert_id)
    if url:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open alert"}, "url": url}]})
    # The fallback `text` is mrkdwn too: severity and class only, the class in a code span.
    fallback = f"IDPS {slack_escape(item.severity or '-')} alert: {slack_code(item.predicted_class, 64)}"
    return {"text": fallback, "blocks": blocks}


# --- email ----------------------------------------------------------------------------------

def _rows(item: Event, url: str | None) -> list[tuple[str, str]]:
    rows = [("Severity", item.severity or "-"),
            ("Source", "rule (Suricata)" if item.source == "rule" else "model (ml)"),
            ("Class", clean(item.predicted_class, 64))]
    if item.source == "rule":
        rows.append(("Rule", clean(item.signature) + (f" (sid {item.sid})" if item.sid else "")))
    rows += [("From", _addr(item.src_ip, item.src_port)), ("To", _addr(item.dst_ip, item.dst_port)),
             ("Sensor", clean(item.sensor, 64)), ("Time", iso(item.at))]
    if url:
        rows.append(("Alert", url))
    return rows


def build_email(item: Item, sender: str, recipients: list[str],
                public_url: str | None) -> EmailMessage:
    """Text and HTML parts. Every value is cleaned (no newline can reach a header) and the HTML
    part escapes everything."""
    if isinstance(item, TestNotice):
        subject, rows = "[IDPS] Test message", [("Note", TEST_TEXT)]
    elif isinstance(item, Digest):
        subject = f"[IDPS] ...and {item.count} more"
        rows = [("Held back", f"{item.count} (rate limit)")] + (
            [("Block events", str(item.blocks))] if item.blocks else []) + [
            (s, str(n)) for s, n in item.by_severity.items()] + [
            (clean(c, 64), str(n)) for c, n in item.top_classes]
    else:
        subject = f"[IDPS] {clean(headline(item), 120)}"
        rows = _rows(item, alert_url(public_url, item.alert_id))
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = clean(subject, 200), sender, ", ".join(recipients)
    msg.set_content("\n".join(f"{k}: {v}" for k, v in rows) + "\n")
    cells = "".join(f"<tr><th align=\"left\">{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
                    for k, v in rows)
    msg.add_alternative(f"<html><body><h3>{html.escape(clean(subject, 200))}</h3>"
                        f"<table>{cells}</table></body></html>", subtype="html")
    return msg


# --- syslog / CEF ---------------------------------------------------------------------------

def cef_header(value: object) -> str:
    """Escape a CEF header field: backslash and pipe; newlines and other control characters out."""
    text = clean(value, 255).replace("\\", "\\\\").replace("|", "\\|")
    return text


def cef_ext(value: object, limit: int = 500) -> str:
    """Escape a CEF extension value: backslash, equals sign and newlines (as \\n, \\r)."""
    raw = str(value)[: limit * 2]
    out = []
    for c in raw:
        if c == "\\":
            out.append("\\\\")
        elif c == "=":
            out.append("\\=")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif unicodedata.category(c) in _UNSAFE or c == "\t":
            out.append(" ")
        else:
            out.append(c)
    return "".join(out)[:limit]


CEF_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}
BLOCK_CEF_SEVERITY = {"blocked": 6, "unblocked": 1, "would_block": 3}
SYSLOG_SEVERITY = {"low": 6, "medium": 5, "high": 4, "critical": 2}  # info, notice, warning, crit
FACILITY_LOCAL0 = 16


def cef_message(item: Item) -> tuple[str, str, int]:
    """(CEF line, MSGID, syslog severity) for an event, a digest or a test."""
    version = idps_version()
    head = f"CEF:0|IDPS|IDPS SOC|{cef_header(version)}|"
    if isinstance(item, TestNotice):
        return (head + "test|IDPS test message|0|msg=" + cef_ext(TEST_TEXT) +
                f" rt={int(item.at.timestamp() * 1000)}", "TEST", 6)
    if isinstance(item, Digest):
        return (head + f"digest|IDPS digest: {item.count} more events|5|cnt={item.count} "
                f"cn1Label=blockEvents cn1={item.blocks}", "DIGEST", 5)
    ts = int(item.at.timestamp() * 1000)
    if item.kind == "block":
        ev = item.block_event or "blocked"
        sev = BLOCK_CEF_SEVERITY.get(ev, 5)
        name = {"blocked": "IP blocked", "unblocked": "IP unblocked",
                "would_block": "IP would be blocked (dry run)"}.get(ev, "IP block event")
        ext = (f"rt={ts} act={cef_ext(ev)} src={cef_ext(item.src_ip)} "
               f"dvchost={cef_ext(clean(item.sensor, 64))} reason={cef_ext(clean(item.reason, 300))}")
        return head + f"{cef_header(ev)}|{cef_header(name)}|{sev}|{ext}", "BLOCK", (
            4 if ev == "blocked" else 6)
    sig_id = str(item.sid) if item.source == "rule" and item.sid is not None \
        else item.predicted_class
    name = item.signature if item.source == "rule" and item.signature else \
        f"{item.predicted_class} detected"
    proto = PROTOCOLS.get(item.protocol, str(item.protocol)) if item.protocol is not None else ""
    ext = [f"rt={ts}", f"src={cef_ext(item.src_ip)}", f"dst={cef_ext(item.dst_ip)}"]
    if item.src_port is not None:
        ext.append(f"spt={item.src_port}")
    if item.dst_port is not None:
        ext.append(f"dpt={item.dst_port}")
    if proto:
        ext.append(f"proto={cef_ext(proto)}")
    ext += [f"cat={cef_ext(clean(item.predicted_class, 64))}",
            f"cs1Label=source cs1={cef_ext(item.source)}",
            f"dvchost={cef_ext(clean(item.sensor, 64))}"]
    if item.source == "rule":
        ext.append(f"cs2Label=ruleSignature cs2={cef_ext(clean(item.signature))}")
        if item.category:
            ext.append(f"cs3Label=ruleCategory cs3={cef_ext(clean(item.category, 100))}")
        ext.append(f"cnt={item.count}")
    if item.alert_id is not None:
        ext.append(f"externalId={item.alert_id}")
    sev = item.severity or "low"
    line = (head + f"{cef_header(sig_id)}|{cef_header(name)}|{CEF_SEVERITY.get(sev, 3)}|"
            + " ".join(ext))
    return line, "ALERT", SYSLOG_SEVERITY.get(sev, 6)


_HOST = None


def _hostname() -> str:
    global _HOST
    if _HOST is None:
        name = socket.gethostname()
        ok = "".join(c for c in name if 33 <= ord(c) <= 126)[:255]
        _HOST = ok or "-"
    return _HOST


def syslog_frame(item: Item, now: datetime | None = None) -> tuple[bytes, bytes]:
    """RFC 5424 message with a CEF payload: (message, octet-counted message for TCP/TLS)."""
    cef, msgid, severity = cef_message(item)
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    pri = FACILITY_LOCAL0 * 8 + severity
    text = f"<{pri}>1 {stamp} {_hostname()} idps-soc - {msgid} - {cef}"
    data = text.encode("utf-8", "replace")
    return data, str(len(data)).encode() + b" " + data


def digest_of(counts_sev: Counter, counts_cls: Counter, total: int, blocks: int = 0) -> Digest:
    sev = {s: counts_sev[s] for s in ("critical", "high", "medium", "low") if counts_sev[s]}
    return Digest(count=total, by_severity=sev, top_classes=counts_cls.most_common(3),
                  blocks=blocks)
