"""Suricata eve.json alert events: parsing, classification and the mapping to a SOC alert.

Pure functions, no I/O, no Docker. Used by the sensor's rule forwarder (idps.rules.forward) and by
scripts/suricata_compare.py (roadmap step 6), which imports the helpers it shares from here.

Three groups of events are told apart:

* engine events: the signature text starts with "SURICATA " (stream, decoder and protocol checks
  such as "SURICATA STREAM Packet with invalid ack"). They fire on ordinary traffic and are not
  attack indications, so the forwarder never sends them.
* informational alerts: ET INFO / ET POLICY / GPL ICMP_INFO / GPL INFO / GPL POLICY signatures, or the
  categories "Not Suspicious Traffic", "Misc activity" and "Potential Corporate Privacy Violation".
  Policy and inventory notes (a ping, a package download), dropped by default.
* everything else: security alerts.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime

ENGINE_PREFIX = "SURICATA "
# Characters the SOC refuses in text (soc/api/common.py UNSAFE_CATEGORIES, mirrored: idps does not import soc).
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58, "ICMPV6": 58, "SCTP": 132, "GRE": 47}

# Informational alerts: an alert is informational when its message starts with one of these
# prefixes or its category is one of these.
INFO_PREFIXES = ("ET INFO ", "ET POLICY ", "GPL ICMP_INFO", "GPL INFO ", "GPL POLICY ")
INFO_CATEGORIES = frozenset({"Not Suspicious Traffic", "Misc activity",
                             "Potential Corporate Privacy Violation"})


def is_engine_event(signature: str) -> bool:
    """Suricata's own protocol/decoder/stream events, not attack signatures."""
    return str(signature).startswith(ENGINE_PREFIX)


# Rulesets that are attack indications whatever their category says: a Misc activity category on an
# ET EXPLOIT or ET MALWARE rule does not make it informational (the prefix wins over the category).
SECURITY_PREFIXES = ("ET SCAN ", "GPL SCAN ", "ET DOS ", "GPL DOS ", "ET WEB_", "GPL WEB_", "ET MALWARE ",
                     "ET TROJAN ", "ET CNC ", "ET MOBILE_MALWARE ", "ET COINMINER ", "ET EXPLOIT ",
                     "GPL EXPLOIT ", "ET SHELLCODE ", "GPL SHELLCODE ", "ET ATTACK_RESPONSE ")


def is_informational(signature: str, category: str | None) -> bool:
    """Informational (ET INFO / ET POLICY / GPL ICMP_INFO style) alert, decided by the message prefix
    or the category; an attack ruleset prefix (SECURITY_PREFIXES) is never informational. Engine
    events are a separate group and are not called informational."""
    sig = str(signature)
    if is_engine_event(sig) or sig.startswith(SECURITY_PREFIXES):
        return False
    return sig.startswith(INFO_PREFIXES) or (category or "") in INFO_CATEGORIES


def eve_timestamp_ms(text: str) -> int:
    """Epoch milliseconds of an eve.json timestamp such as 2017-07-07T11:59:50.315123+0000. Suricata
    writes the local UTC offset, so the offset is applied; a timestamp without one is refused."""
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"eve timestamp without a UTC offset: {text!r}")
    return round(dt.timestamp() * 1000)


def proto_number(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip().upper()
    return int(s) if s.isdigit() else PROTO.get(s)


def parse_alert_line(line: str) -> dict | None:
    """One eve.json line -> alert dict, or None if it is not an alert event. Ports are 0 when absent
    (ICMP), as in the flow table. Raises ValueError (or KeyError/TypeError) on a line that is
    JSON but not a usable alert; callers that read live files catch those and count the line."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    ev = json.loads(line)
    if not isinstance(ev, dict) or ev.get("event_type") != "alert":
        return None
    a = ev.get("alert") or {}
    sig = str(a.get("signature", ""))
    cat = a.get("category")
    return {"ts_ms": eve_timestamp_ms(ev["timestamp"]), "src_ip": ev.get("src_ip"),
            "src_port": int(ev.get("src_port") or 0), "dst_ip": ev.get("dest_ip"),
            "dst_port": int(ev.get("dest_port") or 0), "protocol": proto_number(ev.get("proto")),
            "signature": sig, "sid": a.get("signature_id"), "rev": a.get("rev"), "category": cat,
            "severity": a.get("severity"), "direction": ev.get("direction"),
            "app_proto": ev.get("app_proto"),
            "pkts_toserver": _int((ev.get("flow") or {}).get("pkts_toserver")),
            "pkts_toclient": _int((ev.get("flow") or {}).get("pkts_toclient")),
            "engine": is_engine_event(sig), "informational": is_informational(sig, cat)}


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def is_established_tcp(ev: dict) -> bool:
    """True when the event is TCP on a flow that the server answered: Suricata saw an application
    protocol (it needs both directions to parse one), or packets in both directions. A bare SYN, a
    UDP or ICMP packet and anything else a spoofer can forge with one packet is not established."""
    if ev.get("protocol") != 6:
        return False
    if ev.get("app_proto") not in (None, "", "failed", "unknown"):
        return True
    return ev.get("pkts_toserver", 0) > 0 and ev.get("pkts_toclient", 0) > 0


# --- the SOC side of a rule alert ----------------------------------------------------------------

# Family of a rule alert (becomes the alert's predicted_class). Checked in this order, first match
# wins: keywords in the signature text, then the signature's ruleset prefix (ET SCAN, ET WEB_SERVER,
# ...), then the Suricata category, else FALLBACK_FAMILY. Names that the SOC's severity table
# already knows ("Web Attack", "DoS", "Brute Force") are used as they are.
FALLBACK_FAMILY = "Rule match"
# Whole words only: "SQLI" must not match "SQLITE".
SIGNATURE_KEYWORDS = (
    (re.compile(r"\b(BRUTE[ -]?FORCE)\b"), "Brute Force"),
    (re.compile(r"\b(SQL INJECTION|SQLI|XSS|CROSS SITE SCRIPTING|DIRECTORY TRAVERSAL)\b"), "Web Attack"),
)
# Ruleset prefixes that decide before the keywords (a malware rule that mentions SQLi is malware) ...
STRONG_PREFIX_FAMILIES = (
    (("ET MALWARE ", "ET TROJAN ", "ET CNC ", "ET MOBILE_MALWARE ", "ET COINMINER "), "Malware"),
    (("ET EXPLOIT ", "GPL EXPLOIT ", "ET SHELLCODE ", "GPL SHELLCODE "), "Exploit"),
    (("ET DOS ", "GPL DOS "), "DoS"),
)
# ... and the ones that only decide after them (an ET SCAN rule about brute force is a brute force).
PREFIX_FAMILIES = (
    (("ET SCAN ", "GPL SCAN "), "Scan"),
    (("ET WEB_", "GPL WEB_"), "Web Attack"),
    (INFO_PREFIXES, "Policy"),
)
CATEGORY_FAMILIES = {
    "Web Application Attack": "Web Attack",
    "Attempted Denial of Service": "DoS", "Denial of Service": "DoS",
    "Detection of a Network Scan": "Scan",
    "A Network Trojan was detected": "Malware",
    "Malware Command and Control Activity Detected": "Malware",
    "Crypto Currency Mining Activity Detected": "Malware",
    "Attempted Administrator Privilege Gain": "Exploit", "Successful Administrator Privilege Gain": "Exploit",
    "Attempted User Privilege Gain": "Exploit", "Successful User Privilege Gain": "Exploit",
    "Executable Code was Detected": "Exploit", "Executable code was detected": "Exploit",
    **dict.fromkeys(INFO_CATEGORIES, "Policy"),
}


def _prefix_family(sig: str, table) -> str | None:
    for prefixes, family in table:
        if sig.startswith(tuple(p.upper() for p in prefixes)):
            return family
    return None


def rule_family(signature: str, category: str | None) -> str:
    """A short family for a rule alert: Brute Force, Web Attack, Scan, DoS, Malware, Exploit,
    Policy, or "Rule match". Order: strong ruleset prefix, whole-word keywords in the signature,
    other ruleset prefix, Suricata category."""
    sig = str(signature).upper()
    family = _prefix_family(sig, STRONG_PREFIX_FAMILIES)
    if family:
        return family
    for pattern, family in SIGNATURE_KEYWORDS:
        if pattern.search(sig):
            return family
    return _prefix_family(sig, PREFIX_FAMILIES) or CATEGORY_FAMILIES.get(category or "", FALLBACK_FAMILY)


# Suricata's severity runs 1 (most severe) to 4. It becomes the alert's confidence, so that the
# SOC's own severity rule (class base severity, lowered one level under `low_confidence_below`, 0.6
# by default) applies unchanged: only a severity-4 rule is lowered.
SEVERITY_CONFIDENCE = {1: 0.95, 2: 0.85, 3: 0.70, 4: 0.55}


def clamp_severity(value) -> int:
    """Suricata severity as 1..4 (anything missing or out of range counts as 3, the usual default)."""
    try:
        sev = int(value)
    except (TypeError, ValueError):
        return 3
    return min(max(sev, 1), 4)


def severity_confidence(severity: int) -> float:
    return SEVERITY_CONFIDENCE[clamp_severity(severity)]


def rule_alert_payload(ev: dict, count: int = 1, *, start_ms: int | None = None,
                       end_ms: int | None = None) -> dict | None:
    """One entry of the POST /ingest/alerts body (soc.api.routes.alerts.AlertIn) for a parsed alert
    event (parse_alert_line), with `"source": "rule"` and a `rule` object; None if the event has no
    usable address, protocol, sid or time. Text is cut to what the SOC accepts."""
    from ipaddress import ip_address

    try:
        ip_address(ev["src_ip"])
        ip_address(ev["dst_ip"])
        sid = int(ev["sid"])
    except (KeyError, TypeError, ValueError):
        return None
    proto = ev.get("protocol")
    if proto is None or not 0 <= proto <= 255 or sid < 0:
        return None
    ts = int(ev["ts_ms"])
    start, end = (ts if start_ms is None else start_ms), (ts if end_ms is None else end_ms)
    sig = printable(ev.get("signature"), 300) or f"sid {sid}"
    category = printable(ev.get("category"), 100) or None
    severity = clamp_severity(ev.get("severity"))
    try:
        rev = int(ev["rev"]) if ev.get("rev") is not None else None
    except (TypeError, ValueError):
        rev = None
    family = rule_family(sig, category)
    return {
        "src_ip": ev["src_ip"], "src_port": int(ev["src_port"]),
        "dst_ip": ev["dst_ip"], "dst_port": int(ev["dst_port"]),
        "protocol": proto, "start_ms": start, "end_ms": max(start, end),
        "predicted_class": family, "confidence": severity_confidence(severity),
        "source": "rule",
        "rule": {"sid": sid, "rev": rev, "signature": sig, "category": category,
                 "severity": severity, "count": max(1, int(count))},
    }


def printable(value, limit: int) -> str:
    """`value` as text without control/format characters (the SOC refuses them), at most `limit`."""
    text = "".join(c for c in str(value or "") if unicodedata.category(c) not in UNSAFE_CATEGORIES)
    return text.strip()[:limit]
