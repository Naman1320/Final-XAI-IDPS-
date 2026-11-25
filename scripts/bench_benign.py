"""False-positive test in the Docker lab: run the live sensor while only normal traffic flows from
the client (the attacker container) to the victim and DVWA, and count what it raises.

    python scripts/bench_benign.py                  # 60 minutes of normal traffic
    python scripts/bench_benign.py --minutes 4      # a short smoke run

Needs the lab up (`docker compose up -d --build` in lab/, with the attacker image that has the ssh
client) and lab/.env with LAB_VICTIM_PASSWORD, LAB_SOC_CHECK_USER and LAB_SOC_CHECK_PASSWORD.
Writes reports/lab_benign.json (and reports/lab_benign_activity.log) and prints markdown tables.
Standard library only; runs on the host. See docs/live.md, "False-positive test".
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_sensor as bs  # noqa: E402  (shared helpers: compose, Sensor, log, docker PATH)

ROOT = bs.ROOT
LAB = bs.LAB
REPORT = ROOT / "reports" / "lab_benign.json"
ACTIVITY_LOG = ROOT / "reports" / "lab_benign_activity.log"
ENV_FILE = LAB / ".env"
SOC_URL = "https://127.0.0.1:8443"
OUTBOX_FILE = "/opt/idps/data/processed/live_outbox.json"  # in the sensor container

# The client (10.10.1.10) and the victims (10.10.2.0/24) are deliberately NOT allowlisted, so a
# false alert or would-block on them is visible. Only the infrastructure is.
ALLOWLIST = "10.10.1.1,10.10.1.2,10.10.3.0/24"
LAB_NET = "10.10.0.0/16"
FLUSH_MIN_SECONDS = 150   # flows end 120 s after their last packet
FLUSH_MAX_SECONDS = 600
OVERRUN_SECONDS = 300     # how long benign.sh may run past the requested time (its last activity)
MIN_RUN_FRACTION = 0.8    # benign.sh ending before this share of the time asked for is a failure
WINDOW_SLACK_S = 10       # alerts for flows that ended this long before the traffic began are kept
MATCH_SLACK_S = 3.0       # alert-to-request matching: flow and request times may differ this much
MAX_ALERTS = 50_000       # most alerts read from the SOC
SETUP_DIR = "/var/www/html/benign"  # in the victim container (nginx root)
FILES = {"f_100k.bin": 100 * 1024, "f_1m.bin": 1024**2, "f_10m.bin": 10 * 1024**2,
         "f_50m.bin": 50 * 1024**2}
ASSET_BYTES = {"css": 6 * 1024, "js": 30 * 1024, "png": 20 * 1024}
PAGE_BYTES = {"index.html": 33_000, "page2.html": 8_000, "page3.html": 36_000}  # random text, then x4/3
CONF_BINS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0001]
ACTIVITIES = ("web", "dvwa", "download", "ssh", "scp", "burst", "connreq", "ping")


class Abort(RuntimeError):
    """A pre-flight check failed: nothing has been measured."""


def _now() -> datetime:
    return datetime.now(UTC)


# ---- pure parts (unit-tested) -----------------------------------------------------------------

def parse_env(text: str) -> dict:
    """KEY=VALUE lines of a .env file: blank and `#` lines skipped, an `export ` prefix allowed,
    quoted values unquoted, a ` # comment` after an unquoted value dropped."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in ("'", '"') and v[:1] in v[1:]:
            v = v[1:v.index(v[0], 1)]
        else:
            v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
        out[k.strip()] = v
    return out


def percentile(sorted_vals: list[float], q: float) -> float | None:
    """Linear-interpolated percentile (q in 0..100) of an already sorted list."""
    if not sorted_vals:
        return None
    pos = (len(sorted_vals) - 1) * q / 100
    lo, hi = math.floor(pos), math.ceil(pos)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def confidence_summary(values: list[float]) -> dict:
    """Spread of the confidence of the false alerts: quantiles and a histogram."""
    vals = sorted(values)
    bins = []
    for lo, hi in zip(CONF_BINS, CONF_BINS[1:], strict=False):
        bins.append({"from": lo, "to": min(hi, 1.0), "count": sum(1 for v in vals if lo <= v < hi)})
    below = sum(1 for v in vals if v < CONF_BINS[0])
    r = lambda x: None if x is None else round(x, 4)  # noqa: E731
    return {"n": len(vals), "min": r(vals[0] if vals else None), "p50": r(percentile(vals, 50)),
            "p90": r(percentile(vals, 90)), "max": r(vals[-1] if vals else None),
            "below_0.5": below, "histogram": bins}


def parse_ts(text: str) -> float | None:
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except (ValueError, TypeError):
        return None


def parse_activity_line(line: str) -> str | None:
    """'2026-11-14T10:00:00Z benign web nginx keep-alive ...' -> 'web' (None for other lines,
    including the per-request 'benign req ...' lines)."""
    m = re.match(r"^\S+Z benign (\w+)", line.strip())
    return m[1] if m and m[1] in ACTIVITIES else None


def parse_req_line(line: str) -> dict | None:
    """'TS benign req ACT LPORT SERVER:PORT STATUS SECONDS PATH [expect=404]' -> dict, else None.
    LPORT '-' (ssh, scp, ping) gives lport None; PORT 'icmp' marks a ping."""
    p = line.strip().split()
    if len(p) < 9 or p[1] != "benign" or p[2] != "req":
        return None
    t = parse_ts(p[0])
    ip, _, port = p[5].rpartition(":")
    try:
        lport = None if p[4] == "-" else int(p[4])
        dst_port = "icmp" if port == "icmp" else int(port)
        secs = float(p[7])
        status = int(p[6])
    except ValueError:
        return None
    if t is None or p[3] not in ACTIVITIES or not ip:
        return None
    return {"t": t, "activity": p[3], "lport": lport, "dst_ip": ip, "dst_port": dst_port,
            "status": status, "secs": secs, "path": p[8], "expect_404": "expect=404" in p[9:]}


def parse_requests(lines: list[str]) -> list[dict]:
    return [r for r in map(parse_req_line, lines) if r]


def activity_summary(lines: list[str]) -> dict:
    """Counts per activity, and the lines that show something went wrong (a failed DVWA login, a
    non-zero exit of ssh/scp/ping, an HTTP status of 400 or more other than the deliberate 404s,
    a request that got no answer) so a run with no real traffic is noticed."""
    counts = Counter(a for a in map(parse_activity_line, lines) if a)
    problems = []
    for line in lines:
        a = parse_activity_line(line)
        if a is None and " benign note:" in line:
            problems.append(line.strip())
        elif a == "dvwa" and "failed" in line:
            problems.append(line.strip())
    for r in parse_requests(lines):
        a, s = r["activity"], r["status"]
        bad = (s != 0) if a in ("ssh", "scp", "ping") else (s == 0 or (s >= 400 and not (s == 404 and r["expect_404"])))
        if bad:
            problems.append(f"{a} request {r['dst_ip']}:{r['dst_port']}{r['path']} status={s}")
    return {"counts": {a: counts.get(a, 0) for a in ACTIVITIES}, "total": sum(counts.values()),
            "problems": problems[:20], "problem_count": len(problems)}


def check_traffic(*, rc: int | None, stopped: bool, activity_total: int, elapsed_s: float,
                  requested_s: float) -> list[str]:
    """Reasons the traffic run cannot be trusted: benign.sh failed, did nothing, or stopped early.
    A script we stopped ourselves (Ctrl-C) is judged by the caller as 'interrupted' instead."""
    out = []
    if rc not in (0, None) and not stopped:
        out.append(f"benign.sh exited with status {rc}")
    if activity_total == 0:
        out.append("benign.sh logged no activities")
    if not stopped and elapsed_s < MIN_RUN_FRACTION * requested_s:
        out.append(f"benign.sh ran {elapsed_s:.0f} s of the {requested_s:.0f} s asked for")
    return out


def outbox_alerts(text: str | None) -> int:
    """Alerts held in the sensor's outbox file ({"version": 1, "batches": [[alert, ...], ...]})."""
    if not text or not text.strip():
        return 0
    try:
        doc = json.loads(text)
        return sum(len(b) for b in doc["batches"])
    except (ValueError, KeyError, TypeError) as exc:
        raise Abort(f"cannot read the sensor's outbox file ({exc}); clear it before testing") from exc


def pick_sensor_id(sensors: list[dict]) -> int:
    """The lab sensor: the one active (not revoked) sensor, or the one seen most recently."""
    live = [s for s in sensors if not s.get("revoked")]
    if not live:
        raise Abort("the SOC knows no active sensor")
    live.sort(key=lambda s: (bool(s.get("online")), s.get("last_seen_at") or ""), reverse=True)
    return live[0]["sensor_id"]


def alert_key(a: dict) -> tuple:
    return (a["src_ip"], a["src_port"], a["dst_ip"], a["dst_port"], a["protocol"], a["start_ms"])


def filter_alerts(alerts: list[dict], *, traffic_start_ms: float, sensor_id: int | None,
                  net: str = LAB_NET) -> tuple[list[dict], dict]:
    """Alerts of THIS run: not duplicates, flow ended no earlier than 10 s before the traffic
    began, both addresses in the lab network, from the lab sensor. Returns (kept, excluded) where
    excluded = {"duplicates": n, "count": n, "by_reason": {...}, "by_class": {...}}."""
    network = ipaddress.ip_network(net)
    kept, seen = [], set()
    reasons, classes = Counter(), Counter()
    dup = 0

    def exclude(a: dict, why: str) -> None:
        reasons[why] += 1
        classes[a.get("predicted_class", "?")] += 1

    def inside(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    for a in alerts:
        k = alert_key(a)
        if k in seen:
            dup += 1
            continue
        seen.add(k)
        if a["end_ms"] < traffic_start_ms - WINDOW_SLACK_S * 1000:
            exclude(a, "before_run")
        elif not (inside(a["src_ip"]) and inside(a["dst_ip"])):
            exclude(a, "foreign_address")
        elif sensor_id is not None and a.get("sensor_id") != sensor_id:
            exclude(a, "other_sensor")
        else:
            kept.append(a)
    return kept, {"duplicates": dup, "count": sum(reasons.values()), "by_reason": dict(reasons),
                  "by_class": dict(classes)}


def _req_matches(a: dict, r: dict, slack: float) -> bool:
    if a["end_ms"] / 1000 < r["t"] - r["secs"] - slack or a["start_ms"] / 1000 > r["t"] + slack:
        return False
    if r["dst_port"] == "icmp":
        return a["protocol"] == 1 and r["dst_ip"] in (a["src_ip"], a["dst_ip"])
    fwd = (a["dst_ip"] == r["dst_ip"] and a["dst_port"] == r["dst_port"]
           and (r["lport"] is None or a["src_port"] == r["lport"]))
    rev = (a["src_ip"] == r["dst_ip"] and a["src_port"] == r["dst_port"]  # a flow seen from the reply
           and (r["lport"] is None or a["dst_port"] == r["lport"]))
    return fwd or rev


def match_activity(alert: dict, reqs: list[dict], slack: float = MATCH_SLACK_S) -> str | None:
    """The activity whose request made this flow: same client port and server address:port (client
    port unknown for ssh/scp/ping: address and port only) and overlapping in time. A match on the
    client port wins over one without."""
    hits = [r for r in reqs if _req_matches(alert, r, slack)]
    if not hits:
        return None
    hits.sort(key=lambda r: (r["lport"] is None, r["t"]))
    return hits[0]["activity"]


def connections_per_activity(reqs: list[dict]) -> dict:
    """Connections (about one flow each) per activity: distinct client port + server for HTTP
    requests (a keep-alive connection counts once); every ssh/scp/ping line counts as one."""
    keys: dict[str, set] = {a: set() for a in ACTIVITIES}
    for i, r in enumerate(reqs):
        keys[r["activity"]].add((r["lport"], r["dst_ip"], r["dst_port"]) if r["lport"] else ("line", i))
    return {a: len(k) for a, k in keys.items()}


def per_activity(alerts: list[dict], reqs: list[dict]) -> dict:
    """False alerts and the false-positive rate (alerts per connection) for each activity type,
    matched by client port, server address:port and time. Unmatched alerts are listed apart."""
    conns = connections_per_activity(reqs)
    requests = Counter(r["activity"] for r in reqs)
    hits = Counter(match_activity(a, reqs) or "unmatched" for a in alerts)
    out = {}
    for a in ACTIVITIES:
        c, n = conns[a], hits.get(a, 0)
        out[a] = {"requests": requests.get(a, 0), "connections": c, "false_alerts": n,
                  "rate_per_connection": round(n / c, 4) if c else None}
    out["unmatched"] = {"false_alerts": hits.get("unmatched", 0)}
    return out


def _top(counter: Counter, n: int = 15) -> list[dict]:
    return [{"key": k, "alerts": c} for k, c in counter.most_common(n)]


def summarize_alerts(alerts: list[dict], flows: int | None, hours: float) -> dict:
    """Every alert is a false positive here. Counts by class and by source/destination, the
    confidence spread, false alerts per hour and the rate per flow scored."""
    by_class = Counter(a["predicted_class"] for a in alerts)
    by_src = Counter(a["src_ip"] for a in alerts)
    by_dst = Counter(a["dst_ip"] for a in alerts)
    by_pair = Counter(f"{a['src_ip']} -> {a['dst_ip']}:{a['dst_port']}" for a in alerts)
    by_sev = Counter(a.get("severity", "?") for a in alerts)
    n = len(alerts)

    def rate(c: int) -> float | None:
        return round(c / flows, 6) if flows else None

    return {
        "false_alerts": n,
        "false_alerts_per_hour": round(n / hours, 2) if hours > 0 else None,
        "false_positive_rate": rate(n),
        "by_class": {c: {"alerts": k, "rate_per_flow": rate(k),
                         "per_hour": round(k / hours, 2) if hours > 0 else None}
                     for c, k in by_class.most_common()},
        "by_severity": dict(by_sev),
        "by_src": _top(by_src), "by_dst": _top(by_dst), "by_src_dst_port": _top(by_pair),
        "by_dst_port": _top(Counter(a["dst_port"] for a in alerts)),
        "confidence": confidence_summary([a["confidence"] for a in alerts]),
    }


def invalid_reasons(*, final: dict, kept: int | None, soc_error: str | None, drained: bool,
                    interrupted: bool, traffic_errors: list[str], truncated: bool,
                    problem_count: int, activity_total: int) -> list[str]:
    """Why the result must not be used as the false-positive measurement (empty = valid)."""
    out = list(traffic_errors)
    if interrupted:
        out.append("interrupted before the end")
    if not drained:
        out.append("the sensor was stopped before its flow count was steady")
    if soc_error:
        out.append(f"the SOC could not be read: {soc_error}")
    if truncated:
        out.append("more alerts than were read from the SOC")
    pending = final.get("outbox_pending")
    if pending != 0:
        out.append(f"outbox_pending is {pending} at the end (alerts not yet in the SOC)")
    alerts, sent = final.get("alerts"), final.get("alerts_sent")
    if alerts is None or sent is None or alerts != sent:
        out.append(f"the sensor counted {alerts} alerts but sent {sent}")
    dropped = (final.get("dropped") or {}).get("alerts") or 0
    if dropped:
        out.append(f"the sensor dropped {dropped} alerts")
    if kept is not None and alerts is not None and kept != alerts:
        out.append(f"the sensor counted {alerts} alerts but the SOC holds {kept} for this run")
    if activity_total and problem_count > 0.1 * activity_total:
        out.append(f"{problem_count} problem lines in {activity_total} activities (see activity)")
    return out


def build_report(*, minutes: float, started: datetime, traffic_started: datetime,
                 traffic_ended: datetime, drained: bool, final: dict, kept: list[dict] | None,
                 excluded: dict | None, would_blocks: list[dict], activity: dict, reqs: list[dict],
                 traffic_errors: list[str], soc_error: str | None, sensor_id: int | None,
                 interrupted: bool = False, truncated: bool = False,
                 outbox_at_start: int = 0) -> dict:
    traffic_s = (traffic_ended - traffic_started).total_seconds()
    hours = traffic_s / 3600
    flows = final.get("flows")
    summary = summarize_alerts(kept, flows, hours) if kept is not None else None
    reasons = invalid_reasons(
        final=final, kept=None if kept is None else len(kept), soc_error=soc_error, drained=drained,
        interrupted=interrupted, traffic_errors=traffic_errors, truncated=truncated,
        problem_count=activity.get("problem_count", 0), activity_total=activity.get("total", 0))
    wb = Counter(w["ip"] for w in would_blocks)
    return {
        "generated": _now().isoformat(timespec="seconds"),
        "valid": not reasons,
        "invalid_reasons": reasons,
        "soc_error": soc_error,
        "requested_minutes": minutes,
        "traffic_minutes": round(traffic_s / 60, 1),
        "sensor_started": started.isoformat(timespec="seconds"),
        "traffic_started": traffic_started.isoformat(timespec="seconds"),
        "traffic_ended": traffic_ended.isoformat(timespec="seconds"),
        "drained": drained,
        "interrupted": interrupted,
        "model": bs.MODEL,
        "allowlist": ALLOWLIST,
        "dry_run": True,
        "sensor_id": sensor_id,
        "sensor": {k: final.get(k) for k in
                   ("flows", "malicious", "alerts", "alerts_sent", "below_floor", "would_block",
                    "outbox_pending", "blocks_suppressed", "dropped", "errors", "heartbeat_flows")},
        "reconciliation": {
            "sensor_alerts": final.get("alerts"), "alerts_sent": final.get("alerts_sent"),
            "outbox_pending": final.get("outbox_pending"), "outbox_alerts_at_start": outbox_at_start,
            "soc_alerts_this_run": None if kept is None else len(kept),
            "difference": (None if kept is None or final.get("alerts") is None
                           else final["alerts"] - len(kept)),
            "excluded": excluded, "soc_truncated": truncated},
        "summary": summary,
        "by_activity": None if kept is None else per_activity(kept, reqs),
        "alerts": None if kept is None else [
            {"id": a.get("id"), "class": a["predicted_class"], "confidence": a["confidence"],
             "src": f"{a['src_ip']}:{a['src_port']}", "dst": f"{a['dst_ip']}:{a['dst_port']}",
             "protocol": a["protocol"], "end_ms": a["end_ms"],
             "activity": match_activity(a, reqs) or "unmatched"} for a in kept[:500]],
        "would_block_by_ip": dict(wb.most_common()),
        "activity": activity,
        "notes": (
            "Only normal traffic ran, so every alert counts as a false positive. Alerts are read "
            "from the lab SOC and kept only if they are not duplicates, the flow ended no earlier "
            "than 10 s before the traffic began, both addresses are in 10.10.0.0/16 and the "
            "sensor is the lab sensor; the others are counted under reconciliation.excluded. "
            "Rates per activity are alerts per connection (about one flow each), matched by client "
            "port, server address:port and time from benign.sh's request lines; ssh, scp and ping "
            "have no known client port and match on address and time. The client is the attacker "
            "container (10.10.1.10), the address earlier attack runs used; the model keeps no state "
            "between flows, so that history does not affect the result. The lab round-trip time "
            "is about 0.1 ms, far below a real network's, so timing features (inter-arrival "
            "times, flow durations) are unrealistically short. The victim/client networks were not "
            "allowlisted, so false would-blocks show."),
    }


def _f(v) -> str:
    return "n/a" if v is None else str(v)


def build_table(report: dict) -> str:
    """Markdown: headline numbers, then one row per activity and one per predicted class."""
    s, m = report["summary"], report["sensor"]
    rec = report["reconciliation"]
    lines = ["| Measure | Value |", "|---|---|",
             f"| Valid | {'yes' if report['valid'] else 'NO: ' + '; '.join(report['invalid_reasons'])} |",
             f"| Traffic duration (min) | {_f(report['traffic_minutes'])} |",
             f"| Flows scored | {_f(m.get('flows'))} |",
             f"| Malicious predictions | {_f(m.get('malicious'))} |",
             f"| Alerts (sensor) | {_f(m.get('alerts'))} |",
             f"| Alerts sent / outbox pending | {_f(m.get('alerts_sent'))} / {_f(m.get('outbox_pending'))} |",
             f"| Alerts (SOC, this run) | {_f(rec['soc_alerts_this_run'])} |",
             f"| Excluded from the SOC | {_f((rec['excluded'] or {}).get('count'))} "
             f"(+ {_f((rec['excluded'] or {}).get('duplicates'))} duplicates) |",
             f"| Below the alert floor | {_f(m.get('below_floor'))} |",
             f"| Would-blocks | {_f(m.get('would_block'))} |"]
    if s is None:
        lines.append(f"| SOC error | {_f(report['soc_error'])} |")
        return "\n".join(lines)
    lines += [f"| False alerts per hour | {_f(s['false_alerts_per_hour'])} |",
              f"| False-positive rate (alerts / flows) | {_f(s['false_positive_rate'])} |",
              "", "| Activity | Requests | Connections | False alerts | Rate per connection |",
              "|---|---|---|---|---|"]
    for act, d in report["by_activity"].items():
        if act == "unmatched":
            lines.append(f"| (unmatched) | | | {d['false_alerts']} | |")
        else:
            lines.append(f"| {act} | {d['requests']} | {d['connections']} | {d['false_alerts']} | "
                         f"{_f(d['rate_per_connection'])} |")
    lines += ["", "| Predicted class | Alerts | Per hour | Rate per flow |", "|---|---|---|---|"]
    for cls, d in s["by_class"].items():
        lines.append(f"| {cls} | {d['alerts']} | {_f(d['per_hour'])} | {_f(d['rate_per_flow'])} |")
    if not s["by_class"]:
        lines.append("| (none) | 0 | 0 | 0 |")
    return "\n".join(lines)


# ---- SOC API ----------------------------------------------------------------------------------

LAB_TOTP_FILE = "/var/lib/idps-soc/labcheck_totp"  # in the SOC's own volume (lab/README.md)


def lab_totp_secret() -> str | None:
    """The lab check user's TOTP secret, read from the SOC container (never printed). None when
    the check user has no MFA."""
    r = subprocess.run(["docker", "compose", "exec", "-T", "soc", "cat", LAB_TOTP_FILE], cwd=LAB,
                       env=bs._env(), capture_output=True, text=True, timeout=30)
    return r.stdout.strip() or None if r.returncode == 0 else None


class Soc:
    """The lab SOC API on the published port, trusting the lab CA (read from the sensor)."""

    _last_step: int | None = None  # TOTP step last used by any Soc in this process (no replays)

    def __init__(self, user: str, password: str, ca_pem: str | None = None,
                 totp_secret: str | None = None) -> None:
        """`totp_secret`: for an account with MFA on (the lab check user, see lab_totp_secret)."""
        self.ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
        self.ctx.check_hostname = False  # the certificate is for the lab address, not 127.0.0.1
        self._cred = {"username": user, "password": password}
        self._totp = totp_secret
        self.token: str | None = None
        self.truncated = False

    def _req(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(SOC_URL + path, data=data, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.load(r)

    def login(self) -> None:
        res = self._req("/auth/login", self._cred)
        if res.get("mfa") == "verify":
            if not self._totp:
                raise RuntimeError("this account has MFA on: pass totp_secret (lab_totp_secret())")
            from soc.api import mfa

            step = mfa.current_step()
            if Soc._last_step is not None and step <= Soc._last_step:  # a code works only once
                time.sleep((Soc._last_step + 1) * mfa.STEP_SECONDS - time.time() + 0.5)
                step = mfa.current_step()
            Soc._last_step = step
            res = self._req("/auth/mfa/verify", {"mfa_token": res["mfa_token"],
                                                 "code": mfa.code_at(self._totp, step)})
        elif res.get("mfa") == "enrol":
            raise RuntimeError("this admin account must enrol in MFA first: python -m soc.api "
                               "mfa-enrol USER --secret-file /var/lib/idps-soc/labcheck_totp")
        self.token = res["access_token"]

    def sensor_id(self) -> int:
        return pick_sensor_id(self._req("/sensors/status")["sensors"])

    def pages(self, path: str, params: dict, max_items: int = MAX_ALERTS) -> list[dict]:
        """All pages of a list endpoint, newest first. Stops at `max_items` (never more than that
        are returned) and sets `self.truncated` if there was more."""
        out: list[dict] = []
        cursor = None
        self.truncated = False
        while True:
            q = {**params, "limit": 500, **({"cursor": cursor} if cursor else {})}
            page = self._req(path + "?" + urllib.parse.urlencode(q))
            out += page["items"]
            cursor = page.get("next_cursor")
            if len(out) >= max_items:
                self.truncated = len(out) > max_items or bool(cursor)
                out = out[:max_items]
                break
            if not cursor:
                break
        if self.truncated:
            print(f"warning: stopped reading {path} at {max_items} items; there are more",
                  file=sys.stderr)
        return out

    def alerts_between(self, since: datetime, until: datetime) -> list[dict]:
        return self.pages("/alerts", {"since": since.isoformat(), "until": until.isoformat()})

    def would_blocks_since(self, since: datetime, hours: int) -> list[dict]:
        items = self.pages("/blocks/would", {"since_hours": max(1, hours)})
        return [i for i in items
                if datetime.fromisoformat(i["at"].replace("Z", "+00:00")) >= since]


# ---- running things ---------------------------------------------------------------------------

def victim_sh(script: str, check: bool = True) -> subprocess.CompletedProcess:
    return bs.compose("exec", "-T", "victim", "sh", "-c", script, check=check, timeout=300)


def page_command(name: str, raw_bytes: int) -> str:
    """Shell that writes a page of about raw_bytes * 4/3 + a little of random-looking text (it does
    not compress away) that links the stylesheet, script and an image."""
    head = ("<!doctype html><html><head><title>Lab site</title>"
            "<link rel=stylesheet href=/benign/assets/a1.css>"
            "<script src=/benign/assets/a1.js></script></head><body>")
    return (f"{{ echo '{head}'; head -c {raw_bytes} /dev/urandom | base64 | fold -w 100 "
            f"| sed 's#^#<p>#; s#$#</p>#'; echo '<img src=/benign/assets/a1.png></body></html>'; }} "
            f"> {SETUP_DIR}/{name}")


def setup_victim_files() -> None:
    """Pages, test files and 'site' assets in the victim's nginx root, inside its container."""
    cmds = [f"mkdir -p {SETUP_DIR}/files {SETUP_DIR}/assets"]
    cmds += [page_command(n, b) for n, b in PAGE_BYTES.items()]
    for name, size in FILES.items():
        cmds.append(f"head -c {size} /dev/urandom > {SETUP_DIR}/files/{name}")
    for i in range(1, 9):
        for ext, size in ASSET_BYTES.items():
            cmds.append(f"head -c {size} /dev/urandom > {SETUP_DIR}/assets/a{i}.{ext}")
    cmds.append(f"chmod -R a+rX {SETUP_DIR}")
    victim_sh(" && ".join(cmds))


def cleanup_victim_files() -> None:
    victim_sh(f"rm -rf {SETUP_DIR}; rm -f /tmp/doc_*.dat", check=False)


def outbox_file_alerts() -> int:
    """Alerts waiting in the sensor's outbox file (0 if there is no file)."""
    r = bs.compose("exec", "-T", "sensor", "cat", OUTBOX_FILE, check=False, timeout=30)
    return outbox_alerts(r.stdout if r.returncode == 0 else None)


def fetch_ca() -> str:
    return bs.compose("exec", "-T", "sensor", "cat", "/run/idps-soc/ca.pem").stdout


def traffic_running() -> bool:
    r = bs.compose("exec", "-T", "attacker", "pidof", "-x", "benign.sh", check=False, timeout=30)
    return r.returncode == 0 and bool(r.stdout.strip())


class Traffic:
    """benign.sh in the attacker container, its stdout collected."""

    def __init__(self, seconds: int, password: str) -> None:
        # -e VAR without a value passes the host's value: the password is not in the arguments.
        cmd = ["docker", "compose", "exec", "-T", "-e", "LAB_VICTIM_PASSWORD", "attacker",
               "/attacks/benign.sh", str(seconds)]
        env = {**bs._env(), "LAB_VICTIM_PASSWORD": password}
        self.proc = subprocess.Popen(cmd, cwd=LAB, env=env, text=True, errors="replace",
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.lines: list[str] = []
        self.stopped = False
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            self.lines.append(line.rstrip())

    def wait(self, timeout: float) -> int:
        rc = self.proc.wait(timeout=timeout)
        self._thread.join(timeout=5)
        return rc

    def stop(self) -> None:
        """Ends the script inside the container too (killing `docker exec` does not), and waits
        until it has gone."""
        self.stopped = self.proc.poll() is None or traffic_running()
        for sig in ("TERM", "KILL"):
            if not traffic_running():
                break
            bs.compose("exec", "-T", "attacker", "sh", "-c",
                       f"kill -{sig} $(pidof -x benign.sh) 2>/dev/null; true", check=False, timeout=30)
            end = time.monotonic() + (20 if sig == "TERM" else 5)
            while traffic_running() and time.monotonic() < end:
                time.sleep(0.5)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._thread.join(timeout=5)


class RunSensor(bs.Sensor):
    """bench_sensor's Sensor, but the log is read tolerantly and stop() waits for the process."""

    def __init__(self, duration: int) -> None:
        cmd = ["docker", "compose", "exec", "-T", "-e", f"IDPS_ALLOWLIST={ALLOWLIST}", "sensor",
               "live.sh", "--interface", bs.INTERFACE, "--model", bs.MODEL, "--duration", str(duration)]
        self.proc = subprocess.Popen(cmd, cwd=LAB, env=bs._env(), text=True, errors="replace",
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.metrics: list[dict] = []
        self.lines: list[str] = []
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """SIGTERM (the sensor flushes its outbox and prints a last metrics line), then wait until
        idps.live is really gone, so the SOC holds everything before it is read."""
        for sig, wait_s in (("TERM", 60), ("KILL", 10)):
            if not bs.sensor_running():
                break
            bs.compose("exec", "-T", "sensor", "pkill", f"-{sig}", "-f", "idps.live",
                       check=False, timeout=30)
            end = time.monotonic() + wait_s
            while bs.sensor_running() and time.monotonic() < end:
                time.sleep(0.5)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._thread.join(timeout=10)


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")


def fetch_soc(soc, env_started: datetime, traffic_start: datetime, sensor_id: int | None,
              until: datetime) -> tuple[list[dict], dict, list[dict], bool]:
    """Alerts of this run and would-blocks, read after logging in again (a long run outlives a
    token). Returns (kept, excluded, would_blocks, truncated)."""
    soc.login()
    since = env_started - timedelta(seconds=5)
    raw = soc.alerts_between(since, until)
    truncated = bool(getattr(soc, "truncated", False))
    kept, excluded = filter_alerts(raw, traffic_start_ms=traffic_start.timestamp() * 1000,
                                   sensor_id=sensor_id)
    hours = int((until - since).total_seconds() // 3600) + 1
    would = soc.would_blocks_since(since, hours)
    return kept, excluded, would, truncated


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--minutes", type=float, default=60, help="minutes of normal traffic (default 60)")
    ap.add_argument("-o", "--output", type=Path, default=None,
                    help="report file (default reports/lab_benign.json)")
    args = ap.parse_args(argv)
    if args.minutes <= 0:
        print("--minutes must be positive", file=sys.stderr)
        return 2
    out_path = args.output or REPORT
    env = parse_env(ENV_FILE.read_text()) if ENV_FILE.exists() else {}
    password = env.get("LAB_VICTIM_PASSWORD", "")
    if not password:
        print("LAB_VICTIM_PASSWORD missing in lab/.env", file=sys.stderr)
        return 2
    if not env.get("LAB_SOC_CHECK_USER") or not env.get("LAB_SOC_CHECK_PASSWORD"):
        print("LAB_SOC_CHECK_USER / LAB_SOC_CHECK_PASSWORD missing in lab/.env", file=sys.stderr)
        return 2

    seconds = int(args.minutes * 60)
    # start-up, the traffic, a script that overruns, the flush, and a margin
    duration = bs.READY_TIMEOUT + seconds + OVERRUN_SECONDS + FLUSH_MAX_SECONDS + 60

    old_handlers = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)
                    if n is not None}
    if hasattr(signal, "SIGHUP"):
        old_handlers[signal.SIGHUP] = signal.getsignal(signal.SIGHUP)

    def on_signal(_s, _f):
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), on_signal)

    sensor = traffic = soc = None
    sensor_id = None
    interrupted = False
    failure: str | None = None
    t_start = t_traffic0 = t_traffic1 = None
    rc = None
    traffic_error: str | None = None
    drained = False
    outbox_at_start = 0
    try:
        if bs.sensor_running():
            raise Abort("a live sensor is already running in the container; stop it first")
        outbox_at_start = outbox_file_alerts()
        if outbox_at_start:
            raise Abort(f"the sensor's outbox file holds {outbox_at_start} old alerts; "
                        "they would be re-sent and counted. Clear it first")
        soc = Soc(env["LAB_SOC_CHECK_USER"], env["LAB_SOC_CHECK_PASSWORD"], fetch_ca())
        try:
            soc.login()
            sensor_id = soc.sensor_id()
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            raise Abort(f"cannot log in to the SOC before the run: {exc}") from exc
        bs.log("creating the pages and test files in the victim's nginx root")
        setup_victim_files()
        bs.log(f"starting the dry-run sensor (--duration {duration} s, allowlist {ALLOWLIST})")
        t_start = _now()
        sensor = RunSensor(duration)
        sensor.wait_ready()
        pending = (sensor.metrics[0] or {}).get("outbox_pending") or 0
        if pending > 0:
            raise Abort(f"the sensor starts with {pending} alerts in its outbox; "
                        "they would be counted. Clear data/processed/live_outbox.json first")
        bs.log(f"sensor ready (sensor_id {sensor_id}); normal traffic for {args.minutes:g} min")
        t_traffic0 = _now()
        traffic = Traffic(seconds, password)
        try:
            rc = traffic.wait(timeout=seconds + OVERRUN_SECONDS)
        except subprocess.TimeoutExpired:
            traffic_error = f"benign.sh did not finish within {OVERRUN_SECONDS} s of the asked time"
            bs.log(traffic_error + "; stopping it")
        finally:
            if t_traffic1 is None:
                t_traffic1 = _now()
        bs.log(f"traffic done; waiting for the flows to expire (at least {FLUSH_MIN_SECONDS} s)")
        drained = sensor.wait_drained(FLUSH_MIN_SECONDS, FLUSH_MAX_SECONDS)
        bs.log("drained" if drained else "NOT drained (limit reached): flows may be incomplete")
    except KeyboardInterrupt:
        interrupted = True
        bs.log("interrupted; stopping traffic and the sensor, then reporting what there is")
        if t_traffic0 is not None and t_traffic1 is None:  # an interrupt in the flush keeps its end
            t_traffic1 = _now()
    except Abort as exc:
        failure = str(exc)
    except Exception as exc:  # noqa: BLE001  any failure must still stop the lab processes below
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)  # a second Ctrl-C must not skip the cleanup
        except (ValueError, OSError):
            pass
        for stopper in (traffic.stop if traffic else None, sensor.stop if sensor else None,
                        cleanup_victim_files):
            if stopper is None:
                continue
            try:
                stopper()
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: {type(exc).__name__}: {exc}", file=sys.stderr)
        for sig, handler in old_handlers.items():  # leave the process as we found it
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, TypeError):
                pass

    if t_traffic0 is not None and t_traffic1 is None:
        t_traffic1 = _now()
    if failure and t_traffic0 is None:  # nothing was measured
        print(f"false-positive test not run: {failure}", file=sys.stderr)
        return 1
    if t_traffic0 is None:
        print("interrupted before any traffic", file=sys.stderr)
        return 130 if interrupted else 1
    if not sensor or not sensor.metrics:
        print("the sensor printed no metrics", file=sys.stderr)
        return 1

    final = sensor.metrics[-1]
    lines = traffic.lines if traffic else []
    activity = activity_summary(lines)
    reqs = parse_requests(lines)
    ACTIVITY_LOG.parent.mkdir(exist_ok=True)
    ACTIVITY_LOG.write_text("\n".join(lines) + "\n")
    elapsed = (t_traffic1 - t_traffic0).total_seconds()
    traffic_errors = [] if interrupted else check_traffic(
        rc=rc, stopped=bool(traffic and traffic.stopped and rc is None), activity_total=activity["total"],
        elapsed_s=elapsed, requested_s=seconds)
    if traffic_error:
        traffic_errors.append(traffic_error)
    if failure:
        traffic_errors.append(failure)

    kept = excluded = None
    would: list[dict] = []
    truncated = False
    soc_error = None
    try:
        kept, excluded, would, truncated = fetch_soc(soc, t_start, t_traffic0, sensor_id, _now())
    except (Abort, RuntimeError, urllib.error.URLError, OSError, KeyError, ValueError,
            subprocess.SubprocessError) as exc:
        soc_error = f"{type(exc).__name__}: {exc}"
        print(f"could not read the alerts from the SOC: {soc_error}", file=sys.stderr)

    report = build_report(
        minutes=args.minutes, started=t_start, traffic_started=t_traffic0, traffic_ended=t_traffic1,
        drained=drained and not interrupted, final=final, kept=kept, excluded=excluded,
        would_blocks=would, activity=activity, reqs=reqs, traffic_errors=traffic_errors,
        soc_error=soc_error, sensor_id=sensor_id, interrupted=interrupted, truncated=truncated,
        outbox_at_start=outbox_at_start)
    write_report(out_path, report)
    print(build_table(report))
    print(f"\nactivity: {activity['counts']} ({activity['problem_count']} problem line(s))")
    if not report["valid"]:
        print("\nRESULT INVALID: " + "; ".join(report["invalid_reasons"]), file=sys.stderr)
    print(f"\nwrote {out_path}")
    if interrupted:
        return 130
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
