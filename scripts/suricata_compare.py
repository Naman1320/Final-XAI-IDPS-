"""Rule-based IDS against our ML model: Suricata (ET Open rules) and the full-week XGBoost, per attack.

    python scripts/suricata_compare.py run data/raw/lab_pcaps/portscan_1.pcap --dataset lab
    python scripts/suricata_compare.py run data/raw/pcap/Friday-WorkingHours.pcap --dataset cic --name friday
    python scripts/suricata_compare.py compare --friday            # lab (+ Friday) -> reports/suricata_compare.json
    python scripts/suricata_compare.py all --friday                # run on every pcap, then compare

`run` streams one pcap into Suricata 7 (Docker image jasonish/suricata) on stdin, because Docker Desktop
cannot mount folders under ~/Desktop, with the ET Open rules from the Docker volume `idps-suricata`
(/var/lib/suricata/rules/suricata.rules). It saves the alert events to data/raw/suricata/<name>.alerts.jsonl
and the run metadata (image, rules updated_at and sha256, HOME_NET, packets read, duration) to
<name>.meta.json. HOME_NET is set per dataset (lab 10.10.2.0/24, CIC-IDS2017 192.168.10.0/24) and
EXTERNAL_NET to any: Suricata's default HOME_NET is every private range, which would make the attacker
"home" and stop most ET rules (written $EXTERNAL_NET -> $HOME_NET) from firing.

`compare` matches alerts to labelled flows (same protocol and 5-tuple in either direction, alert time within
1 s of the flow's [start, end]) and reports, per truth label, how many flows each system detects: Suricata
(any attack signature), the week model (any attack class, with and without the 0.5 alert floor) and either.
Engine events (signature text starting "SURICATA ", for example "SURICATA STREAM Packet with invalid ack")
fire on ordinary traffic; they are counted separately and left out of the headline unless --include-engine.
The lab uses data/processed/lab_labelled.parquet. Friday uses only the rows that were in the TEST split of the
week model (rebuilt with the trainer's own make_split on the five labelled days), so the model is not scored
on flows it trained on; Suricata is scored on the same rows.

Needs Docker (run) and the project venv (compare). See docs/live.md, "Suricata comparison".
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_unseen as lu  # noqa: E402
# The eve.json parsing and the engine / informational classification live in the package, where the
# sensor's rule forwarder uses them too (idps/rules/eve.py); re-exported here under the old names.
from idps.rules.eve import (  # noqa: E402,F401
    ENGINE_PREFIX,
    INFO_CATEGORIES,
    INFO_PREFIXES,
    PROTO,
    eve_timestamp_ms,
    is_engine_event,
    is_informational,
    parse_alert_line,
    proto_number,
)

ROOT = lu.ROOT
IMAGE = "jasonish/suricata:7.0.10"
VOLUME = "idps-suricata"
RULES = "/var/lib/suricata/rules/suricata.rules"
DOCKER_BIN = "/Applications/Docker.app/Contents/Resources/bin"
OUT_DIR = ROOT / "data" / "raw" / "suricata"
LAB_PCAPS = lu.PCAP_DIR
FRIDAY_PCAP = ROOT / "data" / "raw" / "pcap" / "Friday-WorkingHours.pcap"
FRIDAY_NAME = "friday"
REPORT = ROOT / "reports" / "suricata_compare.json"
LAB_DATA = lu.DATA
PROCESSED = ROOT / "data" / "processed"
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
HOME_NETS = {"lab": ["10.10.2.0/24"], "cic": ["192.168.10.0/24"]}
SLACK_MS = 1000            # an alert may be this far outside the flow's [start, end]
BENIGN = lu.BENIGN
TOP_SIGNATURES = 5
TOP_BENIGN_SIGNATURES = 10
LOG_TAIL_LINES = 40
RUN_TIMEOUT = 4 * 3600
M_ALERTS, M_LOG, M_END = "@@ALERTS", "@@LOG", "@@END"
M_META = "@@META "


def log(msg: str) -> None:
    print(f"[suricata {datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# ---- pure parts (unit-tested) -----------------------------------------------------------------

def home_net_args(nets: list[str]) -> list[str]:
    """Suricata arguments that set HOME_NET to `nets` and EXTERNAL_NET to any."""
    if not nets or any(not n.strip() or any(c in n for c in "[],!") for n in nets):
        raise ValueError(f"bad HOME_NET list {nets!r}")
    return ["--set", f"vars.address-groups.HOME_NET=[{','.join(n.strip() for n in nets)}]",
            "--set", "vars.address-groups.EXTERNAL_NET=any"]


ALERT_COLUMNS = ["ts_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "signature", "sid",
                 "category", "severity", "engine", "informational"]


def alerts_frame(lines) -> pd.DataFrame:
    rows = [r for r in (parse_alert_line(x) for x in lines) if r is not None]
    return pd.DataFrame(rows, columns=ALERT_COLUMNS)


def load_alerts(path: Path) -> pd.DataFrame:
    with open(path) as fh:
        return alerts_frame(fh)


ICMP_PROTOCOLS = (1, 58)


def _endpoint_key(df: pd.DataFrame, a_ip, a_port, b_ip, b_port) -> pd.Series:
    """Direction-free key: protocol plus the two ip|port endpoints in sorted order. ICMP has no real
    ports (NFStream may put the type/code in dst_port), so its key is the two addresses only."""
    proto = df["protocol"].astype("int64")
    icmp = proto.isin(ICMP_PROTOCOLS)
    pa = df[a_port].astype("int64").astype(str).where(~icmp, "0")
    pb = df[b_port].astype("int64").astype(str).where(~icmp, "0")
    a = df[a_ip].astype(str) + "|" + pa
    b = df[b_ip].astype(str) + "|" + pb
    lo, hi = a.where(a <= b, b), b.where(a <= b, a)
    return proto.astype(str) + "|" + lo + "|" + hi


MATCH_COLUMNS = ["flow", "signature", "sid", "engine", "informational"]


def match_alerts(flows: pd.DataFrame, alerts: pd.DataFrame, slack_ms: int = SLACK_MS) -> pd.DataFrame:
    """Alerts that belong to flows: same protocol and 5-tuple (either direction; ICMP: same two
    addresses) and alert time in [start_ms - slack, end_ms + slack]. Each alert is credited to ONE flow:
    among the candidates the one whose window contains the alert time (else the one nearest to it),
    ties broken by the nearest start. Returns one row per credited alert with the flow's index label in
    `flow`. `flows` needs a unique index."""
    if flows.empty or alerts.empty:
        return pd.DataFrame(columns=MATCH_COLUMNS)
    f = pd.DataFrame({"flow": flows.index, "key": _endpoint_key(flows, "src_ip", "src_port", "dst_ip", "dst_port").to_numpy(),
                      "start": flows["start_ms"].astype("int64").to_numpy(),
                      "end": flows["end_ms"].astype("int64").to_numpy()})
    a = alerts.dropna(subset=["protocol"]).copy()
    a["key"] = _endpoint_key(a, "src_ip", "src_port", "dst_ip", "dst_port")
    if "informational" not in a:
        a["informational"] = False
    a = a.drop_duplicates(subset=["key", "ts_ms", "sid", "signature"]).reset_index(drop=True)
    a["aid"] = a.index
    m = f.merge(a[["aid", "key", "ts_ms", "signature", "sid", "engine", "informational"]], on="key")
    m["dist"] = np.maximum(np.maximum(m["start"] - m["ts_ms"], m["ts_ms"] - m["end"]), 0)
    m = m[m["dist"] <= slack_ms].copy()
    m["off"] = (m["ts_ms"] - m["start"]).abs()
    m = m.sort_values(["aid", "dist", "off", "flow"], kind="stable").drop_duplicates("aid")
    return m[MATCH_COLUMNS].reset_index(drop=True)


def check_time_base(alerts: pd.DataFrame, span: tuple[int, int], what: str = "", min_share: float = 0.5) -> None:
    """Refuse alerts when most of them fall outside `span` (first flow start, last flow end, epoch ms; for
    Friday the whole day's labelled flows). A timezone or wrong-pcap mistake would make every match fail
    silently. A minority outside (alerts before the first or after the last labelled flow) is normal."""
    if alerts.empty:
        return
    lo, hi = span
    t = alerts["ts_ms"]
    share = float(((t >= lo - SLACK_MS) & (t <= hi + SLACK_MS)).mean())
    if share < min_share:
        raise ValueError(f"{what}: only {share:.0%} of the alerts fall inside the flows' time span "
                         f"({pd.Timestamp(lo, unit='ms', tz='UTC')} to {pd.Timestamp(hi, unit='ms', tz='UTC')}); "
                         "wrong pcap or time base")


def flow_span(flows: pd.DataFrame) -> tuple[int, int]:
    return int(flows["start_ms"].min()), int(flows["end_ms"].max())


def flow_hits(n: int, matches: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Boolean arrays over flows 0..n-1: matched by any attack signature (not an engine event), matched by
    an engine event, matched by a security signature (attack signature that is not informational)."""
    attack, engine, security = np.zeros(n, bool), np.zeros(n, bool), np.zeros(n, bool)
    if len(matches):
        eng = matches["engine"].astype(bool).to_numpy()
        info = matches["informational"].astype(bool).to_numpy() if "informational" in matches else np.zeros(len(matches), bool)
        fl = matches["flow"].to_numpy()
        attack[fl[~eng]] = True
        engine[fl[eng]] = True
        security[fl[~eng & ~info]] = True
    return attack, engine, security


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def top_signatures(matches: pd.DataFrame, flows_idx, engine: bool = False, k: int = TOP_SIGNATURES) -> list[dict]:
    """Signatures that matched the most flows among `flows_idx` (flows counted once per signature)."""
    if not len(matches):
        return []
    m = matches[matches["flow"].isin(set(flows_idx)) & (matches["engine"].astype(bool) == engine)]
    m = m.drop_duplicates(subset=["flow", "signature"])
    return [{"signature": s, "flows": int(n)} for s, n in Counter(m["signature"]).most_common(k)]


def alert_counts(alerts: pd.DataFrame) -> dict:
    """Alert totals: attack (all non-engine), security (attack minus informational), informational and
    engine, and the most frequent signatures of each."""
    if alerts.empty:
        return {"total": 0, "attack": 0, "security": 0, "informational": 0, "engine": 0,
                "attack_signatures": 0, "top_attack": [], "top_engine": []}
    eng = alerts["engine"].astype(bool)
    info = alerts["informational"].astype(bool) if "informational" in alerts else pd.Series(False, index=alerts.index)
    top = lambda df: [{"signature": s, "alerts": int(n)} for s, n in
                      df["signature"].value_counts().head(TOP_BENIGN_SIGNATURES).items()]
    return {"total": len(alerts), "attack": int((~eng).sum()), "security": int((~eng & ~info).sum()),
            "informational": int((~eng & info).sum()), "engine": int(eng.sum()),
            "attack_signatures": int(alerts.loc[~eng, "signature"].nunique()),
            "top_attack": top(alerts[~eng]), "top_engine": top(alerts[eng])}


def compare_frame(df: pd.DataFrame, matches: pd.DataFrame, plain: list[str], floored: list[str],
                  model_classes, include_engine: bool = False) -> dict:
    """Per-label and BENIGN comparison. `df` has a unique 0..n-1 index and `label`; `plain` / `floored`
    are the model's predictions (argmax / with the alert floor) per row; `matches` come from match_alerts.
    A flow is Suricata-detected when an attack signature matched (or an engine event too, with
    `include_engine`); ML-detected when the predicted class is not BENIGN. Every Suricata figure comes
    in two kinds: all attack signatures, and `_security` which leaves out informational ones (ET INFO,
    ET POLICY, GPL ICMP_INFO style, see is_informational). `any_alert` is the per-attack view: did
    Suricata (or the model) flag at least one flow of that label."""
    n = len(df)
    attack, engine, security = flow_hits(n, matches)
    suri = attack | engine if include_engine else attack
    ml_plain = np.array([p != BENIGN for p in plain], bool)
    ml_floor = np.array([p != BENIGN for p in floored], bool)
    labels = df["label"].astype(str).to_numpy()
    truth = labels.tolist()
    fam_plain = lu.per_label_metrics(truth, plain, model_classes)
    fam_floor = lu.per_label_metrics(truth, floored, model_classes)
    per_label = {}
    for label in sorted(set(labels) - {BENIGN}):
        idx = np.flatnonzero(labels == label)
        c = len(idx)
        cnt = lambda a: int(a[idx].sum())
        per_label[label] = {
            "flows": c,
            "suricata_recall": _rate(cnt(suri), c),
            "suricata_recall_security": _rate(cnt(security), c),
            "suricata_recall_attack_only": _rate(cnt(attack), c),
            "suricata_recall_with_engine": _rate(cnt(attack | engine), c),
            "engine_only_flows": int((engine & ~attack)[idx].sum()),
            "ml_recall_floor": _rate(cnt(ml_floor), c),
            "ml_recall_no_floor": _rate(cnt(ml_plain), c),
            "ml_family_recall_floor": fam_floor[label]["family_recall"],
            "ml_family_recall_no_floor": fam_plain[label]["family_recall"],
            "union_recall_floor": _rate(cnt(suri | ml_floor), c),
            "union_recall_no_floor": _rate(cnt(suri | ml_plain), c),
            "suricata_only_flows_no_floor": int((suri & ~ml_plain)[idx].sum()),
            "ml_only_flows_no_floor": int((ml_plain & ~suri)[idx].sum()),
            "any_alert": {"suricata": cnt(suri) > 0, "suricata_security": cnt(security) > 0,
                          "ml_floor": cnt(ml_floor) > 0, "ml_no_floor": cnt(ml_plain) > 0,
                          "suricata_flows_alerted": cnt(suri)},
            "top_signatures": top_signatures(matches, idx),
            "ml_top_predicted": fam_floor[label]["top_predicted"][:3],
        }
    bidx = np.flatnonzero(labels == BENIGN)
    b = len(bidx)
    cnt = lambda a: int(a[bidx].sum())
    benign = {
        "flows": b,
        "suricata_false_positive_rate": _rate(cnt(suri), b),
        "suricata_fpr_security": _rate(cnt(security), b),
        "suricata_fpr_attack_only": _rate(cnt(attack), b),
        "suricata_fpr_with_engine": _rate(cnt(attack | engine), b),
        "suricata_false_positives": cnt(suri),
        "ml_fpr_floor": _rate(cnt(ml_floor), b),
        "ml_fpr_no_floor": _rate(cnt(ml_plain), b),
        "ml_false_positives_floor": cnt(ml_floor),
        "ml_false_positives_no_floor": cnt(ml_plain),
        "suricata_top_attack_signatures": top_signatures(matches, bidx, k=TOP_BENIGN_SIGNATURES),
        "suricata_top_engine_signatures": top_signatures(matches, bidx, engine=True, k=TOP_BENIGN_SIGNATURES),
    }
    return {"flows": n, "include_engine": include_engine, "per_label": per_label, "benign": benign}


def session_detection(alerts: pd.DataFrame, attacker: str, flows: int, ml_flagged_floor: int,
                      ml_flagged_no_floor: int) -> dict:
    """Attack-level result for one attack session: did Suricata raise any attack (non-engine) alert on
    traffic to or from the attacker, any security (non-informational) one, and with which signatures."""
    on = alerts[(alerts["src_ip"] == attacker) | (alerts["dst_ip"] == attacker)] if len(alerts) else alerts
    att = on[~on["engine"].astype(bool)] if len(on) else on
    sec = att[~att["informational"].astype(bool)] if len(att) and "informational" in att else att
    eng = len(on) - len(att)
    return {"flows": flows, "suricata_detected": bool(len(att)), "suricata_detected_security": bool(len(sec)),
            "suricata_attack_alerts": len(att), "suricata_security_alerts": len(sec),
            "suricata_engine_alerts": int(eng),
            "suricata_signatures": [{"signature": s, "alerts": int(k)} for s, k in
                                    Counter(att["signature"]).most_common(TOP_SIGNATURES)] if len(att) else [],
            "ml_detected_floor": ml_flagged_floor > 0, "ml_flows_flagged_floor": ml_flagged_floor,
            "ml_detected_no_floor": ml_flagged_no_floor > 0, "ml_flows_flagged_no_floor": ml_flagged_no_floor}


def split_run_output(lines, alerts_out) -> tuple[dict, list[str]]:
    """Split what the container script printed: `@@META key=value` lines, alert lines (written to
    `alerts_out`) and the tail of run.log. Returns (meta, log lines). Raises if the end marker is missing
    (the run was cut short)."""
    meta: dict[str, str] = {}
    log_lines: list[str] = []
    seen_log: set[str] = set()   # the grep and the tail of run.log overlap
    section, ended = None, False
    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith(M_META):
            k, _, v = line[len(M_META):].partition("=")
            meta[k.strip()] = v.strip()
        elif line == M_ALERTS:
            section = "alerts"
        elif line == M_LOG:
            section = "log"
        elif line == M_END:
            ended = True
        elif section == "alerts" and line.startswith("{"):
            alerts_out.write(line + "\n")
        elif section == "log" and line not in seen_log:
            seen_log.add(line)
            log_lines.append(line)
    if not ended:
        raise RuntimeError("the Suricata container output ended early (no end marker)")
    return meta, log_lines


def packets_read(log_lines: list[str]) -> int | None:
    """Packet count from Suricata's run.log ('Pcap-file module read 1 files, 330 packets, 226 bytes')."""
    for line in reversed(log_lines):
        m = re.search(r"read \d+ files?, (\d+) packets", line)
        if m:
            return int(m[1])
    return None


ERROR_LEVELS = "E|C|A|Em|Error|Critical|Alert|Emergency"
ERROR_LINE = re.compile(rf"^\s*({ERROR_LEVELS}):")


def log_errors(log_lines: list[str]) -> list[str]:
    """Error-level lines in run.log (a truncated pcap is one): 'E:' style prefixes without -v, 'Error:'
    style with -v; Warning/W and Info/i lines are not errors."""
    return [x for x in log_lines if ERROR_LINE.match(x)]


RULE_PROBLEMS = re.compile(r"no rules were loaded|no rule files match|no rules loaded", re.I)


def rules_loaded(log_lines: list[str]) -> int | None:
    """Rule count from '53510 rules successfully loaded, 0 rules failed' (None if the line is missing)."""
    for line in log_lines:
        m = re.search(r"(\d+) rules successfully loaded", line)
        if m:
            return int(m[1])
    return None


def rules_failed(log_lines: list[str]) -> int | None:
    """Failed-rule count from '..., 3 rules failed, ...' (None if the line is missing)."""
    for line in log_lines:
        m = re.search(r"(\d+) rules failed", line)
        if m:
            return int(m[1])
    return None


def check_run(meta: dict, log_lines: list[str]) -> None:
    """Refuse a run that cannot be trusted: Suricata failed, or no rules were loaded (every flow would
    silently count as undetected), or the rules' identity is missing."""
    problems = []
    if meta.get("rc") != "0":
        problems.append(f"suricata exited with status {meta.get('rc')}")
    loaded = rules_loaded(log_lines)
    if not loaded:
        problems.append("no rules were loaded" if loaded == 0 else "no 'rules successfully loaded' line in the log")
    failed = rules_failed(log_lines)
    if failed:
        problems.append(f"{failed} rules failed to load")
    if not meta.get("rules_sha256"):
        problems.append("rules_sha256 missing")
    if not str(meta.get("rules_enabled", "")).isdigit() or int(meta["rules_enabled"]) == 0:
        problems.append("rules_enabled missing or 0")
    problems += [x for x in log_lines if RULE_PROBLEMS.search(x)]
    if problems:
        raise RuntimeError("; ".join(problems) + f" | log: {' | '.join(log_lines[-6:])}")


def container_script(home_net: list[str], alert_only: bool = True) -> str:
    """Shell script run in the container: pcap on stdin, alert events and metadata on stdout.
    --init-errors-fatal makes a rule or setting that fails to load stop the run instead of running with
    fewer rules. With `alert_only`, eve.json is a named pipe read by a grep that keeps only the alert
    events (flow, http, dns, tls, anomaly and stats events would take many GB for the Friday pcap and are
    never written to disk); fast.log and stats.log go to /dev/null. Engine events are alerts and stay."""
    args = " ".join(shlex.quote(a) for a in home_net_args(home_net))
    r = shlex.quote(RULES)
    lines = ["mkdir -p /out", "rm -f /out/eve.json /out/fast.log /out/stats.log"]
    if alert_only:
        lines += ["mkfifo /out/eve.json",
                  "grep --line-buffered '\"event_type\":\"alert\"' /out/eve.json > /out/alerts.jsonl </dev/null &",
                  "GREP=$!", "ln -s /dev/null /out/fast.log", "ln -s /dev/null /out/stats.log"]
    lines += [
        f'echo "{M_META}suricata_version=$(suricata -V 2>&1 | head -n 1)"',
        f'echo "{M_META}rules_sha256=$(sha256sum {r} | cut -d" " -f1)"',
        f"echo \"{M_META}rules_updated_at=$(grep -o 'updated_at [0-9_]*' {r} | cut -d' ' -f2 | sort | tail -n 1)\"",
        f"echo \"{M_META}rules_enabled=$(grep -cE '^(alert|drop|reject|pass) ' {r})\"",
        f"suricata -v -k none --init-errors-fatal -r /dev/stdin -l /out -S {r} {args} >/out/run.log 2>&1",
        "RC=$?",
        f'echo "{M_META}rc=$RC"']
    if alert_only:
        # unblock the reader if Suricata never opened the pipe (a failed start), then wait for it
        lines += ["timeout 5 sh -c ': > /out/eve.json' 2>/dev/null", "wait $GREP"]
    lines += [
        f'echo "{M_META}rules_loaded=$(grep -o \'[0-9]* rules successfully loaded\' /out/run.log | head -n 1 | cut -d" " -f1)"',
        f'echo "{M_META}out_kb=$(du -sk /out | cut -f1)"',
        f"echo {M_ALERTS}",
        "cat /out/alerts.jsonl" if alert_only else "grep -h '\"event_type\":\"alert\"' /out/eve.json",
        f"echo {M_LOG}",
        # the whole log is searched for errors, rule problems and the packet count, then its tail is shown
        f"grep -E '^ *({ERROR_LEVELS}):|rules successfully loaded|rules failed|read [0-9]+ files?, [0-9]+ packets|[Nn]o rule files match|[Nn]o rules' /out/run.log | head -n 200",
        f"tail -n {LOG_TAIL_LINES} /out/run.log",
        f"echo {M_END}"]
    return "\n".join(lines)


# ---- running Suricata -------------------------------------------------------------------------

def _env() -> dict:
    import os
    env = dict(os.environ)
    if DOCKER_BIN not in env.get("PATH", ""):
        env["PATH"] = f"{env.get('PATH', '')}:{DOCKER_BIN}"
    return env


def meta_path(name: str, out_dir: Path = OUT_DIR) -> Path:
    return out_dir / f"{name}.meta.json"


def alerts_path(name: str, out_dir: Path = OUT_DIR) -> Path:
    return out_dir / f"{name}.alerts.jsonl"


def docker_cmd(script: str) -> list[str]:
    """The rules volume is mounted read-only: the run only reads the rules."""
    return ["docker", "run", "--rm", "-i", "-v", f"{VOLUME}:/var/lib/suricata:ro", "--entrypoint", "sh",
            IMAGE, "-c", script]


def run_suricata(pcap: Path, dataset: str, name: str | None = None, out_dir: Path = OUT_DIR,
                 home_net: list[str] | None = None, alert_only: bool = True) -> dict:
    """Run Suricata on `pcap` (streamed on stdin) and save <name>.alerts.jsonl and <name>.meta.json.
    Nothing is saved (and the previous files are kept) when the run cannot be trusted (see check_run)."""
    pcap = Path(pcap)
    if not pcap.is_file():
        raise FileNotFoundError(pcap)
    nets = home_net or HOME_NETS[dataset]
    name = name or pcap.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    apath, mpath = alerts_path(name, out_dir), meta_path(name, out_dir)
    tmp = apath.with_name(apath.name + ".tmp")
    cmd = docker_cmd(container_script(nets, alert_only))
    log(f"{pcap.name} ({pcap.stat().st_size / 1e6:.0f} MB), dataset {dataset}, HOME_NET {nets}")
    t0 = time.monotonic()
    try:
        with tempfile.TemporaryFile("w+") as raw, open(pcap, "rb") as src:
            r = subprocess.run(cmd, stdin=src, stdout=raw, stderr=subprocess.PIPE, text=True, env=_env(),
                               timeout=RUN_TIMEOUT)
            duration = round(time.monotonic() - t0, 1)
            if r.returncode != 0:
                raise RuntimeError(f"docker run failed ({r.returncode}): {(r.stderr or '')[-500:]}")
            raw.seek(0)
            with open(tmp, "w") as out:
                meta, log_lines = split_run_output(raw, out)
        check_run(meta, log_lines)
        n_alerts = sum(1 for _ in open(tmp))
        st = pcap.stat()
        info = {"name": name, "dataset": dataset, "pcap": lu._rel(pcap), "pcap_bytes": st.st_size,
                "pcap_mtime_ns": st.st_mtime_ns, "image": IMAGE, "home_net": nets,
                "external_net": "any", "rules_volume": VOLUME, "rules_file": RULES,
                "suricata_version": meta.get("suricata_version"),
                "rules_updated_at": meta.get("rules_updated_at"), "rules_sha256": meta.get("rules_sha256"),
                "rules_enabled": int(meta["rules_enabled"]), "rules_loaded": rules_loaded(log_lines),
                "packets_read": packets_read(log_lines), "log_errors": log_errors(log_lines),
                "alert_only_eve": alert_only, "out_kb": meta.get("out_kb"),
                "alert_events": n_alerts, "duration_s": duration,
                "generated": datetime.now(UTC).isoformat(timespec="seconds"), "log_tail": log_lines[-10:]}
        mpath.write_text(json.dumps(info, indent=2) + "\n")
        tmp.replace(apath)
    finally:
        tmp.unlink(missing_ok=True)
    if info["log_errors"]:
        log(f"  WARNING: Suricata logged errors (a truncated pcap?): {info['log_errors'][:3]}")
    log(f"  {n_alerts} alert events, {info['packets_read']} packets, {duration} s -> {lu._rel(apath)}")
    return info


def current_rules_info() -> dict:
    """sha256 and newest updated_at of the rules in the volume (one small container)."""
    r = _rules_probe_script()
    out = subprocess.run(docker_cmd(r), capture_output=True, text=True, env=_env(), timeout=300, check=True).stdout
    sha, _, upd = out.strip().partition(" ")
    return {"rules_sha256": sha, "rules_updated_at": upd.strip()}


def _rules_probe_script() -> str:
    r = shlex.quote(RULES)
    return (f"echo \"$(sha256sum {r} | cut -d' ' -f1) $(grep -o 'updated_at [0-9_]*' {r} | cut -d' ' -f2 | sort | tail -n 1)\"")


def up_to_date(pcap: Path, name: str, home_net: list[str], out_dir: Path = OUT_DIR,
               rules: dict | None = None) -> bool:
    """True when saved alerts can be reused: same HOME_NET and image, the same rules (sha256 and
    updated_at, compared when `rules` is given), the same pcap (size, mtime) and the run logged no
    errors. If the pcap file is gone the cached alerts are used (and the log says so)."""
    mp = meta_path(name, out_dir)
    if not (mp.exists() and alerts_path(name, out_dir).exists()):
        return False
    try:
        m = json.loads(mp.read_text())
    except ValueError:
        return False
    if m.get("log_errors") or not m.get("rules_sha256") or not m.get("rules_loaded"):
        return False
    if m.get("home_net") != home_net or m.get("image") != IMAGE:
        return False
    if rules is not None and (m.get("rules_sha256") != rules.get("rules_sha256")
                              or m.get("rules_updated_at") != rules.get("rules_updated_at")):
        return False
    try:
        st = Path(pcap).stat()
    except OSError:
        log(f"{name}: pcap {Path(pcap).name} is not there; using the cached alerts")
        return True
    return m.get("pcap_bytes") == st.st_size and m.get("pcap_mtime_ns") == st.st_mtime_ns


# ---- scoring on the host ----------------------------------------------------------------------

def predict_week(df: pd.DataFrame, meta: dict, model_path: Path = lu.MODEL) -> tuple[list[str], list[str], list[str], str]:
    """Week-model predictions for `df`: (plain argmax, with the 0.5 floor, model classes, model sha256)."""
    from idps.detect.bundle import load_bundle, read_digest

    bundle = load_bundle(model_path)  # refuses a model that does not match its .sha256
    proba = bundle.predict_proba(bundle.select(df, meta).astype(float))
    classes = list(bundle.label_encoder.classes_)
    plain = [classes[i] for i in proba.argmax(1)]
    return plain, lu.apply_floor(plain, proba.max(1)), classes, read_digest(model_path)


def friday_test_rows(days_dir: Path = PROCESSED, model_report: Path = lu.MODEL_REPORT) -> tuple[pd.DataFrame, dict, dict]:
    """The Friday rows that were in the week model's TEST split: the five labelled days are loaded and
    split with the trainer's own make_split (class-time, the training defaults); the result must have
    the test size recorded in the model report. Returns (rows, meta, description); the description has
    the row counts, the time span of ALL Friday flows (`friday_span_ms`) and the share of the Friday test
    rows whose feature vector also occurs in train."""
    from idps.detect.data import load_labelled
    from idps.detect.split import _identical_to_train
    from idps.detect.train import make_split
    from idps.features import MODEL_FEATURES, read_features

    files = [days_dir / f"{d}_labelled.parquet" for d in DAYS]
    df, meta = load_labelled(files)
    split = make_split(df, "class-time")
    expected = json.loads(model_report.read_text())["split"]["parts"]["test"]["rows"]
    if len(split.test) != expected:
        raise RuntimeError(f"rebuilt test split has {len(split.test)} rows but {model_report.name} says "
                           f"{expected}; the labelled files are not the ones the model was trained on")
    friday, _ = read_features(files[-1])
    days = set((friday["start_ms"].astype("int64") // 86_400_000).unique())
    test = split.test
    rows = test[(test["start_ms"].astype("int64") // 86_400_000).isin(days)].reset_index(drop=True)
    lo, hi = flow_span(friday)
    desc = {"week_test_rows": len(split.test), "friday_test_rows": len(rows),
            "friday_rows_total": len(friday), "friday_span_ms": [lo, hi],
            "friday_identical_to_train": _identical_to_train(split.train, rows, list(MODEL_FEATURES)),
            "split_mode": "class-time (idps.detect.train.make_split defaults)"}
    return rows, meta, desc


def compare_lab(data: Path = LAB_DATA, out_dir: Path = OUT_DIR, include_engine: bool = False,
                exclude: set[str] | None = None) -> dict:
    """Lab comparison: each session/repeat's flows against the alerts of its own pcap. A session whose
    alerts file is missing, excluded (its Suricata run failed) or unusable is left out and listed
    (`missing_alert_files`, `errors`); the others are still compared."""
    from idps.features import read_features

    df, meta = read_features(data)
    plain, floored, classes, digest = predict_week(df, meta)
    df = df.reset_index(drop=True)
    keep, matches, all_alerts, sessions = np.zeros(len(df), bool), [], [], []
    missing: list[str] = []
    errors: dict[str, str] = {}
    for (session, rep), grp in df.groupby(["session", "repeat"], sort=True):
        name = f"{session}_{rep}"
        ap = alerts_path(name, out_dir)
        if name in (exclude or set()) or not ap.exists():
            missing.append(name)
            continue
        try:
            alerts = load_alerts(ap)
            check_time_base(alerts, flow_span(grp), name)
            m = match_alerts(grp, alerts)
        except Exception as exc:  # noqa: BLE001  one bad session must not stop the others
            errors[name] = str(exc)
            log(f"{name}: {exc}")
            continue
        matches.append(m)
        all_alerts.append(alerts)
        keep[grp.index.to_numpy()] = True
        if session != "benign":
            idx = grp.index.to_numpy()
            sessions.append({"session": session, "repeat": int(rep), "label": grp["label"].iloc[0],
                             **session_detection(alerts, lu.ATTACKER, len(grp),
                                                 sum(floored[i] != BENIGN for i in idx),
                                                 sum(plain[i] != BENIGN for i in idx))})
        else:
            att = alerts[~alerts["engine"].astype(bool)] if len(alerts) else alerts
            sec = att[~att["informational"].astype(bool)] if len(att) else att
            sessions.append({"session": session, "repeat": int(rep), "label": BENIGN, "flows": len(grp),
                             "attack_alerts": len(att), "security_alerts": len(sec),
                             "engine_alerts": len(alerts) - len(att)})
    if not keep.any():
        raise RuntimeError(f"no usable Suricata alerts for any lab session in {out_dir} "
                           f"(missing {missing}, errors {errors}); run `run`/`all` first")
    sel = np.flatnonzero(keep)
    remap = {old: new for new, old in enumerate(sel)}
    sub = df.iloc[sel].reset_index(drop=True)
    mm = pd.concat(matches, ignore_index=True)
    mm = mm.assign(flow=mm["flow"].map(remap))
    res = compare_frame(sub, mm, [plain[i] for i in sel], [floored[i] for i in sel], classes, include_engine)
    res.update({"sessions": sessions, "missing_alert_files": missing, "errors": errors, "data": lu._rel(data),
                "alerts": alert_counts(pd.concat(all_alerts, ignore_index=True)),
                "model_sha256": digest, "model_classes": classes})
    return res


def compare_friday(out_dir: Path = OUT_DIR, include_engine: bool = False, name: str = FRIDAY_NAME) -> dict:
    ap = alerts_path(name, out_dir)
    if not ap.exists():
        raise RuntimeError(f"{ap} missing; run Suricata on the Friday pcap first")
    rows, meta, desc = friday_test_rows()
    plain, floored, classes, digest = predict_week(rows, meta)
    alerts = load_alerts(ap)
    check_time_base(alerts, tuple(desc["friday_span_ms"]), name)  # against all of Friday, not just the test rows
    mm = match_alerts(rows, alerts)
    res = compare_frame(rows, mm, plain, floored, classes, include_engine)
    res.update({"split": desc, "alerts": alert_counts(alerts), "model_sha256": digest,
                "model_classes": classes,
                "scored_on": "Friday rows in the week model's test split (the model never trained on them)"})
    return res


# ---- report -----------------------------------------------------------------------------------

def _pct(v) -> str:
    return "n/a" if v is None else f"{v:.1%}"


def _yn(v) -> str:
    return "yes" if v else "no"


def build_tables(title: str, res: dict) -> str:
    if "error" in res:
        return f"### {title}\n\nFAILED: {res['error']}"
    eng = " or engine event" if res["include_engine"] else ""
    lines = [f"### {title}", "",
             "Flow-level recall (share of the label's flows detected) and per-attack any-alert (at least one "
             "flow of the label flagged: Suricata / Suricata security-only / ML with floor)", "",
             f"| Truth label | Flows | Suricata, all attack signatures{eng} | Suricata, security only | ML (floor) "
             "| ML (no floor) | Either (floor) | Either (no floor) | Any alert (S / S-sec / ML) "
             "| Top Suricata signatures |", "|---|---|---|---|---|---|---|---|---|---|"]
    for label, v in res["per_label"].items():
        sigs = "; ".join(f"{s['signature']} ({s['flows']})" for s in v["top_signatures"][:3]) or "none"
        any_ = v["any_alert"]
        lines.append(f"| {label} | {v['flows']} | {_pct(v['suricata_recall'])} | {_pct(v['suricata_recall_security'])} "
                     f"| {_pct(v['ml_recall_floor'])} | {_pct(v['ml_recall_no_floor'])} | {_pct(v['union_recall_floor'])} "
                     f"| {_pct(v['union_recall_no_floor'])} | {_yn(any_['suricata'])} / {_yn(any_['suricata_security'])} "
                     f"/ {_yn(any_['ml_floor'])} | {sigs} |")
    b = res["benign"]
    lines += ["", f"BENIGN false-positive rate over {b['flows']} flows: Suricata all attack signatures "
              f"{_pct(b['suricata_fpr_attack_only'])}, Suricata security only {_pct(b['suricata_fpr_security'])}, "
              f"Suricata with engine events {_pct(b['suricata_fpr_with_engine'])}, "
              f"ML with floor {_pct(b['ml_fpr_floor'])}, ML without floor {_pct(b['ml_fpr_no_floor'])}."]
    a = res.get("alerts")
    if a:
        lines += ["", f"Alerts: {a['total']} total, {a['attack']} attack ({a['attack_signatures']} signatures; "
                      f"{a['security']} security, {a['informational']} informational), {a['engine']} engine events."]
    if "split" in res:
        s = res["split"]
        ident = s.get("friday_identical_to_train") or {}
        lines += ["", f"ML scored only on the {s['friday_test_rows']} Friday rows in the week model's test split "
                      f"(of {s['friday_rows_total']} Friday flows); Suricata on the same rows. Same day and tools as "
                      f"training, so the ML side is in-distribution; {_pct(ident.get('share'))} of these rows have a "
                      f"feature vector that also occurs in train."]
    if res.get("sessions"):
        lines += ["", "Attack-level detection per session (any attack alert on attacker traffic):", "",
                  "| Session | Flows | Suricata (any) | Suricata (security only) | Attack alerts | ML flows flagged (floor) "
                  "| Top signatures |", "|---|---|---|---|---|---|---|"]
        for s in res["sessions"]:
            if s["session"] == "benign":
                lines.append(f"| benign #{s['repeat']} | {s['flows']} | {s['attack_alerts']} false attack alerts "
                             f"| {s['security_alerts']} | {s['engine_alerts']} engine | - | - |")
                continue
            sigs = "; ".join(f"{x['signature']} ({x['alerts']})" for x in s["suricata_signatures"][:3]) or "none"
            lines.append(f"| {s['session']} #{s['repeat']} | {s['flows']} | {'yes' if s['suricata_detected'] else 'NO'} "
                         f"| {'yes' if s['suricata_detected_security'] else 'NO'} "
                         f"| {s['suricata_attack_alerts']} | {s['ml_flows_flagged_floor']} | {sigs} |")
    if res.get("missing_alert_files"):
        lines += ["", "No Suricata alerts file for: " + ", ".join(res["missing_alert_files"])]
    for k, msg in (res.get("errors") or {}).items():
        lines += ["", f"FAILED {k}: {msg}"]
    return "\n".join(lines)


NOTES = (
    "Suricata 7 with the ET Open rules, run offline on each pcap with HOME_NET set to the victim network "
    "(lab 10.10.2.0/24, CIC-IDS2017 192.168.10.0/24) and EXTERNAL_NET any. A flow counts as detected by "
    "Suricata when an attack signature (message not starting 'SURICATA ') matched it: same protocol and "
    "5-tuple (either direction; ICMP: same two addresses) with the alert time within 1 s of the flow; each "
    "alert is credited to one flow only (the one containing it, else the nearest). Engine events are "
    "reported separately. Informational signatures (message starting ET INFO, ET POLICY, GPL ICMP_INFO, "
    "GPL INFO or GPL POLICY, or category Not Suspicious Traffic, Misc activity or Potential Corporate Privacy "
    "Violation) are counted in 'all attack signatures' and left out of the '_security' figures. The ML model "
    "detects a flow when its predicted class is not BENIGN (any attack class, so SYN flood and SQL injection, "
    "which are not model classes, can still count); ml_family_recall_* is the stricter same-family measure. "
    "'floor' is the sensor's 0.5 alert floor, 'no_floor' plain argmax. Either = Suricata or ML. "
    "Flow-level recall is unfair to Suricata: many ET rules are thresholded (one alert per source per period) "
    "and fire on one packet of a scan or flood, so a scan of 1,000 flows can raise a handful of alerts that "
    "match only a few flows. 'any_alert' (at least one flow of the label alerted) and the per-session "
    "attack-level table are the fairer view of whether the attack was noticed at all. Friday: ML and Suricata "
    "are scored only on Friday rows of the week model's test split; the ML side is in-distribution (same day "
    "and attack tools as training, and part of the test rows have a feature vector that also occurs in train, "
    "see split.friday_identical_to_train), so its recall is optimistic; the lab flows were never in training. "
    "Lab: the flows are the attacker's flows only (attack sessions) or all flows (benign session), so the "
    "BENIGN rates come from the benign sessions; the repeats of one session are not independent. Suricata sees "
    "payloads, the ML model only flow statistics."
)


def write_report(result: dict, report: Path = REPORT) -> None:
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2) + "\n")


def run_compare(args, exclude: dict[str, str] | None = None) -> int:
    """Write the report and print the tables. A dataset (or lab session) that fails is recorded with its
    error and the rest is still reported; the exit code is 1 if anything failed. `exclude` maps names
    whose Suricata run failed to the error (their old alerts are not used)."""
    exclude = exclude or {}
    out = {"generated": datetime.now(UTC).isoformat(timespec="seconds"), "include_engine": args.include_engine,
           "datasets": {}, "notes": NOTES}
    metas = {p.name.removesuffix(".meta.json"): json.loads(p.read_text()) for p in sorted(args.out_dir.glob("*.meta.json"))}
    out["suricata_runs"] = metas
    if exclude:
        out["suricata_run_errors"] = exclude
    tables, failed = [], bool(exclude)
    if args.lab:
        try:
            out["datasets"]["lab"] = compare_lab(args.lab_data, args.out_dir, args.include_engine, set(exclude))
            failed |= bool(out["datasets"]["lab"]["errors"])
        except Exception as exc:  # noqa: BLE001
            out["datasets"]["lab"] = {"error": str(exc)}
            failed = True
        tables.append(build_tables("Lab (our own attacks, unseen by the model)", out["datasets"]["lab"]))
    if args.friday:
        try:
            if FRIDAY_NAME in exclude:
                raise RuntimeError(f"the Suricata run failed: {exclude[FRIDAY_NAME]}")
            out["datasets"]["friday"] = compare_friday(args.out_dir, args.include_engine)
        except Exception as exc:  # noqa: BLE001
            out["datasets"]["friday"] = {"error": str(exc)}
            failed = True
        tables.append(build_tables("CIC-IDS2017 Friday (week model test split rows)", out["datasets"]["friday"]))
    if not tables:
        print("nothing to compare (--no-lab without --friday)", file=sys.stderr)
        return 2
    write_report(out, args.report)
    print("\n\n".join(tables))
    for k, v in exclude.items():
        print(f"FAILED Suricata run {k}: {v}", file=sys.stderr)
    print(f"\nwrote {args.report}")
    return 1 if failed else 0


def run_all(args) -> int:
    pcaps = sorted(args.pcaps_dir.glob("*.pcap")) if args.pcaps_dir.is_dir() else []
    jobs = [(p, "lab", p.stem) for p in pcaps]
    if args.friday:
        jobs.append((args.friday_pcap, "cic", FRIDAY_NAME))
    if not jobs:
        print(f"no pcaps in {args.pcaps_dir}", file=sys.stderr)
        return 2
    rules: dict | None = None
    failures: dict[str, str] = {}
    for pcap, dataset, name in jobs:
        try:
            if not args.force and meta_path(name, args.out_dir).exists():
                rules = rules or current_rules_info()
            if not args.force and up_to_date(pcap, name, HOME_NETS[dataset], args.out_dir, rules):
                log(f"{name}: alerts already saved for this pcap and rules, skipping (--force to rerun)")
                continue
            run_suricata(pcap, dataset, name, args.out_dir, alert_only=not args.full_eve)
        except Exception as exc:  # noqa: BLE001  one failing pcap must not stop the others
            failures[name] = str(exc)
            log(f"{name} failed: {exc}")
    args.lab = bool(pcaps)
    return run_compare(args, failures)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--out-dir", type=Path, default=OUT_DIR, help="alerts and run metadata folder")
        p.add_argument("--full-eve", action="store_true",
                       help="write Suricata's complete eve.json (flow, http, dns... events) in the container "
                            "instead of the alert-only pipe; needs far more disk")

    def cmp_opts(p):
        p.add_argument("--friday", action="store_true", help="include CIC-IDS2017 Friday")
        p.add_argument("--include-engine", action="store_true",
                       help="count engine events (SURICATA ...) as detections in the headline")
        p.add_argument("--report", type=Path, default=REPORT)
        p.add_argument("--lab-data", type=Path, default=LAB_DATA)

    r = sub.add_parser("run", help="run Suricata on one pcap")
    r.add_argument("pcap", type=Path)
    r.add_argument("--dataset", choices=sorted(HOME_NETS), required=True)
    r.add_argument("--name", help="output name (default: the pcap's file name without .pcap)")
    r.add_argument("--home-net", nargs="+", help="override the dataset's HOME_NET")
    common(r)

    c = sub.add_parser("compare", help="compare saved Suricata alerts with the ML model")
    c.add_argument("--no-lab", dest="lab", action="store_false", help="skip the lab data")
    cmp_opts(c)
    common(c)

    a = sub.add_parser("all", help="run Suricata on every lab pcap (and Friday), then compare")
    a.add_argument("--pcaps-dir", type=Path, default=LAB_PCAPS)
    a.add_argument("--friday-pcap", type=Path, default=FRIDAY_PCAP)
    a.add_argument("--force", action="store_true", help="rerun even when alerts for the same pcap exist")
    cmp_opts(a)
    common(a)

    args = ap.parse_args(argv)
    if args.cmd == "run":
        run_suricata(args.pcap, args.dataset, args.name, args.out_dir, args.home_net, not args.full_eve)
        return 0
    return run_compare(args) if args.cmd == "compare" else run_all(args)


if __name__ == "__main__":
    raise SystemExit(main())
