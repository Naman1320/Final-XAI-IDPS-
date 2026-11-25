"""Unseen-data test: score the full-week model on labelled flows from our own lab traffic.

    python scripts/lab_unseen.py                          # every attack + 10 min benign, 2 repeats
    python scripts/lab_unseen.py --sessions portscan benign --repeats 1 --benign-minutes 2 \\
        --out data/processed/lab_smoke.parquet          # a trial run: its own files
    python scripts/lab_unseen.py --sessions slow_dos --append   # add or replace sessions in the data
    python scripts/lab_unseen.py --score-only             # re-score data/processed/lab_labelled.parquet
    python scripts/lab_unseen.py --keep-pcaps             # also keep each session's pcap (for scripts/suricata_compare.py)

Offline only (no live sensor, no SOC). Each session records the attacker's traffic with tcpdump in the
sensor, runs one attack (or benign.sh) in the attacker container, extracts the flows from the pcap
inside the sensor with the same NFStream features the live sensor uses, and copies them to the host.
Ground truth comes from the attacker address: in an attack session every flow to or from
10.10.1.10 gets the attack's label and the rest are dropped; in the benign session every flow is
BENIGN. The labelled flows are saved to data/processed/lab_labelled.parquet and scored on the host
with models/week_xgboost.joblib (its .sha256 is verified on load), twice: with the sensor's
0.5 alert floor (a prediction below it counts as BENIGN, as deployed) and without it (plain argmax,
how the CIC-IDS2017 test split in reports/week_xgboost.json was scored; that one is used in the
comparison). Writes reports/lab_unseen.json and prints markdown tables.

A session whose attack did not exit as expected is an error and its flows are not used. The data file is
written at the end through a temporary file; the previous file is kept as <file>.bak.

Needs the lab up and lab/.env with LAB_VICTIM_PASSWORD. The host needs the idps package, pandas and
numpy (the project venv). See docs/live.md, "Unseen lab data".
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_benign as bb  # noqa: E402
import bench_sensor as bs  # noqa: E402
import lab_attacks as la  # noqa: E402

ROOT = bs.ROOT
DATA = ROOT / "data" / "processed" / "lab_labelled.parquet"
REPORT = ROOT / "reports" / "lab_unseen.json"
MODEL = ROOT / "models" / "week_xgboost.joblib"
MODEL_REPORT = ROOT / "reports" / "week_xgboost.json"
ATTACKER = la.ATTACKER
ALERT_FLOOR = la.ALERT_FLOOR
PCAP = "/tmp/lab_unseen.pcap"
PCAP_DIR = ROOT / "data" / "raw" / "lab_pcaps"  # --keep-pcaps default (git-ignored with data/raw/*)
FLOWS = "/tmp/lab_unseen.parquet"
TCPDUMP_DRAIN = 3          # seconds to let the last packets reach tcpdump before stopping it
TCPDUMP_STOP_WAIT = 15     # seconds for SIGINT to stop tcpdump before SIGKILL
TCPDUMP_KILL_WAIT = 5      # seconds to wait after SIGKILL
BENIGN_OVERRUN = 300       # seconds benign.sh may run past the time asked for
MIN_BENIGN_SECONDS = 60
BENIGN = "BENIGN"
TOP_PREDICTED = 5

# Session name -> truth label. Labels that are not model classes stay as they are (the model can
# only be right at the family level for them).
TRUTH = {
    "portscan": "PortScan",
    "ssh_bruteforce": "SSH-Patator",
    "syn_flood": "DoS SYN flood",
    "slow_dos": "DoS slowloris",
    "web_sqli": "Web Attack - Sql Injection",
    "benign": BENIGN,
}
# Exit codes of the attack command that mean it ran as intended. dos.sh syn is `timeout 20 hping3`,
# which exits 124 when the 20 s are up (the normal end); hydra exits 0 when it finds the password, which
# ssh_bruteforce.sh always appends; nmap, slowhttptest and sqlmap exit 0, and webattack.sh exits 1 when
# DVWA setup or login fails. Anything else, or the time limit, means the traffic is not the attack.
OK_EXIT = {"portscan": (0,), "ssh_bruteforce": (0,), "syn_flood": (0, 124), "slow_dos": (0,),
           "web_sqli": (0,)}
SQLMAP_MARKER = re.compile(r"^webattack: sqlmap-start (\d+)\s*$", re.M)
SESSIONS = list(la.ATTACKS) + ["benign"]
assert set(TRUTH) == set(SESSIONS)

# Class (model class or lab truth label) -> family. Anything else is "Other".
FAMILY = {
    BENIGN: "BENIGN",
    "PortScan": "PortScan",
    "SSH-Patator": "BruteForce", "FTP-Patator": "BruteForce",
    "DDoS": "DoS", "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS", "DoS SYN flood": "DoS",
    "Web Attack - Brute Force": "WebAttack", "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
}
OTHER = "Other"  # Bot, Infiltration, Heartbleed: predicted by the model, no lab attack of that kind


def log(msg: str) -> None:
    print(f"[unseen {datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)




# ---- pure parts (unit-tested) -----------------------------------------------------------------

def family_of(label: str) -> str:
    return FAMILY.get(label, OTHER)


def label_session(df: pd.DataFrame, session: str, repeat: int, attacker: str = ATTACKER,
                  not_before_ms: float | None = None) -> pd.DataFrame:
    """Labelled copy of one session's flows. Attack session: only flows with the attacker as an
    endpoint (and, with `not_before_ms`, that started no earlier), with the attack's truth label.
    Benign session: every flow, BENIGN."""
    if session not in TRUTH:
        raise ValueError(f"unknown session {session!r}")
    label = TRUTH[session]
    out = df if session == "benign" else df[(df["src_ip"] == attacker) | (df["dst_ip"] == attacker)]
    if not_before_ms is not None:
        out = out[out["start_ms"] >= not_before_ms]
    out = out.copy().reset_index(drop=True)
    out.insert(0, "session", session)
    out.insert(1, "repeat", repeat)
    out.insert(2, "label", label)
    out.insert(3, "family", family_of(label))
    return out


def sqlmap_start_ms(text: str | None) -> int | None:
    """Epoch ms from which flows count as sqlmap's: the second after webattack.sh's marker line, so
    the setup and login requests before the marker (and in its own second) are left out. None if the
    marker is missing (an attacker image built before the marker was added)."""
    m = SQLMAP_MARKER.search(text or "")
    return (int(m[1]) + 1) * 1000 if m else None


def session_errors(session: str, info: dict) -> list[str]:
    """Why a session's flows must not be used (empty = fine): the attack did not exit as expected or
    hit its time limit; benign.sh failed; no sqlmap marker."""
    code = info.get("exit")
    if session == "benign":
        return [] if code in (0, None) else [f"benign.sh {'hit its time limit' if code == 'timeout' else f'exited with status {code}'}"]
    if code == "timeout":
        return ["the attack did not finish within its time limit"]
    if code not in OK_EXIT[session]:
        return [f"the attack exited with status {code} (expected {' or '.join(map(str, OK_EXIT[session]))})"]
    if session == "web_sqli" and info.get("sqlmap_start_ms") is None:
        return ["no sqlmap-start marker in the attack output; rebuild the attacker image (lab/attacks/webattack.sh)"]
    return []


def apply_floor(classes, confidence, floor: float = ALERT_FLOOR) -> list[str]:
    """What the live sensor would report: an attack prediction below the floor counts as BENIGN."""
    return [BENIGN if (c != BENIGN and p < floor) else str(c) for c, p in zip(classes, confidence, strict=True)]


def merge_frames(existing: pd.DataFrame | None, new: pd.DataFrame) -> pd.DataFrame:
    """`new` plus the rows of `existing` for sessions/repeats that `new` does not contain."""
    if existing is None or not len(existing):
        return new.reset_index(drop=True)
    keys = set(zip(new["session"], new["repeat"], strict=True))
    keep = [(s, r) not in keys for s, r in zip(existing["session"], existing["repeat"], strict=True)]
    return pd.concat([existing[keep], new], ignore_index=True)


def _f1(tp: int, fp: int, fn: int) -> float:
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def per_label_metrics(truth: list[str], pred: list[str], model_classes) -> dict:
    """One entry per truth label: flows, exact-class recall (None when the label is not a model
    class), family recall and the most common predictions."""
    model_classes = set(model_classes)
    out = {}
    for label in sorted(set(truth)):
        preds = [p for t, p in zip(truth, pred, strict=True) if t == label]
        n = len(preds)
        fam = family_of(label)
        top = Counter(preds).most_common(TOP_PREDICTED)
        out[label] = {
            "family": fam,
            "flows": n,
            "is_model_class": label in model_classes,
            "exact_recall": _rate(sum(p == label for p in preds), n) if label in model_classes else None,
            "family_recall": _rate(sum(family_of(p) == fam for p in preds), n),
            "top_predicted": [{"class": c, "flows": k, "share": round(k / n, 4)} for c, k in top],
        }
    return out


def benign_false_positives(truth: list[str], pred: list[str]) -> dict:
    """Share of BENIGN flows predicted as an attack, and which classes."""
    preds = [p for t, p in zip(truth, pred, strict=True) if t == BENIGN]
    fp = [p for p in preds if p != BENIGN]
    return {"flows": len(preds), "false_positives": len(fp), "false_positive_rate": _rate(len(fp), len(preds)),
            "by_class": dict(Counter(fp).most_common())}


def family_scores(truth_family: list[str], pred_family: list[str]) -> dict:
    """Precision, recall and F1 per family, and macro-F1 over the families that occur in the truth."""
    fams = sorted(set(truth_family))
    per = {}
    for f in fams:
        tp = sum(t == f and p == f for t, p in zip(truth_family, pred_family, strict=True))
        fp = sum(t != f and p == f for t, p in zip(truth_family, pred_family, strict=True))
        fn = sum(t == f and p != f for t, p in zip(truth_family, pred_family, strict=True))
        per[f] = {"support": tp + fn, "precision": _rate(tp, tp + fp), "recall": _rate(tp, tp + fn),
                  "f1": round(_f1(tp, fp, fn), 4)}
    macro = round(sum(v["f1"] for v in per.values()) / len(per), 4) if per else None
    return {"macro_f1": macro, "per_family": per}


def exact_class_scores(truth: list[str], pred: list[str], model_classes) -> dict:
    """Per-class precision/recall/F1 for the lab labels that are model classes, over the flows
    whose truth is a model class (flows with a non-class truth, such as SQL injection, are left
    out so that they do not count against a class they cannot belong to)."""
    model_classes = set(model_classes)
    pairs = [(t, p) for t, p in zip(truth, pred, strict=True) if t in model_classes]
    out = {}
    for c in sorted({t for t, _ in pairs}):
        tp = sum(t == c and p == c for t, p in pairs)
        fp = sum(t != c and p == c for t, p in pairs)
        fn = sum(t == c and p != c for t, p in pairs)
        out[c] = {"support": tp + fn, "precision": _rate(tp, tp + fp), "recall": _rate(tp, tp + fn),
                  "f1": round(_f1(tp, fp, fn), 4)}
    return out


def confusion(truth: list[str], pred: list[str]) -> dict:
    """Truth label (rows) by predicted class (columns) over all flows."""
    rows, cols = sorted(set(truth)), sorted(set(pred))
    count = Counter(zip(truth, pred, strict=True))
    return {"truth": rows, "predicted": cols, "matrix": [[count.get((t, p), 0) for p in cols] for t in rows]}


def compare(lab: dict, test_per_class: dict) -> list[dict]:
    """Rows for the classes present in both: lab F1/recall next to the test-split ones."""
    rows = []
    for c, v in lab.items():
        t = test_per_class.get(c)
        if t is None:
            continue
        rows.append({"class": c, "lab_flows": v["support"], "lab_f1": v["f1"], "lab_recall": v["recall"],
                     "test_support": t.get("support"), "test_f1": round(t["f1"], 4),
                     "test_recall": round(t["recall"], 4),
                     "f1_change": round(v["f1"] - t["f1"], 4)})
    return rows


def score_variant(df: pd.DataFrame, pred: list[str], model_classes, test_per_class: dict) -> dict:
    """All metrics for one set of predictions."""
    truth = df["label"].tolist()
    exact = exact_class_scores(truth, pred, model_classes)
    return {
        "per_label": per_label_metrics(truth, pred, model_classes),
        "benign": benign_false_positives(truth, pred),
        "family": family_scores(df["family"].tolist(), [family_of(p) for p in pred]),
        "exact_class": exact,
        "comparison": compare(exact, test_per_class),
        "confusion": confusion(truth, pred),
    }


def score_frame(df: pd.DataFrame, pred_floor: list[str], pred_plain: list[str], model_classes,
                test_per_class: dict) -> dict:
    """The report body: `with_floor` (as deployed) and `no_floor` (plain argmax, like the test split)."""
    return {
        "flows": len(df),
        "flows_by_session": {f"{s}#{r}": int(n) for (s, r), n in df.groupby(["session", "repeat"]).size().items()},
        "with_floor": score_variant(df, pred_floor, model_classes, test_per_class),
        "no_floor": score_variant(df, pred_plain, model_classes, test_per_class),
    }


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.1%}"


def confusion_table(c: dict) -> str:
    lines = ["| Truth \\ predicted | " + " | ".join(c["predicted"]) + " |",
             "|---|" + "---|" * len(c["predicted"])]
    for t, row in zip(c["truth"], c["matrix"], strict=True):
        lines.append(f"| {t} | " + " | ".join(str(n) if n else "." for n in row) + " |")
    return "\n".join(lines)


def build_table(result: dict, test_macro_f1: float | None = None, test_benign_fpr: float | None = None) -> str:
    w, n = result["with_floor"], result["no_floor"]
    lines = ["Per truth label (the first two recall columns with the 0.5 floor as deployed, the next "
             "two without it; top predictions with the floor)", "",
             "| Truth label | Flows | Exact recall (floor) | Exact recall (no floor) | Family recall (floor) "
             "| Family recall (no floor) | Top predicted (floor) |", "|---|---|---|---|---|---|---|"]
    for label, v in w["per_label"].items():
        nf = n["per_label"][label]
        top = ", ".join(f"{t['class']} {t['share']:.0%}" for t in v["top_predicted"][:3])
        ex = (lambda x: _pct(x["exact_recall"]) if x["is_model_class"] else "not a class")
        lines.append(f"| {label} | {v['flows']} | {ex(v)} | {ex(nf)} | {_pct(v['family_recall'])} "
                     f"| {_pct(nf['family_recall'])} | {top} |")
    for name, blk in (("with floor", w), ("no floor", n)):
        b = blk["benign"]
        lines += ["", f"BENIGN false-positive rate ({name}): {_pct(b['false_positive_rate'])} "
                      f"({b['false_positives']} of {b['flows']} flows)"
                      + (f"; test split {_pct(test_benign_fpr)}" if name == "no floor" and test_benign_fpr is not None else ""),
                  f"Family-level macro-F1 ({name}): {blk['family']['macro_f1']}"
                  + (f"; test split (14 classes) {test_macro_f1:.4f}" if name == "no floor" and test_macro_f1 is not None else "")]
    lines += ["", "| Family (floor) | Flows | Precision | Recall | F1 |", "|---|---|---|---|---|"]
    for f, v in w["family"]["per_family"].items():
        lines.append(f"| {f} | {v['support']} | {_pct(v['precision'])} | {_pct(v['recall'])} | {v['f1']} |")
    lines += ["", "Lab against test split, lab scored without the alert floor (plain argmax, as the test "
                  "split was scored):", "",
              "| Class | Lab flows | Lab F1 | Lab recall | Test-split F1 | Test-split recall | Test support |",
              "|---|---|---|---|---|---|---|"]
    for r in n["comparison"]:
        lines.append(f"| {r['class']} | {r['lab_flows']} | {r['lab_f1']:.3f} | {r['lab_recall']:.3f} "
                     f"| {r['test_f1']:.3f} | {r['test_recall']:.3f} | {r['test_support']} |")
    lines += ["", "Recall is the fair column: F1 depends on the class mix (the lab has far fewer benign flows "
                  "per attack flow than the test split).",
              "", "Confusion, truth label by predicted class, all lab flows (with the floor):", "",
              confusion_table(w["confusion"])]
    return "\n".join(lines)


NOTES = (
    "Lab flows are labelled by address: in an attack session every flow to or from 10.10.1.10 gets the "
    "attack's label and other flows are dropped; in the benign session every flow is BENIGN. A session whose "
    "attack did not exit as expected is an error and contributes no flows. For web_sqli, flows that started "
    "before sqlmap (DVWA setup and login) are dropped using a marker webattack.sh prints. 'DoS SYN flood' and "
    "'Web Attack - Sql Injection' are not model classes, so only their family recall is meaningful. "
    "with_floor counts a prediction below the 0.5 alert floor as BENIGN, as on the live sensor; no_floor is "
    "plain argmax, which is how the test-split scores in reports/week_xgboost.json were computed, so "
    "the comparison uses no_floor. exact_class F1 uses only flows whose truth label is a model class and "
    "depends on the class mix; recall is the fairer comparison. Family-level macro-F1 is over the families "
    "present in the lab data (BENIGN, PortScan, BruteForce, DoS, WebAttack); the test-split macro-F1 is over "
    "14 classes, so the two are not the same measure. The lab has one client and a few services, a "
    "round-trip time of about 0.1 ms and flows cut by NFStream at the end of each recording, so timing "
    "features differ from CIC-IDS2017's; the repeats of one session are not independent. Lab traffic never "
    "entered training, but the lab's attack tools are not the 2017 tools either."
)


# ---- scoring on the host ----------------------------------------------------------------------

def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)


def score(data: Path = DATA, model_path: Path = MODEL, model_report: Path = MODEL_REPORT,
          floor: float = ALERT_FLOOR) -> dict:
    from idps.detect.bundle import load_bundle, read_digest
    from idps.features import read_features

    bundle = load_bundle(model_path)  # refuses a model that does not match its .sha256
    digest = read_digest(model_path)
    df, meta = read_features(data)
    proba = bundle.predict_proba(bundle.select(df, meta).astype(float))
    classes = list(bundle.label_encoder.classes_)
    plain = [classes[i] for i in proba.argmax(1)]
    pred_floor = apply_floor(plain, proba.max(1), floor)
    test = json.loads(model_report.read_text())["metrics"]["test"]
    result = score_frame(df, pred_floor, plain, classes, test["per_class"])
    result.update({
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "model": _rel(model_path),
        "model_sha256": digest,
        "alert_floor": floor,
        "model_classes": classes,
        "data": _rel(data),
        "test_split": {"macro_f1": test.get("macro_f1"),
                       "benign_false_positive_rate": test.get("benign_false_positive_rate"),
                       "scored_without_floor": True, "report": _rel(model_report)},
        "notes": NOTES,
    })
    return result


# ---- lab actions ------------------------------------------------------------------------------

class SessionError(RuntimeError):
    """A session that must not contribute flows; `info` is what was recorded about it."""

    def __init__(self, msg: str, info: dict | None = None) -> None:
        super().__init__(msg)
        self.info = info or {}


def stop_tcpdump(pcap: str = PCAP, wait: float | None = None) -> bool:
    """SIGINT the tcpdump writing `pcap` (so it flushes), SIGKILL it if it is still there after `wait`
    seconds. True when it is gone."""
    pattern = la.tcpdump_pattern(pcap)
    for sig, secs in (("INT", TCPDUMP_STOP_WAIT if wait is None else wait), ("KILL", TCPDUMP_KILL_WAIT)):
        la.sh("sensor", f"pkill -{sig} -f '{pattern}'", timeout=30)
        end = time.monotonic() + secs
        while True:
            if not la.tcpdump_running(pcap):
                return True
            if time.monotonic() > end:
                break
            time.sleep(1)
    return False


def run_traffic(session: str, benign_seconds: int, password: str) -> dict:
    """Run the session's traffic in the attacker container; returns what happened (exit code, seconds,
    sqlmap marker or benign activity summary)."""
    info: dict = {}
    t0 = time.monotonic()
    if session == "benign":
        bb.setup_victim_files()
        traffic = bb.Traffic(benign_seconds, password)
        try:
            try:
                info["exit"] = traffic.wait(timeout=benign_seconds + BENIGN_OVERRUN)
            except la.subprocess.TimeoutExpired:
                info["exit"] = "timeout"
        finally:
            traffic.stop()
            bb.cleanup_victim_files()
        activity = bb.activity_summary(traffic.lines)
        info["activities"] = activity["counts"]
        info["activity_problems"] = activity["problems"]
        info["activity_problem_count"] = activity["problem_count"]
        info["traffic_checks"] = bb.check_traffic(
            rc=info["exit"] if isinstance(info["exit"], int) else None, stopped=info["exit"] == "timeout",
            activity_total=activity["total"], elapsed_s=time.monotonic() - t0, requested_s=benign_seconds)
    else:
        cmd, max_s, _family = la.ATTACKS[session]
        try:
            r = la.sh("attacker", cmd, timeout=max_s,
                      secrets={"LAB_VICTIM_PASSWORD": password} if session == "ssh_bruteforce" else None)
            info["exit"] = r.returncode
            if session == "web_sqli":
                info["sqlmap_start_ms"] = sqlmap_start_ms(r.stdout)
        except la.subprocess.TimeoutExpired:
            info["exit"] = "timeout"
    info["seconds"] = round(time.monotonic() - t0, 1)
    return info


def session_warnings(info: dict) -> list[str]:
    out = list(info.get("traffic_checks") or [])
    if info.get("activity_problem_count"):
        out.append(f"{info['activity_problem_count']} problem line(s) in the benign activity "
                   f"(first: {(info.get('activity_problems') or ['?'])[0]})")
    return out


def pcap_name(session: str, repeat: int) -> str:
    return f"{session}_{repeat}.pcap"


def keep_pcap(session: str, repeat: int, dest_dir: Path) -> Path:
    """Copy the session's pcap out of the sensor to dest_dir/<session>_<repeat>.pcap.part and return
    that temporary path; the caller renames it with `commit_pcap` once the session succeeded."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    part = dest_dir / (pcap_name(session, repeat) + ".part")
    try:
        # Absolute: `docker compose` runs from lab/, so a relative path would land under lab/.
        bs.compose("cp", f"sensor:{PCAP}", str(part.resolve()), timeout=900)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return part


def commit_pcap(part: Path) -> Path:
    final = part.with_name(part.name.removesuffix(".part"))
    os.replace(part, final)
    return final


def run_session(session: str, repeat: int, benign_seconds: int, password: str,
                keep_pcaps: Path | None = None) -> tuple[pd.DataFrame, dict, dict]:
    """Record, run, extract and copy one session. Returns (labelled flows, extraction meta, info);
    raises SessionError (with the info) when the session must not be used. With `keep_pcaps`, the
    pcap is copied out of the sensor before the next session removes it, under a temporary name, and
    renamed to <keep_pcaps>/<session>_<repeat>.pcap only after extraction and labelling succeeded."""
    log(f"{session} #{repeat}")
    info: dict = {"session": session, "repeat": repeat}
    la.sh("sensor", f"pkill -INT -f '{la.tcpdump_pattern(PCAP)}'; rm -f {PCAP} {FLOWS}")
    la.kill_attack()
    stopped = False
    try:
        la.start_tcpdump(PCAP)
        info.update(run_traffic(session, benign_seconds, password))
        time.sleep(TCPDUMP_DRAIN)
    except Exception as exc:
        raise SessionError(repr(exc), info) from exc
    finally:
        stopped = stop_tcpdump(PCAP)
        la.kill_attack()
    if not stopped:
        raise SessionError("tcpdump is still running after SIGKILL; not extracting", info)
    log(f"  traffic done after {info['seconds']} s (exit {info['exit']})")
    errors = session_errors(session, info)
    if errors:
        raise SessionError("; ".join(errors), info)
    part = None
    if keep_pcaps is not None:
        try:
            part = keep_pcap(session, repeat, keep_pcaps)
        except Exception as exc:  # noqa: BLE001
            raise SessionError(f"could not copy the pcap out of the sensor: {exc}", info) from exc
    try:
        labelled, meta = _extract_and_label(session, repeat, info)
        if part is not None:  # only a session that fully succeeded keeps its pcap
            info["pcap"] = _rel(commit_pcap(part))
            log(f"  pcap kept: {info['pcap']}")
    except BaseException:
        if part is not None:
            part.unlink(missing_ok=True)
        raise
    return labelled, meta, info


def _extract_and_label(session: str, repeat: int, info: dict) -> tuple[pd.DataFrame, dict]:
    from idps.features import read_features

    r = la.sh("sensor", la.extract_cmd(PCAP, FLOWS), timeout=900)
    if r.returncode != 0:
        raise SessionError(f"flow extraction failed: {(r.stderr or r.stdout)[-500:]}", info)
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "flows.parquet"
        bs.compose("cp", f"sensor:{FLOWS}", str(local), timeout=300)
        flows, meta = read_features(local)
    start = info.get("sqlmap_start_ms")
    labelled = label_session(flows, session, repeat, not_before_ms=start)
    info.update(flows_total=len(flows), flows_labelled=len(labelled))
    if start is not None:
        info["flows_before_sqlmap"] = len(label_session(flows, session, repeat)) - len(labelled)
    if not len(labelled):
        raise SessionError("no flows to label in the recording", info)
    warns = session_warnings(info)
    if warns:
        info["warnings"] = warns
    log(f"  {len(flows)} flows extracted, {len(labelled)} labelled {TRUTH[session]}")
    return labelled, meta


def write_atomic(df: pd.DataFrame, meta: dict, out: Path) -> None:
    """Write through a temporary file in the same folder and rename it over `out`; an existing `out`
    is first copied to `<out>.bak`."""
    from idps.features import write_features

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    write_features(df, tmp, meta)
    if out.exists():
        shutil.copy2(out, out.with_name(out.name + ".bak"))
    os.replace(tmp, out)


def collect(sessions: list[str], repeats: int, benign_minutes: float, password: str, out: Path,
            append: bool = False, keep_pcaps: Path | None = None) -> dict:
    """Run every session `repeats` times. The data file is written once, at the end (also after a
    Ctrl-C), from the sessions that succeeded: merged into the existing file with `append`, else
    replacing it (the old file is kept as .bak). Nothing is written if no session succeeded."""
    from idps.features import read_features

    frames: list[pd.DataFrame] = []
    meta: dict = {}
    runs: list[dict] = []
    try:
        for rep in range(1, repeats + 1):
            for name in sessions:
                try:
                    extra = {"keep_pcaps": keep_pcaps} if keep_pcaps is not None else {}
                    df, m, info = run_session(name, rep, int(benign_minutes * 60), password, **extra)
                    if meta and m != meta:
                        raise SessionError("extraction metadata differs between sessions", info)
                    meta = meta or m
                    frames.append(df)
                    for w in info.get("warnings", []):
                        log(f"  warning: {w}")
                except Exception as exc:  # noqa: BLE001  record it and go on with the next session
                    log(f"  {name} #{rep} failed: {exc}")
                    info = {**getattr(exc, "info", {}), "session": name, "repeat": rep, "error": str(exc)}
                runs.append(info)
    finally:
        written = False
        if frames:
            new = pd.concat(frames, ignore_index=True)
            existing = None
            if append and out.exists():
                existing, old_meta = read_features(out)
                if old_meta != meta:
                    side = out.with_name(out.name + ".new")
                    write_atomic(new, meta, side)
                    raise RuntimeError(f"{out} was made with different extraction settings; the new "
                                       f"sessions are saved in {side}")
            write_atomic(merge_frames(existing, new), meta, out)
            written = True
    return {"runs": runs, "written": written}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sessions", nargs="+", choices=SESSIONS, default=SESSIONS)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--benign-minutes", type=float, default=10, help="at least 1")
    ap.add_argument("--score-only", action="store_true",
                    help="skip the lab and re-score the existing labelled file")
    ap.add_argument("--append", action="store_true",
                    help="merge the new sessions into the existing labelled file (same session and "
                         "repeat are replaced) instead of replacing it")
    ap.add_argument("--keep-pcaps", nargs="?", type=Path, const=PCAP_DIR, default=None, metavar="DIR",
                    help="copy each session's pcap to DIR/<session>_<repeat>.pcap (default DIR "
                         "data/raw/lab_pcaps); the pcaps and flows then come from the same recording")
    ap.add_argument("--out", type=Path, default=DATA,
                    help="labelled flows file (default data/processed/lab_labelled.parquet)")
    ap.add_argument("--report", type=Path, default=None,
                    help="report file (default reports/lab_unseen.json, or reports/<out name>.json "
                         "when --out is not the default)")
    args = ap.parse_args(argv)
    if args.repeats < 1 or args.benign_minutes * 60 < MIN_BENIGN_SECONDS:
        print(f"--repeats must be at least 1 and --benign-minutes at least {MIN_BENIGN_SECONDS // 60}",
              file=sys.stderr)
        return 2
    report = args.report or (REPORT if args.out == DATA else ROOT / "reports" / f"{args.out.stem}.json")

    runs: list[dict] = []
    if not args.score_only:
        env_file = bs.LAB / ".env"
        env = bb.parse_env(env_file.read_text()) if env_file.exists() else {}
        if not env.get("LAB_VICTIM_PASSWORD"):
            print("LAB_VICTIM_PASSWORD missing in lab/.env", file=sys.stderr)
            return 2
        if bs.sensor_running():
            print("a sensor loop (idps.live) is running in the lab; stop it first", file=sys.stderr)
            return 2
        done = collect(args.sessions, args.repeats, args.benign_minutes, env["LAB_VICTIM_PASSWORD"],
                       args.out, args.append, args.keep_pcaps)
        runs = done["runs"]
        if not done["written"]:
            print("no session succeeded; nothing was written or scored:", file=sys.stderr)
            for r in runs:
                print(f"  {r['session']} #{r['repeat']}: {r.get('error')}", file=sys.stderr)
            return 1
    if not args.out.exists():
        print(f"{args.out} does not exist; nothing to score", file=sys.stderr)
        return 1

    result = score(args.out)
    result["runs"] = runs
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2) + "\n")
    ts = result["test_split"]
    print(build_table(result, ts["macro_f1"], ts["benign_false_positive_rate"]))
    failed = [r for r in runs if "error" in r]
    for r in failed:
        print(f"FAILED {r['session']} #{r['repeat']}: {r['error']}", file=sys.stderr)
    print(f"\nmodel sha256 {result['model_sha256']}\nwrote {report}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
