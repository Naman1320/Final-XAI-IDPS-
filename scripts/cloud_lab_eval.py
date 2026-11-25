"""Lab check of the cloud model: what would the cloud path catch of the lab's own attacks?

    python scripts/cloud_lab_eval.py                         # all sessions, both ACCEPT/REJECT modes
    python scripts/cloud_lab_eval.py --sessions portscan syn_flood --modes sg
    python scripts/cloud_lab_eval.py --model models/cloud_xgboost_noport.joblib --out reports/x.json

Offline and re-runnable, no lab, no AWS. For every recorded lab session (data/raw/lab_pcaps/
<session>_<n>.pcap, made by scripts/lab_unseen.py --keep-pcaps):
  1. `python -m idps.cloud export offline` turns the pcap into 60 s flow-log window files (the
     live exporter's own code), once per security-group mode:
       sg    the emulated security group of infra/ (victim TCP ports 22 and 80 open; everything
             else toward the victim is REJECT, and the victim's reply to a rejected packet is
             dropped). This is what the live cloud path sees.
       open  every victim TCP port and ICMP accepted (UDP stays closed; the lab sessions have
             no UDP to the victim), so every record is ACCEPT, like the training data.
  2. the records go through the collector's own parser and to_flow_rows, and the cloud bundle
     scores the rows (idps.soc_client.score_frame, the collector's function).
  3. rows are labelled with the lab's ground truth, the same rule as scripts/lab_unseen.py:
     only rows to or from the lab's client address (10.10.1.10) are used; in an attack session
     they have the attack's kind, in the benign session they are BENIGN. The records are paired
     file by file, as the collector pairs per S3 object.
Per attack kind it reports the rows, the share of rows alerted (any attack class with confidence
>= 0.5, the collector's default), the share in the right family, the predicted classes, the share
of REJECT rows, the first alert's delay after the session's first packet (window close; S3
delivery adds minutes, not simulated) and whether the attacker would reach the collector's block
threshold (IDPS_CLOUD_MIN_FLOWS = 5 alerted rows in one window). The lab model's result on the same
sessions is read from reports/lab_unseen.json for comparison (different features: the lab model sees
every packet, the cloud model only the flow-log counters).

Weak spots, stated: the pcaps are two short repeats per attack; the SYN flood and the portscan
are single bursts; the web attack session has 4 flows. Rows are labelled by address and session,
not by packet: the few legitimate packets of an attack session (for example the SSH handshake of a
login that succeeded) carry the attack's label.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np

from idps.cloud import flowlogs
from idps.cloud.collector import load_cloud_bundle
from idps.soc_client import score_frame

ATTACKER = "10.10.1.10"
ALERT_FLOOR = 0.5  # the collector's default min_alert_confidence
MIN_FLOWS = 5  # the collector's default IDPS_CLOUD_MIN_FLOWS
PCAP_DIR = ROOT / "data" / "raw" / "lab_pcaps"
LAB_REPORT = ROOT / "reports" / "lab_unseen.json"
OUT = ROOT / "reports" / "cloud_lab_eval.json"
MODEL = ROOT / "models" / "cloud_xgboost.joblib"
BENIGN = "BENIGN"
# session -> (lab truth label in reports/lab_unseen.json, families that count as the right one)
SESSIONS = {
    "portscan": ("PortScan", {"PortScan"}),
    "ssh_bruteforce": ("SSH-Patator", {"BruteForce"}),
    "syn_flood": ("DoS SYN flood", {"DoS"}),
    "slow_dos": ("DoS slowloris", {"DoS"}),
    "web_sqli": ("Web Attack - Sql Injection", {"WebAttack"}),
    "benign": (BENIGN, {BENIGN}),
}
FAMILY = {
    "BENIGN": "BENIGN", "PortScan": "PortScan", "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce", "DDoS": "DoS", "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS", "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack", "Web Attack - Sql Injection": "WebAttack",
}  # fmt: skip
MODES = ("sg", "open")


def family_of(label: str) -> str:
    return FAMILY.get(label, "Other")


def export_pcap(pcap: Path, out_dir: Path, mode: str) -> list[Path]:
    """Run the exporter's offline mode (a subprocess: exactly the documented command)."""
    if out_dir.exists():  # never mix in window files of an earlier run
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    cmd = [sys.executable, "-m", "idps.cloud", "export", "offline", "--pcap", str(pcap),
           "--out", str(out_dir)]  # fmt: skip
    if mode == "open":
        cmd += ["--allow-ports", " ".join(map(str, range(1, 65536))), "--allow-icmp"]
    else:  # the security group of infra/, stated here so the environment cannot change it
        cmd += ["--allow-ports", "22 80", "--allow-udp-ports", ""]
    done = subprocess.run(cmd, check=False, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    if done.returncode != 0:
        raise RuntimeError(
            f"exporter failed for {pcap.name} ({mode}): {done.stderr.strip()[-500:]}"
        )
    return sorted(out_dir.glob("*.flows"))


def read_rows(files: list[Path]) -> tuple[list[dict], dict]:
    """Rows of the window files, paired file by file: the collector pairs the two directions
    within one S3 object (`Collector._process`), and a window file is one object."""
    stats = flowlogs.ParseStats()
    rows: list[dict] = []
    for f in files:
        with open(f, encoding="ascii") as fh:
            rows.extend(flowlogs.to_flow_rows(flowlogs.parse_lines(fh, stats)))
    return rows, stats.as_dict()


def evaluate_session(bundle, rows: list[dict], families: set[str]) -> dict:
    """Score the rows of one session. Only rows to or from the attacker address are used (in a
    benign session that is the benign client, in an attack session the attacker); `families` are
    the predicted families that count as the right one for this session's kind."""
    mine = [r for r in rows if ATTACKER in (r["src_ip"], r["dst_ip"])]
    dropped = len(rows) - len(mine)
    out: dict = {"rows": len(mine), "rows_not_attacker": dropped}
    if not mine:
        return out
    frame = flowlogs.rows_to_frame(mine)
    preds = score_frame(bundle, frame)
    labels = [p.label for p in preds]
    conf = np.array([p.confidence for p in preds])
    alert = np.array([lab != BENIGN for lab in labels]) & (conf >= ALERT_FLOOR)
    right = np.array([family_of(lab) in families for lab in labels]) & alert
    rejected = frame["rejected"].to_numpy() > 0
    out.update({
        "rejected_share": float(rejected.mean()),
        "predicted": {k: int(v) for k, v in Counter(labels).most_common()},
        "alerted": int(alert.sum()),
        "alerted_share": float(alert.mean()),
        "right_family_share": float(right.mean()),
        "alerted_rejected_share": float(alert[rejected].mean()) if rejected.any() else None,
        "alerted_accepted_share": float(alert[~rejected].mean()) if (~rejected).any() else None,
        "feature_medians": {c: float(frame[c].median()) for c in flowlogs.CLOUD_STAT_FEATURES},
    })  # fmt: skip
    per_window: dict[int, int] = defaultdict(int)
    first_start = int(min(r["start_ms"] for r in mine)) // 1000
    for r, a in zip(mine, alert, strict=True):
        if a:
            per_window[r["start_ms"] // 1000 // 60 * 60] += 1
    out["alerted_windows"] = len(per_window)
    out["max_alerted_rows_in_a_window"] = max(per_window.values(), default=0)
    out["would_reach_block_threshold"] = out["max_alerted_rows_in_a_window"] >= MIN_FLOWS
    out["first_alert_delay_s"] = (
        (min(per_window) + 60 - first_start) if per_window else None
    )  # window close minus the session's first packet
    return out


def lab_result(label: str, report: dict) -> dict:
    """The lab model's (reports/lab_unseen.json, with the 0.5 alert floor) numbers for a label."""
    per = report["with_floor"]["per_label"][label]
    benign_share = next((t["share"] for t in per["top_predicted"] if t["class"] == BENIGN), 0.0)
    return {
        "flows": per["flows"],
        "alerted_share": 1.0 - benign_share,
        "right_family_share": per["family_recall"],
        "top_predicted": per["top_predicted"][:3],
    }


def load_bundle(path: str, public_key: str | None, allow_experiment: bool):
    """The collector's loader; with `allow_experiment` an experiment bundle (its extractor name
    makes load_cloud_bundle refuse it) is read after the same sha256 check."""
    if not allow_experiment:
        return load_cloud_bundle(path, public_key)
    import io

    import joblib

    from idps.cloud.train_model import EXPERIMENT_EXTRACTOR
    from idps.detect.bundle import _read_verified

    bundle = joblib.load(io.BytesIO(_read_verified(Path(path), public_key)))
    if bundle.extraction_meta.get("extractor") != EXPERIMENT_EXTRACTOR:
        raise ValueError(f"{path} is not an experiment bundle; load it without --allow-experiment")
    return bundle


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default=str(MODEL))
    ap.add_argument("--pcaps", default=str(PCAP_DIR))
    ap.add_argument("--sessions", nargs="*", default=list(SESSIONS), choices=list(SESSIONS))
    ap.add_argument("--repeats", nargs="*", type=int, default=[1, 2])
    ap.add_argument("--modes", nargs="*", default=list(MODES), choices=MODES)
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--work", help="keep the window files here (default: a temporary folder)")
    ap.add_argument(
        "--allow-experiment",
        action="store_true",
        help="load an experiment bundle (models/experiments; the collector refuses these)",
    )
    ap.add_argument("--public-key", help="verify the bundle's .sig with this key first")
    args = ap.parse_args(argv)

    bundle = load_bundle(args.model, args.public_key, args.allow_experiment)
    lab = json.loads(LAB_REPORT.read_text()) if LAB_REPORT.exists() else None
    result: dict = {"model": args.model, "version": getattr(bundle, "version", None),
                    "alert_floor": ALERT_FLOOR, "min_flows": MIN_FLOWS, "attacker": ATTACKER,
                    "modes": {}}  # fmt: skip
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(args.work) if args.work else Path(tmp)
        for mode in args.modes:
            per_kind: dict = {}
            for kind in args.sessions:
                truth, families = SESSIONS[kind]
                rows, parse = [], {"records": 0, "malformed": 0}
                for n in args.repeats:
                    pcap = Path(args.pcaps) / f"{kind}_{n}.pcap"
                    if not pcap.exists():
                        print(f"skip {pcap}: not found", file=sys.stderr)
                        continue
                    files = export_pcap(pcap, work / mode / f"{kind}_{n}", mode)
                    session_rows, stats = read_rows(files)
                    parse["records"] += stats["records"]
                    parse["malformed"] += stats["malformed"]
                    rows.append((n, session_rows))
                if not rows:
                    continue
                # Each repeat is scored on its own (own windows), then summed.
                repeats = {str(n): evaluate_session(bundle, r, families) for n, r in rows}
                total_rows = sum(v["rows"] for v in repeats.values())
                alerted = sum(v.get("alerted", 0) for v in repeats.values())
                right = sum(v.get("right_family_share", 0) * v["rows"] for v in repeats.values())
                per_kind[kind] = {
                    "truth": truth, "rows": total_rows, "sessions": len(repeats),
                    "rows_per_session": {n: v["rows"] for n, v in repeats.items()},
                    "alerted_share": alerted / total_rows if total_rows else None,
                    "right_family_share": right / total_rows if total_rows else None,
                    "records_parsed": parse["records"], "records_malformed": parse["malformed"],
                    "repeats": repeats,
                    "lab_model": lab_result(truth, lab) if lab else None,
                }  # fmt: skip
                a, r = per_kind[kind]["alerted_share"], per_kind[kind]["right_family_share"]
                print(f"[{mode}] {kind:15s} sessions={len(repeats)} rows={total_rows:6d} alerted={a:.3f} "
                      f"right_family={r:.3f}", file=sys.stderr)  # fmt: skip
            result["modes"][mode] = per_kind
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
