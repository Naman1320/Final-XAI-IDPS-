"""Byte parity check: CIC rows converted by idps.cloud.train_data against the lab's own flow logs.

    python scripts/cloud_byte_parity.py            # needs data/processed/cloud and data/raw/lab_pcaps

For a TCP port scan (rows of one packet each way), SSH brute force and benign traffic it compares
the byte counts the model sees: the CIC rows as converted now ("after"), as the first converter
version made them ("before": CIC payload + a flat 40 bytes per TCP packet) and the rows the exporter's
offline mode makes from the lab pcaps (all ports accepted). Writes reports/cloud_byte_parity.json.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_lab_eval as ev
import pandas as pd

from idps.cloud import flowlogs
from idps.cloud.train_data import load_rows

CIC = ROOT / "data" / "raw" / "cic-ids2017" / "TrafficLabelling"
OUT = ROOT / "reports" / "cloud_byte_parity.json"


def pairs(frame: pd.DataFrame, top: int = 6) -> list[dict]:
    c = Counter(zip(frame["fwd_bytes"].astype(int), frame["bwd_bytes"].astype(int), strict=True))
    return [
        {"fwd_bytes": a, "bwd_bytes": b, "share": n / len(frame)}
        for (a, b), n in c.most_common(top)
    ]


def medians(frame: pd.DataFrame) -> dict:
    return {c: float(frame[c].median()) for c in ("fwd_pkt_len_mean", "bwd_pkt_len_mean")}


def lab_rows(kind: str, work: Path) -> pd.DataFrame:
    frames = []
    for n in (1, 2):
        files = ev.export_pcap(
            ROOT / "data/raw/lab_pcaps" / f"{kind}_{n}.pcap", work / f"{kind}{n}", "open"
        )
        rows, _ = ev.read_rows(files)
        frames.append(
            flowlogs.rows_to_frame([r for r in rows if ev.ATTACKER in (r["src_ip"], r["dst_ip"])])
        )
    return pd.concat(frames, ignore_index=True)


def cic_before(csv: str, label: str, packets: tuple[int, int] | None) -> pd.DataFrame:
    """The first converter version's bytes: CIC payload + 40 per TCP packet (flows, not rows)."""
    raw = pd.read_csv(
        CIC / csv,
        encoding="latin-1",
        usecols=lambda c: (
            c.strip()
            in {
                "Label",
                "Protocol",
                "Total Fwd Packets",
                "Total Backward Packets",
                "Total Length of Fwd Packets",
                "Total Length of Bwd Packets",
            }
        ),
    )
    raw.columns = [c.strip() for c in raw.columns]
    raw = raw[(raw["Label"] == label) & (raw["Protocol"] == 6)]
    if packets:
        raw = raw[
            (raw["Total Fwd Packets"] == packets[0]) & (raw["Total Backward Packets"] == packets[1])
        ]
    f, b = raw["Total Fwd Packets"], raw["Total Backward Packets"]
    return pd.DataFrame(
        {
            "fwd_bytes": raw["Total Length of Fwd Packets"] + 40 * f,
            "bwd_bytes": raw["Total Length of Bwd Packets"] + 40 * b,
            "fwd_pkt_len_mean": (raw["Total Length of Fwd Packets"] + 40 * f) / f.clip(lower=1),
            "bwd_pkt_len_mean": (raw["Total Length of Bwd Packets"] + 40 * b) / b.clip(lower=1),
        }
    )


def main() -> int:
    cic = load_rows(ROOT / "data" / "processed" / "cloud")
    cic["label"] = cic["label"].astype(str)
    result: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        scan_lab = lab_rows("portscan", work)
        ssh_lab = lab_rows("ssh_bruteforce", work)
        ben_lab = lab_rows("benign", work)
    scan_after = cic[
        (cic.label == "PortScan")
        & (cic.protocol == 6)
        & (cic.fwd_packets == 1)
        & (cic.bwd_packets == 1)
    ]
    scan_before = cic_before(
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan", (1, 1)
    )
    scan_lab = scan_lab[(scan_lab.fwd_packets == 1) & (scan_lab.bwd_packets == 1)]
    result["portscan_1_packet_each_way"] = {
        "cic_before": {"n": len(scan_before), "top_byte_pairs": pairs(scan_before)},
        "cic_after": {"n": len(scan_after), "top_byte_pairs": pairs(scan_after)},
        "lab_exporter_open_mode": {"n": len(scan_lab), "top_byte_pairs": pairs(scan_lab)},
    }
    ssh_before = cic_before("Tuesday-WorkingHours.pcap_ISCX.csv", "SSH-Patator", None)
    ssh_after = cic[(cic.label == "SSH-Patator")]
    result["ssh_bruteforce_medians"] = {
        "cic_before_flows": medians(ssh_before),
        "cic_after_rows": medians(ssh_after),
        "lab_exporter_rows": medians(ssh_lab),
    }
    ben_after = cic[(cic.label == "BENIGN") & (cic.protocol == 6)]
    result["benign_tcp_medians"] = {
        "cic_after_rows": medians(ben_after),
        "lab_exporter_rows": medians(ben_lab),
    }
    OUT.write_text(json.dumps(result, indent=2, default=float))
    print(json.dumps(result, indent=1, default=float))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
