"""Training data for the cloud model: CIC-IDS2017 flows reduced to what a VPC flow log keeps.

A VPC flow log has no flags, packet sizes or inter-arrival times: per interface, 5-tuple,
direction and 60 s capture window it holds addresses, ports, protocol, packets, bytes, first and
last packet second, and ACCEPT/REJECT. This module rebuilds those records from the labelled CIC
flows (TrafficLabelling CSVs) and feeds them through the SAME `idps.cloud.flowlogs.to_flow_rows`
the collector uses, so training rows and live rows are built by one function.

For every CIC flow:
  1. The flow's time span [start, start + duration] is cut at the wall-clock minute boundaries.
  2. Each direction's packets are split over the windows in proportion to the time overlap, by
     cumulative rounding (round(P * fraction) differences), so the pieces always add up to the
     CIC total. Bytes follow the packets of their piece (cumulative rounding of B * packets share):
     a piece with no packets has no bytes, and the totals are conserved too.
  3. One record per direction (forward = CIC source to destination, backward = reply) and window;
     a direction with no packets in a window has no record (a flow log omits it too). Both
     directions share the piece's first/last second: real logs differ by a second or two per
     direction (`flowlogs._same_window` allows for that).
  4. Records with the same directed 5-tuple and window are ADDED (a flow log has one record per
     5-tuple, direction and window, however many connections reuse the 5-tuple): packets and
     bytes summed, first second the minimum, last second the maximum.
  5. The records go through `to_flow_rows`, which pairs the two directions into one row.

Approximations (state them wherever the results are quoted; docs/cloud.md has the list):
  - Timestamps. Seven of the eight CSVs have only minute resolution (the eighth, second
    resolution): the real start second inside the minute is unknown, so each flow gets a seeded
    uniform offset inside its timestamp's resolution (60 s or 1 s). Without it every flow would
    start at second 0 of its minute and no flow would ever straddle a window boundary.
    Timestamps are as published (CIC local clock); `idps.features.labels.parse_cic_timestamps`
    fixes the 12-hour files (a heuristic).
  - CIC flow timeout. CICFlowMeter ends a flow after 120 s (and at a FIN), so a long connection
    is several CIC flows; a flow log has one record per window. Merging by 5-tuple and window
    (step 4) undoes the cut when the pieces land in the same window and is otherwise exact only
    in the packet counts. CIC's FIN handling also leaves stray one- or two-packet flows with the
    same 5-tuple; they merge into the main flow here, as they would in a flow log.
  - Packets are spread uniformly over the flow's duration (a burst at the start of a long flow
    is smeared over its windows).
  - Bytes. CIC's "Total Length" counts payload plus the padding Ethernet adds to frames under
    60 bytes; a flow log counts the whole IP packet. `ip_bytes` rebuilds it: for TCP 20 bytes of
    IP header + CIC's own "Header Length" (TCP header, options included) + the payload with
    the padding of all-padding directions removed (a RST/ACK is 40 bytes, not 46); UDP and ICMP
    get 28 header bytes per packet, other protocols 20, and no padding rule. Pure ACKs inside a
    data flow keep up to 6 padding bytes each (not recoverable from the aggregates).
  - Direction. CIC calls the first packet's sender "forward"; `to_flow_rows` re-derives the
    initiator from the ports (well-known destination port, else the higher source port), as it
    does for live data, so a row's fwd/bwd can differ from CIC's (CICFlowMeter also swaps the
    two for some flows).
  - Action. Every record is ACCEPT: the CIC traffic was not rejected by a firewall, so the
    `rejected` feature is always 0 in training data (the live lab exporter can produce REJECT
    rows; see docs/cloud.md, "REJECT").
  - Flow log timestamps are whole seconds: a flow shorter than a second inside one window has
    duration 0 and zero rates, exactly like a real record.
  - Labels. CIC's labels are known to contain errors (the CIC-IDS2017 papers by Engelen et al.
    and Lanvin et al. document stray FIN flows, flows labelled attack outside the attack window
    and mislabelled benign traffic); they are used as published.

Label of a row (one unordered endpoint pair, protocol and window): the label with the most
packets over the CIC flows merged into it; on a tie an attack label beats BENIGN, and between
attack labels the alphabetically first wins. Rows that merged more than one label are flagged
(`mixed_label`) and counted in the report.

Memory: one CSV at a time, only the needed columns, IP addresses as categories, and the records
are turned into Python objects in batches of whole windows. The caps of `idps.public.sampling`
(per day and original label, default 250,000 BENIGN and 150,000 attack rows per file) are
applied to rows BEFORE the records are built, so both directions of a kept row stay together.

    python -m idps.cloud.train_data convert --out data/processed/cloud [--max-rows 50000]
"""

from __future__ import annotations

import argparse
import json
import sys
import zlib
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from idps.cloud.flowlogs import (
    AGGREGATION_SECONDS,
    CLOUD_STAT_FEATURES,
    FlowLogRecord,
    to_flow_rows,
)
from idps.features.labels import parse_cic_timestamps
from idps.public.labels import BENIGN, LABEL_TABLE, common_label
from idps.public.sampling import DAY_SECONDS, Caps, select_rows

WINDOW_MS = AGGREGATION_SECONDS * 1000
DEFAULT_SEED = 42
DEFAULT_BATCH_RECORDS = 60_000
ACCOUNT = "000000000000"
INTERFACE = "eni-cic-ids2017"
# Whole-packet overhead the flow log counts and CIC's payload-only length does not.
HEADER_BYTES = {6: 40, 17: 28, 1: 28}
OTHER_HEADER_BYTES = 20

# Output columns of a converted file (the model features, then bookkeeping).
ROW_COLUMNS = [
    "start_ms", "end_ms", "dst_port", "protocol", *CLOUD_STAT_FEATURES,
    "label", "label_any", "mixed_label", "key_id",
]  # fmt: skip

_CIC_NAMES = {
    "Source IP": "src_ip", "Source Port": "src_port", "Destination IP": "dst_ip",
    "Destination Port": "dst_port", "Protocol": "protocol", "Timestamp": "timestamp",
    "Flow Duration": "duration_us", "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets", "Total Length of Fwd Packets": "fwd_payload",
    "Total Length of Bwd Packets": "bwd_payload", "Label": "label_raw",
}  # fmt: skip
FLOW_COLUMNS = list(_CIC_NAMES.values())


def _clean(label: str) -> str:
    return label.replace("\x96", "-").replace("–", "-").strip()


# Every CIC-IDS2017 label (the label column is a fixed-category column: 1.8 million rows would
# otherwise hold 1.8 million separate strings).
ALL_LABELS = sorted({_clean(a) for _, a, _ in LABEL_TABLE if a})


def header_bytes(protocol: np.ndarray) -> np.ndarray:
    """Per-packet IP + transport header bytes for each protocol number."""
    out = np.full(len(protocol), OTHER_HEADER_BYTES, dtype=np.int64)
    for proto, size in HEADER_BYTES.items():
        out[protocol == proto] = size
    return out


MAX_FLOW_MS = 3_600_000  # CIC flows last at most 120 s; a longer duration is corrupt and is capped
ETH_MIN_FRAME = 60  # Ethernet pads frames below 60 bytes (without the FCS)
ETH_IP_HEADERS = 14 + 20  # Ethernet + IPv4 header, no options


def ip_bytes(
    payload: np.ndarray,
    packets: np.ndarray,
    tcp_header_sum: np.ndarray | None,
    protocol: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """What a flow log counts for one direction of a CIC flow: IP-layer bytes.

    CICFlowMeter's "Total Length of ... Packets" is frame length minus its header length, so it
    includes the padding Ethernet adds to a frame shorter than 60 bytes (a TCP RST/ACK of 54
    bytes shows 6 bytes of "payload", a SYN with MSS option 2). The flow log counts the IP
    packet: 20 bytes of IP header + the TCP header + real payload.

    TCP: `tcp_header_sum` is CIC's "Fwd/Bwd Header Length" (the TCP headers of the direction,
    options included); an average outside 20..60 bytes per packet (a CIC glitch) is replaced by
    20. A packet's padding is at most max(0, 26 - header) bytes (60 - 14 - 20 - header), so
    when the direction's whole "payload" is no more than that allowance for every packet it is
    padding and counted as 0 real bytes. A direction that carries real data keeps its payload
    as is: its pure-ACK packets still contribute up to 6 padding bytes each (an over-count of at
    most that, not corrected: the aggregates do not say how many packets were pure ACKs).
    Other protocols: payload + HEADER_BYTES (28 UDP/ICMP, 20 otherwise), no padding rule.

    Returns (bytes, padding_removed); a direction without packets has 0 bytes."""
    n = np.asarray(packets, dtype=np.int64)
    pay = np.rint(np.asarray(payload, dtype=np.float64)).astype(np.int64)
    tcp = np.asarray(protocol) == 6
    if tcp_header_sum is None:
        hdr = 20.0 * n
    else:
        hdr = np.asarray(tcp_header_sum, dtype=np.float64)
        avg = np.divide(hdr, n, out=np.zeros(len(n)), where=n > 0)
        hdr = np.where((avg >= 20) & (avg <= 60), hdr, 20.0 * n)
    avg_hdr = np.divide(hdr, n, out=np.zeros(len(n)), where=n > 0)
    allowance = np.maximum(0.0, ETH_MIN_FRAME - ETH_IP_HEADERS - avg_hdr) * n
    all_padding = tcp & (pay <= np.floor(allowance + 1e-9))
    real = np.where(all_padding, 0, pay)
    other = header_bytes(np.asarray(protocol)) * n
    total = np.where(tcp, real + 20 * n + np.rint(hdr).astype(np.int64), real + other)
    return np.where(n > 0, total, 0), np.where(n > 0, pay - real, 0)


def clean_label(raw: pd.Series) -> pd.Series:
    """The CIC label with the Windows-1252 en dash turned into a plain hyphen and no padding."""
    return (raw.astype(str).str.replace("\x96", "-", regex=False)
            .str.replace("–", "-", regex=False).str.strip())  # fmt: skip


# --- Reading one CSV -----------------------------------------------------------------------


def read_cic_csv(path: str | Path, max_rows: int | None = None) -> tuple[pd.DataFrame, dict]:
    """One TrafficLabelling CSV -> (flows with FLOW_COLUMNS + start_ms + resolution_ms, stats).

    Only the 12 needed columns are read. Rows with a missing label, an unparseable timestamp,
    a non-numeric field or a label that `common_label` does not know are dropped and counted."""
    path = Path(path)
    header = pd.read_csv(path, encoding="latin-1", nrows=0).columns
    raw_name: dict[str, str] = {}
    for c in header:  # the first of two columns with one name ("Fwd Header Length" is listed twice)
        raw_name.setdefault(str(c).strip(), c)
    missing = [c for c in _CIC_NAMES if c not in raw_name]
    if missing:
        raise ValueError(f"{path.name} lacks column(s) {missing}")
    optional = {"Fwd Header Length": "fwd_hdr", "Bwd Header Length": "bwd_hdr"}
    names = {**_CIC_NAMES, **{k: v for k, v in optional.items() if k in raw_name}}
    wanted = [raw_name[c] for c in names]
    raw = pd.read_csv(
        path, encoding="latin-1", nrows=max_rows, usecols=wanted, low_memory=False,
        dtype={raw_name["Source IP"]: "category", raw_name["Destination IP"]: "category"},
    )  # fmt: skip
    renamed = {raw_name[k]: v for k, v in names.items()}
    raw.columns = [renamed[c] for c in raw.columns]
    n_in = len(raw)
    ts = parse_cic_timestamps(raw["timestamp"].astype(str))
    resolution = np.where(raw["timestamp"].astype(str).str.count(":") >= 2, 1000, WINDOW_MS)
    nums = ["src_port", "dst_port", "protocol", "duration_us", "fwd_packets", "bwd_packets",
            "fwd_payload", "bwd_payload"]  # fmt: skip
    for c in [*nums, *(c for c in ("fwd_hdr", "bwd_hdr") if c in raw)]:
        raw[c] = pd.to_numeric(raw[c], errors="coerce")
    raw["label_raw"] = clean_label(raw["label_raw"])
    ok = ts.notna() & raw[nums].notna().all(axis=1) & raw["label_raw"].ne("nan")
    ok &= raw["src_ip"].notna() & raw["dst_ip"].notna()
    known = {x: True for x in raw.loc[ok, "label_raw"].unique() if _knows(x)}
    unknown_label = ok & ~raw["label_raw"].isin(known)
    ok &= ~unknown_label
    bad_ports = ok & ((raw["src_port"] < 0) | (raw["src_port"] > 65535)
                      | (raw["dst_port"] < 0) | (raw["dst_port"] > 65535)
                      | (raw["protocol"] < 0) | (raw["protocol"] > 255))  # fmt: skip
    ok &= ~bad_ports
    negative = ok & ((raw["fwd_packets"] < 0) | (raw["bwd_packets"] < 0)
                     | (raw["fwd_payload"] < 0) | (raw["bwd_payload"] < 0))  # fmt: skip
    ok &= ~negative
    flows = raw[ok].copy()
    del raw
    start_s = ((ts[ok] - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)).to_numpy("int64")
    flows["start_ms"] = start_s * 1000
    flows["resolution_ms"] = resolution[ok.to_numpy()]
    flows["src_ip"] = flows["src_ip"].astype("category")
    flows["dst_ip"] = flows["dst_ip"].astype("category")
    for c in ("src_port", "dst_port", "protocol", "fwd_packets", "bwd_packets"):
        flows[c] = flows[c].astype("int64")
    for c in ("duration_us", "fwd_payload", "bwd_payload", "fwd_hdr", "bwd_hdr"):
        if c in flows:
            flows[c] = flows[c].astype("float64")
    stats = {
        "file": path.name,
        "rows_read": n_in,
        "rows_kept": len(flows),
        "dropped_bad_timestamp_or_field": int((~ok).sum() - unknown_label.sum()
                                              - bad_ports.sum() - negative.sum()),
        "dropped_unknown_label": int(unknown_label.sum()),
        "dropped_bad_port_or_protocol": int(bad_ports.sum()),
        "dropped_negative_counts": int(negative.sum()),
        "negative_duration_set_to_zero": int((flows["duration_us"] < 0).sum()),
        "timestamp_resolution_ms": {str(k): int(v) for k, v in
                                    zip(*np.unique(flows["resolution_ms"], return_counts=True),
                                        strict=True)},
    }  # fmt: skip
    return flows.reset_index(drop=True), stats


def _knows(label: str) -> bool:
    try:
        common_label(label)
    except ValueError:
        return False
    return True


# --- Flows -> window pieces ------------------------------------------------------------------


def _cum(total: np.ndarray, fraction: np.ndarray) -> np.ndarray:
    """round(total * fraction), exact at fraction 0 (0) and 1 (total): cumulative rounding."""
    return np.floor(total * fraction + 0.5).astype(np.int64)


def window_pieces(
    start_ms: np.ndarray,
    duration_ms: np.ndarray,
    fwd_packets: np.ndarray,
    bwd_packets: np.ndarray,
    fwd_bytes: np.ndarray,
    bwd_bytes: np.ndarray,
) -> dict:
    """Cut every flow at the wall-clock minute boundaries.

    Returns arrays with one entry per (flow, window) piece: `flow` (index into the inputs),
    `window` (window start, ms), `lo`/`hi` (the piece's time span, ms), and per direction
    `fwd_pk`, `bwd_pk`, `fwd_by`, `bwd_by`. For every flow the pieces of a quantity add up to its
    input exactly. A direction with no packets in a piece has no bytes in it either (bytes of a
    direction with no packets at all are dropped: a flow log has no record for it)."""
    start = np.asarray(start_ms, dtype=np.int64)
    dur = np.maximum(np.asarray(duration_ms, dtype=np.int64), 0)
    end = start + dur
    first = start // WINDOW_MS
    last = np.where(dur > 0, np.maximum((end - 1) // WINDOW_MS, first), first)
    count = last - first + 1
    flow = np.repeat(np.arange(len(start)), count)
    offset = np.arange(len(flow)) - np.repeat(np.cumsum(count) - count, count)
    window = (first[flow] + offset) * WINDOW_MS
    s, d, e = start[flow], dur[flow], end[flow]
    lo = np.maximum(s, window)
    hi = np.minimum(e, window + WINDOW_MS)
    positive = d > 0
    is_first = offset == 0
    is_last = offset == (count[flow] - 1)
    with np.errstate(divide="ignore", invalid="ignore"):
        f_lo = np.where(is_first | ~positive, 0.0, (lo - s) / d)
        f_hi = np.where(is_last | ~positive, 1.0, (hi - s) / d)
    out = {"flow": flow, "window": window, "lo": lo, "hi": hi}
    for name, pk_in, by_in in (("fwd", fwd_packets, fwd_bytes), ("bwd", bwd_packets, bwd_bytes)):
        pk_tot = np.asarray(pk_in, dtype=np.int64)[flow]
        by_tot = np.asarray(by_in, dtype=np.int64)[flow]
        c_lo, c_hi = _cum(pk_tot, f_lo), _cum(pk_tot, f_hi)
        share_lo = np.divide(c_lo, pk_tot, out=np.zeros(len(flow)), where=pk_tot > 0)
        share_hi = np.divide(c_hi, pk_tot, out=np.zeros(len(flow)), where=pk_tot > 0)
        out[f"{name}_pk"] = c_hi - c_lo
        out[f"{name}_by"] = _cum(by_tot, share_hi) - _cum(by_tot, share_lo)
    return out


# --- Pieces -> aggregated records -> rows ------------------------------------------------------


@dataclass
class ConversionStats:
    flows_in: int = 0
    pieces: int = 0
    keys: int = 0
    keys_kept: int = 0
    mixed_label_keys: int = 0
    rows_out: int = 0
    records: int = 0
    packets_in: int = 0
    packets_in_records: int = 0
    bytes_in: int = 0
    bytes_in_records: int = 0
    flows_spanning_windows: int = 0
    dropped_bytes_without_packets: int = 0
    durations_capped: int = 0
    padding_bytes_removed: int = 0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _label_winners(
    table: pd.DataFrame, kid_count: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Label code per key id by the packet-weighted rule, whether the key had several labels,
    and the label code under the "any attack flow" rule (-1: no attack flow).

    `table` has `kid`, `label_code`, `attack` (1 for an attack label), `weight` (packets)."""
    per = table.groupby(["kid", "label_code", "attack"], sort=False)["weight"].sum().reset_index()
    per = per.sort_values(
        ["kid", "weight", "attack", "label_code"],
        ascending=[True, False, False, True],
        kind="stable",
    )
    winners = per.drop_duplicates("kid")
    codes = np.full(kid_count, -1, dtype=np.int64)
    codes[winners["kid"].to_numpy()] = winners["label_code"].to_numpy()
    n_labels = per.groupby("kid").size()
    mixed = np.zeros(kid_count, dtype=bool)
    mixed[n_labels.index.to_numpy()] = n_labels.to_numpy() > 1
    # The "any attack flow in the row" label: the heaviest attack label, -1 if there is none.
    attacks = per[per["attack"] == 1].drop_duplicates("kid")
    any_codes = np.full(kid_count, -1, dtype=np.int64)
    any_codes[attacks["kid"].to_numpy()] = attacks["label_code"].to_numpy()
    return codes, mixed, any_codes


def convert_flows(
    flows: pd.DataFrame,
    caps: Caps | None = None,
    seed: int = DEFAULT_SEED,
    batch_records: int = DEFAULT_BATCH_RECORDS,
    jitter: bool = True,
    file_key: str = "",
) -> tuple[pd.DataFrame, ConversionStats]:
    """convert_flows_links without the flow links."""
    rows, stats, _ = convert_flows_links(flows, caps, seed, batch_records, jitter, file_key)
    return rows, stats


def convert_flows_links(
    flows: pd.DataFrame,
    caps: Caps | None = None,
    seed: int = DEFAULT_SEED,
    batch_records: int = DEFAULT_BATCH_RECORDS,
    jitter: bool = True,
    file_key: str = "",
) -> tuple[pd.DataFrame, ConversionStats, pd.DataFrame]:
    """Canonical CIC flows (see read_cic_csv; `src_ip`/`dst_ip` may be plain strings) -> rows with
    ROW_COLUMNS, built by to_flow_rows from the flow-log records of the flows.

    `caps`: per (UTC day, original label) cap on rows (None: keep all). `jitter`: add the seeded
    uniform start offset inside each timestamp's resolution (see the module docstring).

    Also returns `links` (key_id, flow_id): which CIC flows went into which row, so that a split
    can be audited for flows that straddle a cut. `key_id` (a column of the rows) and `flow_id`
    carry a 31-bit hash of `file_key` in their high bits, so they are unique across files."""
    stats = ConversionStats(flows_in=len(flows))
    if flows.empty:
        return pd.DataFrame(columns=ROW_COLUMNS), stats, pd.DataFrame(columns=["key_id", "flow_id"])
    prefix = (zlib.crc32(file_key.encode()) & 0x7FFFFFFF) << 32
    flows = flows.reset_index(drop=True)
    start = flows["start_ms"].to_numpy("int64").copy()
    if jitter:
        rng = np.random.default_rng([seed, zlib.crc32(file_key.encode())])
        start += (rng.random(len(flows)) * flows["resolution_ms"].to_numpy()).astype("int64")
    dur_ms = np.rint(np.maximum(flows["duration_us"].to_numpy(), 0) / 1000.0)
    stats.durations_capped = int((dur_ms > MAX_FLOW_MS).sum())
    dur_ms = np.minimum(dur_ms, MAX_FLOW_MS).astype("int64")
    proto = flows["protocol"].to_numpy("int64")
    fp, bp = flows["fwd_packets"].to_numpy("int64"), flows["bwd_packets"].to_numpy("int64")
    fhdr = flows["fwd_hdr"].to_numpy() if "fwd_hdr" in flows else None
    bhdr = flows["bwd_hdr"].to_numpy() if "bwd_hdr" in flows else None
    fb, f_pad = ip_bytes(flows["fwd_payload"].to_numpy(), fp, fhdr, proto)
    bb, b_pad = ip_bytes(flows["bwd_payload"].to_numpy(), bp, bhdr, proto)
    stats.padding_bytes_removed = int(f_pad.sum() + b_pad.sum())
    stats.dropped_bytes_without_packets = int(
        (np.rint(flows["fwd_payload"].to_numpy())[fp == 0]).sum()
        + (np.rint(flows["bwd_payload"].to_numpy())[bp == 0]).sum()
    )
    stats.packets_in, stats.bytes_in = int(fp.sum() + bp.sum()), int(fb.sum() + bb.sum())
    pieces = window_pieces(start, dur_ms, fp, bp, fb, bb)
    stats.pieces = len(pieces["flow"])
    stats.flows_spanning_windows = int(
        (np.bincount(pieces["flow"], minlength=len(flows)) > 1).sum()
    )

    ip_names = pd.Index(
        pd.concat([flows["src_ip"].astype(str), flows["dst_ip"].astype(str)]).unique()
    )
    src_code = ip_names.get_indexer(flows["src_ip"].astype(str)).astype("int64")
    dst_code = ip_names.get_indexer(flows["dst_ip"].astype(str)).astype("int64")
    sport = flows["src_port"].to_numpy("int64")
    dport = flows["dst_port"].to_numpy("int64")
    label_names = pd.Index(sorted(flows["label_raw"].unique()))
    label_code = label_names.get_indexer(flows["label_raw"]).astype("int64")
    label_attack = np.array([common_label(x) != BENIGN for x in label_names], dtype=np.int64)

    flow = pieces["flow"]
    window = pieces["window"]
    # Two direction records per piece (forward, backward) with their endpoints.
    frames = []
    for name, a_ip, a_port, b_ip, b_port in (
        ("fwd", src_code, sport, dst_code, dport),
        ("bwd", dst_code, dport, src_code, sport),
    ):
        pk, by = pieces[f"{name}_pk"], pieces[f"{name}_by"]
        keep = pk > 0
        frames.append(pd.DataFrame({
            "src": a_ip[flow][keep], "sport": a_port[flow][keep],
            "dst": b_ip[flow][keep], "dport": b_port[flow][keep],
            "proto": proto[flow][keep], "window": window[keep],
            "pk": pk[keep], "by": by[keep],
            "s": pieces["lo"][keep] // 1000,
            "e": np.minimum((pieces["hi"][keep]) // 1000, window[keep] // 1000
                            + AGGREGATION_SECONDS - 1),
            "label": label_code[flow][keep], "flow": flow[keep],
        }))  # fmt: skip
    rec = pd.concat(frames, ignore_index=True)
    del frames, pieces
    rec["e"] = np.maximum(rec["e"], rec["s"])
    # Unordered key: the two endpoints (ip code, port) in a fixed order, protocol and window.
    e1, e2 = rec["src"] * 65536 + rec["sport"], rec["dst"] * 65536 + rec["dport"]
    rec["ep_a"], rec["ep_b"] = np.minimum(e1, e2), np.maximum(e1, e2)
    del e1, e2
    rec["kid"] = rec.groupby(["ep_a", "ep_b", "proto", "window"], sort=False).ngroup()
    kid_count = int(rec["kid"].max()) + 1 if len(rec) else 0
    stats.keys = kid_count
    codes, mixed, any_codes = _label_winners(
        pd.DataFrame({"kid": rec["kid"], "label_code": rec["label"],
                      "attack": label_attack[rec["label"].to_numpy()], "weight": rec["pk"]}),
        kid_count)  # fmt: skip
    window_of_kid = np.zeros(kid_count, dtype=np.int64)
    window_of_kid[rec["kid"].to_numpy()] = rec["window"].to_numpy()

    keep_kid = np.ones(kid_count, dtype=bool)
    if caps is not None:
        names = label_names.to_numpy(dtype=object)[codes]
        cap_of = {x: caps.for_class(common_label(x)) for x in set(names)}
        keep_kid = select_rows(
            window_of_kid // 1000 // DAY_SECONDS,
            names,
            window_of_kid // 1000,
            cap_of.__getitem__,
            seed,
        )
    stats.keys_kept = int(keep_kid.sum())
    stats.mixed_label_keys = int(mixed[keep_kid].sum())
    rec = rec[keep_kid[rec["kid"].to_numpy()]]
    links = rec[["kid", "flow"]].drop_duplicates()
    links = pd.DataFrame({"key_id": prefix | links["kid"].to_numpy().astype("int64"),
                          "flow_id": prefix | links["flow"].to_numpy().astype("int64")})  # fmt: skip
    # One record per directed 5-tuple and window: add the pieces.
    rec = (rec.groupby(["kid", "src", "sport"], sort=False)
           .agg(dst=("dst", "first"), dport=("dport", "first"), proto=("proto", "first"),
                window=("window", "first"), pk=("pk", "sum"), by=("by", "sum"),
                s=("s", "min"), e=("e", "max"))
           .reset_index().sort_values(["window", "kid"], kind="stable").reset_index(drop=True))  # fmt: skip
    stats.records = len(rec)
    stats.packets_in_records = int(rec["pk"].sum())
    stats.bytes_in_records = int(rec["by"].sum())

    ip_list = ip_names.to_numpy(dtype=object)
    label_list = label_names.to_numpy(dtype=object)
    out_parts = []
    for lo, hi in _batches(rec["window"].to_numpy(), batch_records):
        part = rec.iloc[lo:hi]
        records, kid_of = _records(part, ip_list)
        rows = to_flow_rows(records)
        out_parts.append(_rows_frame(rows, kid_of, codes, mixed, any_codes, label_list, prefix))
    out = (
        pd.concat(out_parts, ignore_index=True) if out_parts else pd.DataFrame(columns=ROW_COLUMNS)
    )
    stats.rows_out = len(out)
    return out, stats, links


def _batches(windows: np.ndarray, size: int) -> Iterator[tuple[int, int]]:
    """Index ranges of about `size` records that never cut a window in two."""
    n, lo = len(windows), 0
    while lo < n:
        hi = min(lo + size, n)
        if hi < n:
            hi = int(np.searchsorted(windows, windows[hi - 1], side="right"))
        yield lo, hi
        lo = hi


def _records(part: pd.DataFrame, ip_list: np.ndarray) -> tuple[list[FlowLogRecord], dict]:
    """FlowLogRecords of a batch, and {(proto, endpoint, endpoint, window second): kid}."""
    records, kid_of = [], {}
    cols = {
        c: part[c].to_numpy()
        for c in ("kid", "src", "sport", "dst", "dport", "proto", "window", "pk", "by", "s", "e")
    }
    for i in range(len(part)):
        src, dst = str(ip_list[cols["src"][i]]), str(ip_list[cols["dst"][i]])
        sport, dport = int(cols["sport"][i]), int(cols["dport"][i])
        records.append(
            FlowLogRecord(
                account_id=ACCOUNT,
                interface_id=INTERFACE,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=int(cols["proto"][i]),
                packets=int(cols["pk"][i]),
                byte_count=int(cols["by"][i]),
                start=int(cols["s"][i]),
                end=int(cols["e"][i]),
                action="ACCEPT",
            )
        )
        ends = sorted([(src, sport), (dst, dport)])
        kid_of[(int(cols["proto"][i]), *ends[0], *ends[1], int(cols["window"][i]))] = int(
            cols["kid"][i])  # fmt: skip
    return records, kid_of


def _rows_frame(
    rows: list[dict],
    kid_of: dict,
    codes: np.ndarray,
    mixed: np.ndarray,
    any_codes: np.ndarray,
    label_list: np.ndarray,
    prefix: int = 0,
) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=ROW_COLUMNS)
    kids = np.empty(len(rows), dtype=np.int64)
    for i, r in enumerate(rows):
        ends = sorted([(r["src_ip"], r["src_port"]), (r["dst_ip"], r["dst_port"])])
        window = (r["start_ms"] // 1000 // AGGREGATION_SECONDS) * AGGREGATION_SECONDS * 1000
        kids[i] = kid_of[(r["protocol"], *ends[0], *ends[1], window)]
    df = pd.DataFrame(rows)
    out = pd.DataFrame({"start_ms": df["start_ms"].astype("int64"),
                        "end_ms": df["end_ms"].astype("int64"),
                        "dst_port": df["dst_port"].astype("int32"),
                        "protocol": df["protocol"].astype("int16")})  # fmt: skip
    for c in CLOUD_STAT_FEATURES:
        out[c] = df[c].astype("float32")
    out["label"] = pd.Categorical(label_list[codes[kids]], categories=ALL_LABELS)
    any_label = np.where(any_codes[kids] >= 0, label_list[np.maximum(any_codes[kids], 0)], BENIGN)
    out["label_any"] = pd.Categorical(any_label, categories=ALL_LABELS)
    out["mixed_label"] = mixed[kids]
    out["key_id"] = prefix | kids
    return out


# --- Whole files -----------------------------------------------------------------------------


def convert_file(
    path: str | Path,
    caps: Caps | None = None,
    seed: int = DEFAULT_SEED,
    max_rows: int | None = None,
    batch_records: int = DEFAULT_BATCH_RECORDS,
    links_out: str | Path | None = None,
) -> tuple[pd.DataFrame, dict]:
    """One CSV -> (rows, report); `links_out`: where to write the (key_id, flow_id) links."""
    flows, read_stats = read_cic_csv(path, max_rows)
    rows, stats, links = convert_flows_links(
        flows, caps, seed, batch_records, file_key=Path(path).name
    )
    if links_out is not None:
        Path(links_out).parent.mkdir(parents=True, exist_ok=True)
        links.to_parquet(links_out, index=False)
    del flows
    report = {**read_stats, "conversion": stats.as_dict(),
              "label_counts_rows": {str(k): int(v) for k, v in
                                    rows["label"].astype(str).value_counts().items()}}  # fmt: skip
    return rows, report


def convert_directory(
    data_dir: str | Path,
    out_dir: str | Path,
    caps: Caps | None = None,
    seed: int = DEFAULT_SEED,
    max_rows: int | None = None,
    files: list[str] | None = None,
) -> dict:
    """Convert every CSV (or the named ones), one at a time, to `<out_dir>/<csv stem>.parquet`
    and write `<out_dir>/conversion_report.json`."""
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted(data_dir.glob("*.csv"))
    if files:
        paths = [p for p in paths if any(f in p.name for f in files)]
    if not paths:
        raise ValueError(f"no CIC-IDS2017 CSV files found in {data_dir}")
    reports = []
    for path in paths:
        rows, report = convert_file(
            path, caps, seed, max_rows, links_out=out_dir / "links" / f"{path.stem}.parquet"
        )
        target = out_dir / f"{path.stem}.parquet"
        rows.to_parquet(target, index=False)
        report["output"] = str(target)
        reports.append(report)
        print(f"{path.name}: {report['rows_kept']} flows -> {len(rows)} rows", file=sys.stderr)
        del rows
    labels: Counter = Counter()
    for r in reports:
        labels.update(r["label_counts_rows"])
    summary = {
        "dataset": "CIC-IDS2017 TrafficLabelling, reduced to VPC flow-log fields",
        "caps": caps.as_dict() if caps else None, "seed": seed, "max_rows_per_file": max_rows,
        "byte_accounting": "TCP: IP header 20 + CIC TCP header length + payload, Ethernet "
        "padding removed (ip_bytes); other protocols: payload + header_bytes",
        "header_bytes_non_tcp": {"17": 28, "1": 28, "other": OTHER_HEADER_BYTES},
        "files": reports, "label_counts_rows": dict(sorted(labels.items())),
    }  # fmt: skip
    (out_dir / "conversion_report.json").write_text(json.dumps(summary, indent=2))
    return summary


def load_rows(out_dir: str | Path) -> pd.DataFrame:
    """All converted parquet files of `out_dir` as one frame (files in name order)."""
    paths = sorted(Path(out_dir).glob("*.parquet"))
    if not paths:
        raise ValueError(
            f"no converted files in {out_dir}; run: python -m idps.cloud.train_data convert"
        )
    frames = []
    for p in paths:
        frame = pd.read_parquet(p)
        for col in ("label", "label_any"):
            frame[col] = pd.Categorical(frame[col].astype(str), categories=ALL_LABELS)
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def load_links(out_dir: str | Path) -> pd.DataFrame:
    """The (key_id, flow_id) links of every converted file."""
    paths = sorted((Path(out_dir) / "links").glob("*.parquet"))
    if not paths:
        raise ValueError(
            f"no links in {out_dir}/links; run: python -m idps.cloud.train_data convert"
        )
    return pd.concat([pd.read_parquet(p) for p in paths], ignore_index=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m idps.cloud.train_data", description=__doc__.split("\n")[0]
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert", help="CIC-IDS2017 CSVs -> flow-log rows, one file at a time")
    c.add_argument("--data-dir", default="data/raw/cic-ids2017/TrafficLabelling")
    c.add_argument("--out", default="data/processed/cloud")
    c.add_argument(
        "--max-rows", type=int, default=None, help="read only the first N flows of each CSV"
    )
    c.add_argument("--files", nargs="*", help="only CSVs whose name contains one of these")
    c.add_argument("--cap-benign", type=int, default=Caps().benign)
    c.add_argument("--cap-attack", type=int, default=Caps().attack)
    c.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = ap.parse_args(argv)
    summary = convert_directory(
        args.data_dir,
        args.out,
        Caps(args.cap_benign, args.cap_attack),
        args.seed,
        args.max_rows,
        args.files,
    )
    print(json.dumps(summary["label_counts_rows"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
