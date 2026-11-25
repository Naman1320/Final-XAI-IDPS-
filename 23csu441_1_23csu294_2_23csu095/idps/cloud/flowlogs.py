"""Parse AWS VPC Flow Logs (default version-2 format) into NetFlow-style flow rows.

A version-2 record has 14 space-separated fields:

    version account-id interface-id srcaddr dstaddr srcport dstport protocol
    packets bytes start end action log-status

Flow logs are aggregated per capture window (we ask for 60 s) and carry no flags, no packet
sizes and no inter-arrival times, so the rows built here are much coarser than the lab's
CICFlowMeter-style features (idps.features). A model for the cloud is trained separately,
on NetFlow datasets such as NF-UNSW-NB15; see docs/cloud.md.
"""

from __future__ import annotations

import gzip
import io
import logging
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from idps.respond.policy import normalise_ip

if TYPE_CHECKING:  # pandas is imported only when a frame is built: the exporter does not need it
    import pandas as pd

log = logging.getLogger("idps.cloud.flowlogs")

V2_FIELDS = (
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log-status",
)
NO_DATA_STATUSES = frozenset({"NODATA", "SKIPDATA"})
ACTIONS = frozenset({"ACCEPT", "REJECT"})
# A flow-log file is a few MB at most; this stops a corrupt or hostile .gz from filling memory.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
# Sanity bounds for the integers in a record: a hostile or corrupt object must not be able to
# overflow the float/int64 conversions later (one bad object would otherwise pin the checkpoint).
MAX_EPOCH_SECONDS = 4_102_444_800  # 2100-01-01, the SOC's own limit
MAX_PACKETS = 2**40
MAX_BYTE_COUNT = 2**50
MAX_ERROR_SAMPLES = 10


class FlowLogError(ValueError):
    """A flow-log file could not be read at all (corrupt gzip, too large)."""


# --- Feature layout -------------------------------------------------------------------------

# Same identity columns as the lab's idps.features.ID_COLUMNS.
CLOUD_ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms", "end_ms"]
# fwd = initiator -> responder (NetFlow IN_*), bwd = responder -> initiator (NetFlow OUT_*).
CLOUD_STAT_FEATURES = [
    "duration_ms", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "bytes_per_s", "packets_per_s", "down_up_ratio",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean", "rejected",
]
# Every column rows_to_frame() returns, in this exact order. Do not reorder: saved models rely on it.
CLOUD_FEATURE_COLUMNS: list[str] = CLOUD_ID_COLUMNS + CLOUD_STAT_FEATURES
# What a cloud model should be trained on.
CLOUD_MODEL_FEATURES: list[str] = ["dst_port", "protocol"] + CLOUD_STAT_FEATURES
CLOUD_EXTRACTOR = "vpc-flow-logs-v2"
AGGREGATION_SECONDS = 60  # max_aggregation_interval set in infra/


def cloud_extraction_meta() -> dict:
    """Stored in a cloud model bundle; checked when the collector loads it."""
    return {
        "extractor": CLOUD_EXTRACTOR,
        "idle_timeout": 0,
        "active_timeout": AGGREGATION_SECONDS,
        "feature_columns": CLOUD_FEATURE_COLUMNS,
    }


# --- Records --------------------------------------------------------------------------------

@dataclass(frozen=True)
class FlowLogRecord:
    account_id: str
    interface_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    byte_count: int
    start: int  # seconds since the epoch
    end: int
    action: str  # ACCEPT or REJECT
    log_status: str = "OK"


@dataclass
class ParseStats:
    lines: int = 0
    records: int = 0
    header: int = 0
    blank: int = 0
    no_data: int = 0  # NODATA / SKIPDATA
    malformed: int = 0
    errors: list[str] = field(default_factory=list)  # first few, for the log

    def add_error(self, lineno: int, message: str) -> None:
        self.malformed += 1
        if len(self.errors) < MAX_ERROR_SAMPLES:
            self.errors.append(f"line {lineno}: {message}")

    def as_dict(self) -> dict:
        return {
            "lines": self.lines, "records": self.records, "header": self.header,
            "blank": self.blank, "no_data": self.no_data, "malformed": self.malformed,
        }


def _uint(text: str, name: str, *, maximum: int | None = None, dash_is_zero: bool = False) -> int:
    if dash_is_zero and text == "-":
        return 0
    if not (text.isascii() and text.isdigit()) or len(text) > 20:
        raise ValueError(f"{name} is not a non-negative integer: {text[:24]!r}")
    value = int(text)
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} out of range: {value}")
    return value


def _build(parts: list[str]) -> FlowLogRecord:
    if parts[0] != "2":
        raise ValueError(f"unsupported flow log version {parts[0]!r} (only the default v2 format)")
    if parts[13] != "OK":
        raise ValueError(f"unknown log-status {parts[13]!r}")
    if parts[12] not in ACTIONS:
        raise ValueError(f"unknown action {parts[12]!r}")
    src = normalise_ip(parts[3])
    dst = normalise_ip(parts[4])
    if src is None or dst is None:
        raise ValueError(f"bad address: {parts[3]!r} -> {parts[4]!r}")
    return FlowLogRecord(
        account_id=parts[1],
        interface_id=parts[2],
        src_ip=str(src),
        dst_ip=str(dst),
        src_port=_uint(parts[5], "srcport", maximum=65535, dash_is_zero=True),
        dst_port=_uint(parts[6], "dstport", maximum=65535, dash_is_zero=True),
        protocol=_uint(parts[7], "protocol", maximum=255),
        packets=_uint(parts[8], "packets", maximum=MAX_PACKETS),
        byte_count=_uint(parts[9], "bytes", maximum=MAX_BYTE_COUNT),
        start=_uint(parts[10], "start", maximum=MAX_EPOCH_SECONDS),
        end=_uint(parts[11], "end", maximum=MAX_EPOCH_SECONDS),
        action=parts[12],
        log_status=parts[13],
    )


def parse_lines(lines: Iterable[str], stats: ParseStats | None = None) -> Iterator[FlowLogRecord]:
    """Yield records from flow-log lines. Header lines and NODATA/SKIPDATA records are skipped;
    a malformed line is counted in `stats` and skipped, never raised."""
    stats = stats if stats is not None else ParseStats()
    for lineno, raw in enumerate(lines, start=1):
        stats.lines += 1
        parts = raw.split()
        if not parts:
            stats.blank += 1
            continue
        if parts[0] == "version":
            stats.header += 1
            continue
        if len(parts) != len(V2_FIELDS):
            stats.add_error(lineno, f"expected {len(V2_FIELDS)} fields, got {len(parts)}")
            continue
        if parts[13] in NO_DATA_STATUSES:
            stats.no_data += 1
            continue
        try:
            record = _build(parts)
        except ValueError as exc:
            stats.add_error(lineno, str(exc))
            continue
        stats.records += 1
        yield record


# --- Reading files and S3 objects -------------------------------------------------------------

def _iter_text_lines(fileobj: BinaryIO, max_bytes: int) -> Iterator[str]:
    """Lines of a plain or gzip file, decompressing in chunks and refusing more than max_bytes."""
    head = fileobj.read(2)
    fileobj.seek(0)
    stream = gzip.GzipFile(fileobj=fileobj, mode="rb") if head == b"\x1f\x8b" else fileobj
    total = 0
    pending = b""
    try:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise FlowLogError(f"flow log is larger than {max_bytes} bytes; refusing it")
            *complete, pending = (pending + chunk).split(b"\n")
            for line in complete:
                yield line.decode("utf-8", "replace")
    except (OSError, EOFError, zlib.error) as exc:
        raise FlowLogError(f"cannot read flow log: {exc}") from exc
    if pending:
        yield pending.decode("utf-8", "replace")


def read_path(path: str | Path, stats: ParseStats | None = None,
              max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[FlowLogRecord]:
    """Records from a local .log or .log.gz file (gzip is detected from the content)."""
    with open(path, "rb") as fh:
        yield from parse_lines(_iter_text_lines(fh, max_bytes), stats)


def read_bytes(data: bytes, stats: ParseStats | None = None,
               max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[FlowLogRecord]:
    yield from parse_lines(_iter_text_lines(io.BytesIO(data), max_bytes), stats)


def read_s3_object(s3, bucket: str, key: str, stats: ParseStats | None = None,
                   max_bytes: int = DEFAULT_MAX_BYTES) -> list[FlowLogRecord]:
    """Download one flow-log object and parse it. `s3` is a boto3 S3 client."""
    response = s3.get_object(Bucket=bucket, Key=key)
    length = response.get("ContentLength")
    if length is not None and length > max_bytes:
        raise FlowLogError(f"s3://{bucket}/{key} is {length} bytes; the limit is {max_bytes}")
    body = response["Body"]
    try:
        data = body.read()
    finally:
        close = getattr(body, "close", None)
        if close:
            close()
    return list(read_bytes(data, stats, max_bytes))


# --- Records -> NetFlow-style rows ------------------------------------------------------------

WELL_KNOWN_PORT = 1024


def _is_initiator(rec: FlowLogRecord, other: FlowLogRecord | None = None) -> bool:
    """Heuristic: does `rec` describe the side that started the connection?

    With both directions: the record whose destination is a well-known service port (< 1024)
    while the other's is not, else the one with the higher source port (ephemeral -> service),
    else the lower (address, port) so the answer is stable.
    """
    if other is not None:
        mine = 0 < rec.dst_port < WELL_KNOWN_PORT
        theirs = 0 < other.dst_port < WELL_KNOWN_PORT
        if mine != theirs:
            return mine
    if rec.src_port != rec.dst_port:
        return rec.src_port > rec.dst_port
    return (rec.src_ip, rec.src_port) <= (rec.dst_ip, rec.dst_port)


def _row(initiator: list[FlowLogRecord], responder: list[FlowLogRecord]) -> dict:
    first = initiator[0]
    both = initiator + responder
    start_ms = min(r.start for r in both) * 1000
    end_ms = max(max(r.end for r in both) * 1000, start_ms)
    duration = end_ms - start_ms
    seconds = duration / 1000.0
    fwd_packets = sum(r.packets for r in initiator)
    bwd_packets = sum(r.packets for r in responder)
    fwd_bytes = sum(r.byte_count for r in initiator)
    bwd_bytes = sum(r.byte_count for r in responder)
    packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    return {
        "src_ip": first.src_ip, "src_port": first.src_port,
        "dst_ip": first.dst_ip, "dst_port": first.dst_port,
        "protocol": first.protocol, "start_ms": start_ms, "end_ms": end_ms,
        "duration_ms": duration,
        "fwd_packets": fwd_packets, "bwd_packets": bwd_packets,
        "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
        # Rates are 0 for a zero-length window rather than infinite (same rule as the lab).
        "bytes_per_s": total_bytes / seconds if seconds > 0 else 0.0,
        "packets_per_s": packets / seconds if seconds > 0 else 0.0,
        "down_up_ratio": bwd_bytes / fwd_bytes if fwd_bytes else 0.0,
        "fwd_pkt_len_mean": fwd_bytes / fwd_packets if fwd_packets else 0.0,
        "bwd_pkt_len_mean": bwd_bytes / bwd_packets if bwd_packets else 0.0,
        "rejected": int(any(r.action == "REJECT" for r in both)),
    }


def _same_window(a: FlowLogRecord, b: FlowLogRecord) -> bool:
    """Two directions of one connection are logged in the same capture window, but their start
    and end are the first and last packet seen in each direction and differ by a second or two.
    So: same aligned window bucket, or overlapping [start, end] intervals."""
    if a.start // AGGREGATION_SECONDS == b.start // AGGREGATION_SECONDS:
        return True
    return a.start <= b.end and b.start <= a.end


def _record_order(r: FlowLogRecord) -> tuple:
    return (r.start, r.end, r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.packets, r.byte_count,
            r.action)


def _pair_group(records: list[FlowLogRecord]) -> list[tuple[list, list]]:
    """Records of one (interface, protocol, endpoint pair): match each record with at most one
    record of the opposite direction from the same window; the rest stay one-way."""
    records = sorted(records, key=_record_order)
    used = [False] * len(records)
    pairs: list[tuple[list, list]] = []
    for i, first in enumerate(records):
        if used[i]:
            continue
        used[i] = True
        best = None
        for j in range(i + 1, len(records)):
            other = records[j]
            if used[j] or (other.src_ip, other.src_port) == (first.src_ip, first.src_port):
                continue
            if _same_window(first, other):
                best = j
                break  # sorted by start: the earliest candidate is the nearest one
        if best is None:
            pairs.append(([first], []))
            continue
        used[best] = True
        second = records[best]
        if _is_initiator(first, second) or not _is_initiator(second, first):
            pairs.append(([first], [second]))
        else:
            pairs.append(([second], [first]))
    return pairs


def to_flow_rows(records: Iterable[FlowLogRecord], *, pair_directions: bool = True) -> list[dict]:
    """Records -> one dict per flow, with exactly the CLOUD_FEATURE_COLUMNS keys.

    A flow log holds one record per direction. With `pair_directions`, the two directions of a
    connection (same interface, protocol and unordered endpoint pair, in the same capture window;
    see _same_window: start and end may differ by a few seconds) become one row: the initiator
    (see _is_initiator) is src, the other side fills the bwd_* columns. Without a reverse record
    (a REJECTed or one-way flow) the bwd_* columns are 0.
    """
    records = list(records)
    if not pair_directions:
        rows = [_row([r], []) for r in records]
    else:
        groups: dict[tuple, list[FlowLogRecord]] = {}
        for r in records:
            ends = sorted([(r.src_ip, r.src_port), (r.dst_ip, r.dst_port)])
            groups.setdefault((r.interface_id, r.protocol, *ends), []).append(r)
        rows = [_row(fwd, bwd) for recs in groups.values() for fwd, bwd in _pair_group(recs)]
    rows.sort(key=lambda r: (r["start_ms"], r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]))
    return rows


def rows_to_frame(rows: Iterable[dict]) -> pd.DataFrame:
    """Rows -> DataFrame with exactly CLOUD_FEATURE_COLUMNS, in order (empty input: 0 rows)."""
    import pandas as pd

    return pd.DataFrame(list(rows), columns=CLOUD_FEATURE_COLUMNS)
