"""Live flow-log exporter for the emulated cloud (docs/cloud-plan.md step C3).

Turns the lab's packets into AWS VPC Flow Log version-2 records and delivers them to the EMULATED
S3 bucket with the real key layout, so the collector (idps.cloud.collector) reads them exactly as
it would read Amazon's:

    AWSLogs/<account>/vpcflowlogs/<region>/YYYY/MM/DD/
        <account>_vpcflowlogs_<region>_fl-<id>_<YYYYMMDD>T<HHMM>Z_<hash>.log.gz

Two halves, run in two containers (lab/cloud/README.md):

* the WRITER (`python -m idps.cloud export writer`) captures packets read-only on one sensor
  interface (or reads a pcap with `export offline`), aggregates them per direction, 5-tuple and
  wall-clock minute, and writes each finished minute as a plain file into a folder. It never
  touches AWS or the network.
* the SHIPPER (`python -m idps.cloud export ship`) reads those files, gzips them and PUTs them
  into the emulator. It runs the billing guard first (lab/cloud/guard.py), never creates the
  bucket, and remembers what it shipped so a restart does not duplicate anything.

This is an EMULATION of VPC Flow Logs, not Amazon's. See lab/cloud/README.md for the differences.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import gzip
import hashlib
import importlib.util
import io
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import stat
import struct
import sys
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from idps.cloud.flowlogs import V2_FIELDS, FlowLogRecord, ParseStats, parse_lines

log = logging.getLogger("idps.cloud.flowlog_export")

WINDOW_SECONDS = 60  # max_aggregation_interval in infra/target.tf
EMULATOR_ACCOUNT = "000000000000"
DEFAULT_REGION = "eu-west-1"
DEFAULT_VICTIM_CIDR = "10.10.2.0/24"  # the lab's victim network (used when no host list is set)
# The "ENI": the hosts behind it. lab/docker-compose.yml: victim 10.10.2.10, dvwa 10.10.2.11 (the
# sensor .2 and the gateway .1 are not victims: a sweep must not create records for them).
DEFAULT_VICTIM_HOSTS = ("10.10.2.10", "10.10.2.11")
# The ports infra/ lets the attacker CIDRs reach (variables.tf attacker_ports default).
DEFAULT_ALLOW_PORTS = (22, 80)
HEADER = " ".join(V2_FIELDS)
FILE_RE = re.compile(r"(\d{8}T\d{4}Z)-([0-9a-f]{8})\.flows")  # <window>-<run id>.flows (fullmatch)
# Live writer: at most this many records per minute (~500 B each in memory, so ~25 MB per window
# held); a new flow beyond it is NOT recorded, but counted, logged and noted in the window's
# loss sidecar (real AWS writes a SKIPDATA record for the same situation). A pcap replayed with
# `export offline` runs on the host, not in a 256 MB container, so it may hold more.
MAX_RECORDS_PER_WINDOW = 50_000
OFFLINE_MAX_RECORDS_PER_WINDOW = 200_000
# The shipper streams a file line by line, so its memory does not grow with the file; these bounds
# only refuse absurd or hostile files. They are above what the writer can produce.
MAX_FILE_RECORDS = 4 * OFFLINE_MAX_RECORDS_PER_WINDOW
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 512
# Anti-flip trackers (see Aggregator): entries live one to two windows, at most this many per
# window-generation.
MAX_TRACKED_TUPLES = 100_000
SNAPLEN = 256  # bytes read per packet: the headers are all that is needed (lengths come from the IP header)
RCVBUF_BYTES = 8 * 1024 * 1024
MAX_WRITE_ATTEMPTS = (
    5  # a window that cannot be written is retried once a second, then dropped (counted)
)
MAX_VERIFY_ENTRIES = 1000  # shipped entries re-checked against the bucket at shipper start
LINE_RE = re.compile(r"[0-9A-Za-z.:\-]+(?: [0-9A-Za-z.:\-]+)*")
LOSS_SUFFIX = ".loss.json"
FLUSH_GRACE_SECONDS = 3.0  # a window is written this long after its last second
KEEP_HOURS = 12.0  # the writer deletes its own window files after this long
NOBODY = 65534
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
ICMP_ERROR_TYPES = frozenset({3, 4, 5, 11, 12})  # unreachable, redirect, time exceeded, ...


class ExportError(Exception):
    """A problem to show the user (not a bug): bad setting, missing bucket, guard refusal."""


class BucketMissing(ExportError):
    pass


# --- Identities ---------------------------------------------------------------------------------


def _hex_id(seed: str, length: int = 17) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:length]


def default_interface_id(account: str = EMULATOR_ACCOUNT, region: str = DEFAULT_REGION) -> str:
    """A fake but stable ENI id (the same in the writer and the shipper without sharing config)."""
    return "eni-" + _hex_id(f"idps-lab-eni/{account}/{region}")


def default_flow_log_id(account: str = EMULATOR_ACCOUNT, region: str = DEFAULT_REGION) -> str:
    return "fl-" + _hex_id(f"idps-lab-flowlog/{account}/{region}")


def default_bucket(account: str = EMULATOR_ACCOUNT) -> str:
    return f"idps-fyp-flowlogs-{account}"


# --- Packets ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Packet:
    ts: float  # epoch seconds
    src: int  # IPv4 address as an integer
    dst: int
    proto: int
    sport: int
    dport: int
    length: int  # IP total length (header + payload), what VPC Flow Logs count as bytes
    icmp_type: int = -1
    ident: int = 0  # IP identification, to match fragments
    frag_offset: int = 0  # non-zero: a non-first fragment (no transport header in it)
    more_fragments: bool = False


SUPPORTED_LINKTYPES = (1, 12, 101)  # Ethernet, raw IP (two numberings)


def parse_frame(frame: bytes, ts: float, linktype: int = 1) -> Packet | None:
    """An Ethernet (linktype 1) or raw-IP (101/12) frame -> Packet, or None if it is not IPv4.

    Only IPv4 is handled: IPv6, ARP, QinQ (0x88a8) and anything else is ignored (None); a single
    802.1Q tag is skipped over."""
    off = 0
    if linktype == 1:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        off = 14
        if ethertype == 0x8100 and len(frame) >= 18:  # one VLAN tag
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            off = 18
        if ethertype != 0x0800:
            return None
    elif linktype not in (12, 101):
        return None
    if len(frame) < off + 20 or frame[off] >> 4 != 4:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl:
        return None
    total = struct.unpack_from("!H", frame, off + 2)[0]
    ident = struct.unpack_from("!H", frame, off + 4)[0]
    flags_frag = struct.unpack_from("!H", frame, off + 6)[0]
    frag = flags_frag & 0x1FFF
    more = bool(flags_frag & 0x2000)
    proto = frame[off + 9]
    src = int.from_bytes(frame[off + 12 : off + 16], "big")
    dst = int.from_bytes(frame[off + 16 : off + 20], "big")
    sport = dport = 0
    icmp_type = -1
    body = off + ihl
    if frag == 0:
        if proto in (PROTO_TCP, PROTO_UDP) and len(frame) >= body + 4:
            sport, dport = struct.unpack_from("!HH", frame, body)
        elif proto == PROTO_ICMP and len(frame) > body:
            icmp_type = frame[body]
    return Packet(ts, src, dst, proto, sport, dport, total, icmp_type, ident, frag, more)


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """IPv4 packets of a classic pcap file (scapy is imported only here)."""
    from scapy.utils import RawPcapReader

    with open(path, "rb") as fh:
        if fh.read(4) == b"\x0a\x0d\x0d\x0a":
            raise ExportError(f"{path} is pcapng; convert it first (editcap -F pcap)")
    with RawPcapReader(str(path)) as reader:
        if reader.linktype not in SUPPORTED_LINKTYPES:
            raise ExportError(
                f"{path} has link type {reader.linktype}; only Ethernet (1) and raw IP (12, 101) "
                "are supported (a Linux cooked capture, 113, has to be re-captured or converted)"
            )
        for data, meta in reader:
            packet = parse_frame(bytes(data), float(meta.sec), reader.linktype)
            if packet is not None:
                yield packet


# --- Aggregation --------------------------------------------------------------------------------


def _network(text: str) -> tuple[int, int]:
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError as exc:
        raise ExportError(f"bad victim address or CIDR {text!r}: {exc}") from exc
    if net.version != 4:
        raise ExportError("only IPv4 is supported")
    return int(net.network_address), int(net.netmask)


@dataclass
class ExportConfig:
    account: str = EMULATOR_ACCOUNT
    region: str = DEFAULT_REGION
    interface_id: str = ""
    victim_cidr: str = DEFAULT_VICTIM_CIDR
    # Addresses (or CIDRs) behind the ENI. Only traffic with exactly one end among them is
    # recorded. Empty: the whole victim_cidr.
    victim_hosts: tuple[str, ...] = DEFAULT_VICTIM_HOSTS
    allow_tcp_ports: frozenset[int] = frozenset(DEFAULT_ALLOW_PORTS)
    allow_udp_ports: frozenset[int] = frozenset()
    allow_icmp: bool = False
    max_records_per_window: int = MAX_RECORDS_PER_WINDOW

    def __post_init__(self) -> None:
        if not re.fullmatch(r"\d{12}", self.account):
            raise ExportError(f"account id must be 12 digits, got {self.account!r}")
        if not self.interface_id:
            self.interface_id = default_interface_id(self.account, self.region)
        self.victim_hosts = tuple(self.victim_hosts)
        self._targets = [_network(h) for h in self.victim_hosts] or [_network(self.victim_cidr)]

    def in_victim(self, address: int) -> bool:
        return any(address & mask == net for net, mask in self._targets)

    def allowed(self, proto: int, port: int) -> bool:
        if proto == PROTO_TCP:
            return port in self.allow_tcp_ports
        if proto == PROTO_UDP:
            return port in self.allow_udp_ports
        if proto == PROTO_ICMP:
            return self.allow_icmp
        return False


def _ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def window_of(ts: float) -> int:
    """Start (epoch seconds) of the wall-clock minute `ts` falls in."""
    return int(ts) // WINDOW_SECONDS * WINDOW_SECONDS


class _Expiring:
    """A bounded map whose entries live one to two windows (two generations).

    `advance(window)` moves to a new window: the current generation becomes the previous one and
    the older one is forgotten. A generation holds at most `limit` entries; when full, the OLDEST
    entry is evicted and counted. This replaces a set that was cleared when full."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.cur: dict = {}
        self.prev: dict = {}
        self.window: int | None = None
        self.evictions = 0
        self.last_eviction_window: int | None = None

    def advance(self, window: int) -> None:
        if self.window is None:
            self.window = window
        elif window > self.window:
            self.prev = self.cur if window == self.window + WINDOW_SECONDS else {}
            self.cur = {}
            self.window = window

    def get(self, key, default=None):
        if key in self.cur:
            return self.cur[key]
        return self.prev.get(key, default)

    def __contains__(self, key) -> bool:
        return key in self.cur or key in self.prev

    def put(self, key, value=True) -> None:
        if key not in self.cur and len(self.cur) >= self.limit:
            del self.cur[next(iter(self.cur))]
            self.evictions += 1
            self.last_eviction_window = self.window
        self.cur[key] = value

    def evicted_recently(self) -> bool:
        """An entry may have been lost in the last two windows."""
        return (
            self.last_eviction_window is not None
            and self.window is not None
            and self.window - self.last_eviction_window <= WINDOW_SECONDS
        )

    def __len__(self) -> int:
        return len(self.cur) + len(self.prev)


def _pack(src: int, dst: int, sport: int, dport: int, proto: int) -> int:
    return (((((src << 32 | dst) << 16 | sport) << 16) | dport) << 8) | proto


@dataclass
class WindowStats:
    """What happened to the packets of one window (logged; a sidecar is written on loss)."""

    seen: int = 0
    ignored: int = 0  # not this ENI's traffic, or an answer the emulated security group drops
    skipped_records: int = 0  # new flows not recorded because the window was full
    evictions: int = 0  # tracker entries evicted (see Aggregator)
    ambiguous_dropped: int = 0  # victim packets dropped rather than guessed after an eviction
    fragments_ignored: int = 0  # non-first fragments whose first fragment was not seen
    kernel_drops: int = 0  # packets the kernel dropped from the capture socket's buffer
    records: int = 0

    @property
    def loss(self) -> bool:
        return bool(
            self.skipped_records
            or self.evictions
            or self.ambiguous_dropped
            or self.fragments_ignored
            or self.kernel_drops
        )

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


class Aggregator:
    """Packets -> flow-log records, one per direction, 5-tuple and aligned 60 s window.

    ACCEPT/REJECT is decided like the victim's security group would (the emulation; the lab's
    real decisions are the sensor's nftables and the victim host):
      * toward the victim: ACCEPT if the destination port is on the allow-list (or the packet
        answers a connection the victim opened), else REJECT;
      * from the victim: the answer to a packet that was REJECTed (the lab victim's RST or ICMP
        unreachable) is dropped, because behind a real security group the victim never saw the
        packet and answered nothing; every other packet is ACCEPT (egress is open).
    Traffic that does not have exactly one end among the victim hosts is not this ENI's and is
    ignored.

    The two trackers behind this ("rejected" and "victim-opened") expire after one to two
    windows and are bounded. If a bound ever evicts a rejected tuple, the victim's answers to it
    could no longer be recognised; instead of guessing (which would turn REJECT traffic into
    ACCEPT egress records and then ACCEPT replies) the victim's unexplained packets are DROPPED
    and counted in `ambiguous_dropped` until the loss has aged out.

    IP fragments: the first fragment carries the ports; later fragments (offset > 0) inherit the
    ports and so the decision of their first fragment, matched by (src, dst, protocol, IP id). A
    later fragment whose first fragment was not seen is ignored and counted.
    """

    def __init__(self, config: ExportConfig, tracked_limit: int = MAX_TRACKED_TUPLES) -> None:
        self.config = config
        self.windows: dict[int, dict[tuple, list]] = {}
        self.stats: dict[int, WindowStats] = {}
        self._rejected = _Expiring(tracked_limit)
        self._outbound = _Expiring(tracked_limit)
        self._frags = _Expiring(tracked_limit)
        self._trackers = (self._rejected, self._outbound, self._frags)
        self.packets_seen = 0
        self.packets_ignored = 0
        self.skipped_records = 0  # new records refused because a window was full (all windows)

    def _stat(self, window: int) -> WindowStats:
        st = self.stats.get(window)
        if st is None:
            st = self.stats[window] = WindowStats()
        return st

    def expire(self, now: float) -> None:
        """Let the trackers age with the clock even when no packet arrives."""
        for tracker in self._trackers:
            tracker.advance(window_of(now))

    def add_kernel_drops(self, window: int, count: int) -> None:
        if count > 0:
            self._stat(window).kernel_drops += count

    def _decide(self, p: Packet, st: WindowStats) -> str | None:
        cfg = self.config
        src_in, dst_in = cfg.in_victim(p.src), cfg.in_victim(p.dst)
        if src_in == dst_in:
            return None
        if dst_in:  # toward the victim
            if cfg.allowed(p.proto, p.dport):
                return "ACCEPT"
            if _pack(p.dst, p.src, p.dport, p.sport, p.proto) in self._outbound:
                return "ACCEPT"  # reply to something the victim started
            self._rejected.put(_pack(p.src, p.dst, p.sport, p.dport, p.proto))
            return "REJECT"
        # from the victim
        if p.proto == PROTO_ICMP and p.icmp_type in ICMP_ERROR_TYPES:
            return None  # lab artefact: an error message about a packet the real SG would drop
        if _pack(p.dst, p.src, p.dport, p.sport, p.proto) in self._rejected:
            return None  # lab artefact: the victim answered a packet the real SG would have dropped
        if not cfg.allowed(p.proto, p.sport):
            if self._rejected.evicted_recently():
                st.ambiguous_dropped += 1  # might be an answer to a REJECT we forgot: do not guess
                return None
            self._outbound.put(_pack(p.src, p.dst, p.sport, p.dport, p.proto))
        return "ACCEPT"

    def add(self, p: Packet) -> None:
        self.packets_seen += 1
        window = window_of(p.ts)
        for tracker in self._trackers:
            tracker.advance(window)
        st = self._stat(window)
        st.seen += 1
        if p.frag_offset:  # a later fragment: ports come from the first one
            ports = self._frags.get((p.src, p.dst, p.proto, p.ident))
            if ports is None:
                st.fragments_ignored += 1
                st.ignored += 1
                self.packets_ignored += 1
                return
            p = dataclasses.replace(p, sport=ports[0], dport=ports[1])
        elif p.more_fragments:
            self._frags.put((p.src, p.dst, p.proto, p.ident), (p.sport, p.dport))
        evicted_before = self._rejected.evictions + self._outbound.evictions + self._frags.evictions
        action = self._decide(p, st)
        st.evictions += (
            self._rejected.evictions + self._outbound.evictions + self._frags.evictions
        ) - evicted_before
        if action is None:
            st.ignored += 1
            self.packets_ignored += 1
            return
        rows = self.windows.setdefault(window, {})
        key = (p.src, p.dst, p.sport, p.dport, p.proto)
        rec = rows.get(key)
        second = int(p.ts)
        if rec is None:
            if len(rows) >= self.config.max_records_per_window:
                self.skipped_records += 1
                st.skipped_records += 1
                return
            rows[key] = [1, p.length, second, second, action]
            return
        rec[0] += 1
        rec[1] += p.length
        rec[2] = min(rec[2], second)
        rec[3] = max(rec[3], second)

    def _lines(self, window: dict[tuple, list]) -> list[str]:
        cfg = self.config
        out = []
        for (src, dst, sport, dport, proto), (pkts, size, start, end, action) in sorted(
            window.items(), key=lambda kv: (kv[1][2], kv[0])
        ):
            out.append(
                f"2 {cfg.account} {cfg.interface_id} {_ip(src)} {_ip(dst)} {sport} {dport} "
                f"{proto} {pkts} {size} {start} {end} {action} OK"
            )
        return out

    def pop_finished(self, now: float, grace: float = FLUSH_GRACE_SECONDS) -> dict[int, list[str]]:
        """Remove and return the windows that ended at least `grace` seconds before `now`.
        Windows that only have counters (no records) come back with an empty list."""
        due = sorted(w for w in {*self.windows, *self.stats} if w + WINDOW_SECONDS + grace <= now)
        done = {w: self._lines(self.windows.pop(w, {})) for w in due}
        for w, lines in done.items():
            self._stat(w).records = len(lines)
        return done

    def pop_all(self) -> dict[int, list[str]]:
        done = {
            w: self._lines(self.windows.pop(w, {})) for w in sorted({*self.windows, *self.stats})
        }
        for w, lines in done.items():
            self._stat(w).records = len(lines)
        return done

    def pop_stats(self, window: int) -> WindowStats:
        return self.stats.pop(window, WindowStats())


# --- Window files -------------------------------------------------------------------------------


def window_filename(window_start: int, run_id: str) -> str:
    return f"{datetime.fromtimestamp(window_start, UTC):%Y%m%dT%H%MZ}-{run_id}.flows"


def _unique_path(
    out_dir: Path, window_start: int, run_id: str, suffix: str = ""
) -> tuple[Path, str]:
    path = out_dir / (window_filename(window_start, run_id) + suffix)
    while path.exists():  # the same window again in one run (out-of-order packets): new name
        run_id = hashlib.sha256(run_id.encode()).hexdigest()[:8]
        path = out_dir / (window_filename(window_start, run_id) + suffix)
    return path, run_id


def write_window(out_dir: Path, window_start: int, lines: list[str], run_id: str) -> Path | None:
    """Write one finished window as a plain file (atomically: temp file, then rename)."""
    if not lines:
        return None
    path, _ = _unique_path(out_dir, window_start, run_id)
    tmp = out_dir / (path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="ascii")
    os.replace(tmp, path)
    return path


def write_loss_sidecar(out_dir: Path, window_start: int, stats: WindowStats, run_id: str) -> Path:
    """`<window>-<run>.flows.loss.json`: written only for a window that lost something (kernel
    drops, records over the cap, evictions, orphan fragments). The shipper ignores it."""
    path, _ = _unique_path(out_dir, window_start, run_id, LOSS_SUFFIX)
    tmp = out_dir / (path.name + ".tmp")
    body = {"window_start": window_start, "run_id": run_id, **stats.as_dict()}
    tmp.write_text(json.dumps(body, indent=1) + "\n", encoding="ascii")
    os.replace(tmp, path)
    return path


def prune_old(out_dir: Path, keep_hours: float = KEEP_HOURS, now: float | None = None) -> int:
    """Delete window files, loss sidecars and leftover temp files older than `keep_hours`."""
    cutoff = (time.time() if now is None else now) - keep_hours * 3600
    removed = 0
    for pattern in ("*.flows", "*.flows.tmp", "*" + LOSS_SUFFIX, "*" + LOSS_SUFFIX + ".tmp"):
        for path in out_dir.glob(pattern):
            with contextlib.suppress(OSError):
                if path.lstat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
    return removed


class WindowWriter:
    """Writes finished windows; a window that cannot be written (full or read-only volume) is
    kept and retried up to MAX_WRITE_ATTEMPTS times, then dropped and COUNTED."""

    def __init__(self, out_dir: Path, run_id: str) -> None:
        self.out_dir, self.run_id = out_dir, run_id
        self.pending: dict[int, list] = {}  # window -> [lines, stats, attempts]
        self.written = 0
        self.dropped_windows = 0
        self.last_ok = True

    @property
    def healthy(self) -> bool:
        return self.last_ok and not self.pending

    def submit(self, window: int, lines: list[str], stats: WindowStats) -> None:
        if not lines and not stats.loss:
            return
        self.pending[window] = [lines, stats, 0]
        self._attempt(window)

    def retry(self) -> None:
        for window in list(self.pending):
            self._attempt(window)

    def _attempt(self, window: int) -> None:
        lines, stats, attempts = self.pending[window]
        try:
            path = write_window(self.out_dir, window, lines, self.run_id)
            if stats.loss:
                write_loss_sidecar(self.out_dir, window, stats, self.run_id)
        except OSError as exc:
            self.last_ok = False
            self.pending[window][2] = attempts + 1
            if attempts + 1 >= MAX_WRITE_ATTEMPTS:
                del self.pending[window]
                self.dropped_windows += 1
                log.error(
                    "DROPPED window %s (%d records) after %d failed writes: %s "
                    "(%d windows dropped so far)",
                    window,
                    len(lines),
                    attempts + 1,
                    exc,
                    self.dropped_windows,
                )
            else:
                log.error(
                    "cannot write window %s (attempt %d), will retry: %s", window, attempts + 1, exc
                )
            return
        del self.pending[window]
        self.last_ok = True
        self.written += 1
        label = path.name if path else f"window {window}"
        extra = f" LOSS {json.dumps(stats.as_dict())}" if stats.loss else ""
        log.log(
            logging.WARNING if stats.loss else logging.INFO,
            "wrote %s: %d records, %d packets seen, %d ignored%s",
            label,
            len(lines),
            stats.seen,
            stats.ignored,
            extra,
        )


def export_packets(
    packets: Iterable[Packet], config: ExportConfig, out_dir: Path, run_id: str
) -> list[Path]:
    """Offline mode: every packet in, every window out (window files on disk). Used for pcaps."""
    agg = Aggregator(config)
    written: list[Path] = []

    def flush(done: dict[int, list[str]]) -> None:
        for w, lines in done.items():
            stats = agg.pop_stats(w)
            if (path := write_window(out_dir, w, lines, run_id)) is not None:
                written.append(path)
            if stats.loss:
                log.warning("window %s lost data: %s", w, json.dumps(stats.as_dict()))
                write_loss_sidecar(out_dir, w, stats, run_id)

    for packet in packets:
        agg.add(packet)
        # Windows older than the current packet's can be written as soon as time moves on.
        flush(agg.pop_finished(packet.ts, grace=0))
    flush(agg.pop_all())
    return written


# --- Live capture -------------------------------------------------------------------------------


def drop_privileges(uid: int = NOBODY, gid: int = NOBODY) -> None:
    """After the capture socket is open nothing needs root or any capability: give both up.
    (The open AF_PACKET socket itself stays usable, including for sending; see the README.)"""
    if os.getuid() != 0:
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        os.setuid(0)
    except PermissionError:
        return
    raise ExportError("could not give up root")  # pragma: no cover


SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_STATISTICS = 6


def open_capture_socket(interface: str) -> socket.socket:
    if not hasattr(socket, "AF_PACKET"):
        raise ExportError("live capture needs Linux (AF_PACKET); use `export offline` for a pcap")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
    try:
        sock.bind((interface, 0))
    except OSError as exc:
        sock.close()
        raise ExportError(f"cannot capture on {interface!r}: {exc}") from exc
    with contextlib.suppress(OSError):  # the kernel caps this at net.core.rmem_max
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
    with contextlib.suppress(OSError):
        log.info("capture buffer: %d bytes", sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    sock.settimeout(1.0)
    return sock


def read_kernel_drops(sock) -> int:
    """Packets the kernel dropped since the last call (PACKET_STATISTICS resets on read).
    0 when the socket cannot tell (not AF_PACKET, a test double)."""
    try:
        raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        _packets, drops = struct.unpack("II", raw)
    except (OSError, AttributeError, struct.error, TypeError):
        return 0
    return drops


def run_writer(
    config: ExportConfig,
    interface: str,
    out_dir: Path,
    *,
    run_id: str,
    keep_hours: float = KEEP_HOURS,
    drop: bool = True,
    alive_file: Path | None = Path("/tmp/alive"),
    stop: Callable[[], bool] = lambda: False,
    sock: socket.socket | None = None,
    clock: Callable[[], float] = time.time,
) -> None:
    """Capture until `stop()` and write each finished window. The healthcheck file is touched
    only while the last window write succeeded and nothing is waiting to be retried."""
    sock = sock or open_capture_socket(interface)
    if drop:
        drop_privileges()
    out_dir.mkdir(parents=True, exist_ok=True)
    if not os.access(out_dir, os.W_OK):
        raise ExportError(f"{out_dir} is not writable by uid {os.getuid()}")
    agg = Aggregator(config)
    writer = WindowWriter(out_dir, run_id)
    log.info(
        "capturing on %s: ENI %s, victim hosts %s, allow tcp %s udp %s icmp %s, up to %d records/window",
        interface,
        config.interface_id,
        list(config.victim_hosts) or config.victim_cidr,
        sorted(config.allow_tcp_ports),
        sorted(config.allow_udp_ports),
        config.allow_icmp,
        config.max_records_per_window,
    )
    next_housekeeping = next_prune = 0.0
    skipped_logged = 0
    try:
        while not stop():
            try:
                frame = sock.recv(SNAPLEN)
            except TimeoutError:
                frame = None
            now = clock()
            if frame:
                packet = parse_frame(frame, now, 1)
                if packet is not None:
                    agg.add(packet)
                else:
                    agg.packets_seen += 1
                    agg.packets_ignored += 1
            if now >= next_housekeeping:
                next_housekeeping = now + 1.0
                agg.expire(now)
                agg.add_kernel_drops(window_of(now), read_kernel_drops(sock))
                for w, lines in agg.pop_finished(now).items():
                    writer.submit(w, lines, agg.pop_stats(w))
                writer.retry()
                if alive_file is not None and writer.healthy:
                    with contextlib.suppress(OSError):
                        alive_file.touch()
                if now >= next_prune:
                    next_prune = now + 300
                    prune_old(out_dir, keep_hours)
                    if agg.skipped_records > skipped_logged:  # the change since last time
                        log.warning(
                            "%d new flow records skipped in the last 5 minutes (a window holds at "
                            "most %d)",
                            agg.skipped_records - skipped_logged,
                            config.max_records_per_window,
                        )
                        skipped_logged = agg.skipped_records
    finally:
        agg.add_kernel_drops(window_of(clock()), read_kernel_drops(sock))
        for w, lines in agg.pop_all().items():  # a partial minute beats a lost one
            writer.submit(w, lines, agg.pop_stats(w))
        writer.retry()
        if writer.dropped_windows:
            log.error(
                "%d windows were dropped because they could not be written", writer.dropped_windows
            )
        sock.close()


# --- Shipping -----------------------------------------------------------------------------------


def load_guard():
    """lab/cloud/guard.py, the one billing guard (copied into the image beside idps/)."""
    path = Path(__file__).resolve().parents[2] / "lab" / "cloud" / "guard.py"
    if not path.is_file():
        raise ExportError(
            f"billing guard not found at {path}; the shipper refuses to run without it"
        )
    spec = importlib.util.spec_from_file_location("idps_cloud_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def object_key(account: str, region: str, flow_log_id: str, window_start: int, digest: str) -> str:
    when = datetime.fromtimestamp(window_start, UTC)
    return (
        f"AWSLogs/{account}/vpcflowlogs/{region}/{when:%Y/%m/%d}/"
        f"{account}_vpcflowlogs_{region}_{flow_log_id}_{when:%Y%m%dT%H%M}Z_{digest}.log.gz"
    )


def key_prefix(account: str, region: str) -> str:
    return f"AWSLogs/{account}/vpcflowlogs/{region}/"


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


@dataclass
class ShipperConfig:
    in_dir: Path
    state_dir: Path
    bucket: str = ""
    account: str = EMULATOR_ACCOUNT
    region: str = DEFAULT_REGION
    flow_log_id: str = ""

    def __post_init__(self) -> None:
        self.in_dir, self.state_dir = Path(self.in_dir), Path(self.state_dir)
        self.bucket = self.bucket or default_bucket(self.account)
        self.flow_log_id = self.flow_log_id or default_flow_log_id(self.account, self.region)


@dataclass
class ShipResult:
    shipped: list[str] = field(default_factory=list)
    already: int = 0  # known from the state file, or already in the bucket
    bad: int = 0
    failed: int = 0  # transient problems (S3 error, unreadable file): retried next cycle


def canonical_line(rec: FlowLogRecord) -> str:
    """The record rebuilt from its parsed fields: exactly what a reader will see."""
    return (
        f"{V2_VERSION} {rec.account_id} {rec.interface_id} {rec.src_ip} {rec.dst_ip} "
        f"{rec.src_port} {rec.dst_port} {rec.protocol} {rec.packets} {rec.byte_count} "
        f"{rec.start} {rec.end} {rec.action} {rec.log_status}"
    )


V2_VERSION = 2


class Shipper:
    def __init__(self, config: ShipperConfig, s3) -> None:
        self.config, self.s3 = config, s3
        self.state_path = config.state_dir / "shipped.json"
        self.shipped: dict[str, str] = {}  # window file -> S3 key
        self.bad: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.state_path.read_text())
            self.shipped = {str(k): str(v) for k, v in data.get("shipped", {}).items()}
            self.bad = {str(k) for k in data.get("bad", [])}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            # A damaged state file only means "unknown": the content-addressed keys and the
            # head_object check keep shipping idempotent.
            log.error("ignoring unreadable state %s: %s", self.state_path, exc)
            self.shipped, self.bad = {}, set()

    def _save(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"shipped": self.shipped, "bad": sorted(self.bad)}, indent=1))
        os.replace(tmp, self.state_path)

    def reset(self) -> None:
        """Forget what was shipped (`--reship`): everything still in the folder is sent again
        unless the bucket already holds the same object."""
        self.shipped, self.bad = {}, set()
        self._save()

    def check_bucket(self) -> None:
        """Stop if the bucket is not there. The shipper never creates it."""
        try:
            self.s3.head_bucket(Bucket=self.config.bucket)
        except Exception as exc:
            if _error_code(exc) in {"404", "NoSuchBucket", "NotFound"}:
                raise BucketMissing(_missing_bucket_message(self.config.bucket)) from exc
            raise ExportError(f"cannot reach bucket {self.config.bucket}: {exc}") from exc

    def verify_shipped(self) -> int:
        """Forget state entries whose object is no longer in the bucket (a Moto restart empties
        it), so those windows are sent again. Returns how many were forgotten. Looks at the
        newest MAX_VERIFY_ENTRIES entries; a transient error leaves an entry alone."""
        forgotten = 0
        for name in sorted(self.shipped)[-MAX_VERIFY_ENTRIES:]:
            try:
                if not self._exists(self.shipped[name]):
                    del self.shipped[name]
                    forgotten += 1
            except BucketMissing:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("could not verify %s: %s", name, exc)
        if forgotten:
            log.warning(
                "%d windows in the state file are not in the bucket (emulator restarted?): "
                "sending them again",
                forgotten,
            )
            self._save()
        return forgotten

    def _build(self, path: Path) -> tuple[int, str, bytes]:
        """Validate a window file while compressing it; return (window start, object key, gzip).

        Streams the file one line at a time (memory stays small however long the file is), accepts
        only lines that are exactly one v2 record (no header, NODATA, blank or control-character
        lines) and uploads the record REBUILT from its parsed fields, so the object holds exactly
        what the collector's parser will read."""
        match = FILE_RE.fullmatch(path.name)
        if match is None:
            raise ValueError("file name is not <YYYYMMDDTHHMMZ>-<run id>.flows")
        window = int(
            datetime.strptime(match.group(1), "%Y%m%dT%H%MZ").replace(tzinfo=UTC).timestamp()
        )
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            if path.is_symlink():
                raise ValueError("file is a symbolic link") from exc
            raise
        buf = io.BytesIO()
        digest = hashlib.sha256()
        records = 0
        with (
            os.fdopen(fd, "rb") as fh,
            gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, filename="") as gz,
        ):
            info = os.fstat(fh.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("not a regular file")
            if info.st_size > MAX_FILE_BYTES:
                raise ValueError("file is too large")

            def emit(text: str) -> None:
                data = (text + "\n").encode("ascii")
                digest.update(data)
                gz.write(data)

            emit(HEADER)
            for number, raw in enumerate(fh, start=1):  # splits on \n only, like the collector
                if len(raw) > MAX_LINE_BYTES:
                    raise ValueError(f"line {number} is too long")
                line = raw.rstrip(b"\n").decode("ascii")  # UnicodeDecodeError is a ValueError
                if not LINE_RE.fullmatch(line):
                    raise ValueError(
                        f"line {number} is not a plain record (control characters, "
                        "extra spaces or a non-record line)"
                    )
                stats = ParseStats()
                parsed = list(parse_lines([line], stats))
                if len(parsed) != 1 or stats.malformed:
                    raise ValueError(f"line {number} is not a valid v2 record: {stats.errors[:1]}")
                rec = parsed[0]
                if rec.account_id != self.config.account:
                    raise ValueError(
                        f"record for account {rec.account_id}, expected {self.config.account}"
                    )
                if window_of(rec.start) != window:
                    raise ValueError("record outside the window named by the file")
                records += 1
                if records > MAX_FILE_RECORDS:
                    raise ValueError(f"more than {MAX_FILE_RECORDS} records")
                emit(canonical_line(rec))
        if records == 0:
            raise ValueError("no records")
        key = object_key(
            self.config.account,
            self.config.region,
            self.config.flow_log_id,
            window,
            digest.hexdigest()[:8],
        )
        return window, key, buf.getvalue()

    def _exists(self, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=self.config.bucket, Key=key)
        except Exception as exc:
            if _error_code(exc) in {"404", "NoSuchKey", "NotFound"}:
                return False
            if _error_code(exc) == "NoSuchBucket":
                raise BucketMissing(_missing_bucket_message(self.config.bucket)) from exc
            raise
        return True

    def ship_once(self) -> ShipResult:
        result = ShipResult()
        files = sorted(self.config.in_dir.glob("*.flows"))
        changed = False
        for path in files:
            name = path.name
            if name in self.shipped:
                result.already += 1
                continue
            if name in self.bad:
                result.bad += 1
                continue
            if path.is_symlink():
                log.error("not shipping %s: it is a symbolic link", name)
                self.bad.add(name)
                result.bad += 1
                changed = True
                continue
            if not path.is_file():
                continue
            try:
                _, key, data = self._build(path)
            except OSError as exc:  # transient (I/O error, file vanished): try again next cycle
                log.error("cannot read %s, will retry: %s", name, exc)
                result.failed += 1
                continue
            except ValueError as exc:  # includes UnicodeDecodeError: the file itself is wrong
                log.error("not shipping %s: %s", name, exc)
                self.bad.add(name)
                result.bad += 1
                changed = True
                continue
            try:
                if self._exists(key):
                    result.already += 1
                else:
                    self.s3.put_object(
                        Bucket=self.config.bucket,
                        Key=key,
                        Body=data,
                        ContentType="application/octet-stream",
                    )
                    result.shipped.append(key)
                    log.info("shipped s3://%s/%s", self.config.bucket, key)
            except BucketMissing:
                raise
            except Exception as exc:
                if _error_code(exc) == "NoSuchBucket":
                    raise BucketMissing(_missing_bucket_message(self.config.bucket)) from exc
                log.error("could not ship %s, will retry: %s", name, exc)
                result.failed += 1
                continue
            finally:
                del data  # the compressed object is not kept past this file
            self.shipped[name] = key
            changed = True
            self._save()  # after every object, so a crash cannot repeat more than one
        present = {p.name for p in files}
        stale = [n for n in self.shipped if n not in present]
        stale_bad = [n for n in self.bad if n not in present]
        if stale or stale_bad:  # the writer pruned them: forget them
            for n in stale:
                del self.shipped[n]
            self.bad -= set(stale_bad)
            changed = True
        if changed:
            self._save()
        return result


def _missing_bucket_message(bucket: str) -> str:
    return (
        f"bucket {bucket!r} does not exist in the emulator. Run `lab/cloud/tf.sh apply` first "
        "(it creates the bucket); the shipper never creates it."
    )


def make_s3_client(env: Mapping[str, str]):
    """boto3 S3 client pinned to the emulator endpoint with the fake credentials."""
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=env["AWS_ENDPOINT_URL"],
        region_name=env.get("AWS_REGION") or DEFAULT_REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(
            s3={"addressing_style": "path"},
            proxies={},
            retries={"max_attempts": 2},
            connect_timeout=5,
            read_timeout=15,
        ),
    )


def run_shipper(
    config: ShipperConfig,
    env: Mapping[str, str],
    *,
    interval: float = 10.0,
    once: bool = False,
    reship: bool = False,
    guard=None,
    s3=None,
    stop: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    recheck_seconds: float = 300.0,
    alive_file: Path | None = None,
) -> int:
    """Guard, bucket check, state check, then ship every `interval` seconds. Returns an exit
    code. `alive_file` (the container's healthcheck) is touched after each cycle without a
    failure."""
    guard = guard or load_guard()
    found = guard.problems(dict(env))
    if found:
        print("billing guard: REFUSED, nothing was shipped", file=sys.stderr)
        for item in found:
            print(f"  - {item}", file=sys.stderr)
        return 1
    s3 = s3 or make_s3_client(env)
    shipper = Shipper(config, s3)
    try:
        shipper.check_bucket()
        if reship:
            shipper.reset()
        else:
            shipper.verify_shipped()
        recheck = monotonic() + recheck_seconds
        while True:
            result = shipper.ship_once()
            if result.shipped or result.failed or result.bad:
                log.info(
                    json.dumps(
                        {
                            "event": "ship",
                            "shipped": len(result.shipped),
                            "already": result.already,
                            "bad": result.bad,
                            "failed": result.failed,
                        }
                    )
                )
            if alive_file is not None and not result.failed:
                with contextlib.suppress(OSError):
                    alive_file.touch()
            if once or stop():
                return 0 if not result.failed else 1
            for _ in range(max(1, int(interval))):  # short sleeps so SIGTERM is prompt
                if stop():
                    return 0
                sleep(min(1.0, interval))
            if monotonic() >= recheck:  # the guard again, now and then
                recheck = monotonic() + recheck_seconds
                found = guard.problems(dict(env))
                if found:
                    print("billing guard: REFUSED on recheck: " + "; ".join(found), file=sys.stderr)
                    return 1
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3 if isinstance(exc, BucketMissing) else 1


# --- Command line -------------------------------------------------------------------------------


def _ports(text: str) -> frozenset[int]:
    try:
        ports = frozenset(int(p) for p in text.replace(",", " ").split())
    except ValueError as exc:
        raise ExportError(f"bad port list {text!r}") from exc
    if any(not 0 < p < 65536 for p in ports):
        raise ExportError(f"ports must be 1-65535: {text!r}")
    return ports


def _truthy(text: str) -> bool:
    return text.strip().lower() in {"1", "true", "yes", "on"}


def _number(value, env_name: str, default: float, cast=float) -> float:
    """An option, else the environment variable, else the default. Parsed only when an export
    command runs, so a bad variable cannot break `python -m idps.cloud collect`."""
    raw = value if value is not None else os.environ.get(env_name, "").strip()
    if raw in (None, ""):
        return default
    try:
        number = cast(raw)
    except ValueError:
        raise ExportError(f"{env_name or 'option'} must be a number, got {raw!r}") from None
    if number <= 0:
        raise ExportError(f"{env_name} must be positive, got {raw!r}")
    return number


def _config_from(args: argparse.Namespace, default_cap: int) -> ExportConfig:
    hosts_text = (
        args.victim_hosts
        if args.victim_hosts is not None
        else os.environ.get("IDPS_FLOWLOG_VICTIM_HOSTS")
    )
    cidr_text = (
        args.victim_cidr
        if args.victim_cidr is not None
        else os.environ.get("IDPS_FLOWLOG_VICTIM_CIDR")
    )
    if hosts_text is not None and hosts_text.strip():
        hosts = (
            ()
            if hosts_text.strip().lower() == "all"
            else tuple(hosts_text.replace(",", " ").split())
        )
    elif cidr_text:  # an explicit network and no host list: the whole network, as before
        hosts = ()
    else:
        hosts = DEFAULT_VICTIM_HOSTS
    cap = int(_number(args.max_records, "IDPS_FLOWLOG_MAX_RECORDS", default_cap, int))
    return ExportConfig(
        account=args.account,
        region=args.region,
        interface_id=args.interface_id or "",
        victim_cidr=cidr_text or DEFAULT_VICTIM_CIDR,
        victim_hosts=hosts,
        allow_tcp_ports=_ports(args.allow_ports),
        allow_udp_ports=_ports(args.allow_udp_ports),
        allow_icmp=args.allow_icmp,
        max_records_per_window=cap,
    )


@contextlib.contextmanager
def _stop_signals():
    """SIGTERM/SIGINT set a flag the loops poll; the previous handlers come back afterwards (so
    running a command from a test or another program does not leave them swallowed)."""
    flag = {"stop": False}

    def handler(signum, frame):
        flag["stop"] = True

    old = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        old[sig] = signal.signal(sig, handler)
    try:
        yield lambda: flag["stop"]
    finally:
        for sig, previous in old.items():
            signal.signal(sig, previous)


def add_export_parser(sub) -> None:
    """Only strings are read from the environment here; numbers are parsed when a command runs."""
    env = os.environ.get
    p = sub.add_parser("export", help="live flow-log exporter for the emulated cloud (step C3)")
    esub = p.add_subparsers(dest="export_command", required=True)

    def common(q: argparse.ArgumentParser) -> None:
        q.add_argument("--account", default=env("IDPS_CLOUD_ACCOUNT", EMULATOR_ACCOUNT))
        q.add_argument("--region", default=env("IDPS_CLOUD_REGION", DEFAULT_REGION))
        q.add_argument(
            "--interface-id",
            default=env("IDPS_FLOWLOG_ENI"),
            help="fake ENI id (default: derived from account and region)",
        )
        q.add_argument(
            "--victim-hosts",
            default=None,
            help="addresses or CIDRs behind the ENI, space or comma separated; 'all' = the whole "
            "victim network (env IDPS_FLOWLOG_VICTIM_HOSTS; default "
            + " ".join(DEFAULT_VICTIM_HOSTS)
            + ", the lab's victim and dvwa)",
        )
        q.add_argument(
            "--victim-cidr",
            default=None,
            help="the victim network, used (as a whole) when no --victim-hosts is given "
            "(env IDPS_FLOWLOG_VICTIM_CIDR)",
        )
        q.add_argument(
            "--allow-ports",
            default=env("IDPS_FLOWLOG_ALLOW_PORTS", " ".join(map(str, DEFAULT_ALLOW_PORTS))),
            help="victim TCP ports the emulated security group allows; other ports "
            "are REJECT (default %(default)s, as in infra/)",
        )
        q.add_argument("--allow-udp-ports", default=env("IDPS_FLOWLOG_ALLOW_UDP_PORTS", ""))
        q.add_argument(
            "--allow-icmp", action="store_true", default=_truthy(env("IDPS_FLOWLOG_ALLOW_ICMP", ""))
        )
        q.add_argument(
            "--max-records",
            default=None,
            help=f"most records per 60 s window (env IDPS_FLOWLOG_MAX_RECORDS; default "
            f"{MAX_RECORDS_PER_WINDOW} live, {OFFLINE_MAX_RECORDS_PER_WINDOW} offline)",
        )

    w = esub.add_parser("writer", help="capture on a sensor interface, write 60 s window files")
    common(w)
    w.add_argument("--interface", default=env("IDPS_FLOWLOG_INTERFACE", "lab_attack"))
    w.add_argument("--out", default=env("IDPS_FLOWLOG_OUT", "/var/lib/flowlog-out"))
    w.add_argument("--keep-hours", default=None, help="env IDPS_FLOWLOG_KEEP_HOURS (default 12)")
    w.add_argument("--no-drop-privileges", action="store_true")
    w.set_defaults(func=_writer)

    o = esub.add_parser("offline", help="turn a pcap file into window files (tests, demo)")
    common(o)
    o.add_argument("--pcap", required=True)
    o.add_argument("--out", required=True)
    o.set_defaults(func=_offline)

    s = esub.add_parser("ship", help="gzip window files and PUT them into the emulated S3 bucket")
    s.add_argument("--account", default=env("IDPS_CLOUD_ACCOUNT", EMULATOR_ACCOUNT))
    s.add_argument("--region", default=env("IDPS_CLOUD_REGION", DEFAULT_REGION))
    s.add_argument("--bucket", default=env("IDPS_CLOUD_BUCKET", ""))
    s.add_argument("--flow-log-id", default=env("IDPS_FLOWLOG_ID", ""))
    s.add_argument("--in", dest="in_dir", default=env("IDPS_FLOWLOG_IN", "/var/lib/flowlog-out"))
    s.add_argument("--state-dir", default=env("IDPS_FLOWLOG_STATE", "/var/lib/flowlog-state"))
    s.add_argument(
        "--interval",
        default=None,
        help="seconds between cycles (env IDPS_FLOWLOG_SHIP_INTERVAL, default 10)",
    )
    s.add_argument("--once", action="store_true", help="ship what is there and exit")
    s.add_argument(
        "--reship",
        action="store_true",
        help="forget what was shipped and send every window in the folder again (after the "
        "emulator was reset); objects already in the bucket are not duplicated",
    )
    s.set_defaults(func=_ship)


def _run_id() -> str:
    return hashlib.sha256(f"{time.time_ns()}{os.getpid()}".encode()).hexdigest()[:8]


def _writer(args: argparse.Namespace) -> int:
    try:
        config = _config_from(args, MAX_RECORDS_PER_WINDOW)
        keep = _number(args.keep_hours, "IDPS_FLOWLOG_KEEP_HOURS", KEEP_HOURS)
        with _stop_signals() as stop:
            run_writer(
                config,
                args.interface,
                Path(args.out),
                run_id=_run_id(),
                keep_hours=keep,
                drop=not args.no_drop_privileges,
                stop=stop,
            )
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _offline(args: argparse.Namespace) -> int:
    try:
        config = _config_from(args, OFFLINE_MAX_RECORDS_PER_WINDOW)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        paths = export_packets(read_pcap(args.pcap), config, out, _run_id())
    except (ExportError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(path)
    return 0


def _ship(args: argparse.Namespace) -> int:
    try:
        config = ShipperConfig(
            in_dir=Path(args.in_dir),
            state_dir=Path(args.state_dir),
            bucket=args.bucket,
            account=args.account,
            region=args.region,
            flow_log_id=args.flow_log_id,
        )
        interval = _number(args.interval, "IDPS_FLOWLOG_SHIP_INTERVAL", 10.0)
        alive = os.environ.get("IDPS_FLOWLOG_ALIVE_FILE", "")
        with _stop_signals() as stop:
            return run_shipper(
                config,
                os.environ,
                interval=interval,
                once=args.once,
                reship=args.reship,
                stop=stop,
                alive_file=Path(alive) if alive else None,
            )
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
