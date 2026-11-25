"""Small scapy-based flow builder: the fallback extractor when NFStream is unavailable.

It follows the same rules as the NFStream backend (checked against NFStream 6.6.0):
- bidirectional 5-tuple flows; the first packet fixes the "forward" direction;
- a flow ends when the gap since its last packet is >= the idle timeout, or the time since
  its first packet is >= the active timeout (or when the capture ends);
- timestamps are truncated (not rounded) to whole milliseconds;
- whole-frame sizes; sample standard deviations;
- IPv6 extension headers are skipped to find the transport protocol and ports;
- only the first fragment of a fragmented IP packet is counted (later fragments carry no
  ports, and NFStream ignores them);
- the VLAN id is part of the flow key: the same 5-tuple on different VLANs is a different
  flow. NFStream uses the INNERMOST 802.1Q tag (not the outermost), and VLAN 0 counts as no
  VLAN. NFStream does not parse 802.1ad (0x88a8) frames at all, so those packets are skipped;
- packet time never goes backwards: a packet stamped earlier than the latest time seen so far
  in the capture (any flow) is treated as arriving at that latest time. So flow start is the
  first packet in capture order, end is the latest time, inter-arrival times are never negative.
"""

import heapq
import logging
import math
import queue
import time
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from decimal import Decimal
from itertools import pairwise

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import Dot1AD, Dot1Q
from scapy.packet import Packet

from idps.capture.flow import Flow

log = logging.getLogger(__name__)

_FLAGS = {"F": "fin", "S": "syn", "R": "rst", "P": "psh", "A": "ack", "U": "urg", "E": "ece", "C": "cwr"}
# IPv6 extension headers to skip: hop-by-hop, routing, fragment, destination options.
_IPV6_EXT = {0, 43, 44, 60}

DEFAULT_IDLE_TIMEOUT = 120.0
DEFAULT_ACTIVE_TIMEOUT = 120.0
# Open flows kept at most; beyond this the least recently seen flow is ended early
# (protects memory under floods with a new source port per packet).
DEFAULT_MAX_OPEN_FLOWS = 500_000
# Live capture: packets buffered between the sniffer thread and the flow table.
LIVE_QUEUE_SIZE = 100_000


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    """(min, max, mean, sample std); zeros for an empty list."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(values) / n
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1)) if n > 1 else 0.0
    return float(min(values)), float(max(values)), mean, std


def _to_ms(t) -> int:
    """Packet time -> whole milliseconds, truncated like NFStream (exact, no float error)."""
    return int(Decimal(str(t)) * 1000)


class _Acc:
    """Accumulates one flow."""

    __slots__ = (
        "dport",
        "dst",
        "first",
        "flags",
        "key",
        "last",
        "proto",
        "seq",
        "sizes",
        "sport",
        "src",
        "t",
    )

    def __init__(self, key, src, sport, dst, dport, proto, ts_ms, seq):
        self.seq = seq  # unique per flow, so stale heap entries can be recognised
        self.key, self.src, self.sport, self.dst, self.dport, self.proto = (
            key, src, sport, dst, dport, proto)
        self.first = self.last = ts_ms
        self.t = {True: [], False: []}  # per direction: packet times (ms)
        self.sizes = {True: [], False: []}
        self.flags = dict.fromkeys(_FLAGS.values(), 0)

    def to_flow(self) -> Flow:
        fwd_t, bwd_t = self.t[True], self.t[False]
        all_t = sorted(fwd_t + bwd_t)
        iat = lambda ts: [b - a for a, b in pairwise(ts)]
        fs, bs = self.sizes[True], self.sizes[False]
        kw = {}
        for prefix, vals in (("pkt_len", fs + bs), ("fwd_pkt_len", fs), ("bwd_pkt_len", bs),
                             ("iat", iat(all_t)), ("fwd_iat", iat(fwd_t)), ("bwd_iat", iat(bwd_t))):
            kw.update(zip((f"{prefix}_{s}" for s in ("min", "max", "mean", "std")), _stats(vals)))
        return Flow(
            src_ip=self.src, src_port=self.sport, dst_ip=self.dst, dst_port=self.dport,
            protocol=self.proto, start_ms=self.first, end_ms=self.last,
            fwd_packets=len(fs), bwd_packets=len(bs), fwd_bytes=sum(fs), bwd_bytes=sum(bs),
            **kw, **{f"{n}_count": c for n, c in self.flags.items()},
        )


def _vlan(pkt: Packet) -> int | None:
    """Innermost 802.1Q VLAN id before the IP header (0 = none), or None for an 802.1ad
    frame, which NFStream does not parse."""
    vid = 0
    for layer in pkt.iterpayloads():
        if isinstance(layer, (IP, IPv6)):
            break
        if isinstance(layer, Dot1AD):
            return None
        if isinstance(layer, Dot1Q):
            vid = int(layer.vlan)
    return vid


def _parse(pkt: Packet):
    """(src, dst, proto, l4 layer or None), or None if the packet isn't counted."""
    if IP in pkt:
        ip = pkt[IP]
        if int(ip.frag) > 0:  # a later fragment: no transport header, not counted
            return None
        return ip.src, ip.dst, int(ip.proto), ip.payload
    if IPv6 in pkt:
        ip = pkt[IPv6]
        nh, layer = int(ip.nh), ip.payload
        while nh in _IPV6_EXT and hasattr(layer, "nh"):
            if isinstance(layer, IPv6ExtHdrFragment) and int(layer.offset) > 0:
                return None
            nh, layer = int(layer.nh), layer.payload
        return ip.src, ip.dst, nh, layer
    return None


class FlowTable:
    """Feed packets with add(); collect finished flows from expire()/flush().

    Expiry is cheap: flows are kept in least-recently-seen order (for the idle timeout) and
    in a heap by first-seen time (for the active timeout), so each packet costs O(log n)
    instead of a scan over every open flow.
    """

    def __init__(self, idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                 active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
                 max_open_flows: int = DEFAULT_MAX_OPEN_FLOWS):
        self.idle_ms = int(idle_timeout * 1000)
        self.active_ms = int(active_timeout * 1000)
        self.max_open_flows = max_open_flows
        self._flows: OrderedDict[tuple, _Acc] = OrderedDict()
        self._by_first: list[tuple[int, int, tuple]] = []  # (first_ms, seq, key)
        self._seq = 0
        self._clock = 0  # latest packet time seen (ms); packet time never goes backwards
        self.evicted = 0  # flows ended early because of max_open_flows

    def add(self, pkt: Packet) -> list[Flow]:
        """Add one packet; returns flows that ended because of this packet's timestamp."""
        parsed = _parse(pkt)
        if parsed is None:
            return []
        src, dst, proto, l4 = parsed
        vlan = _vlan(pkt)
        if vlan is None:
            return []
        ts = self._clock = max(_to_ms(pkt.time), self._clock)
        done = self.expire(ts)
        sport = dport = 0
        flags = ""
        if proto in (6, 17) and hasattr(l4, "sport"):
            sport, dport = int(l4.sport), int(l4.dport)
            if proto == 6:
                flags = str(l4.flags)
        a, b = (src, sport), (dst, dport)
        lo, hi = min(a, b), max(a, b)
        key = (proto, vlan, *lo, *hi)
        acc = self._flows.get(key)
        if acc is None:
            if len(self._flows) >= self.max_open_flows:
                _, old = self._flows.popitem(last=False)
                done.append(old.to_flow())
                self.evicted += 1
            self._seq += 1
            acc = self._flows[key] = _Acc(key, src, sport, dst, dport, proto, ts, self._seq)
            heapq.heappush(self._by_first, (ts, self._seq, key))
        else:
            self._flows.move_to_end(key)
        fwd = (src, sport) == (acc.src, acc.sport)
        acc.t[fwd].append(ts)
        acc.sizes[fwd].append(len(pkt))
        acc.last = ts
        for ch in flags:
            if ch in _FLAGS:
                acc.flags[_FLAGS[ch]] += 1
        return done

    def expire(self, now_ms: int) -> list[Flow]:
        out = []
        # Idle: the front of the ordered dict is the least recently seen flow.
        while self._flows:
            key, acc = next(iter(self._flows.items()))
            if now_ms - acc.last < self.idle_ms:
                break
            del self._flows[key]
            out.append(acc.to_flow())
        # Active: the heap top is the oldest flow still possibly open.
        while self._by_first and now_ms - self._by_first[0][0] >= self.active_ms:
            _, seq, key = heapq.heappop(self._by_first)
            acc = self._flows.get(key)
            if acc is not None and acc.seq == seq:  # skip entries for flows already ended
                del self._flows[key]
                out.append(acc.to_flow())
        return sorted(out, key=lambda f: f.start_ms)

    def flush(self) -> list[Flow]:
        out = sorted((a.to_flow() for a in self._flows.values()), key=lambda f: f.start_ms)
        self._flows.clear()
        self._by_first.clear()
        return out


def flows_from_packets(packets: Iterable[Packet], idle_timeout: float,
                       active_timeout: float) -> Iterator[Flow]:
    table = FlowTable(idle_timeout, active_timeout)
    for pkt in packets:
        yield from table.add(pkt)
    yield from table.flush()
    if table.evicted:
        log.warning("scapy extractor: %d flows ended early (more than %d open flows)",
                    table.evicted, table.max_open_flows)


def flows_from_pcap_scapy(path: str, idle_timeout: float, active_timeout: float) -> Iterator[Flow]:
    from scapy.utils import PcapReader

    with PcapReader(path) as reader:
        yield from flows_from_packets(reader, idle_timeout, active_timeout)


def flows_from_interface_scapy(name: str, idle_timeout: float, active_timeout: float,
                               bpf_filter: str | None, max_flows: int | None,
                               duration: float | None) -> Iterator[Flow]:
    """Sniff live. Ends after `duration` seconds or `max_flows` flows; remaining flows are flushed.

    The sniffer hands packets over through a bounded queue; when it is full, packets are
    dropped and counted (a warning is logged at the end) instead of using unbounded memory.
    """
    from scapy.sendrecv import AsyncSniffer

    q: queue.Queue = queue.Queue(maxsize=LIVE_QUEUE_SIZE)
    dropped = 0

    def enqueue(pkt):
        nonlocal dropped
        try:
            q.put_nowait(pkt)
        except queue.Full:
            dropped += 1

    sniffer = AsyncSniffer(iface=name, filter=bpf_filter, store=False, prn=enqueue)
    deadline = None if duration is None else time.monotonic() + duration
    table = FlowTable(idle_timeout, active_timeout)
    emitted = 0
    sniffer.start()
    try:
        while deadline is None or time.monotonic() < deadline:
            try:
                pkt = q.get(timeout=0.2)
            except queue.Empty:
                finished = table.expire(int(time.time() * 1000))
            else:
                finished = table.add(pkt)
            for flow in finished:
                yield flow
                emitted += 1
                if max_flows is not None and emitted >= max_flows:
                    return
    finally:
        if sniffer.running:
            sniffer.stop()
        if dropped or table.evicted:
            log.warning("scapy live capture: %d packets dropped (queue full), %d flows ended early",
                        dropped, table.evicted)
    while not q.empty():
        table.add(q.get_nowait())
    for flow in table.flush():
        if max_flows is not None and emitted >= max_flows:
            return
        yield flow
        emitted += 1
