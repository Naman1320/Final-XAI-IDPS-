"""NFStream backend (preferred extractor). Imported lazily: it may be missing or unusable."""

from collections.abc import Iterator

from idps.capture.flow import Flow

_PREFIX = {"": "bidirectional", "fwd_": "src2dst", "bwd_": "dst2src"}


def _to_flow(f) -> Flow:
    kw = {}
    for ours, theirs in _PREFIX.items():
        for s in ("min", "max", "mean", "stddev"):
            kw[f"{ours}pkt_len_{s.replace('stddev', 'std')}"] = float(getattr(f, f"{theirs}_{s}_ps"))
            kw[f"{ours}iat_{s.replace('stddev', 'std')}"] = float(getattr(f, f"{theirs}_{s}_piat_ms"))
    for flag in ("syn", "fin", "rst", "psh", "ack", "urg", "cwr", "ece"):
        kw[f"{flag}_count"] = int(getattr(f, f"bidirectional_{flag}_packets"))
    return Flow(
        src_ip=f.src_ip, src_port=int(f.src_port), dst_ip=f.dst_ip, dst_port=int(f.dst_port),
        protocol=int(f.protocol),
        start_ms=int(f.bidirectional_first_seen_ms), end_ms=int(f.bidirectional_last_seen_ms),
        fwd_packets=int(f.src2dst_packets), bwd_packets=int(f.dst2src_packets),
        fwd_bytes=int(f.src2dst_bytes), bwd_bytes=int(f.dst2src_bytes), **kw,
    )


def available() -> bool:
    try:
        import nfstream  # noqa: F401
    except Exception:  # noqa: BLE001  missing package, missing shared library, unsupported platform
        return False
    return True


def flows_from_source(source: str, idle_timeout: float, active_timeout: float,
                      bpf_filter: str | None = None, max_flows: int | None = None) -> Iterator[Flow]:
    """`source` is a PCAP path or an interface name; NFStream treats both the same way."""
    from nfstream import NFStreamer

    streamer = NFStreamer(
        source=source,
        statistical_analysis=True,
        n_dissections=0,  # no nDPI application labels: they are not features
        n_meters=1,  # one meter keeps flow order deterministic
        idle_timeout=int(idle_timeout),
        active_timeout=int(active_timeout),
        bpf_filter=bpf_filter,
        promiscuous_mode=True,
    )
    for count, nf in enumerate(streamer, start=1):
        yield _to_flow(nf)
        if max_flows is not None and count >= max_flows:
            return
