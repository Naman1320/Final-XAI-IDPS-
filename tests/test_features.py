import os
import sys

import pandas as pd
import pytest
from pcap_factory import (
    CLIENT,
    PAYLOAD_REQ,
    PAYLOAD_RESP,
    SERVER,
    T0,
    ping,
    tcp_session,
    udp_exchange,
    write_pcap,
)

from idps.capture import flows_from_interface, flows_from_pcap, select_backend
from idps.capture.flow import FLOW_FIELDS
from idps.features import FEATURE_COLUMNS, MODEL_FEATURES, to_frame
from idps.features.__main__ import main as cli_main

try:
    select_backend("nfstream")
    HAVE_NFSTREAM = True
except Exception:  # noqa: BLE001
    HAVE_NFSTREAM = False

BACKENDS = ["scapy", pytest.param("nfstream", marks=pytest.mark.skipif(
    not HAVE_NFSTREAM, reason="NFStream not available"))]


@pytest.fixture(params=BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def mixed_pcap(tmp_path):
    return write_pcap(tmp_path / "mixed.pcap", tcp_session() + udp_exchange() + ping())


def test_columns_cover_flow_fields():
    assert len(set(FEATURE_COLUMNS)) == len(FEATURE_COLUMNS)
    assert set(FLOW_FIELDS) <= set(FEATURE_COLUMNS)
    assert set(MODEL_FEATURES) <= set(FEATURE_COLUMNS)
    assert FEATURE_COLUMNS[:7] == ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms", "end_ms"]


def test_empty_input_has_columns():
    assert list(to_frame([]).columns) == FEATURE_COLUMNS


def test_tcp_flow(tmp_path, backend):
    pcap = write_pcap(tmp_path / "tcp.pcap", tcp_session())
    flows = list(flows_from_pcap(pcap, backend=backend))
    assert len(flows) == 1
    f = flows[0]
    # direction: the SYN sender is the forward side
    assert (f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.protocol) == (CLIENT, 40000, SERVER, 80, 6)
    assert (f.fwd_packets, f.bwd_packets) == (6, 4)
    assert f.fwd_bytes + f.bwd_bytes == 10 * 54 + PAYLOAD_REQ + PAYLOAD_RESP
    assert f.fwd_bytes == 6 * 54 + PAYLOAD_REQ and f.bwd_bytes == 4 * 54 + PAYLOAD_RESP
    assert f.end_ms - f.start_ms == 90
    assert f.start_ms == int(T0 * 1000)
    assert (f.syn_count, f.fin_count, f.rst_count, f.psh_count) == (2, 2, 0, 2)
    assert f.pkt_len_max == 54 + PAYLOAD_RESP and f.pkt_len_min == 54


def test_udp_flow(tmp_path, backend):
    pcap = write_pcap(tmp_path / "udp.pcap", udp_exchange())
    (f,) = list(flows_from_pcap(pcap, backend=backend))
    assert (f.src_port, f.dst_port, f.protocol) == (50000, 53, 17)
    assert (f.fwd_packets, f.bwd_packets) == (2, 2)
    assert f.fwd_bytes == 2 * (42 + 30) and f.bwd_bytes == 2 * (42 + 80)
    assert f.end_ms - f.start_ms == 300
    assert f.syn_count == 0


def test_flow_counts_and_reverse_direction(tmp_path, backend):
    # reply packets seen first: the first packet seen defines "forward"
    pkts = udp_exchange()
    pcap = write_pcap(tmp_path / "rev.pcap", pkts[1:])
    (f,) = list(flows_from_pcap(pcap, backend=backend))
    assert (f.src_port, f.dst_port) == (53, 50000)
    pcap = write_pcap(tmp_path / "many.pcap", tcp_session() + tcp_session(sport=40001) + udp_exchange())
    assert len(list(flows_from_pcap(pcap, backend=backend))) == 3


def test_idle_timeout_splits_flow(tmp_path, backend):
    late = udp_exchange(t0=T0 + 1.0 + 300)
    pcap = write_pcap(tmp_path / "split.pcap", udp_exchange() + late)
    assert len(list(flows_from_pcap(pcap, backend=backend, idle_timeout=120))) == 2


def test_to_frame_columns_and_values(mixed_pcap, backend):
    df = to_frame(flows_from_pcap(mixed_pcap, backend=backend))
    assert list(df.columns) == FEATURE_COLUMNS
    assert len(df) == 3
    tcp = df[df.protocol == 6].iloc[0]
    assert tcp.duration_ms == 90 and tcp.fwd_packets == 6
    assert tcp.bytes_per_s == pytest.approx(1140 / 0.09)
    single = df[df.protocol == 1].iloc[0]  # one-packet ICMP flow: no division by zero
    assert single.duration_ms == 0 and single.bytes_per_s == 0.0
    assert not df[MODEL_FEATURES].isna().any().any()


@pytest.mark.skipif(not HAVE_NFSTREAM, reason="NFStream not available")
def test_backends_agree(mixed_pcap):
    a = to_frame(flows_from_pcap(mixed_pcap, backend="nfstream"))
    b = to_frame(flows_from_pcap(mixed_pcap, backend="scapy"))
    pd.testing.assert_frame_equal(a, b, check_dtype=False, rtol=1e-6)


def test_cli_extract(mixed_pcap, tmp_path):
    out = tmp_path / "out.parquet"
    assert cli_main(["extract", str(mixed_pcap), "-o", str(out), "--backend", "scapy"]) == 0
    assert list(pd.read_parquet(out).columns) == FEATURE_COLUMNS


def test_unknown_backend_and_missing_file(tmp_path):
    with pytest.raises(ValueError):
        select_backend("bogus")
    with pytest.raises(FileNotFoundError):
        flows_from_pcap(tmp_path / "nope.pcap")


# --- live interface -----------------------------------------------------------------

def _live_interface():
    """An interface we may sniff on, or None. Opt in with IDPS_TEST_IFACE (needs root)."""
    name = os.environ.get("IDPS_TEST_IFACE")
    if not name or not sys.platform.startswith("linux") or os.geteuid() != 0:
        return None
    return name


@pytest.mark.skipif(_live_interface() is None,
                    reason="live capture needs Linux, root and IDPS_TEST_IFACE")
def test_live_and_pcap_have_same_columns(mixed_pcap, backend):
    """Traffic must be generated by the caller while this runs (e.g. a ping); we only check
    that whatever flows come out have the same columns as the PCAP path."""
    live = to_frame(flows_from_interface(_live_interface(), backend=backend, idle_timeout=2,
                                         active_timeout=5, max_flows=1, duration=20))
    pcap = to_frame(flows_from_pcap(mixed_pcap, backend=backend))
    assert list(live.columns) == list(pcap.columns) == FEATURE_COLUMNS


# --- the two backends must agree on edge cases (review findings) ----------------------

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.layers.l2 import Dot1AD, Dot1Q, Ether
from scapy.utils import wrpcap

from idps.capture import check_timeouts
from idps.capture.scapy_flows import FlowTable
from idps.features import (
    check_same_extraction,
    extraction_meta,
    read_features,
    write_features,
)

_MAC = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def _at(layer, t):
    p = Ether(**_MAC) / layer
    p.time = t
    return p


def _udp(t, sport=1234, dport=5678, payload=b"x" * 10, src=CLIENT, dst=SERVER):
    return _at(IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload, t)


def _both(pcap, **kw):
    """Run both backends; return the scapy frame (and assert it equals NFStream's)."""
    b = to_frame(flows_from_pcap(pcap, backend="scapy", **kw))
    if HAVE_NFSTREAM:
        a = to_frame(flows_from_pcap(pcap, backend="nfstream", **kw))
        key = ["start_ms", "src_ip", "src_port"]
        pd.testing.assert_frame_equal(a.sort_values(key).reset_index(drop=True),
                                      b.sort_values(key).reset_index(drop=True),
                                      check_dtype=False, rtol=1e-6)
    return b


def test_sub_millisecond_times_are_truncated(tmp_path):
    pcap = write_pcap(tmp_path / "subms.pcap", [_udp(T0 + 0.0004), _udp(T0 + 0.0016)])
    df = _both(pcap)
    assert df.duration_ms[0] == 1  # 1.6 ms truncated to 1, 0.4 ms truncated to 0


def test_idle_gap_equal_to_timeout_splits(tmp_path):
    pcap = write_pcap(tmp_path / "gap.pcap", [_udp(T0 + i * 5) for i in range(3)])
    assert len(_both(pcap, idle_timeout=5)) == 3


def test_active_timeout_boundary(tmp_path):
    pcap = write_pcap(tmp_path / "beacon.pcap", [_udp(T0 + i) for i in range(12)])
    df = _both(pcap, active_timeout=3)
    assert list(df.fwd_packets) == [3, 3, 3, 3]


def test_only_first_fragment_counts(tmp_path):
    first = _at(IP(src=CLIENT, dst=SERVER, flags="MF", frag=0, id=7)
                / UDP(sport=1234, dport=5678, len=1508) / (b"a" * 1000), T0)
    later = _at(IP(src=CLIENT, dst=SERVER, frag=126, id=7, proto=17) / (b"b" * 500), T0 + 0.001)
    df = _both(write_pcap(tmp_path / "frag.pcap", [first, later]))
    assert len(df) == 1 and df.fwd_packets[0] == 1 and df.dst_port[0] == 5678


def test_ipv6_extension_headers(tmp_path):
    hbh = _at(IPv6(src="fe80::1", dst="fe80::2") / IPv6ExtHdrHopByHop()
              / UDP(sport=7, dport=8) / b"z", T0)
    frag_first = _at(IPv6(src="fe80::1", dst="fe80::3") / IPv6ExtHdrFragment(offset=0, m=1, id=5)
                     / UDP(sport=9, dport=10) / (b"q" * 100), T0 + 0.002)
    frag_later = _at(IPv6(src="fe80::1", dst="fe80::3")
                     / IPv6ExtHdrFragment(offset=20, m=0, id=5, nh=17) / (b"r" * 50), T0 + 0.003)
    df = _both(write_pcap(tmp_path / "v6.pcap", [hbh, frag_first, frag_later]))
    assert sorted(zip(df.protocol, df.src_port, df.dst_port, df.fwd_packets)) == [
        (17, 7, 8, 1), (17, 9, 10, 1)]


def test_timeouts_must_be_whole_seconds():
    for bad in (0, -1, 0.5, 2.5):
        with pytest.raises(ValueError):
            check_timeouts(bad, 120)
    check_timeouts(1, 120.0)


def test_flood_of_new_flows_is_bounded():
    table = FlowTable(idle_timeout=120, active_timeout=120, max_open_flows=100)
    ended = []
    for i in range(1000):
        ended += table.add(_udp(T0 + i * 0.0001, sport=10_000 + i))
    assert len(table._flows) == 100 and table.evicted == 900 and len(ended) == 900


def test_default_backend_is_nfstream_not_silent_fallback(monkeypatch):
    monkeypatch.delenv("IDPS_EXTRACTOR", raising=False)
    if HAVE_NFSTREAM:
        assert select_backend() == "nfstream"
    else:
        with pytest.raises(RuntimeError):
            select_backend()


@pytest.mark.parametrize("suffix", [".parquet", ".csv"])
def test_feature_files_record_extraction(tmp_path, mixed_pcap, suffix):
    df = to_frame(flows_from_pcap(mixed_pcap, backend="scapy"))
    meta = extraction_meta("scapy", 120, 120)
    write_features(df, tmp_path / f"f{suffix}", meta)
    back, got = read_features(tmp_path / f"f{suffix}")
    assert got == meta and list(back.columns) == FEATURE_COLUMNS
    check_same_extraction(meta, got)
    with pytest.raises(ValueError, match="extractor"):
        check_same_extraction(meta, extraction_meta("nfstream", 120, 120))


def test_cli_extract_records_backend(mixed_pcap, tmp_path):
    out = tmp_path / "out.parquet"
    assert cli_main(["extract", str(mixed_pcap), "-o", str(out), "--backend", "scapy"]) == 0
    assert read_features(out)[1]["extractor"] == "scapy"


# --- VLAN ids and out-of-order timestamps (extractor divergence findings) ---------------

def _tagged(t, *vlans, outer_ad=None, sport=1234, rev=False):
    """A UDP packet inside the given 802.1Q tags (outermost first); optionally under 802.1ad."""
    src, dst = (SERVER, CLIENT) if rev else (CLIENT, SERVER)
    sp, dp = (5678, sport) if rev else (sport, 5678)
    p = Ether(**_MAC)
    if outer_ad is not None:
        p = p / Dot1AD(vlan=outer_ad)
    for v in vlans:
        p = p / Dot1Q(vlan=v)
    p = p / IP(src=src, dst=dst) / UDP(sport=sp, dport=dp) / (b"x" * 10)
    p.time = t
    return p


def test_vlan_id_is_part_of_the_flow_key(tmp_path):
    pkts = [_tagged(T0, 10), _tagged(T0 + 0.01, 20), _tagged(T0 + 0.02, 10),
            _tagged(T0 + 0.03), _tagged(T0 + 0.04, 10, rev=True)]
    df = _both(write_pcap(tmp_path / "vlan.pcap", pkts))
    assert sorted(zip(df.fwd_packets, df.bwd_packets)) == [(1, 0), (1, 0), (2, 1)]


def test_vlan_zero_is_untagged_and_innermost_tag_wins(tmp_path):
    df = _both(write_pcap(tmp_path / "v0.pcap", [_tagged(T0), _tagged(T0 + 0.01, 0)]))
    assert len(df) == 1 and df.fwd_packets[0] == 2
    # NFStream keys on the innermost tag: same inner id merges, different inner id splits.
    same_inner = [_tagged(T0, 100, 5), _tagged(T0 + 0.01, 101, 5)]
    assert len(_both(write_pcap(tmp_path / "qq1.pcap", same_inner))) == 1
    other_inner = [_tagged(T0, 100, 5), _tagged(T0 + 0.01, 100, 6)]
    assert len(_both(write_pcap(tmp_path / "qq2.pcap", other_inner))) == 2


def test_8021ad_frames_are_skipped_like_nfstream(tmp_path):
    pkts = [_tagged(T0, 5), _tagged(T0 + 0.01, 5, outer_ad=100)]
    df = _both(write_pcap(tmp_path / "ad.pcap", pkts))
    assert len(df) == 1 and df.fwd_packets[0] == 1


def _unsorted_pcap(path, packets):
    wrpcap(str(path), packets)  # capture order kept as given (write_pcap sorts by time)
    return path


def test_out_of_order_timestamps_match_nfstream(tmp_path):
    ms = lambda v: T0 + v / 1000
    pkts = [_udp(ms(100)), _udp(ms(110), src=SERVER, dst=CLIENT, sport=5678, dport=1234),
            _udp(ms(105)), _udp(ms(130), src=SERVER, dst=CLIENT, sport=5678, dport=1234),
            _udp(ms(120)), _udp(ms(90), src=SERVER, dst=CLIENT, sport=5678, dport=1234)]
    df = _both(_unsorted_pcap(tmp_path / "ooo.pcap", pkts))
    f = df.iloc[0]
    # Start is the first packet in capture order, end the latest time; nothing is negative.
    assert f.start_ms == int(T0 * 1000) + 100 and f.duration_ms == 30
    assert f.iat_min >= 0 and f.fwd_iat_min >= 0 and f.bwd_iat_min >= 0


def test_time_never_goes_backwards_across_flows(tmp_path):
    ms = lambda v: T0 + v / 1000
    pkts = [_udp(ms(100), sport=1), _udp(ms(200), sport=2), _udp(ms(150), sport=1)]
    df = _both(_unsorted_pcap(tmp_path / "xflow.pcap", pkts)).sort_values("src_port")
    assert list(df.duration_ms) == [100, 0] and df.iat_max.iloc[0] == 100
