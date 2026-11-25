"""VPC Flow Log parsing and the NetFlow-style feature rows (local files only, no AWS)."""

import gzip
from pathlib import Path

import pytest

from idps.cloud import flowlogs
from idps.cloud.flowlogs import (
    CLOUD_FEATURE_COLUMNS,
    CLOUD_MODEL_FEATURES,
    FlowLogError,
    ParseStats,
    cloud_extraction_meta,
    parse_lines,
    read_bytes,
    read_path,
    rows_to_frame,
    to_flow_rows,
)

SAMPLE = Path(__file__).parent / "data" / "flowlogs_sample.log"
ACCOUNT = "123456789010"
ENI = "eni-0a1b2c3d4e5f60718"


def line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="22", proto="6",
         pkts="20", byts="4000", start="1700000000", end="1700000060", action="ACCEPT",
         status="OK", version="2"):
    return (f"{version} {ACCOUNT} {ENI} {src} {dst} {sport} {dport} {proto} {pkts} {byts} "
            f"{start} {end} {action} {status}")


def test_sample_file_counts():
    stats = ParseStats()
    records = list(read_path(SAMPLE, stats))
    assert stats.header == 1
    assert stats.no_data == 2  # NODATA and SKIPDATA
    assert stats.malformed == 0
    assert len(records) == stats.records == 6
    assert records[0].src_ip == "203.0.113.12" and records[0].dst_port == 22
    assert records[0].packets == 20 and records[0].byte_count == 4000
    assert records[0].start == 1700000000 and records[0].action == "ACCEPT"


def test_gzip_is_detected_from_content(tmp_path):
    gz = tmp_path / "x.log.gz"
    gz.write_bytes(gzip.compress(SAMPLE.read_bytes()))
    renamed = tmp_path / "no-extension"
    renamed.write_bytes(gz.read_bytes())
    assert list(read_path(gz)) == list(read_path(SAMPLE)) == list(read_path(renamed))
    assert list(read_bytes(gzip.compress(SAMPLE.read_bytes()))) == list(read_path(SAMPLE))


def test_ipv6_records_parse():
    (rec,) = list(parse_lines([line(src="2001:db8::1", dst="2001:DB8::2")]))
    assert (rec.src_ip, rec.dst_ip) == ("2001:db8::1", "2001:db8::2")


def test_ipv4_mapped_ipv6_is_unwrapped():
    (rec,) = list(parse_lines([line(src="::ffff:203.0.113.9")]))
    assert rec.src_ip == "203.0.113.9"


@pytest.mark.parametrize("bad", [
    "garbage",
    line()[:-3],                      # too few fields
    line() + " extra",                # too many
    line(src="not-an-ip"),
    line(sport="70000"),              # port out of range
    line(sport="-5"),
    line(proto="999"),
    line(pkts="x"),
    line(start="yesterday"),
    line(action="MAYBE"),
    line(status="WEIRD"),
    line(version="5"),                # only the default v2 format
])
def test_malformed_lines_are_counted_not_raised(bad):
    stats = ParseStats()
    good = line()
    records = list(parse_lines([bad, good], stats))
    assert records == list(parse_lines([good]))
    assert stats.malformed == 1 and stats.records == 1
    assert stats.errors and stats.errors[0].startswith("line 1:")


def test_blank_and_header_lines_and_nodata():
    stats = ParseStats()
    lines = [
        ("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes "
         "start end action log-status"),
        "", "   ",
        f"2 {ACCOUNT} {ENI} - - - - - - - 1700000060 1700000120 - NODATA",
        f"2 {ACCOUNT} {ENI} - - - - - - - 1700000060 1700000120 - SKIPDATA",
        line(),
    ]
    assert len(list(parse_lines(lines, stats))) == 1
    assert (stats.header, stats.blank, stats.no_data, stats.malformed) == (1, 2, 2, 0)


def test_dash_ports_count_as_zero():
    (rec,) = list(parse_lines([line(sport="-", dport="-", proto="1")]))
    assert (rec.src_port, rec.dst_port) == (0, 0)


def test_corrupt_gzip_raises_flowlogerror():
    data = gzip.compress(b"x" * 5000)[:-20]
    with pytest.raises(FlowLogError):
        list(read_bytes(data))


def test_size_cap_is_enforced():
    with pytest.raises(FlowLogError, match="larger than"):
        list(read_bytes(gzip.compress(line().encode() * 1000), max_bytes=1000))


def test_last_line_without_newline_is_read():
    assert len(list(read_bytes(line().encode()))) == 1


# --- Rows and feature columns -----------------------------------------------------------------

def test_feature_columns_are_stable():
    # Saved models depend on this exact order: changing it is a breaking change.
    assert CLOUD_FEATURE_COLUMNS == [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms", "end_ms",
        "duration_ms", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
        "bytes_per_s", "packets_per_s", "down_up_ratio",
        "fwd_pkt_len_mean", "bwd_pkt_len_mean", "rejected",
    ]
    assert set(CLOUD_MODEL_FEATURES) <= set(CLOUD_FEATURE_COLUMNS)
    assert not {"src_ip", "dst_ip", "src_port", "start_ms", "end_ms"} & set(CLOUD_MODEL_FEATURES)
    meta = cloud_extraction_meta()
    assert meta["feature_columns"] == CLOUD_FEATURE_COLUMNS
    assert meta["extractor"] == flowlogs.CLOUD_EXTRACTOR


def test_directions_are_paired_into_one_row():
    rows = to_flow_rows(read_path(SAMPLE))
    ssh = next(r for r in rows if r["dst_port"] == 22)
    assert (ssh["src_ip"], ssh["src_port"]) == ("203.0.113.12", 44321)  # higher port = initiator
    assert (ssh["fwd_packets"], ssh["bwd_packets"]) == (20, 18)
    assert (ssh["fwd_bytes"], ssh["bwd_bytes"]) == (4000, 3600)
    assert ssh["duration_ms"] == 60_000
    assert ssh["start_ms"] == 1_700_000_000_000 and ssh["end_ms"] == 1_700_000_060_000
    assert ssh["bytes_per_s"] == pytest.approx(7600 / 60)
    assert ssh["packets_per_s"] == pytest.approx(38 / 60)
    assert ssh["down_up_ratio"] == pytest.approx(0.9)
    assert ssh["fwd_pkt_len_mean"] == pytest.approx(200)
    assert ssh["rejected"] == 0
    assert len(rows) == 5  # ssh pair, 2 rejects, ipv6, icmp


def test_unpaired_reject_and_zero_length_window():
    rows = to_flow_rows(read_path(SAMPLE))
    rdp = next(r for r in rows if r["dst_port"] == 3389)
    assert rdp["rejected"] == 1 and rdp["bwd_packets"] == 0 and rdp["down_up_ratio"] == 0.0
    icmp = next(r for r in rows if r["protocol"] == 1)
    assert icmp["duration_ms"] == 0
    assert icmp["bytes_per_s"] == 0.0 and icmp["packets_per_s"] == 0.0  # not infinite


def test_pairing_can_be_switched_off():
    assert len(to_flow_rows(read_path(SAMPLE), pair_directions=False)) == 6


def test_frame_has_exactly_the_columns_in_order():
    df = rows_to_frame(to_flow_rows(read_path(SAMPLE)))
    assert list(df.columns) == CLOUD_FEATURE_COLUMNS
    assert df[CLOUD_MODEL_FEATURES].notna().all().all()
    empty = rows_to_frame([])
    assert list(empty.columns) == CLOUD_FEATURE_COLUMNS and len(empty) == 0


def test_rows_are_sorted_and_deterministic():
    records = list(read_path(SAMPLE))
    assert to_flow_rows(records) == to_flow_rows(reversed(records))


def test_end_before_start_is_clamped():
    (row,) = to_flow_rows(parse_lines([line(start="1700000100", end="1700000050")]))
    assert row["end_ms"] == row["start_ms"] and row["duration_ms"] == 0


def test_cli_parse(capsys):
    from idps.cloud.__main__ import main

    assert main(["parse", str(SAMPLE), "--rows", "2"]) == 0
    out = capsys.readouterr().out
    assert '"records": 6' in out and '"no_data": 2' in out
    assert main(["parse", str(SAMPLE.parent / "missing.log")]) == 1


# --- Pairing with real-world timestamps --------------------------------------------------------
# In real VPC Flow Logs the two directions of a connection are separate records whose start and
# end are the first and last packet seen in each direction: they differ by a second or two.

def test_directions_with_different_start_and_end_still_pair():
    lines = [
        line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="443",
             pkts="20", byts="4000", start="1700000003", end="1700000058"),
        line(src="10.60.1.10", dst="203.0.113.12", sport="443", dport="44321",
             pkts="18", byts="3600", start="1700000004", end="1700000059"),
    ]
    (row,) = to_flow_rows(parse_lines(lines))
    assert (row["src_ip"], row["src_port"], row["dst_port"]) == ("203.0.113.12", 44321, 443)
    assert (row["fwd_packets"], row["bwd_packets"]) == (20, 18)
    assert (row["fwd_bytes"], row["bwd_bytes"]) == (4000, 3600)
    assert row["start_ms"] == 1_700_000_003_000 and row["end_ms"] == 1_700_000_059_000


def test_pairing_does_not_depend_on_record_order_or_which_direction_is_first():
    lines = [
        line(src="10.60.1.10", dst="203.0.113.12", sport="22", dport="44321",
             pkts="18", byts="3600", start="1700000001", end="1700000059"),
        line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="22",
             pkts="20", byts="4000", start="1700000002", end="1700000058"),
    ]
    forward = to_flow_rows(parse_lines(lines))
    assert forward == to_flow_rows(parse_lines(reversed(lines)))
    assert len(forward) == 1 and forward[0]["src_port"] == 44321  # service port is not the initiator


def test_directions_on_either_side_of_a_window_boundary_pair_when_the_intervals_overlap():
    # 1700000040 is a multiple of 60: the two starts fall into different aligned minutes.
    lines = [
        line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="80",
             start="1700000038", end="1700000044"),
        line(src="10.60.1.10", dst="203.0.113.12", sport="80", dport="44321",
             start="1700000041", end="1700000045"),
    ]
    assert len(to_flow_rows(parse_lines(lines))) == 1


def test_consecutive_windows_of_one_connection_stay_separate_rows():
    lines = []
    for base in (1700000000, 1700000060):
        lines += [
            line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="443",
                 start=str(base + 1), end=str(base + 57)),
            line(src="10.60.1.10", dst="203.0.113.12", sport="443", dport="44321",
                 start=str(base + 2), end=str(base + 58)),
        ]
    rows = to_flow_rows(parse_lines(lines))
    assert len(rows) == 2 and all(r["bwd_packets"] > 0 for r in rows)


def test_other_interfaces_protocols_and_ports_are_never_paired():
    a = line(src="203.0.113.12", dst="10.60.1.10", sport="44321", dport="443")
    other_eni = line(src="10.60.1.10", dst="203.0.113.12", sport="443", dport="44321").replace(ENI, "eni-0ffffffffffffffff")
    other_proto = line(src="10.60.1.10", dst="203.0.113.12", sport="443", dport="44321", proto="17")
    other_port = line(src="10.60.1.10", dst="203.0.113.12", sport="443", dport="44322")
    assert len(to_flow_rows(parse_lines([a, other_eni, other_proto, other_port]))) == 4


def test_the_service_port_side_is_not_taken_as_initiator_even_with_a_higher_source_port():
    # Both ports are above 1023 here: the higher source port starts the connection.
    lines = [
        line(src="203.0.113.12", dst="10.60.1.10", sport="52000", dport="8080", start="1700000001", end="1700000050"),
        line(src="10.60.1.10", dst="203.0.113.12", sport="8080", dport="52000", start="1700000002", end="1700000051"),
    ]
    (row,) = to_flow_rows(parse_lines(lines))
    assert (row["src_ip"], row["dst_port"]) == ("203.0.113.12", 8080)
    # A well-known destination port wins over the port-number comparison.
    lines = [
        line(src="203.0.113.12", dst="10.60.1.10", sport="1030", dport="25", start="1700000001", end="1700000050"),
        line(src="10.60.1.10", dst="203.0.113.12", sport="25", dport="1030", start="1700000002", end="1700000051"),
    ]
    (row,) = to_flow_rows(parse_lines(lines))
    assert row["dst_port"] == 25


# --- Bounds on the integers --------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("start", "99999999999"), ("end", "4102444801"), ("pkts", str(2**41)),
    ("byts", str(2**51)), ("byts", "9" * 5000), ("start", "1" * 30),
])
def test_absurd_integers_make_the_line_malformed(field, value):
    stats = ParseStats()
    assert list(parse_lines([line(**{field: value})], stats)) == []
    assert stats.malformed == 1 and stats.errors[0].startswith("line 1:")
    assert len(stats.errors[0]) < 200  # the huge number is not echoed back


def test_the_largest_accepted_values_convert_without_overflow():
    (row,) = to_flow_rows(parse_lines([line(start="4102444800", end="4102444800",
                                            pkts=str(2**40), byts=str(2**50))]))
    df = rows_to_frame([row])
    assert df[CLOUD_MODEL_FEATURES].astype(float).notna().all().all()


def test_decompressed_size_cap_is_64_mb():
    assert flowlogs.DEFAULT_MAX_BYTES == 64 * 1024 * 1024
