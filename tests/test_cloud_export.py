"""Step C3: the live flow-log exporter (idps.cloud.flowlog_export).

Everything here is offline: synthetic pcaps (tests/pcap_factory.py), a stub S3 and a fake capture
socket. The last test talks to the local Moto emulator and is skipped when it is not running.
"""

import gzip
import io
import os
import re
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from pcap_factory import CLIENT, SERVER, T0, _pkt, tcp_session, write_pcap
from scapy.layers.inet import ICMP, IP, TCP, UDP

from idps.cloud import flowlog_export as fx
from idps.cloud import flowlogs
from idps.cloud.__main__ import main
from idps.cloud.collector import Checkpoint, Collector, CollectorConfig, list_new_objects

ACCOUNT = "000000000000"
REGION = "eu-west-1"
BUCKET = "idps-fyp-flowlogs-000000000000"
MINUTE = 60
BOUNDARY = (int(T0) // MINUTE + 1) * MINUTE  # 1_700_000_040: the next whole minute after T0

KEY_RE = re.compile(
    r"^AWSLogs/000000000000/vpcflowlogs/eu-west-1/(\d{4})/(\d{2})/(\d{2})/"
    r"000000000000_vpcflowlogs_eu-west-1_fl-[0-9a-f]{17}_(\d{8})T(\d{4})Z_[0-9a-f]{8}\.log\.gz$"
)


# --- helpers ------------------------------------------------------------------------------------


class StubS3:
    """The few S3 calls the shipper and the collector make, with S3's error codes."""

    def __init__(self, bucket_exists=True):
        self.bucket_exists = bucket_exists
        self.objects = {}
        self.modified = {}
        self.calls = []

    def _err(self, code, op):
        return ClientError({"Error": {"Code": code, "Message": code}}, op)

    def head_bucket(self, Bucket):
        self.calls.append("head_bucket")
        if not self.bucket_exists:
            raise self._err("404", "HeadBucket")

    def head_object(self, Bucket, Key):
        self.calls.append("head_object")
        if not self.bucket_exists:
            raise self._err("NoSuchBucket", "HeadObject")
        if Key not in self.objects:
            raise self._err("404", "HeadObject")

    def put_object(self, Bucket, Key, Body, **_):
        self.calls.append("put_object")
        if not self.bucket_exists:
            raise self._err("NoSuchBucket", "PutObject")
        self.objects[Key] = Body
        self.modified[Key] = datetime.now(UTC)

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        self.calls.append("list_objects_v2")
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        return {
            "Contents": [{"Key": k, "LastModified": self.modified[k]} for k in keys],
            "IsTruncated": False,
        }

    def get_object(self, Bucket, Key):
        data = self.objects[Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data)}


class AllowGuard:
    def problems(self, env):
        return []


def config(**kw):
    return fx.ExportConfig(**kw)


def export_pcap(tmp_path, packets, cfg=None, name="in.pcap"):
    pcap = write_pcap(tmp_path / name, packets)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    paths = fx.export_packets(fx.read_pcap(pcap), cfg or config(), out, "aaaaaaaa")
    return out, paths


def records_of(paths):
    out = []
    for path in sorted(paths):
        out += list(flowlogs.parse_lines(path.read_text().splitlines()))
    return out


def ship(out, tmp_path, s3=None, **kw):
    s3 = s3 or StubS3()
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "state", **kw), s3)
    return shipper, s3, shipper.ship_once()


def syn(sport, dport, t, src=CLIENT, dst=SERVER, flags="S"):
    return _pkt(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags), t)


# --- aggregation: counts, directions, ACCEPT/REJECT ----------------------------------------------


def test_normal_web_session_counts_and_directions(tmp_path):
    _out, paths = export_pcap(tmp_path, tcp_session())
    assert len(paths) == 1
    by_src = {r.src_ip: r for r in records_of(paths)}
    assert set(by_src) == {CLIENT, SERVER}
    up, down = by_src[CLIENT], by_src[SERVER]
    # tcp_session: client sends 6 packets (5 bare = 40 B, one with 100 B data = 140 B)
    assert (up.packets, up.byte_count) == (6, 5 * 40 + 140)
    assert (up.src_port, up.dst_port, up.protocol) == (40000, 80, 6)
    assert (down.packets, down.byte_count) == (4, 3 * 40 + 540)
    assert (down.src_port, down.dst_port) == (80, 40000)
    assert up.action == down.action == "ACCEPT"
    assert up.start == up.end == T0 and up.log_status == "OK"
    assert up.account_id == ACCOUNT and up.interface_id == down.interface_id
    assert up.interface_id.startswith("eni-")


def test_port_scan_gives_reject_for_closed_ports_and_drops_the_lab_resets(tmp_path):
    t = T0 + 1
    packets = []
    for i, port in enumerate(range(1, 201)):
        packets.append(syn(50000, port, t + i * 0.01))
        if port in (22, 80):
            packets.append(
                syn(port, 50000, t + i * 0.01 + 0.001, src=SERVER, dst=CLIENT, flags="SA")
            )
        else:  # the lab victim answers a closed port with RST
            packets.append(
                syn(port, 50000, t + i * 0.01 + 0.001, src=SERVER, dst=CLIENT, flags="RA")
            )
    _, paths = export_pcap(tmp_path, packets)
    recs = records_of(paths)
    inbound = [r for r in recs if r.dst_ip == SERVER]
    outbound = [r for r in recs if r.src_ip == SERVER]
    assert len(inbound) == 200
    assert {r.dst_port for r in inbound if r.action == "ACCEPT"} == {22, 80}
    assert sum(r.action == "REJECT" for r in inbound) == 198
    # Behind a real security group the victim never saw the rejected SYNs: no RST records.
    assert {r.src_port for r in outbound} == {22, 80}
    assert all(r.action == "ACCEPT" for r in outbound)
    assert all(r.packets == 1 and r.byte_count == 40 for r in recs)
    rows = flowlogs.to_flow_rows(recs)
    assert sum(r["rejected"] for r in rows) == 198


def test_syn_flood_is_one_record_per_source_port_and_one_for_a_fixed_port(tmp_path):
    packets = [syn(1024 + i, 80, T0 + i * 0.01) for i in range(500)]  # distinct source ports
    packets += [syn(4444, 9999, T0 + i * 0.01) for i in range(1000)]  # one source port, closed port
    _, paths = export_pcap(tmp_path, packets)
    recs = records_of(paths)
    web = [r for r in recs if r.dst_port == 80]
    assert len(web) == 500 and all(r.packets == 1 and r.action == "ACCEPT" for r in web)
    (closed,) = [r for r in recs if r.dst_port == 9999]
    assert (closed.packets, closed.byte_count, closed.action) == (1000, 40_000, "REJECT")
    assert closed.start == T0 and closed.end == T0 + 9  # 1000 packets at 10 ms: T0 .. T0+9.99


def test_window_split_at_the_minute_boundary(tmp_path):
    # Two packets before the boundary, one exactly on it, one after: same 5-tuple.
    times = [BOUNDARY - 2, BOUNDARY - 1, BOUNDARY, BOUNDARY + 5]
    packets = [syn(5555, 80, t + 0.5 if t < BOUNDARY else t) for t in times]
    _, paths = export_pcap(tmp_path, packets)
    assert len(paths) == 2
    first, second = sorted(paths)
    assert first.name.startswith("20231114T2213Z") and second.name.startswith("20231114T2214Z")
    (a,) = records_of([first])
    (b,) = records_of([second])
    assert (a.packets, a.start, a.end) == (2, BOUNDARY - 2, BOUNDARY - 1)
    assert (b.packets, b.start, b.end) == (2, BOUNDARY, BOUNDARY + 5)
    # a long connection shows up once per window and pairs up again in the rows
    assert len(flowlogs.to_flow_rows([a, b])) == 2


def test_custom_allow_list_and_victim_initiated_traffic():
    cfg = config(allow_tcp_ports=frozenset({8080}))
    agg = fx.Aggregator(cfg)
    ip = lambda s: int.from_bytes(socket.inet_aton(s), "big")
    cl, sv = ip(CLIENT), ip(SERVER)
    P = fx.Packet
    agg.add(P(T0, cl, sv, 6, 40000, 8080, 60))  # allowed port
    agg.add(P(T0, cl, sv, 6, 40000, 80, 60))  # 80 is not allowed in this config
    agg.add(P(T0, sv, cl, 6, 41000, 443, 60))  # the victim opens a connection: egress is open
    agg.add(P(T0, cl, sv, 6, 443, 41000, 60))  # ... and the answer is let back in
    agg.add(P(T0, cl, ip("203.0.113.9"), 6, 1, 2, 60))  # neither end is the victim
    agg.add(P(T0, sv, ip("10.10.2.11"), 6, 1, 2, 60))  # both ends are
    (lines,) = agg.pop_all().values()
    actions = {(rec.src_ip, rec.dst_port): rec.action for rec in flowlogs.parse_lines(lines)}
    assert actions == {
        (CLIENT, 8080): "ACCEPT",
        (CLIENT, 80): "REJECT",
        (SERVER, 443): "ACCEPT",
        (CLIENT, 41000): "ACCEPT",
    }
    assert agg.packets_ignored == 2


def test_ping_is_rejected_by_default_and_its_reply_dropped():
    agg = fx.Aggregator(config())
    ip = lambda s: int.from_bytes(socket.inet_aton(s), "big")
    cl, sv = ip(CLIENT), ip(SERVER)
    agg.add(fx.Packet(T0, cl, sv, 1, 0, 0, 48, icmp_type=8))
    agg.add(fx.Packet(T0, sv, cl, 1, 0, 0, 48, icmp_type=0))  # echo reply: the lab victim's answer
    agg.add(fx.Packet(T0, sv, cl, 1, 0, 0, 56, icmp_type=3))  # port unreachable
    (lines,) = agg.pop_all().values()
    (rec,) = flowlogs.parse_lines(lines)
    assert (rec.src_ip, rec.action, rec.protocol, rec.src_port, rec.dst_port) == (
        CLIENT,
        "REJECT",
        1,
        0,
        0,
    )


def test_window_cap_counts_skipped_records():
    agg = fx.Aggregator(config(max_records_per_window=3))
    ip = lambda s: int.from_bytes(socket.inet_aton(s), "big")
    for sport in range(10):
        agg.add(fx.Packet(T0, ip(CLIENT), ip(SERVER), 6, 2000 + sport, 80, 40))
    assert agg.skipped_records == 7
    assert len(next(iter(agg.windows.values()))) == 3


def test_pop_finished_waits_for_the_grace_period():
    agg = fx.Aggregator(config())
    ip = lambda s: int.from_bytes(socket.inet_aton(s), "big")
    agg.add(fx.Packet(BOUNDARY - 5, ip(CLIENT), ip(SERVER), 6, 1000, 80, 40))
    assert agg.pop_finished(BOUNDARY + 1) == {}
    assert list(agg.pop_finished(BOUNDARY + fx.FLUSH_GRACE_SECONDS)) == [BOUNDARY - MINUTE]
    assert agg.windows == {}


def test_non_ip_and_short_frames_are_ignored():
    assert fx.parse_frame(b"\x00" * 10, T0) is None
    arp = bytes(6) + bytes(6) + b"\x08\x06" + bytes(28)
    assert fx.parse_frame(arp, T0) is None
    assert fx.parse_frame(b"x" * 40, T0, linktype=147) is None


def test_udp_and_icmp_ports_in_pcap(tmp_path):
    packets = [
        _pkt(IP(src=CLIENT, dst=SERVER) / UDP(sport=5000, dport=53) / (b"q" * 30), T0),
        _pkt(IP(src=CLIENT, dst=SERVER) / ICMP() / (b"x" * 20), T0 + 1),
    ]
    _, paths = export_pcap(tmp_path, packets)
    udp, icmp = sorted(records_of(paths), key=lambda r: r.protocol)[::-1]
    assert (udp.protocol, udp.dst_port, udp.byte_count, udp.action) == (17, 53, 58, "REJECT")
    assert (icmp.protocol, icmp.src_port, icmp.dst_port, icmp.action) == (1, 0, 0, "REJECT")


def test_config_validation():
    with pytest.raises(fx.ExportError):
        config(account="123")
    with pytest.raises(fx.ExportError):
        config(victim_hosts=(), victim_cidr="not-a-cidr")
    assert config().interface_id == fx.default_interface_id()
    assert fx.default_flow_log_id() == fx.default_flow_log_id()  # fixed, not random


# --- window files, key layout and the parser round trip -----------------------------------------


def test_key_layout_gzip_content_and_round_trip_through_the_parser(tmp_path):
    out, paths = export_pcap(tmp_path, tcp_session() + [syn(50000, 3306, T0 + 2)])
    _, s3, result = ship(out, tmp_path)
    assert len(result.shipped) == 1
    (key,) = s3.objects
    match = KEY_RE.match(key)
    assert match, key
    assert match.group(1, 2, 3) == ("2023", "11", "14") and match.group(4, 5) == (
        "20231114",
        "2213",
    )
    raw = s3.objects[key]
    assert raw[:2] == b"\x1f\x8b"
    text = gzip.decompress(raw).decode()
    lines = text.splitlines()
    assert lines[0] == (
        "version account-id interface-id srcaddr dstaddr srcport dstport protocol "
        "packets bytes start end action log-status"
    )
    assert all(len(line.split()) == 14 for line in lines)
    # the parser reads it all, no malformed line, and the files' records survive unchanged
    stats = flowlogs.ParseStats()
    records = list(flowlogs.read_bytes(raw, stats))
    assert stats.header == 1 and stats.malformed == 0 and stats.records == 3
    assert records == records_of(paths)
    rows = flowlogs.to_flow_rows(records)
    web = next(r for r in rows if r["dst_port"] == 80)
    assert (web["fwd_packets"], web["bwd_packets"], web["rejected"]) == (6, 4, 0)
    assert web["fwd_bytes"] == 340 and web["bwd_bytes"] == 660
    assert next(r for r in rows if r["dst_port"] == 3306)["rejected"] == 1
    assert list(flowlogs.rows_to_frame(rows).columns) == flowlogs.CLOUD_FEATURE_COLUMNS


def test_collector_lists_and_reads_what_the_shipper_wrote(tmp_path):
    now = int(time.time())
    t0 = now - 600
    out, _ = export_pcap(tmp_path, tcp_session(t0=t0) + [syn(50000, 3306, t0 + 2)])
    _, s3, _ = ship(out, tmp_path)
    prefix = fx.key_prefix(ACCOUNT, REGION)
    cfg = CollectorConfig(bucket=BUCKET, prefix=prefix, region=REGION, state_dir=tmp_path / "cs")
    cfg.validate()
    found = list_new_objects(
        s3,
        BUCKET,
        cfg.prefix,
        Checkpoint(tmp_path / "cp.json"),
        datetime.now(UTC),
        timedelta(hours=1),
        settle=timedelta(0),
    )
    assert [o["Key"] for o in found] == list(s3.objects)
    result = Collector(cfg, s3, now=lambda: datetime.now(UTC) + timedelta(seconds=400)).run_once()
    assert result.objects == 1 and result.records == 3 and result.malformed == 0
    assert result.rows == 2


def test_two_runs_in_one_window_never_overwrite_each_other(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    fx.write_window(out, BOUNDARY, ["x"], "aaaaaaaa")
    fx.write_window(out, BOUNDARY, ["y"], "aaaaaaaa")
    assert len(list(out.glob("*.flows"))) == 2
    assert fx.write_window(out, BOUNDARY, [], "aaaaaaaa") is None


def test_prune_old_removes_only_old_window_files(tmp_path):
    old = fx.write_window(tmp_path, BOUNDARY, ["x"], "aaaaaaaa")
    new = fx.write_window(tmp_path, BOUNDARY + 600, ["y"], "bbbbbbbb")
    os.utime(old, (T0, T0))
    assert fx.prune_old(tmp_path, keep_hours=1) == 1
    assert not old.exists() and new.exists()


# --- shipping: idempotence, bad files, refusals -------------------------------------------------


def test_shipping_twice_and_after_a_restart_does_not_duplicate(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())
    shipper, s3, first = ship(out, tmp_path)
    assert len(first.shipped) == 1
    again = shipper.ship_once()
    assert again.shipped == [] and again.already == 1
    # "restart": a new Shipper with the same state folder
    restarted = fx.Shipper(shipper.config, s3)
    assert restarted.ship_once().shipped == []
    assert s3.calls.count("put_object") == 1
    # state lost: the deterministic key is found in the bucket, still no second PUT
    (tmp_path / "state" / "shipped.json").unlink()
    fresh = fx.Shipper(shipper.config, s3)
    result = fresh.ship_once()
    assert result.shipped == [] and result.already == 1
    assert s3.calls.count("put_object") == 1 and len(s3.objects) == 1


def test_a_new_window_file_ships_next_cycle(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())
    shipper, s3, _ = ship(out, tmp_path)
    fx.write_window(
        out,
        BOUNDARY + 120,
        [
            f"2 {ACCOUNT} eni-0 10.10.1.5 10.10.2.10 1 80 6 1 40 {BOUNDARY + 121} {BOUNDARY + 121} ACCEPT OK"
        ],
        "cccccccc",
    )
    result = shipper.ship_once()
    assert len(result.shipped) == 1 and len(s3.objects) == 2


def test_unreadable_or_foreign_files_are_not_shipped(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    good = f"2 {ACCOUNT} eni-0 10.10.1.5 10.10.2.10 1 80 6 1 40 {BOUNDARY} {BOUNDARY} ACCEPT OK"
    (out / "20231114T2214Z-aaaaaaaa.flows").write_text(good + "\nthis is not a record\n")
    (out / "20231114T2214Z-bbbbbbbb.flows").write_text(good.replace(ACCOUNT, "123456789012") + "\n")
    (out / "20231114T2214Z-cccccccc.flows").write_text(
        good.replace(f"{BOUNDARY} {BOUNDARY}", f"{BOUNDARY - 600} {BOUNDARY - 600}") + "\n"
    )
    (out / "garbage.flows").write_text(good + "\n")
    (out / "20231114T2214Z-dddddddd.flows.tmp").write_text(good + "\n")  # half-written: ignored
    shipper, s3, result = ship(out, tmp_path)
    assert result.shipped == [] and result.bad == 4 and s3.objects == {}
    assert shipper.ship_once().bad == 4  # remembered, not retried loudly


def test_s3_failure_is_retried_next_cycle(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())

    class Flaky(StubS3):
        fail = True

        def put_object(self, **kw):
            if self.fail:
                raise self._err("InternalError", "PutObject")
            return super().put_object(**kw)

    flaky = Flaky()
    sh = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "s2"), flaky)
    assert sh.ship_once().failed == 1
    flaky.fail = False
    assert len(sh.ship_once().shipped) == 1


def test_guard_refuses_real_looking_credentials_and_ships_nothing(tmp_path, capsys):
    out, _ = export_pcap(tmp_path, tcp_session())
    s3 = StubS3()
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP",
        "AWS_SECRET_ACCESS_KEY": "s",
        "AWS_ENDPOINT_URL": "http://127.0.0.1:4566",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    }
    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"), env, once=True, s3=s3
    )
    assert code == 1 and s3.calls == []
    err = capsys.readouterr().err
    assert "REFUSED" in err and "real AWS key" in err


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://s3.eu-west-1.amazonaws.com",
        "http://127.0.0.1:4567",
        "http://example.com:4566",
        "",
    ],
)
def test_guard_refuses_any_endpoint_but_the_emulator(tmp_path, capsys, endpoint):
    s3 = StubS3()
    env = {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_ENDPOINT_URL": endpoint,
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    }
    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=tmp_path, state_dir=tmp_path / "st"), env, once=True, s3=s3
    )
    assert code == 1 and s3.calls == []
    assert "REFUSED" in capsys.readouterr().err


def test_guard_refuses_when_the_endpoint_is_not_moto_or_the_account_is_wrong(tmp_path, capsys):
    real_guard = fx.load_guard()
    env = {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_ENDPOINT_URL": "http://10.10.4.10:4566",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    }

    class Guard:
        def __init__(self, **kw):
            self.kw = kw

        def problems(self, e):
            return real_guard.problems(e, **self.kw)

    cfg = fx.ShipperConfig(in_dir=tmp_path, state_dir=tmp_path / "st")
    for guard, text in [
        (Guard(probe=lambda ep: False), "not answering as Moto"),
        (
            Guard(probe=lambda ep: True, account_of=lambda e: "123456789012"),
            "expected the emulator account",
        ),
    ]:
        s3 = StubS3()
        assert fx.run_shipper(cfg, env, once=True, guard=guard, s3=s3) == 1
        assert s3.calls == []
        assert text in capsys.readouterr().err
    # and the same environment passes when Moto answers with the emulator account
    ok = Guard(probe=lambda ep: True, account_of=lambda e: ACCOUNT)
    assert real_guard.problems(env, probe=lambda ep: True, account_of=lambda e: ACCOUNT) == []
    assert fx.run_shipper(cfg, env, once=True, guard=ok, s3=StubS3()) == 0


def test_missing_bucket_stops_with_a_clear_message_and_never_creates_it(tmp_path, capsys):
    out, _ = export_pcap(tmp_path, tcp_session())
    s3 = StubS3(bucket_exists=False)
    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"),
        {},
        once=True,
        guard=AllowGuard(),
        s3=s3,
    )
    assert code == 3
    err = capsys.readouterr().err
    assert BUCKET in err and "lab/cloud/tf.sh apply" in err
    assert "put_object" not in s3.calls and not hasattr(s3, "create_bucket")
    assert not s3.objects


def test_bucket_deleted_while_running_also_stops(tmp_path, capsys):
    out, _ = export_pcap(tmp_path, tcp_session())
    s3 = StubS3()
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"), s3)
    s3.bucket_exists = False
    with pytest.raises(fx.BucketMissing, match="tf.sh apply"):
        shipper.ship_once()


# --- command line --------------------------------------------------------------------------------


def test_cli_offline_then_ship_refuses_without_the_fake_credentials(tmp_path, monkeypatch, capsys):
    pcap = write_pcap(tmp_path / "in.pcap", tcp_session())
    out = tmp_path / "out"
    assert main(["export", "offline", "--pcap", str(pcap), "--out", str(out)]) == 0
    assert len(list(out.glob("*.flows"))) == 1
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAABCDEFGHIJKLMNOP")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "whatever")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://s3.amazonaws.com")
    code = main(["export", "ship", "--once", "--in", str(out), "--state-dir", str(tmp_path / "st")])
    assert code == 1
    assert "REFUSED" in capsys.readouterr().err
    assert not (tmp_path / "st" / "shipped.json").exists()


def test_cli_rejects_bad_settings(tmp_path, capsys):
    pcap = write_pcap(tmp_path / "in.pcap", tcp_session())
    assert (
        main(
            [
                "export",
                "offline",
                "--pcap",
                str(pcap),
                "--out",
                str(tmp_path / "o"),
                "--allow-ports",
                "80,notaport",
            ]
        )
        == 1
    )
    assert "bad port list" in capsys.readouterr().err
    assert (
        main(
            [
                "export",
                "offline",
                "--pcap",
                str(pcap),
                "--out",
                str(tmp_path / "o"),
                "--victim-cidr",
                "bogus",
            ]
        )
        == 1
    )


# --- the live writer loop, with a fake capture socket ------------------------------------------------


class FakeSock:
    def __init__(self, frames, clock_state):
        self.frames, self.state, self.closed = list(frames), clock_state, False

    def recv(self, n):
        if not self.frames:
            raise TimeoutError
        ts, frame = self.frames.pop(0)
        self.state["t"] = ts
        return frame

    def close(self):
        self.closed = True


def test_writer_loop_writes_finished_windows_and_the_partial_one_at_stop(tmp_path):
    state = {"t": float(T0)}
    frames = [(p.time, bytes(p)) for p in tcp_session()]
    frames += [(BOUNDARY + 70.0, bytes(syn(5555, 80, BOUNDARY + 70)))]  # a later minute
    sock = FakeSock(frames, state)
    out = tmp_path / "out"
    fx.run_writer(
        config(),
        "lab_attack",
        out,
        run_id="deadbeef",
        drop=False,
        alive_file=None,
        stop=lambda: not sock.frames,
        sock=sock,
        clock=lambda: state["t"],
    )
    names = sorted(p.name for p in out.glob("*.flows"))
    assert names == ["20231114T2213Z-deadbeef.flows", "20231114T2215Z-deadbeef.flows"]
    assert sock.closed
    assert len(records_of(sorted(out.glob("*.flows"))[:1])) == 2


def test_live_capture_needs_linux_or_says_so(monkeypatch):
    monkeypatch.delattr(socket, "AF_PACKET", raising=False)
    with pytest.raises(fx.ExportError, match="Linux"):
        fx.open_capture_socket("lab_attack")


# --- optional: the real emulator -----------------------------------------------------------------------


def _emulator_up():
    try:
        socket.create_connection(("127.0.0.1", 4566), timeout=1).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _emulator_up(), reason="the Moto emulator is not running on 127.0.0.1:4566")
def test_live_emulator_round_trip(tmp_path, monkeypatch):
    for name in list(os.environ):
        if name.startswith(("AWS_", "HTTP", "http", "ALL_PROXY", "all_proxy")):
            monkeypatch.delenv(name)
    for name, value in {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_REGION": REGION,
        "AWS_ENDPOINT_URL": "http://127.0.0.1:4566",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "NO_PROXY": "127.0.0.1",
    }.items():
        monkeypatch.setenv(name, value)
    s3 = fx.make_s3_client(os.environ)
    try:
        s3.head_bucket(Bucket=BUCKET)
    except Exception:  # noqa: BLE001
        pytest.skip("the flow-log bucket does not exist (run lab/cloud/tf.sh apply)")
    out, _ = export_pcap(tmp_path, tcp_session())
    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"), os.environ, once=True
    )
    assert code == 0
    prefix = fx.key_prefix(ACCOUNT, REGION) + "2023/11/14/"
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET, Prefix=prefix).get("Contents", [])]
    try:
        assert keys and all(KEY_RE.match(k) for k in keys)
        body = s3.get_object(Bucket=BUCKET, Key=keys[-1])["Body"].read()
        assert len(list(flowlogs.read_bytes(body))) == 2
    finally:
        for key in keys:
            s3.delete_object(Bucket=BUCKET, Key=key)


# --- the compose services: the isolation argument, checked statically --------------------------------


def _service_block(text, name):
    """The text of one top-level service in lab/cloud/docker-compose.yml (no YAML library needed)."""
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, re.DOTALL | re.MULTILINE)
    assert match, name
    return "\n".join(ln for ln in match.group(1).splitlines() if not ln.lstrip().startswith("#"))


def test_compose_keeps_the_writer_in_the_lab_and_the_shipper_in_the_cloud():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    text = (root / "lab" / "cloud" / "docker-compose.yml").read_text()
    writer = _service_block(text, "flowlog-writer")
    shipper = _service_block(text, "flowlog-shipper")
    net = _service_block(text, "flowlog-shipper-net")
    # writer: the sensor's namespace, read-only capture, no NET_ADMIN, nothing but a local folder
    assert 'network_mode: "container:idps-sensor"' in writer
    assert "cap_drop: [ALL]" in writer and "cap_add: [NET_RAW, SETUID, SETGID]" in writer
    assert "NET_ADMIN" not in writer and "read_only: true" in writer and "mem_limit: 256m" in writer
    assert "networks:" not in writer and "ports:" not in writer
    # shipper: cloud_net only (through its own locked namespace), the folder read-only, fake creds
    assert 'network_mode: "service:flowlog-shipper-net"' in shipper
    assert "networks:" not in shipper and "cap_add" not in shipper and "cap_drop: [ALL]" in shipper
    assert "cloud_net:" in net and "ipv4_address: 10.10.4.20" in net
    assert "mem_limit: 128m" in shipper and "read_only: true" in shipper
    assert "flowlog_out:/var/lib/flowlog-out:ro" in shipper
    assert "AWS_ACCESS_KEY_ID: test" in shipper and "AWS_SECRET_ACCESS_KEY: test" in shipper
    assert "AWS_ENDPOINT_URL: http://10.10.4.10:4566" in shipper
    # crash recovery: both restart on failure, both have a healthcheck that needs a live loop
    assert "restart: on-failure" in writer and "restart: on-failure" in shipper
    assert "healthcheck:" in writer and "healthcheck:" in shipper and "/tmp/alive" in shipper
    assert "IDPS_FLOWLOG_ALIVE_FILE: /tmp/alive" in shipper
    assert "IDPS_FLOWLOG_VICTIM_HOSTS" in writer and "10.10.2.10 10.10.2.11" in writer
    # neither service is on a lab network, and the lab's own compose file does not mention them
    assert "flowlog" not in (root / "lab" / "docker-compose.yml").read_text()
    # (C4: the file now also declares mgmt_net for collector-net only; the exporter's services never use it)
    for name in ("attack_net", "victim_net", "mgmt_net"):
        assert all(name not in block for block in (writer, shipper, net))
    assert "attack_net" not in text and "victim_net" not in text
    guard = (root / "lab" / "cloud" / "netguard_shipper.sh").read_text()
    assert "ip route del default" in guard and "ip daddr 10.10.4.10 tcp dport 4566 accept" in guard


# === Review round 2: robustness and fidelity ========================================================

import struct as _struct

from scapy.layers.inet import fragment
from scapy.layers.l2 import CookedLinux, Dot1Q


def _frame(layer, vlan=None):
    from scapy.layers.l2 import Ether

    eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if vlan is not None:
        eth = eth / Dot1Q(vlan=vlan)
    return bytes(eth / layer)


def _ip(text):
    return int.from_bytes(socket.inet_aton(text), "big")


def _ptk(ts, src, dst, sport, dport, proto=6, length=40, **kw):
    return fx.Packet(ts, _ip(src), _ip(dst), proto, sport, dport, length, **kw)


# --- 2. fragments -----------------------------------------------------------------------------------


def _fragments(dport, ident=77, size=3000):
    pkt = IP(src=CLIENT, dst=SERVER, id=ident) / TCP(sport=40001, dport=dport) / (b"x" * size)
    frags = fragment(pkt, fragsize=1000)
    assert len(frags) >= 3
    return [fx.parse_frame(_frame(f), T0 + i * 0.01) for i, f in enumerate(frags)], frags


@pytest.mark.parametrize(("dport", "action"), [(80, "ACCEPT"), (9999, "REJECT")])
def test_fragments_inherit_ports_and_decision_of_the_first_fragment(dport, action):
    packets, frags = _fragments(dport)
    assert packets[0].dport == dport and all(p.dport == 0 for p in packets[1:])
    assert packets[0].more_fragments and not packets[-1].more_fragments
    agg = fx.Aggregator(config())
    for p in packets:
        agg.add(p)
    (lines,) = agg.pop_all().values()
    (rec,) = flowlogs.parse_lines(lines)
    assert (rec.dst_port, rec.action, rec.packets) == (dport, action, len(frags))
    assert rec.byte_count == sum(p.length for p in packets)
    assert agg.stats == {} or all(not s.loss for s in agg.stats.values())


def test_a_fragment_whose_first_fragment_was_not_seen_is_ignored_and_counted():
    packets, _ = _fragments(80, ident=78)
    agg = fx.Aggregator(config())
    for p in packets[1:]:  # the first fragment never arrived
        agg.add(p)
    assert agg.windows == {} and agg.packets_ignored == len(packets) - 1
    (stats,) = agg.stats.values()
    assert stats.fragments_ignored == len(packets) - 1 and stats.loss


def test_fragment_answers_are_dropped_after_a_rejected_first_fragment():
    packets, _ = _fragments(9999, ident=79)
    agg = fx.Aggregator(config())
    for p in packets:
        agg.add(p)
    agg.add(_ptk(T0 + 1, SERVER, CLIENT, 9999, 40001))  # the victim's RST
    (lines,) = agg.pop_all().values()
    assert [r.action for r in flowlogs.parse_lines(lines)] == ["REJECT"]


# --- VLAN, IPv6, ICMP errors ------------------------------------------------------------------------


def test_vlan_tag_is_skipped_but_qinq_and_ipv6_are_ignored():
    tagged = fx.parse_frame(_frame(IP(src=CLIENT, dst=SERVER) / TCP(sport=1, dport=80), vlan=5), T0)
    assert tagged and (tagged.dport, tagged.src) == (80, _ip(CLIENT))
    qinq = bytearray(_frame(IP(src=CLIENT, dst=SERVER) / TCP(sport=1, dport=80), vlan=5))
    qinq[12:14] = b"\x88\xa8"  # an 802.1ad outer tag
    assert fx.parse_frame(bytes(qinq), T0) is None
    from scapy.layers.inet6 import IPv6

    assert fx.parse_frame(_frame(IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP()), T0) is None


def test_icmp_errors_from_the_victim_are_dropped_but_other_icmp_is_not():
    agg = fx.Aggregator(config(allow_icmp=True))
    for icmp_type in (3, 11, 0):  # unreachable, time exceeded, echo reply
        agg.add(_ptk(T0, SERVER, CLIENT, 0, 0, proto=1, icmp_type=icmp_type))
    (lines,) = agg.pop_all().values()
    (rec,) = flowlogs.parse_lines(lines)
    assert rec.packets == 1 and rec.action == "ACCEPT"


# --- 5. tracker expiry and eviction -------------------------------------------------------------------


def test_expiring_map_keeps_entries_for_one_to_two_windows():
    m = fx._Expiring(10)
    m.advance(1200)
    m.put("a")
    m.advance(1260)
    assert "a" in m  # the previous window
    m.advance(1320)
    assert "a" not in m  # two windows later
    m.put("b")
    m.advance(1500)  # a gap of more than one window forgets everything
    assert "b" not in m and len(m) == 0


def test_expiring_map_evicts_the_oldest_and_counts():
    m = fx._Expiring(2)
    m.advance(1200)
    for key in "abc":
        m.put(key)
    assert "a" not in m and "b" in m and "c" in m and m.evictions == 1
    assert m.evicted_recently()
    m.advance(1320)
    assert not m.evicted_recently()


def test_a_victim_answer_to_an_old_reject_is_no_longer_dropped_after_expiry():
    agg = fx.Aggregator(config())
    agg.add(_ptk(T0, CLIENT, SERVER, 5000, 9999))  # REJECT
    agg.add(_ptk(T0 + 0.1, SERVER, CLIENT, 9999, 5000))  # its RST: dropped
    assert agg.packets_ignored == 1
    agg.add(_ptk(T0 + 200, SERVER, CLIENT, 9999, 5000))  # three windows later: just a new packet
    assert agg.packets_ignored == 1


def test_eviction_never_turns_reject_traffic_into_accept():
    agg = fx.Aggregator(config(), tracked_limit=3)
    for i in range(10):  # ten rejected SYNs: the oldest seven tuples are evicted
        agg.add(_ptk(T0 + i * 0.01, CLIENT, SERVER, 5000, 9000 + i))
    for i in range(10):  # the victim's RSTs for all of them
        agg.add(_ptk(T0 + 1 + i * 0.01, SERVER, CLIENT, 9000 + i, 5000))
    # A late attacker packet to a tuple whose RST was forgotten must still be REJECT.
    agg.add(_ptk(T0 + 2, CLIENT, SERVER, 5000, 9000))
    (lines,) = agg.pop_all().values()
    recs = list(flowlogs.parse_lines(lines))
    assert all(r.action == "REJECT" for r in recs if r.dst_ip == SERVER)
    assert not [
        r
        for r in recs
        if r.src_ip == SERVER and r.action == "ACCEPT" and r.src_port >= 9000 and r.src_port <= 9006
    ]
    assert sum(1 for r in recs if r.src_ip == SERVER) <= 3  # the remembered ones were dropped too


def test_eviction_is_counted_and_recovers_when_it_has_aged_out():
    agg = fx.Aggregator(config(), tracked_limit=2)
    for i in range(5):
        agg.add(_ptk(T0 + i * 0.01, CLIENT, SERVER, 5000, 9000 + i))
    stats = agg.stats[fx.window_of(T0)]
    assert stats.evictions == 3 and stats.loss
    agg.add(_ptk(T0 + 1, SERVER, CLIENT, 9000, 5000))  # RST of a forgotten SYN
    assert stats.ambiguous_dropped == 1
    # Two windows later the doubt is over: a victim-opened connection is ACCEPT again.
    agg.add(_ptk(T0 + 130, SERVER, CLIENT, 4444, 5555))
    rows = agg.windows[fx.window_of(T0 + 130)]
    assert [v[4] for v in rows.values()] == ["ACCEPT"]


# --- 9. the ENI's hosts -------------------------------------------------------------------------------


def test_default_victim_hosts_are_victim_and_dvwa_not_the_sensor_or_gateway():
    cfg = config()
    assert cfg.victim_hosts == ("10.10.2.10", "10.10.2.11")
    agg = fx.Aggregator(cfg)
    for host in ("10.10.2.1", "10.10.2.2", "10.10.2.10", "10.10.2.11", "10.10.2.53"):
        agg.add(_ptk(T0, CLIENT, host, 4000, 80))
    (lines,) = agg.pop_all().values()
    assert sorted(r.dst_ip for r in flowlogs.parse_lines(lines)) == ["10.10.2.10", "10.10.2.11"]
    whole = fx.Aggregator(config(victim_hosts=()))
    whole.add(_ptk(T0, CLIENT, "10.10.2.2", 4000, 80))
    assert len(whole.windows[fx.window_of(T0)]) == 1


def test_cli_victim_hosts_and_cidr_options(tmp_path):
    sweep = [syn(5000, 80, T0 + i * 0.01, dst=f"10.10.2.{i}") for i in (1, 2, 10, 11)]
    pcap = write_pcap(tmp_path / "sweep.pcap", sweep)

    def dsts(*extra):
        out = tmp_path / ("o" + str(len(extra)) + "".join(extra).replace(".", "").replace(" ", ""))
        assert main(["export", "offline", "--pcap", str(pcap), "--out", str(out), *extra]) == 0
        return sorted(r.dst_ip for r in records_of(out.glob("*.flows")))

    assert dsts() == ["10.10.2.10", "10.10.2.11"]
    assert dsts("--victim-hosts", "10.10.2.2") == ["10.10.2.2"]
    assert len(dsts("--victim-hosts", "all")) == 4
    assert len(dsts("--victim-cidr", "10.10.2.0/24")) == 4  # a network and no host list: all of it


# --- 3. packet loss: counters, sidecar, log ----------------------------------------------------------


class DropSock(FakeSock):
    """A fake AF_PACKET socket that reports kernel drops through PACKET_STATISTICS."""

    def __init__(self, frames, state, drops):
        super().__init__(frames, state)
        self.drops = list(drops)

    def getsockopt(self, level, name, size):
        assert (level, name, size) == (fx.SOL_PACKET, fx.PACKET_STATISTICS, 8)
        return _struct.pack("II", 100, self.drops.pop(0) if self.drops else 0)


def test_kernel_drops_are_read_logged_and_written_to_a_loss_sidecar(tmp_path, caplog):
    state = {"t": float(T0)}
    frames = [(p.time, bytes(p)) for p in tcp_session()]
    frames.append((BOUNDARY + 70.0, bytes(syn(5555, 80, BOUNDARY + 70))))
    sock = DropSock(frames, state, drops=[0, 7])  # 7 packets lost in the second housekeeping tick
    out = tmp_path / "out"
    caplog.set_level("INFO", logger="idps.cloud.flowlog_export")
    fx.run_writer(
        config(),
        "x",
        out,
        run_id="deadbeef",
        drop=False,
        alive_file=None,
        stop=lambda: not sock.frames,
        sock=sock,
        clock=lambda: state["t"],
    )
    sidecars = sorted(out.glob("*.loss.json"))
    assert sidecars, list(out.iterdir())
    import json

    body = json.loads(sidecars[0].read_text())
    assert body["kernel_drops"] == 7 and body["window_start"] == fx.window_of(BOUNDARY + 70)
    assert any("LOSS" in r.message and "kernel_drops" in r.message for r in caplog.records)
    assert any("packets seen" in r.message for r in caplog.records)
    # the shipper never uploads a sidecar
    _, s3, result = ship(out, tmp_path)
    assert len(result.shipped) == len(list(out.glob("*.flows"))) and all(
        k.endswith(".log.gz") for k in s3.objects
    )


def test_read_kernel_drops_is_zero_when_the_socket_cannot_tell():
    assert fx.read_kernel_drops(object()) == 0

    class Broken:
        def getsockopt(self, *a):
            raise OSError("nope")

    assert fx.read_kernel_drops(Broken()) == 0


def test_cap_overflow_writes_a_sidecar_and_logs_per_interval_deltas(tmp_path, caplog):
    state = {"t": float(T0)}
    frames = [(T0 + i, bytes(syn(6000 + i, 80, T0 + i))) for i in range(3)]  # 3 flows, cap 1
    frames += [(T0 + 400.0, bytes(syn(7000, 80, T0 + 400)))]  # a prune tick: delta 2
    frames += [(T0 + 800.0, bytes(syn(7001, 80, T0 + 800)))]  # another tick: nothing new
    sock = FakeSock(frames, state)
    caplog.set_level("INFO", logger="idps.cloud.flowlog_export")
    out = tmp_path / "out"
    fx.run_writer(
        config(max_records_per_window=1),
        "x",
        out,
        run_id="deadbeef",
        drop=False,
        alive_file=None,
        stop=lambda: not sock.frames,
        sock=sock,
        clock=lambda: state["t"],
    )
    import json

    first = json.loads(min(out.glob("*.loss.json")).read_text())
    assert first["skipped_records"] == 2
    warnings = [r.message for r in caplog.records if "skipped in the last 5 minutes" in r.message]
    assert len(warnings) == 1 and warnings[0].startswith("2 new flow records")


# --- 4. crash recovery: failed writes, healthchecks ---------------------------------------------------


def test_failed_window_writes_are_retried_then_counted_and_never_look_healthy(
    tmp_path, monkeypatch
):
    real = fx.write_window
    calls = {"n": 0}

    def failing(*a, **k):
        calls["n"] += 1
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(fx, "write_window", failing)
    w = fx.WindowWriter(tmp_path, "aaaaaaaa")
    w.submit(BOUNDARY, ["x"], fx.WindowStats())
    assert not w.healthy and w.pending and calls["n"] == 1
    for _ in range(fx.MAX_WRITE_ATTEMPTS - 1):
        w.retry()
    assert calls["n"] == fx.MAX_WRITE_ATTEMPTS
    assert w.dropped_windows == 1 and not w.pending and not w.healthy  # counted, not silent
    monkeypatch.setattr(fx, "write_window", real)
    w.submit(BOUNDARY + 60, ["y"], fx.WindowStats())
    assert w.healthy and w.written == 1


def test_a_window_that_fails_once_is_written_on_the_retry(tmp_path, monkeypatch):
    real = fx.write_window
    state = {"fail": True}

    def flaky(*a, **k):
        if state["fail"]:
            raise OSError("read-only file system")
        return real(*a, **k)

    monkeypatch.setattr(fx, "write_window", flaky)
    w = fx.WindowWriter(tmp_path, "aaaaaaaa")
    w.submit(BOUNDARY, ["z"], fx.WindowStats())
    assert not w.healthy
    state["fail"] = False
    w.retry()
    assert w.healthy and len(list(tmp_path.glob("*.flows"))) == 1


def test_writer_loop_does_not_touch_the_alive_file_while_writes_fail(tmp_path, monkeypatch):
    def failing(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(fx, "write_window", failing)
    state = {"t": float(T0)}
    frames = [(p.time, bytes(p)) for p in tcp_session()]
    frames.append((BOUNDARY + 70.0, bytes(syn(5555, 80, BOUNDARY + 70))))
    touched = []

    class Alive:
        def touch(self):
            touched.append(state["t"])

    sock = FakeSock(frames, state)
    fx.run_writer(
        config(),
        "x",
        tmp_path / "out",
        run_id="deadbeef",
        drop=False,
        alive_file=Alive(),
        stop=lambda: not sock.frames,
        sock=sock,
        clock=lambda: state["t"],
    )
    # healthy at the first tick (nothing to write yet), never again once a window failed
    assert touched and all(t < BOUNDARY for t in touched)


def test_shipper_touches_its_alive_file_only_after_cycles_without_failure(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())
    alive = tmp_path / "alive"

    class Failing(StubS3):
        def put_object(self, **kw):
            raise self._err("InternalError", "PutObject")

    cfg = fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st")
    assert (
        fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=Failing(), alive_file=alive) == 1
    )
    assert not alive.exists()
    assert (
        fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=StubS3(), alive_file=alive) == 0
    )
    assert alive.exists()


# --- 1. shipper memory --------------------------------------------------------------------------------


def _big_window(path, records=50_000):
    base = f"2 {ACCOUNT} eni-0a1b2c3d4e5f60718 "
    with open(path, "w") as fh:
        for i in range(records):
            sport = 1024 + i % 60000
            dport = 1 + i // 60000
            fh.write(
                f"{base}10.10.1.{10 + i % 200} 10.10.2.10 {sport} {dport} 6 3 {120 + i % 1000} "
                f"{BOUNDARY + i % 55} {BOUNDARY + 55} REJECT OK\n"
            )


def test_a_50k_record_window_ships_with_small_peak_memory(tmp_path):
    import tracemalloc

    out = tmp_path / "out"
    out.mkdir()
    name = fx.window_filename(BOUNDARY, "bbbbbbbb")
    _big_window(out / name)
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"), StubS3())
    tracemalloc.start()
    window, key, data = shipper._build(out / name)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert window == BOUNDARY and key.endswith(".log.gz")
    assert peak < 12 * 1024 * 1024, f"peak {peak / 1e6:.1f} MB for 50,000 records"
    stats = flowlogs.ParseStats()
    assert len(list(flowlogs.read_bytes(data, stats))) == 50_000 and stats.malformed == 0
    # and the whole cycle, including the PUT, stays small too
    tracemalloc.start()
    result = shipper.ship_once()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(result.shipped) == 1 and peak < 16 * 1024 * 1024


def test_the_writer_cap_is_below_what_the_shipper_accepts():
    assert fx.MAX_RECORDS_PER_WINDOW == 50_000
    assert fx.MAX_FILE_RECORDS >= fx.OFFLINE_MAX_RECORDS_PER_WINDOW > fx.MAX_RECORDS_PER_WINDOW


def test_too_many_records_in_one_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fx, "MAX_FILE_RECORDS", 5)
    out = tmp_path / "out"
    out.mkdir()
    _big_window(out / fx.window_filename(BOUNDARY, "bbbbbbbb"), records=6)
    _, _, result = ship(out, tmp_path)
    assert result.bad == 1 and not result.shipped


# --- 6 and 7. what the shipper accepts ---------------------------------------------------------------


GOOD = f"2 {ACCOUNT} eni-0 10.10.1.5 10.10.2.10 1 80 6 1 40 {BOUNDARY} {BOUNDARY} ACCEPT OK"


def _window_file(out, text, run="aaaaaaaa", window=BOUNDARY):
    out.mkdir(exist_ok=True)
    path = out / fx.window_filename(window, run)
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    return path


@pytest.mark.parametrize(
    "text",
    [
        "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        + GOOD
        + "\n",
        GOOD + "\n- - - - - - - - - - " + str(BOUNDARY) + " " + str(BOUNDARY + 1) + " - NODATA\n",
        GOOD + "\r\n",  # a carriage return: the collector splits on \n and would see it differently
        GOOD + "\n\n",  # a blank line
        GOOD.replace(" ", "  ", 1) + "\n",  # a doubled space
        GOOD + "\x0b" + GOOD + "\n",  # splitlines() would split here, the collector would not
        GOOD.replace("ACCEPT", "ACC\x00EPT") + "\n",
        "2 " + ACCOUNT + " eni-é 10.10.1.5 10.10.2.10 1 80 6 1 40 1 1 ACCEPT OK\n",
    ],
    ids=["header", "nodata", "cr", "blank", "double-space", "vt", "nul", "non-ascii"],
)
def test_files_that_are_not_pure_records_are_refused(tmp_path, text):
    out = tmp_path / "out"
    _window_file(out, text)
    _, s3, result = ship(out, tmp_path)
    assert result.bad == 1 and s3.objects == {}


def test_the_uploaded_text_is_rebuilt_from_the_parsed_records(tmp_path):
    out = tmp_path / "out"
    v6 = f"2 {ACCOUNT} eni-0 2001:DB8::1 10.10.2.10 1 80 6 1 40 {BOUNDARY} {BOUNDARY} ACCEPT OK"
    _window_file(out, v6 + "\n")
    _, s3, result = ship(out, tmp_path)
    (body,) = s3.objects.values()
    text = gzip.decompress(body).decode()
    assert "2001:db8::1" in text and "2001:DB8::1" not in text
    assert text.splitlines()[0].startswith("version ") and len(text.splitlines()) == 2
    assert result.shipped


def test_a_symbolic_link_is_refused_and_not_followed(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    real = tmp_path / "secret.txt"
    real.write_text(GOOD + "\n")
    link = out / fx.window_filename(BOUNDARY, "cccccccc")
    link.symlink_to(real)
    _, s3, result = ship(out, tmp_path)
    assert result.bad == 1 and s3.objects == {}
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st2"), StubS3())
    with pytest.raises(ValueError, match="symbolic link"):
        shipper._build(link)


def test_a_file_name_with_a_trailing_newline_does_not_match(tmp_path):
    assert fx.FILE_RE.fullmatch("20231114T2214Z-aaaaaaaa.flows")
    assert not fx.FILE_RE.fullmatch("20231114T2214Z-aaaaaaaa.flows\n")
    path = tmp_path / "20231114T2214Z-aaaaaaaa.flows\n"
    path.write_text(GOOD + "\n")
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=tmp_path, state_dir=tmp_path / "st"), StubS3())
    with pytest.raises(ValueError, match="file name"):
        shipper._build(path)


def test_an_oversize_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(fx, "MAX_FILE_BYTES", 100)
    out = tmp_path / "out"
    _window_file(out, (GOOD + "\n") * 5)
    _, s3, result = ship(out, tmp_path)
    assert result.bad == 1 and s3.objects == {}
    monkeypatch.setattr(fx, "MAX_FILE_BYTES", 10_000)
    monkeypatch.setattr(fx, "MAX_LINE_BYTES", 20)
    shipper = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st2"), StubS3())
    with pytest.raises(ValueError, match="too long"):
        shipper._build(next(out.glob("*.flows")))


def test_a_transient_read_error_is_retried_not_marked_bad(tmp_path, monkeypatch):
    out, _ = export_pcap(tmp_path, tcp_session())
    real_open = os.open
    state = {"fail": True}

    def flaky(path, *a, **k):
        if state["fail"] and str(path).endswith(".flows"):
            state["fail"] = False
            raise OSError(5, "Input/output error")
        return real_open(path, *a, **k)

    monkeypatch.setattr(fx.os, "open", flaky)
    shipper, s3, first = ship(out, tmp_path)
    assert first.failed == 1 and first.bad == 0 and not shipper.bad and s3.objects == {}
    assert len(shipper.ship_once().shipped) == 1


def test_prune_removes_leftover_temp_files_and_sidecars_too(tmp_path):
    names = [
        "20231114T2214Z-aaaaaaaa.flows",
        "20231114T2214Z-aaaaaaaa.flows.tmp",
        "20231114T2214Z-aaaaaaaa.flows.loss.json",
        "keep.txt",
    ]
    for n in names:
        (tmp_path / n).write_text("x")
        os.utime(tmp_path / n, (T0, T0))
    assert fx.prune_old(tmp_path, keep_hours=1) == 3
    assert [p.name for p in tmp_path.iterdir()] == ["keep.txt"]


# --- state file, restarts of the emulator, --reship (10) ---------------------------------------------


@pytest.mark.parametrize(
    "junk", ["not json", "[1, 2]", '{"shipped": [1, 2]}', '{"shipped": {"a": 1}, "bad": 5}', ""]
)
def test_a_damaged_state_file_is_ignored_and_shipping_stays_idempotent(tmp_path, junk):
    out, _ = export_pcap(tmp_path, tcp_session())
    state = tmp_path / "state"
    state.mkdir()
    (state / "shipped.json").write_text(junk)
    s3 = StubS3()
    first = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=state), s3).ship_once()
    assert len(first.shipped) == 1
    again = fx.Shipper(fx.ShipperConfig(in_dir=out, state_dir=state), s3).ship_once()
    assert again.shipped == [] and len(s3.objects) == 1


def test_after_an_emulator_restart_windows_missing_from_the_bucket_are_sent_again(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())
    s3 = StubS3()
    cfg = fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st")
    assert fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=s3) == 0
    (key,) = s3.objects
    s3.objects.clear()  # Moto restarted and tf.sh apply made an empty bucket again
    assert fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=s3) == 0
    assert list(s3.objects) == [key] and s3.calls.count("put_object") == 2
    # unchanged bucket: nothing is sent a third time
    assert fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=s3) == 0
    assert s3.calls.count("put_object") == 2


def test_reship_resets_the_state_but_never_duplicates_what_the_bucket_has(tmp_path):
    out, _ = export_pcap(tmp_path, tcp_session())
    s3 = StubS3()
    cfg = fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st")
    fx.run_shipper(cfg, {}, once=True, guard=AllowGuard(), s3=s3)
    assert fx.run_shipper(cfg, {}, once=True, reship=True, guard=AllowGuard(), s3=s3) == 0
    assert s3.calls.count("put_object") == 1 and len(s3.objects) == 1
    s3.objects.clear()
    assert fx.run_shipper(cfg, {}, once=True, reship=True, guard=AllowGuard(), s3=s3) == 0
    assert len(s3.objects) == 1


def test_a_bucket_lost_in_the_middle_of_a_run_stops_the_shipper_with_exit_3(tmp_path, capsys):
    out, _ = export_pcap(tmp_path, tcp_session())

    class Vanishing(StubS3):
        def head_bucket(self, Bucket):
            super().head_bucket(Bucket)
            self.bucket_exists = False  # the emulator restarted right after the start check

    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"),
        {},
        once=True,
        guard=AllowGuard(),
        s3=Vanishing(),
    )
    assert code == 3 and "tf.sh apply" in capsys.readouterr().err


# --- guard recheck -------------------------------------------------------------------------------------


def test_the_guard_is_checked_again_every_five_minutes(tmp_path, capsys):
    out, _ = export_pcap(tmp_path, tcp_session())
    clock = {"t": 0.0}

    class Guard:
        calls = 0

        def problems(self, env):
            self.calls += 1
            return [] if self.calls < 3 else ["AWS_PROFILE is set"]

    guard = Guard()

    def monotonic():
        return clock["t"]

    def sleep(seconds):
        clock["t"] += 100.0  # each ten-second wait "takes" 100 s: a recheck every 3 waits

    code = fx.run_shipper(
        fx.ShipperConfig(in_dir=out, state_dir=tmp_path / "st"),
        {},
        interval=1,
        guard=guard,
        s3=StubS3(),
        sleep=sleep,
        monotonic=monotonic,
        recheck_seconds=300.0,
    )
    assert code == 1 and guard.calls == 3  # start, first recheck (ok), second recheck (refused)
    assert "REFUSED on recheck" in capsys.readouterr().err


# --- make_s3_client pinning ---------------------------------------------------------------------------


def test_make_s3_client_is_pinned_to_the_emulator_with_fake_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALLOOKINGKEY0")  # must be ignored
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "tok")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://s3.amazonaws.com")
    client = fx.make_s3_client({"AWS_ENDPOINT_URL": "http://10.10.4.10:4566", "AWS_REGION": REGION})
    assert client.meta.endpoint_url == "http://10.10.4.10:4566"
    creds = client._request_signer._credentials
    assert (creds.access_key, creds.secret_key, creds.token) == ("test", "test", None)
    cfg = client.meta.config
    assert cfg.proxies == {} and cfg.s3["addressing_style"] == "path"
    assert client.meta.region_name == REGION


# --- CLI: environment parsed lazily, link types -------------------------------------------------------


def test_a_bad_export_variable_breaks_only_the_export_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDPS_FLOWLOG_SHIP_INTERVAL", "ten")
    monkeypatch.setenv("IDPS_FLOWLOG_KEEP_HOURS", "lots")
    monkeypatch.setenv("IDPS_FLOWLOG_MAX_RECORDS", "many")
    sample = Path(__file__).parent / "data" / "flowlogs_sample.log"
    assert main(["parse", str(sample)]) == 0  # an unrelated command still works
    assert (
        main(["export", "ship", "--once", "--in", str(tmp_path), "--state-dir", str(tmp_path)]) == 1
    )
    assert "IDPS_FLOWLOG_SHIP_INTERVAL must be a number" in capsys.readouterr().err
    assert main(["export", "writer", "--out", str(tmp_path)]) == 1
    assert "must be a number" in capsys.readouterr().err
    pcap = write_pcap(tmp_path / "in.pcap", tcp_session())
    assert main(["export", "offline", "--pcap", str(pcap), "--out", str(tmp_path / "o")]) == 1
    assert "IDPS_FLOWLOG_MAX_RECORDS" in capsys.readouterr().err


def test_unsupported_link_types_are_an_error_not_empty_output(tmp_path, capsys):
    pkt = CookedLinux() / IP(src=CLIENT, dst=SERVER) / TCP(sport=1, dport=80)
    pkt.time = T0
    pcap = tmp_path / "cooked.pcap"
    from scapy.utils import wrpcap

    wrpcap(str(pcap), [pkt])
    assert main(["export", "offline", "--pcap", str(pcap), "--out", str(tmp_path / "o")]) == 1
    err = capsys.readouterr().err
    assert "link type 113" in err and "Ethernet" in err


# --- 11. the baked billing guard ----------------------------------------------------------------------


def test_the_image_bakes_the_repos_guard_and_the_shipper_loads_that_file():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "lab" / "cloud" / "Dockerfile.flowlog").read_text()
    assert "COPY lab/cloud/guard.py ./lab/cloud/guard.py" in dockerfile
    script = (root / "lab" / "cloud" / "build_flowlog.sh").read_text()
    assert (
        "sha256" in script and "--check" in script and "differs from lab/cloud/guard.py" in script
    )
    guard_path = Path(fx.__file__).resolve().parents[2] / "lab" / "cloud" / "guard.py"
    assert guard_path == root / "lab" / "cloud" / "guard.py"
    assert fx.load_guard().problems.__code__.co_filename == str(guard_path)


def test_the_built_image_guard_matches_the_repo_when_the_image_exists():
    import hashlib
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        pytest.skip("docker is not available")
    root = Path(__file__).resolve().parents[1]
    try:
        have = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "sha256sum",
                "idps-lab-flowlog:latest",
                "/opt/idps/lab/cloud/guard.py",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker is not answering")
    if have.returncode != 0:
        pytest.skip("the idps-lab-flowlog image is not built")
    want = hashlib.sha256((root / "lab" / "cloud" / "guard.py").read_bytes()).hexdigest()
    assert have.stdout.split()[0] == want, "rebuild: lab/cloud/build_flowlog.sh"
