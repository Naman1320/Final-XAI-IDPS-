"""scripts/bench_sensor.py: the pure parts (tcpreplay, docker stats, metrics lines, table)."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "bench_sensor.py"
_spec = importlib.util.spec_from_file_location("bench_sensor", _PATH)
bench = importlib.util.module_from_spec(_spec)
sys.modules["bench_sensor"] = bench
_spec.loader.exec_module(bench)

TCPREPLAY = """\
sending out lab_attack
processed file: /tmp/bench_sample.pcap
Actual: 1234567 packets (345678901 bytes) sent in 27.65 seconds
Rated: 12500000.0 Bps, 100.00 Mbps, 44650.12 pps

Flows: 0 flows, 0.00 fps, 0 unique flow packets, 0 unique non-flow packets
Statistics for network device: lab_attack
\tSuccessful packets:        1234560
\tFailed packets:            7
\tTruncated packets:         0
"""

METRICS = {"event": "metrics", "uptime_s": 190.0, "flows": 100, "flows_per_s": 0.5, "alerts": 90,
           "alerts_sent": 90, "dropped": {"alerts": 0, "explanations": 3},
           "errors": {"explain": 0}, "shap_ms_per_alert": {"p50": 0.1, "p95": 0.3, "n": 90},
           "latency_flow_end_to_alert_s": {"p50": 121.2, "p95": 121.8, "n": 90}}


def test_parse_tcpreplay():
    r = bench.parse_tcpreplay(TCPREPLAY)
    assert r == {"packets_sent": 1234567, "bytes_sent": 345678901, "seconds": 27.65,
                 "mbps": 100.0, "pps": 44650.12, "failed_packets": 7}


def test_parse_tcpreplay_garbage_gives_none():
    r = bench.parse_tcpreplay("tcpreplay: error")
    assert all(v is None for v in r.values())


@pytest.mark.parametrize("text,mib", [("512MiB", 512.0), ("1.5GiB", 1536.0), ("1024KiB", 1.0),
                                      ("1048576B", 1.0), ("2MB", 2e6 / 1024**2)])
def test_parse_size_mib(text, mib):
    assert bench.parse_size_mib(text) == pytest.approx(mib)


def test_parse_size_mib_rejects_junk():
    assert bench.parse_size_mib("lots") is None
    assert bench.parse_size_mib("12 parsecs") is None


def test_parse_docker_stats():
    line = json.dumps({"Name": "idps-sensor", "CPUPerc": "123.45%",
                       "MemUsage": "812.3MiB / 3.82GiB", "MemPerc": "20.77%"})
    assert bench.parse_docker_stats(line) == {"cpu_pct": 123.45, "mem_mib": pytest.approx(812.3)}


@pytest.mark.parametrize("line", ["", "not json", '{"CPUPerc": "--"}',
                                  '{"CPUPerc": "1%", "MemUsage": "?? / 1GiB"}'])
def test_parse_docker_stats_bad_lines(line):
    assert bench.parse_docker_stats(line) is None


def test_parse_metrics_line_plain_and_prefixed():
    raw = json.dumps(METRICS)
    assert bench.parse_metrics_line(raw)["flows"] == 100
    assert bench.parse_metrics_line("2026-11-14 10:00:00 INFO idps.live " + raw)["alerts"] == 90


def test_parse_metrics_line_ignores_other_lines():
    assert bench.parse_metrics_line("starting up") is None
    assert bench.parse_metrics_line('{"event": "alert", "x": 1}') is None
    assert bench.parse_metrics_line('INFO {"event": "metrics", broken') is None


def test_summarize_stats():
    busy = [{"cpu_pct": 100.0, "mem_mib": 500.0}, {"cpu_pct": 300.0, "mem_mib": 700.0}]
    s = bench.summarize_stats(busy)
    assert (s["cpu_mean_pct"], s["cpu_max_pct"], s["mem_max_mib"], s["samples"]) == (200.0, 300.0, 700.0, 2)
    assert bench.summarize_stats([])["cpu_mean_pct"] is None


def test_summarize_stats_cpu_over_busy_samples_memory_over_all():
    busy = [{"cpu_pct": 400.0, "mem_mib": 600.0, "source": "cgroup"}]
    idle = [{"cpu_pct": 0.0, "mem_mib": 900.0}]
    s = bench.summarize_stats(busy, busy + idle)
    assert (s["cpu_mean_pct"], s["mem_max_mib"], s["busy_samples"], s["samples"]) == (400.0, 900.0, 1, 2)
    assert s["source"] == "cgroup"


def test_parse_cgroup_sample_and_cpu_pct():
    text = "usage_usec 5000000 3145728000 inactive_file 1048576000"
    a = bench.parse_cgroup_sample("usage_usec 1000000 2147483648 inactive_file 1073741824")
    assert a == {"usage_usec": 1000000, "mem_mib": 1024.0}
    b = bench.parse_cgroup_sample(text)
    assert b["usage_usec"] == 5000000
    # 4 CPU-seconds in 2 wall seconds: two cores busy
    assert bench.cgroup_cpu_pct(a, b, 2.0) == 200.0
    assert bench.parse_cgroup_sample("cat: no such file") is None


def test_net_counters_and_delta():
    before = bench.parse_net_counters("100 1 0 5\n")
    after = bench.parse_net_counters("1100 3 0 9")
    assert bench.counter_delta(before, after) == {"rx_packets": 1000, "rx_dropped": 2,
                                                  "rx_errors": 0, "softnet_dropped": 4}
    assert bench.parse_net_counters("cat: no such file") == {}


def test_capture_ratio():
    assert bench.capture_ratio(95, 100) == 0.95
    assert bench.capture_ratio(0, 100) == 0.0
    assert bench.capture_ratio(None, 100) is None
    assert bench.capture_ratio(5, 0) is None


def test_estimate_duration_grows_as_rate_falls():
    slow = bench.estimate_duration(300_000_000, 10)
    fast = bench.estimate_duration(300_000_000, 200)
    assert slow > fast > bench.FLUSH_SECONDS + bench.STARTUP_SECONDS  # always leaves the flush cap
    assert slow >= 300_000_000 * 8 / 10e6  # at least the replay time itself


def _entry(rate, flows):
    return bench.build_entry(
        rate, {"packets_sent": 1000, "mbps": rate * 0.99}, {**METRICS, "flows": flows}, 812.0,
        {"cpu_mean_pct": 150.0, "cpu_max_pct": 400.0, "mem_max_mib": 900.0}, 100, {})


def test_build_entry_picks_the_numbers():
    e = _entry(50, 90)
    assert e["capture_ratio"] == 0.9
    assert e["latency_p95_s"] == 121.8 and e["shap_p95_ms"] == 0.3
    assert e["flows_per_s_peak"] == 812.0 and e["alerts_sent"] == 90


def test_build_table_has_a_row_per_rate_and_marks_missing_values():
    entries = [_entry(10, 100), _entry(200, 80)]
    entries[1]["latency_p50_s"] = None
    lines = bench.build_table(entries).splitlines()
    assert len(lines) == 4  # header, separator, two rows
    assert lines[0].startswith("| Target Mbit/s")
    assert "0.800" in lines[3] and "n/a/121.8" in lines[3]
    assert len({line.count("|") for line in lines}) == 1  # every row has the same columns


def test_drained_needs_a_steady_flow_count():
    assert not bench.drained([])
    assert not bench.drained([5, 5, 5])  # too few lines
    assert not bench.drained([0, 10, 20, 30, 40, 40])
    assert bench.drained([0, 10, 20, 40, 40, 40, 40, 40])
    assert not bench.drained([40, 40, 40, 40, 41])
