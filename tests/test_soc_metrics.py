"""SOC API: metrics summary and topology."""

import time

import pytest
from conftest import alert_payload, ingest


def now_ms():
    return int(time.time() * 1000)


def test_empty_metrics(client, analyst_headers):
    m = client.get("/metrics/summary", headers=analyst_headers).json()
    assert m["alerts_total"] == 0 and m["by_class"] == {} and m["top_sources"] == []
    assert m["by_severity"] == {"low": 0, "medium": 0, "high": 0, "critical": 0}
    assert m["false_positive_rate"] is None
    assert m["detection_latency"] == {"p50_ms": None, "p95_ms": None, "samples": 0}
    assert m["active_blocks"] == 0 and sum(b["count"] for b in m["alerts_per_bucket"]) == 0
    assert m["bucket_seconds"] == 3600 and len(m["alerts_per_bucket"]) in (24, 25)


def test_metrics_summary(client, analyst_headers, sensor_headers):
    end = now_ms() - 2000  # detected about 2 s after the flow ended
    ids = ingest(
        client, sensor_headers,
        *[alert_payload(src_ip="198.51.100.1", end_ms=end, start_ms=end - 10) for _ in range(3)],
        alert_payload(src_ip="198.51.100.2", predicted_class="DDoS", end_ms=end, start_ms=end - 5),
        alert_payload(src_ip="198.51.100.3", predicted_class="PortScan", end_ms=end,
                      start_ms=end - 5))
    client.patch(f"/alerts/{ids[0]}", json={"status": "false_positive"}, headers=analyst_headers)
    client.patch(f"/alerts/{ids[1]}", json={"status": "resolved"}, headers=analyst_headers)
    client.patch(f"/alerts/{ids[2]}", json={"status": "acknowledged"}, headers=analyst_headers)
    client.post("/ingest/blocks", headers=sensor_headers, json={"events": [
        {"event": "blocked", "ip": "198.51.100.1", "ttl_seconds": 60}]})

    m = client.get("/metrics/summary?hours=24", headers=analyst_headers).json()
    assert m["alerts_total"] == 5
    assert m["by_class"] == {"SSH-Patator": 3, "DDoS": 1, "PortScan": 1}
    assert m["by_severity"] == {"low": 1, "medium": 3, "high": 0, "critical": 1}
    assert m["top_sources"][0] == {"ip": "198.51.100.1", "count": 3}
    assert m["triaged"] == 3 and m["false_positives"] == 1
    assert m["false_positive_rate"] == pytest.approx(1 / 3)
    lat = m["detection_latency"]
    assert lat["samples"] == 5 and 1500 < lat["p50_ms"] < 15_000 and lat["p95_ms"] >= lat["p50_ms"]
    assert m["active_blocks"] == 1
    assert sum(b["count"] for b in m["alerts_per_bucket"]) == 5


def test_top_sources_capped_at_ten(client, analyst_headers, sensor_headers):
    ingest(client, sensor_headers, *[alert_payload(src_ip=f"198.51.100.{i}") for i in range(1, 16)])
    m = client.get("/metrics/summary", headers=analyst_headers).json()
    assert len(m["top_sources"]) == 10


def test_long_windows_use_daily_buckets(client, analyst_headers):
    m = client.get("/metrics/summary?hours=720", headers=analyst_headers).json()
    assert m["bucket_seconds"] == 86400 and 30 <= len(m["alerts_per_bucket"]) <= 32


@pytest.mark.parametrize("path", ["/metrics/summary?hours=0", "/metrics/summary?hours=721",
                                  "/metrics/summary?hours=x", "/topology?hours=0",
                                  "/topology?hours=721"])
def test_hours_validation(client, analyst_headers, path):
    assert client.get(path, headers=analyst_headers).status_code == 422


def test_topology(client, analyst_headers, sensor_headers):
    ingest(
        client, sensor_headers,
        alert_payload(src_ip="198.51.100.1", dst_ip="10.0.0.5", predicted_class="PortScan"),
        alert_payload(src_ip="198.51.100.1", dst_ip="10.0.0.5", predicted_class="DDoS"),
        alert_payload(src_ip="198.51.100.1", dst_ip="10.0.0.6", predicted_class="PortScan"),
        alert_payload(src_ip="10.0.0.5", dst_ip="10.0.0.5", predicted_class="PortScan"))
    t = client.get("/topology?hours=1", headers=analyst_headers).json()
    edges = {(e["src"], e["dst"]): e for e in t["edges"]}
    assert edges[("198.51.100.1", "10.0.0.5")]["count"] == 2
    assert edges[("198.51.100.1", "10.0.0.5")]["max_severity"] == "critical"
    assert edges[("198.51.100.1", "10.0.0.6")]["max_severity"] == "low"
    nodes = {n["ip"]: n for n in t["nodes"]}
    assert set(nodes) == {"198.51.100.1", "10.0.0.5", "10.0.0.6"}
    assert nodes["198.51.100.1"]["alert_count"] == 3
    assert nodes["10.0.0.5"]["alert_count"] == 3  # 2 as target, 1 self-edge counted once
    assert nodes["10.0.0.5"]["max_severity"] == "critical"
    assert nodes["10.0.0.6"]["alert_count"] == 1


def test_topology_empty(client, analyst_headers):
    assert client.get("/topology", headers=analyst_headers).json() == {
        "hours": 1, "nodes": [], "edges": []}
