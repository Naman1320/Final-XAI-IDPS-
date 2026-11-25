# ruff: noqa: F811  (the `pinned` fixture is imported from cloud_helpers)
"""Cloud management: mock metrics, health, cost, overview, alerts and notifications."""

from datetime import timedelta

import pytest
from cloud_helpers import T0, activity, by_name, pinned  # noqa: F401

from soc.api.cloud import metrics

STOPPED_SERIES = ("cpu_pct", "memory_pct", "net_in_mbps", "net_out_mbps")


def get_metrics(client, h, iid, rng="1h"):
    r = client.get(f"/cloud/instances/{iid}/metrics", headers=h, params={"range": rng})
    assert r.status_code == 200, r.text
    return r.json()


# --- metrics ------------------------------------------------------------------------------------

def test_metrics_shape_and_labels(client, pinned, admin_headers):
    iid = by_name(client, admin_headers, "web-1")["id"]
    for rng, points, step in (("1h", 60, 60), ("24h", 96, 900), ("7d", 168, 3600)):
        m = get_metrics(client, admin_headers, iid, rng)
        assert m["step_seconds"] == step and len(m["timestamps"]) == points
        assert set(m["series"]) == {"cpu_pct", "memory_pct", "disk_pct", "net_in_mbps",
                                    "net_out_mbps"}
        assert all(len(v) == points for v in m["series"].values())
        assert m["metrics_source"] == "mock" and "Mock metrics" in m["metrics_label"]
        assert m["data_source"] == "mock" and m["state"] == "running"
        assert m["timestamps"] == sorted(m["timestamps"])
        for name in ("cpu_pct", "memory_pct", "disk_pct"):
            assert all(0 <= v <= 100 for v in m["series"][name] if v is not None)
    assert client.get(f"/cloud/instances/{iid}/metrics", headers=admin_headers,
                      params={"range": "1y"}).status_code == 422
    assert client.get("/cloud/instances/i-ffffffff/metrics",
                      headers=admin_headers).status_code == 404


def test_metrics_are_deterministic_and_stable_between_calls(client, soc_app, pinned,
                                                            admin_headers):
    iid = by_name(client, admin_headers, "web-2")["id"]
    a = get_metrics(client, admin_headers, iid, "24h")
    assert get_metrics(client, admin_headers, iid, "24h") == a
    # a minute later (in the same 15 minute slot) nothing changed; 15 minutes later the window
    # moved by one point and every overlapping sample is identical
    pinned.set(T0 + timedelta(minutes=15))
    b = get_metrics(client, admin_headers, iid, "24h")
    assert b["timestamps"][:-1] == a["timestamps"][1:]
    for name in a["series"]:
        assert b["series"][name][:-1] == a["series"][name][1:], name
    # the same values come out of the generator directly: nothing is stored
    from datetime import datetime
    ts = datetime.fromisoformat(a["timestamps"][10])
    assert metrics.value(iid, "cpu_pct", ts, running_at=True) == a["series"]["cpu_pct"][10]
    assert metrics.value(iid, "cpu_pct", ts, running_at=True) == metrics.value(
        iid, "cpu_pct", ts, running_at=True)
    # and they differ between instances
    other = get_metrics(client, admin_headers, by_name(client, admin_headers, "api-1")["id"],
                        "24h")
    assert other["series"]["cpu_pct"] != a["series"]["cpu_pct"]


def test_a_stopped_instance_is_zero_and_flat(client, pinned, admin_headers):
    build = by_name(client, admin_headers, "build-1")["id"]  # stopped 3 days ago
    m = get_metrics(client, admin_headers, build, "24h")
    assert m["state"] == "stopped"
    for name in STOPPED_SERIES:
        assert set(m["series"][name]) == {0.0}, name
    assert len(set(m["series"]["disk_pct"])) == 1 and m["series"]["disk_pct"][0] > 0
    assert m["current"]["cpu_pct"] == 0.0
    # 7 days: running until 3 days ago, then zero
    m = get_metrics(client, admin_headers, build, "7d")
    assert any(v > 0 for v in m["series"]["cpu_pct"]) and m["series"]["cpu_pct"][-1] == 0.0
    assert m["series"]["cpu_pct"][-71:] == [0.0] * 71  # the 71 hourly points after the stop


def test_a_terminated_instance_is_zero(client, pinned, admin_headers):
    old = by_name(client, admin_headers, "batch-old")["id"]
    m = get_metrics(client, admin_headers, old, "24h")
    assert m["state"] == "terminated"
    for name in m["series"]:
        assert set(m["series"][name]) == {0.0}, name


def test_metrics_follow_stop_and_start(client, pinned, admin_headers):
    web = by_name(client, admin_headers, "web-1")["id"]
    before = get_metrics(client, admin_headers, web, "1h")
    assert before["series"]["cpu_pct"][-1] > 0
    pinned.set(T0 + timedelta(minutes=30))
    assert client.post(f"/cloud/instances/{web}/stop", headers=admin_headers).status_code == 200
    pinned.set(T0 + timedelta(minutes=50))
    m = get_metrics(client, admin_headers, web, "1h")
    stamps = m["timestamps"]
    stop_at = (T0 + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    for i, t in enumerate(stamps):
        for name in STOPPED_SERIES:
            if t >= stop_at:
                assert m["series"][name][i] == 0.0, (t, name)
        if t < stop_at:
            assert m["series"]["cpu_pct"][i] > 0, t  # it was running until the stop
    assert m["current"]["cpu_pct"] == 0.0
    # start it again: pending (zero), then running after the settle time
    assert client.post(f"/cloud/instances/{web}/start", headers=admin_headers).status_code == 200
    pinned.set(T0 + timedelta(minutes=52))
    m = get_metrics(client, admin_headers, web, "1h")  # this read settles pending -> running
    assert m["state"] == "running" and m["current"]["cpu_pct"] > 0
    assert m["series"]["cpu_pct"][-1] > 0
    # the history of the stopped stretch stays zero
    i = stamps.index(stop_at) if stop_at in stamps else None
    assert i is None or m["series"]["cpu_pct"][i] == 0.0


def test_a_new_instance_has_no_history_before_it_existed(client, pinned, admin_headers):
    from test_soc_cloud import _create_body

    r = client.post("/cloud/instances", json=_create_body(client, admin_headers),
                    headers=admin_headers)
    iid = r.json()["id"]
    pinned.set(T0 + timedelta(minutes=30))
    m = get_metrics(client, admin_headers, iid, "1h")
    nulls = [v for v in m["series"]["cpu_pct"] if v is None]
    assert nulls and m["series"]["cpu_pct"][-1] is not None and m["series"]["cpu_pct"][-1] > 0


# --- health ---------------------------------------------------------------------------------------

def test_health_comes_from_the_metrics(client, pinned, admin_headers):
    items = client.get("/cloud/instances", headers=admin_headers, params={"limit": 200}).json()["items"]
    for i in items:
        h = i["health"]
        if i["state"] != "running":
            assert h["status"] == "unknown"
            continue
        sample = get_metrics(client, admin_headers, i["id"], "1h")["current"]
        assert {c["name"] for c in h["checks"]} == {"instance_state", "cpu_pct", "memory_pct",
                                                    "disk_pct"}
        for c in h["checks"]:
            if c["name"] in sample:
                assert c["value"] == sample[c["name"]]
        worst = max(("healthy", "degraded", "critical").index(c["status"]) for c in h["checks"])
        assert h["status"] == ("healthy", "degraded", "critical")[worst]


@pytest.mark.parametrize("sample,expected", [
    ({"cpu_pct": 10, "memory_pct": 20, "disk_pct": 30}, "healthy"),
    ({"cpu_pct": 80, "memory_pct": 20, "disk_pct": 30}, "degraded"),
    ({"cpu_pct": 10, "memory_pct": 85, "disk_pct": 30}, "degraded"),
    ({"cpu_pct": 10, "memory_pct": 20, "disk_pct": 80}, "degraded"),
    ({"cpu_pct": 95, "memory_pct": 20, "disk_pct": 30}, "critical"),
    ({"cpu_pct": 10, "memory_pct": 95, "disk_pct": 30}, "critical"),
    ({"cpu_pct": 10, "memory_pct": 20, "disk_pct": 90}, "critical"),
    ({"cpu_pct": 80, "memory_pct": 20, "disk_pct": 90}, "critical"),
])
def test_health_thresholds(sample, expected):
    assert metrics.health("running", sample)["status"] == expected
    assert metrics.health("stopped", sample)["status"] == "unknown"


def test_the_demo_has_a_hot_and_a_full_instance(client, pinned, admin_headers):
    tiers = {i["name"]: metrics.tier(i["id"]) for i in client.get(
        "/cloud/instances", headers=admin_headers, params={"limit": 200}).json()["items"]}
    assert tiers["api-1"] == "hot" and tiers["db-1"] == "full" and tiers["build-1"] == "idle"


def test_fleet_summary(client, pinned, admin_headers):
    r = client.get("/cloud/metrics/summary", headers=admin_headers).json()
    assert r["metrics_source"] == "mock" and r["data_source"] == "mock"
    fleet = r["fleet"]
    assert fleet["running_instances"] == 6 and 0 < fleet["avg_cpu_pct"] <= fleet["max_cpu_pct"] <= 100
    assert 0 < fleet["avg_memory_pct"] < 100
    st = r["storage"]
    assert st["instance_disk_gb"] > 0 and 0 < st["instance_disk_used_pct"] < 100
    assert st["volumes_gb"] >= st["volumes_in_use_gb"] > 0
    assert len(r["busiest"]) == 5 and r["busiest"][0]["cpu_pct"] >= r["busiest"][-1]["cpu_pct"]
    assert len(r["cpu_trend_24h"]["timestamps"]) == 96 == len(r["cpu_trend_24h"]["avg_cpu_pct"])
    # it follows a state change: stopping everything leaves no running instances
    for i in client.get("/cloud/instances", headers=admin_headers,
                        params={"state": "running"}).json()["items"]:
        client.post(f"/cloud/instances/{i['id']}/stop", headers=admin_headers)
    r = client.get("/cloud/metrics/summary", headers=admin_headers).json()
    assert r["fleet"]["running_instances"] == 0 and r["fleet"]["avg_cpu_pct"] == 0.0
    assert r["busiest"] == []


def test_overview(client, pinned, admin_headers):
    r = client.get("/cloud/overview", headers=admin_headers).json()
    assert r["data_source"] == "mock" and r["region"] == "eu-west-1"
    assert r["instances"]["by_state"] == {"running": 6, "stopped": 1, "pending": 0,
                                          "terminated": 1}
    assert r["instances"]["total"] == 7 and sum(r["instances"]["by_type"].values()) == 7
    assert r["totals"]["vcpus_running"] > 0 and r["totals"]["buckets"] == 4
    assert r["totals"]["vpcs"] == 2 and r["totals"]["security_groups"] == 3
    assert sum(r["health"].values()) == 7 and r["health"]["unknown"] == 1
    assert r["alerts"]["open"] == 3 and r["alerts"]["acknowledged"] == 1
    assert r["alerts"]["critical_open"] == 2
    c = r["cost"]
    assert c["month_to_date"] > 0 and c["last_month_total"] > c["month_to_date"]
    assert c["month"] == "2026-03" and c["last_month_same_period"] > 0
    assert c["forecast_month_total"] == pytest.approx(c["month_to_date"] / 15 * 31, abs=0.01)
    assert c["change_vs_same_period_pct"] is not None
    client.post(f"/cloud/instances/{by_name(client, admin_headers, 'web-1')['id']}/stop",
                headers=admin_headers)
    r2 = client.get("/cloud/overview", headers=admin_headers).json()
    assert r2["instances"]["by_state"]["running"] == 5 and r2["instances"]["by_state"][
        "stopped"] == 2


# --- cost -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("rng,days", [("7d", 7), ("30d", 30), ("90d", 90)])
def test_cost_totals_are_consistent(client, pinned, admin_headers, rng, days):
    r = client.get("/cloud/cost", headers=admin_headers, params={"range": rng}).json()
    assert r["data_source"] == "mock" and r["currency"] == "USD" and r["available"] is True
    assert set(r["by_service"]) == {"compute", "storage", "network", "other"}
    assert r["total"] == pytest.approx(sum(r["by_service"].values()), abs=1e-6)
    assert r["total"] == pytest.approx(sum(d["total"] for d in r["by_day"]), abs=1e-6)
    assert len(r["by_day"]) == days and r["by_day"][-1]["day"] == "2026-03-15"
    assert r["first_day"] == r["by_day"][0]["day"]
    for d in r["by_day"]:
        assert d["total"] == pytest.approx(sum(d["services"].values()), abs=1e-6)
        assert set(d["services"]) == {"compute", "storage", "network", "other"}
    for s in r["by_service"]:
        assert r["by_service"][s] == pytest.approx(
            sum(d["services"][s] for d in r["by_day"]), abs=1e-6)
    assert "not a bill" in r["cost_note"]


def test_cost_keeps_pace_with_the_clock(client, pinned, admin_headers):
    first = client.get("/cloud/cost", headers=admin_headers, params={"range": "7d"}).json()
    by_day = {d["day"]: d for d in first["by_day"]}
    pinned.set(T0 + timedelta(days=4))  # first access was on the 15th: now it is the 19th
    r = client.get("/cloud/cost", headers=admin_headers, params={"range": "7d"}).json()
    assert r["last_day"] == "2026-03-19" and len(r["by_day"]) == 7
    assert all(d["total"] > 0 for d in r["by_day"])  # no empty days at the end
    for d in r["by_day"]:  # days that existed before are unchanged
        if d["day"] in by_day:
            assert d == by_day[d["day"]]
    f = r["forecast"]
    assert f["days_elapsed"] == 19
    mtd = sum(d["total"] for d in client.get(
        "/cloud/cost", headers=admin_headers, params={"range": "30d"}).json()["by_day"]
        if d["day"].startswith("2026-03"))
    assert f["month_to_date"] == pytest.approx(mtd, abs=0.02)
    assert client.get("/cloud/overview", headers=admin_headers).json()["cost"][
        "month_to_date"] == pytest.approx(mtd, abs=0.02)
    # a long gap is capped at the seeded window and still gapless
    pinned.set(T0 + timedelta(days=200))
    r = client.get("/cloud/cost", headers=admin_headers, params={"range": "90d"}).json()
    assert len(r["by_day"]) == 90 and all(d["total"] > 0 for d in r["by_day"])


def test_cost_days_are_a_pure_function_of_the_date():
    from datetime import date

    from soc.api.cloud import seed

    a = [(r.day, r.service, r.amount_usd) for r in seed.cost_rows(date(2026, 5, 1),
                                                                 date(2026, 5, 9))]
    b = [(r.day, r.service, r.amount_usd) for r in seed.cost_rows(date(2026, 5, 4),
                                                                 date(2026, 5, 9))]
    assert set(b) <= set(a)


def test_cost_forecast_is_linear(client, pinned, admin_headers):
    r = client.get("/cloud/cost", headers=admin_headers, params={"range": "30d"}).json()
    f = r["forecast"]
    assert f["month"] == "2026-03" and f["days_elapsed"] == 15 and f["days_in_month"] == 31
    mtd = sum(d["total"] for d in r["by_day"] if d["day"].startswith("2026-03"))
    assert f["month_to_date"] == pytest.approx(mtd, abs=0.011)
    assert f["projected_month_total"] == pytest.approx(mtd / 15 * 31, abs=0.02)
    assert "linear" in f["method"]
    pinned.set(T0 + timedelta(days=10))  # the forecast follows the calendar
    f2 = client.get("/cloud/cost", headers=admin_headers).json()["forecast"]
    assert f2["days_elapsed"] == 25


def test_top_cost_drivers_are_price_times_running_hours(client, pinned, admin_headers):
    from soc.api.cloud.catalog import INSTANCE_TYPES

    r = client.get("/cloud/cost", headers=admin_headers, params={"range": "7d"}).json()
    top = r["top_drivers"]
    assert 1 <= len(top) <= 5
    assert [d["estimated_usd"] for d in top] == sorted((d["estimated_usd"] for d in top),
                                                       reverse=True)
    for d in top:
        assert d["estimated_usd"] == pytest.approx(
            d["running_hours"] * INSTANCE_TYPES[d["instance_type"]][2], abs=0.02)
        assert d["running_hours"] <= 7 * 24
    names = {d["name"] for d in top}
    assert "batch-old" not in names  # terminated 6 days ago, ran one day of the 7
    by_type = {t["instance_type"]: t for t in r["by_instance_type"]}
    assert by_type["m5.large"]["instances"] == 2
    # a stopped instance stops adding hours
    web = by_name(client, admin_headers, "web-1")["id"]
    full = next(d for d in client.get("/cloud/cost", headers=admin_headers,
                                      params={"range": "7d"}).json()["by_instance_type"]
                if d["instance_type"] == "t3.medium")
    pinned.set(T0 + timedelta(hours=1))
    client.post(f"/cloud/instances/{web}/stop", headers=admin_headers)
    pinned.set(T0 + timedelta(hours=5))
    after = next(d for d in client.get("/cloud/cost", headers=admin_headers,
                                       params={"range": "7d"}).json()["by_instance_type"]
                 if d["instance_type"] == "t3.medium")
    assert after["running_hours"] < full["running_hours"] + 2 * 5  # 2 instances x 5 h, not more
    assert after["running_hours"] < full["running_hours"] + 9.5


def test_cost_validation(client, pinned, admin_headers):
    for bad in ("1d", "365d", "", "7"):
        assert client.get("/cloud/cost", headers=admin_headers,
                          params={"range": bad}).status_code == 422


# --- alerts ---------------------------------------------------------------------------------------

def _hot_minute(client, h, base):
    """A clock reading at which api-1's CPU is over the warning threshold (the load is a daily
    wave, so look for one)."""
    iid = by_name(client, h, "api-1")["id"]
    for n in range(0, 24 * 60, 7):
        t = base + timedelta(minutes=n)
        if metrics.current(iid, "running", base - timedelta(days=30), base - timedelta(days=30),
                           None, t)["cpu_pct"] >= 80:
            return t
    raise AssertionError("no hot minute")


def test_seeded_alerts_and_filters(client, pinned, admin_headers):
    al = client.get("/cloud/alerts", headers=admin_headers).json()
    assert al["total"] == 5 and al["data_source"] == "mock"
    assert {a["status"] for a in al["items"]} == {"open", "acknowledged", "resolved"}
    crit = client.get("/cloud/alerts", headers=admin_headers,
                      params={"severity": "critical"}).json()["items"]
    assert crit and {a["severity"] for a in crit} == {"critical"}
    opened = client.get("/cloud/alerts", headers=admin_headers, params={"status": "open"}).json()
    assert {a["status"] for a in opened["items"]} == {"open"} and opened["total"] == 3
    one = client.get("/cloud/alerts", headers=admin_headers, params={"limit": 2, "offset": 2}).json()
    assert len(one["items"]) == 2 and one["offset"] == 2
    for bad in ({"status": "closed"}, {"severity": "fatal"}, {"limit": 0}):
        assert client.get("/cloud/alerts", headers=admin_headers, params=bad).status_code == 422


def test_evaluate_creates_alerts_and_dedupes(client, pinned, admin_headers):
    client.get("/cloud/overview", headers=admin_headers)  # seed
    pinned.set(_hot_minute(client, admin_headers, T0))
    first = client.post("/cloud/alerts/evaluate", headers=admin_headers).json()
    assert first["data_source"] == "mock" and first["findings"] >= 3
    # the seeded open alerts (api-1 CPU, the public bucket, the open SSH group) are not repeated
    made = {(a["rule"], a["resource_id"]) for a in first["created"]}
    assert not [m for m in made if m[0] in ("bucket_public", "sg_open_admin", "cpu_high")
                and m[1] in ("idps-demo-static-assets",)]
    assert ("bucket_unencrypted", "idps-demo-scratch") in made  # a new finding
    assert ("volume_unencrypted", next(a["resource_id"] for a in first["created"]
                                       if a["rule"] == "volume_unencrypted")) in made
    assert first["already_open"] >= 3
    keys = [(a["rule"], a["resource_type"], a["resource_id"]) for a in client.get(
        "/cloud/alerts", headers=admin_headers, params={"limit": 200}).json()["items"]
        if a["status"] != "resolved"]
    assert len(keys) == len(set(keys))  # no duplicate of an open alert, ever
    second = client.post("/cloud/alerts/evaluate", headers=admin_headers).json()
    assert second["created"] == [] and second["already_open"] == second["findings"]
    third = client.get("/cloud/alerts", headers=admin_headers, params={"limit": 200}).json()
    assert third["total"] == 5 + len(first["created"])


def test_acknowledged_alerts_still_dedupe_and_resolved_ones_do_not(client, pinned, admin_headers):
    client.get("/cloud/overview", headers=admin_headers)
    pinned.set(_hot_minute(client, admin_headers, T0))
    client.post("/cloud/alerts/evaluate", headers=admin_headers)
    opened = client.get("/cloud/alerts", headers=admin_headers,
                        params={"status": "open", "limit": 200}).json()["items"]
    target = next(a for a in opened if a["rule"] == "bucket_unencrypted")
    r = client.post(f"/cloud/alerts/{target['id']}/acknowledge", headers=admin_headers)
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert r.json()["updated_by"] == "admin"
    assert client.post("/cloud/alerts/evaluate", headers=admin_headers).json()["created"] == []
    assert client.post(f"/cloud/alerts/{target['id']}/acknowledge",
                       headers=admin_headers).status_code == 409
    r = client.post(f"/cloud/alerts/{target['id']}/resolve", headers=admin_headers)
    assert r.json()["status"] == "resolved"
    assert client.post(f"/cloud/alerts/{target['id']}/resolve", headers=admin_headers).status_code == 409
    assert client.post(f"/cloud/alerts/{target['id']}/acknowledge",
                       headers=admin_headers).status_code == 409
    # the problem is still there, so the next evaluation raises a NEW alert for it
    again = client.post("/cloud/alerts/evaluate", headers=admin_headers).json()["created"]
    assert [(a["rule"], a["resource_id"]) for a in again] == [("bucket_unencrypted",
                                                               "idps-demo-scratch")]
    assert again[0]["id"] != target["id"]


def test_evaluate_sees_configuration_changes(client, pinned, admin_headers):
    h = admin_headers
    client.post("/cloud/alerts/evaluate", headers=h)
    r = client.post("/cloud/buckets", json={"name": "risky-bucket", "encrypted": False,
                                            "public_access_blocked": False}, headers=h)
    assert r.status_code == 201
    made = client.post("/cloud/alerts/evaluate", headers=h).json()["created"]
    rules = {(a["rule"], a["resource_id"]): a["severity"] for a in made}
    assert rules[("bucket_public", "risky-bucket")] == "critical"
    assert rules[("bucket_unencrypted", "risky-bucket")] == "warning"
    vpc = client.get("/cloud/network/vpcs", headers=h).json()["items"][0]["id"]
    sg = client.post("/cloud/network/security-groups", json={"name": "wide-open", "vpc_id": vpc},
                     headers=h).json()["id"]
    client.post(f"/cloud/network/security-groups/{sg}/rules", headers=h, json={
        "direction": "in", "protocol": "tcp", "port_from": 3389, "cidr": "0.0.0.0/0",
        "confirm_open_to_world": True})
    made = client.post("/cloud/alerts/evaluate", headers=h).json()["created"]
    assert [(a["rule"], a["severity"]) for a in made] == [("sg_open_admin", "critical")]


def test_a_metric_alert_escalates_instead_of_duplicating(client, pinned, admin_headers):
    h = admin_headers
    api = by_name(client, h, "api-1")["id"]
    created = client.get("/cloud/alerts", headers=h, params={"resource_id": api}).json()["items"]
    seeded = next(a for a in created if a["rule"] == "cpu_high")
    assert seeded["severity"] == "warning"
    # find a minute where CPU is critical (>= 95)
    for n in range(24 * 60):
        t = T0 + timedelta(minutes=n)
        if metrics.current(api, "running", T0 - timedelta(days=60), T0 - timedelta(days=60),
                           None, t)["cpu_pct"] >= 95:
            pinned.set(t)
            break
    else:
        pytest.skip("this instance never reaches 95% in a day")
    r = client.post("/cloud/alerts/evaluate", headers=h).json()
    assert [a["id"] for a in r["escalated"]] == [seeded["id"]]
    assert r["escalated"][0]["severity"] == "critical"
    assert activity(client, h, action="alert.escalate")


def test_delete_alert_and_404s(client, pinned, admin_headers):
    h = admin_headers
    a = client.get("/cloud/alerts", headers=h).json()["items"][0]
    assert client.delete(f"/cloud/alerts/{a['id']}", headers=h).status_code == 200
    assert client.delete(f"/cloud/alerts/{a['id']}", headers=h).status_code == 404
    assert client.post("/cloud/alerts/999999/acknowledge", headers=h).status_code == 404
    assert client.post("/cloud/alerts/999999/resolve", headers=h).status_code == 404
    assert client.post("/cloud/alerts/0/resolve", headers=h).status_code == 422
    assert client.get("/cloud/alerts", headers=h).json()["total"] == 4


def test_notifications_are_the_unresolved_alerts(client, pinned, admin_headers):
    h = admin_headers
    n = client.get("/cloud/notifications", headers=h).json()
    assert n["data_source"] == "mock"
    assert n["total"] == 4 and n["open"] == 3 and n["acknowledged"] == 1
    assert {a["status"] for a in n["items"]} <= {"open", "acknowledged"}
    order = [{"critical": 2, "warning": 1, "info": 0}[a["severity"]] for a in n["items"]]
    assert order == sorted(order, reverse=True)
    first = n["items"][0]
    client.post(f"/cloud/alerts/{first['id']}/resolve", headers=h)
    n2 = client.get("/cloud/notifications", headers=h).json()
    assert n2["total"] == 3 and first["id"] not in [a["id"] for a in n2["items"]]
    assert len(client.get("/cloud/notifications", headers=h, params={"limit": 1}).json()["items"]) == 1


def test_viewers_can_read_alerts_but_not_manage_them(client, soc_app, pinned, analyst_headers):
    assert client.get("/cloud/alerts", headers=analyst_headers).status_code == 200
    assert client.get("/cloud/notifications", headers=analyst_headers).status_code == 200
    assert client.post("/cloud/alerts/evaluate", headers=analyst_headers).status_code == 403
