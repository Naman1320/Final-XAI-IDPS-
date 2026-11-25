"""SOC API: dry-run would_block events and the class-by-day summary."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import alert_payload, ingest

from soc.api.models import Alert, AlertStatus, Block, Severity, WouldBlock


def would(**kw):
    return {"event": "would_block", "ip": "203.0.113.7", "reason": "5 flows >= 0.9",
            "ttl_seconds": 900, "source": "auto"} | kw


def post_events(client, headers, *events):
    return client.post("/ingest/blocks", headers=headers, json={"events": list(events)})


def test_would_block_is_stored_apart_from_blocks(client, soc_app, sensor_headers, analyst_headers):
    r = post_events(client, sensor_headers, would())
    assert r.status_code == 201 and r.json() == {"blocked": 0, "unblocked": 0, "would_block": 1}
    with soc_app.state.session_factory() as db:
        assert db.query(Block).count() == 0 and db.query(WouldBlock).count() == 1
    assert client.get("/blocks", headers=analyst_headers).json()["items"] == []
    assert client.get("/blocks?active=true", headers=analyst_headers).json()["items"] == []
    m = client.get("/metrics/summary", headers=analyst_headers).json()
    assert m["active_blocks"] == 0 and m["would_blocks"] == 1


def test_would_block_does_not_touch_real_blocks(client, soc_app, sensor_headers, analyst_headers):
    post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.7",
                                         "ttl_seconds": 600, "source": "auto"})
    r = post_events(client, sensor_headers, would(), would(ip="203.0.113.8"))
    assert r.json() == {"blocked": 0, "unblocked": 0, "would_block": 2}
    items = client.get("/blocks?active=true", headers=analyst_headers).json()["items"]
    assert [b["ip"] for b in items] == ["203.0.113.7"]  # unchanged, not refreshed or closed
    assert items[0]["unblocked_at"] is None
    m = client.get("/metrics/summary", headers=analyst_headers).json()
    assert m["active_blocks"] == 1 and m["would_blocks"] == 2


def test_an_unblock_event_does_not_remove_would_blocks(client, soc_app, sensor_headers):
    post_events(client, sensor_headers, would(), {"event": "unblocked", "ip": "203.0.113.7"})
    with soc_app.state.session_factory() as db:
        assert db.query(WouldBlock).count() == 1


def test_would_block_needs_a_sensor_token_and_is_validated(client, analyst_headers, sensor_headers):
    assert post_events(client, analyst_headers, would()).status_code == 401
    assert post_events(client, sensor_headers, would(expires_at="2999-01-01T00:00:00Z")
                       ).status_code == 422
    assert post_events(client, sensor_headers, would(ip="nope")).status_code == 422
    assert post_events(client, sensor_headers, would(ttl_seconds=0)).status_code == 422
    assert post_events(client, sensor_headers, would(reason="x" * 501)).status_code == 422
    assert post_events(client, sensor_headers, would(extra=1)).status_code == 422
    assert post_events(client, sensor_headers, *[would()] * 101).status_code == 422
    assert post_events(client, sensor_headers, would(ttl_seconds=None, reason="")).status_code == 201


def test_would_block_with_an_alert_id(client, sensor_headers, analyst_headers):
    (alert_id,) = ingest(client, sensor_headers, alert_payload())
    assert post_events(client, sensor_headers, would(alert_id=alert_id)).status_code == 201
    assert post_events(client, sensor_headers, would(alert_id=alert_id + 99)).status_code == 422
    (item,) = client.get("/blocks/would", headers=analyst_headers).json()["items"]
    assert item["alert_id"] == alert_id


def test_list_would_blocks_filters_and_pages(client, soc_app, sensor_headers, analyst_headers):
    assert client.get("/blocks/would").status_code == 401
    assert client.get("/blocks/would", headers=sensor_headers).status_code == 401
    post_events(client, sensor_headers, *[would(ip=f"198.51.100.{i}") for i in range(1, 6)])
    page = client.get("/blocks/would?limit=2", headers=analyst_headers).json()
    assert [i["ip"] for i in page["items"]] == ["198.51.100.5", "198.51.100.4"]
    assert page["next_cursor"] is not None
    nxt = client.get(f"/blocks/would?limit=2&cursor={page['next_cursor']}",
                     headers=analyst_headers).json()
    assert [i["ip"] for i in nxt["items"]] == ["198.51.100.3", "198.51.100.2"]
    one = client.get("/blocks/would?ip=198.51.100.2", headers=analyst_headers).json()["items"]
    assert len(one) == 1 and one[0]["ttl_seconds"] == 900 and one[0]["source"] == "auto"
    assert set(one[0]) == {"id", "sensor_id", "ip", "reason", "source", "alert_id", "at",
                           "ttl_seconds"}
    # since_hours: age one row beyond the window
    with soc_app.state.session_factory() as db:
        db.query(WouldBlock).filter_by(ip="198.51.100.2").update(
            {"at": datetime.now(UTC) - timedelta(hours=5)})
        db.commit()
    assert client.get("/blocks/would?ip=198.51.100.2&since_hours=1",
                      headers=analyst_headers).json()["items"] == []
    assert len(client.get("/blocks/would?ip=198.51.100.2&since_hours=6",
                          headers=analyst_headers).json()["items"]) == 1
    assert client.get("/blocks/would?since_hours=0", headers=analyst_headers).status_code == 422
    assert client.get("/blocks/would?limit=501", headers=analyst_headers).status_code == 422


def test_metrics_would_blocks_follow_the_window(client, soc_app, sensor_headers, analyst_headers):
    post_events(client, sensor_headers, would(), would())
    with soc_app.state.session_factory() as db:
        first = db.query(WouldBlock).first()
        first.at = datetime.now(UTC) - timedelta(hours=3)
        db.commit()
    assert client.get("/metrics/summary?hours=1", headers=analyst_headers
                      ).json()["would_blocks"] == 1
    assert client.get("/metrics/summary?hours=24", headers=analyst_headers
                      ).json()["would_blocks"] == 2


# --- by_class_per_day -----------------------------------------------------------------------

def add_alert(db, received_at, cls="SSH-Patator", anomaly=0.1, sensor_id=1):
    db.add(Alert(sensor_id=sensor_id, received_at=received_at, src_ip="203.0.113.7", src_port=1,
                 dst_ip="10.10.1.5", dst_port=22, protocol=6, start_ms=1, end_ms=2,
                 predicted_class=cls, confidence=0.9, anomaly_score=anomaly,
                 severity=Severity.MEDIUM, explanation={}, status=AlertStatus.NEW))


NOW = datetime(2026, 11, 13, 0, 0, 30, tzinfo=UTC)  # 30 s after midnight: boundaries are close
TODAY = NOW.replace(second=0)


@pytest.fixture
def pinned(monkeypatch):
    """The SOC's clock fixed at NOW, so no test depends on when it runs (midnight included)."""
    from soc.api.routes import metrics

    monkeypatch.setattr(metrics, "_utcnow", lambda: NOW)
    return metrics


def per_day(client, headers, hours=1):
    m = client.get(f"/metrics/summary?hours={hours}", headers=headers).json()
    return [(r["day"], r["class"], r["count"]) for r in m["by_class_per_day"]]


def test_by_class_per_day_buckets_by_utc_day(pinned, client, soc_app, sensor_token, analyst_headers):
    today = TODAY
    day = lambda n: (today - timedelta(days=n)).strftime("%Y-%m-%d")
    with soc_app.state.session_factory() as db:
        add_alert(db, today + timedelta(microseconds=1), "DDoS", anomaly=None)  # first instant today
        add_alert(db, today - timedelta(microseconds=1), "DDoS", anomaly=None)  # last instant yday
        add_alert(db, today - timedelta(days=1), "DDoS", anomaly=None)  # first instant yday
        add_alert(db, today - timedelta(days=6), "PortScan", anomaly=None)  # oldest day kept
        add_alert(db, today - timedelta(days=6, microseconds=1), "PortScan")  # too old: 8 days
        db.commit()
    rows = per_day(client, analyst_headers)
    assert rows == [(day(6), "PortScan", 1), (day(1), "DDoS", 2), (day(0), "DDoS", 1)]


def test_by_class_per_day_ignores_the_hours_parameter(pinned, client, soc_app, sensor_token,
                                                      analyst_headers):
    today = TODAY
    with soc_app.state.session_factory() as db:
        add_alert(db, today - timedelta(days=3, hours=-1), "Bot", anomaly=None)
        db.commit()
    assert per_day(client, analyst_headers, hours=1) == per_day(client, analyst_headers, hours=720)
    assert len(per_day(client, analyst_headers, hours=1)) == 1
    # by_class itself still follows the window
    assert client.get("/metrics/summary?hours=1", headers=analyst_headers).json()["by_class"] == {}


def test_empty_by_class_per_day(pinned, client, analyst_headers):
    assert per_day(client, analyst_headers) == []


def test_by_class_per_day_groups_the_rest_as_other(pinned, client, soc_app, sensor_token,
                                                   analyst_headers, monkeypatch):
    monkeypatch.setattr(pinned, "MAX_CLASSES", 2)
    now = NOW
    with soc_app.state.session_factory() as db:
        for _ in range(3):
            add_alert(db, now, "A", anomaly=None)
        for _ in range(2):
            add_alert(db, now, "B", anomaly=None)
        add_alert(db, now, "C", anomaly=None)
        add_alert(db, now, "D", anomaly=None)
        db.commit()
    got = {c: n for _, c, n in per_day(client, analyst_headers)}
    assert got == {"A": 3, "B": 2, "(other)": 2}


def test_anomaly_per_day_counts_alerts_the_isolation_forest_flagged(pinned, client, soc_app,
                                                                    sensor_token, analyst_headers):
    now = NOW
    with soc_app.state.session_factory() as db:
        add_alert(db, now, "SSH-Patator", anomaly=0.2)    # flagged
        add_alert(db, now, "DDoS", anomaly=0.01)           # flagged
        add_alert(db, now, "DDoS", anomaly=0.0)            # on the boundary: not flagged
        add_alert(db, now, "DDoS", anomaly=-0.3)           # inlier
        add_alert(db, now, "DDoS", anomaly=None)           # no anomaly detector in the bundle
        db.commit()
    got = {c: n for _, c, n in per_day(client, analyst_headers)}
    assert got == {"DDoS": 4, "SSH-Patator": 1}  # no synthetic "Anomaly" class row any more
    m = client.get("/metrics/summary", headers=analyst_headers).json()
    assert m["anomaly_per_day"] == [{"day": "2026-11-13", "count": 2}]


def test_anomaly_per_day_buckets_by_day_and_omits_empty_days(pinned, client, soc_app,
                                                             sensor_token, analyst_headers):
    with soc_app.state.session_factory() as db:
        add_alert(db, TODAY - timedelta(microseconds=1), "DDoS", anomaly=0.5)  # yesterday
        add_alert(db, TODAY, "DDoS", anomaly=0.5)  # today
        add_alert(db, TODAY - timedelta(days=6), "Bot", anomaly=0.1)
        add_alert(db, TODAY - timedelta(days=7), "Bot", anomaly=0.1)  # outside the 7 days
        add_alert(db, TODAY - timedelta(days=3), "Bot", anomaly=-1.0)  # inlier: day omitted
        db.commit()
    m = client.get("/metrics/summary?hours=1", headers=analyst_headers).json()
    assert m["anomaly_per_day"] == [{"day": "2026-11-07", "count": 1},
                                    {"day": "2026-11-12", "count": 1},
                                    {"day": "2026-11-13", "count": 1}]
    assert all(r["class"] != "Anomaly" for r in m["by_class_per_day"])


def test_an_empty_anomaly_series(pinned, client, analyst_headers):
    assert client.get("/metrics/summary", headers=analyst_headers).json()["anomaly_per_day"] == []

def test_by_class_per_day_is_cached_per_day_and_expires(pinned, client, soc_app, sensor_token,
                                                        analyst_headers, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(pinned, "_monotonic", lambda: clock[0])
    with soc_app.state.session_factory() as db:
        add_alert(db, NOW, "DDoS", anomaly=None)
        db.commit()
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 1)]
    with soc_app.state.session_factory() as db:
        add_alert(db, NOW, "DDoS", anomaly=None)
        db.commit()
    clock[0] += 59
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 1)]  # still cached
    clock[0] += 2
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 2)]  # expired
    pinned.clear_class_per_day_cache()
    with soc_app.state.session_factory() as db:
        add_alert(db, NOW, "DDoS", anomaly=None)
        db.commit()
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 3)]


def test_the_cache_never_serves_yesterdays_buckets_on_a_new_day(pinned, client, soc_app,
                                                                sensor_token, analyst_headers,
                                                                monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(pinned, "_monotonic", lambda: clock[0])
    with soc_app.state.session_factory() as db:
        add_alert(db, NOW, "DDoS", anomaly=None)
        db.commit()
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 1)]
    later = NOW + timedelta(days=1)  # within the cache's age, but the next UTC day
    monkeypatch.setattr(pinned, "_utcnow", lambda: later)
    clock[0] += 5
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 1)]
    assert [r["day"] for r in client.get("/metrics/summary", headers=analyst_headers
                                         ).json()["by_class_per_day"]] == ["2026-11-13"]
    with soc_app.state.session_factory() as db:
        add_alert(db, later, "Bot", anomaly=None)
        db.commit()
    pinned.clear_class_per_day_cache()
    assert per_day(client, analyst_headers) == [("2026-11-13", "DDoS", 1), ("2026-11-14", "Bot", 1)]


def test_by_class_per_day_is_one_query(pinned, client, soc_app, sensor_token, analyst_headers):
    from sqlalchemy import event

    engine = soc_app.state.engine
    seen = []

    def record(conn, cursor, statement, *rest):
        seen.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        per_day(client, analyst_headers)
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert len([q for q in seen if "GROUP BY" in q and "anomaly_score" in q]) == 1


# --- decided_at -----------------------------------------------------------------------------

def stored_at(soc_app):
    with soc_app.state.session_factory() as db:
        return db.query(WouldBlock).order_by(WouldBlock.id.desc()).first().at


def test_decided_at_is_stored_as_the_event_time(client, soc_app, sensor_headers):
    past = datetime.now(UTC) - timedelta(hours=2)
    assert post_events(client, sensor_headers, would(decided_at=past.isoformat())
                       ).status_code == 201
    assert abs(stored_at(soc_app) - past) < timedelta(seconds=1)


def test_a_missing_decided_at_falls_back_to_receive_time(client, soc_app, sensor_headers):
    post_events(client, sensor_headers, would())
    assert abs(datetime.now(UTC) - stored_at(soc_app)) < timedelta(seconds=30)


def test_a_future_decided_at_is_clamped_to_now(client, soc_app, sensor_headers):
    post_events(client, sensor_headers,
                would(decided_at=(datetime.now(UTC) + timedelta(days=3)).isoformat()))
    assert abs(datetime.now(UTC) - stored_at(soc_app)) < timedelta(seconds=30)
    post_events(client, sensor_headers,  # within the skew allowance: never later than now
                would(decided_at=(datetime.now(UTC) + timedelta(seconds=30)).isoformat()))
    assert stored_at(soc_app) <= datetime.now(UTC)


def test_decided_at_must_have_a_timezone_and_only_suits_would_block(client, sensor_headers):
    assert post_events(client, sensor_headers, would(decided_at="2026-11-13T10:00:00")
                       ).status_code == 422
    assert post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.7",
                                                "ttl_seconds": 60,
                                                "decided_at": "2026-11-13T10:00:00Z"}
                       ).status_code == 422


def test_decision_time_helper():
    from soc.api.routes.blocks import decision_time

    assert decision_time(None, NOW) == NOW
    assert decision_time(NOW - timedelta(hours=1), NOW) == NOW - timedelta(hours=1)
    assert decision_time(NOW + timedelta(seconds=61), NOW) == NOW
    assert decision_time(NOW + timedelta(seconds=59), NOW) == NOW


def test_a_very_old_decided_at_falls_back_to_receive_time(client, soc_app, sensor_headers):
    from soc.api.routes.blocks import MAX_DECISION_AGE, decision_time

    assert decision_time(NOW - MAX_DECISION_AGE, NOW) == NOW - MAX_DECISION_AGE  # edge: kept
    assert decision_time(NOW - MAX_DECISION_AGE - timedelta(seconds=1), NOW) == NOW
    post_events(client, sensor_headers,
                would(decided_at=(datetime.now(UTC) - timedelta(days=400)).isoformat()))
    assert abs(datetime.now(UTC) - stored_at(soc_app)) < timedelta(seconds=30)
    post_events(client, sensor_headers,  # a plausible outbox delay is honoured
                would(decided_at=(datetime.now(UTC) - timedelta(hours=20)).isoformat()))
    assert datetime.now(UTC) - stored_at(soc_app) > timedelta(hours=19)


def test_the_cache_cannot_be_changed_through_a_returned_list(pinned, client, soc_app,
                                                             sensor_token, analyst_headers):
    from soc.api.routes.metrics import class_per_day

    with soc_app.state.session_factory() as db:
        add_alert(db, NOW, "DDoS", anomaly=None)
        db.commit()
        add_alert(db, NOW, "DDoS", anomaly=1.0)
        db.commit()
        classes, outliers = class_per_day(db, NOW)
        classes.clear()
        outliers.clear()
        again_classes, again_outliers = class_per_day(db, NOW)  # served from the cache
        again_classes.append("junk")
        again_outliers.append("junk")
        classes, outliers = class_per_day(db, NOW)
        assert [(r.day, r.class_, r.count) for r in classes] == [("2026-11-13", "DDoS", 2)]
        assert [(r.day, r.count) for r in outliers] == [("2026-11-13", 1)]


# --- sensor-supplied text (L5) and class names (L6) -----------------------------------------

def test_a_would_block_cannot_claim_an_analyst(client, soc_app, sensor_headers, analyst_headers):
    r = post_events(client, sensor_headers, would(source="analyst"))
    assert r.status_code == 201
    (item,) = client.get("/blocks/would", headers=analyst_headers).json()["items"]
    assert item["source"] == "auto"


def test_real_analyst_blocks_still_keep_their_source(client, sensor_headers, analyst_headers):
    post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.9",
                                         "ttl_seconds": 60, "source": "analyst"})
    (b,) = client.get("/blocks", headers=analyst_headers).json()["items"]
    assert b["source"] == "analyst"


def test_reasons_lose_control_and_direction_characters_and_nul_is_refused(
        client, sensor_headers, analyst_headers):
    r = post_events(client, sensor_headers, would(reason="5 flows\u202e\n\x1b[31m ok\u200b"))
    assert r.status_code == 201
    (item,) = client.get("/blocks/would", headers=analyst_headers).json()["items"]
    assert item["reason"] == "5 flows[31m ok"
    assert post_events(client, sensor_headers, would(reason="a\x00b")).status_code == 422
    assert post_events(client, sensor_headers, {"event": "blocked", "ip": "203.0.113.9",
                                                "reason": "a\x00b", "ttl_seconds": 60}
                       ).status_code == 422


@pytest.mark.parametrize("name", ["(other)", "(anything)", " (x)"])
def test_a_class_starting_with_a_parenthesis_is_refused_at_ingest(client, sensor_headers, name):
    r = client.post("/ingest/alerts", headers=sensor_headers,
                    json={"alerts": [alert_payload(predicted_class=name)]})
    assert r.status_code == 422


def test_nul_and_control_characters_in_alert_text_are_refused(client, sensor_headers):
    def post_alert(**kw):
        return client.post("/ingest/alerts", headers=sensor_headers,
                           json={"alerts": [alert_payload(**kw)]}).status_code

    assert post_alert(predicted_class="Do\x00S") == 422
    assert post_alert(predicted_class="Do\u202eS") == 422
    expl = {"method": "shap", "top_features": [{"feature": "a\x00b", "value": 1.0,
                                                 "contribution": 0.1}]}
    assert post_alert(explanation=expl) == 422
    assert post_alert(explanation={"method": "sh\x00ap"}) == 422
    assert post_alert(explanation={"k\x00": 1}) == 422
    assert post_alert(predicted_class="Web Attack – Brute Force") == 201  # ordinary unicode


def test_nul_in_an_action_result_is_refused(client, soc_app, sensor_headers, admin_headers):
    r = client.post("/sensor/actions/1/result", headers=sensor_headers,
                    json={"success": False, "result": {"error": "bad\x00"}})
    assert r.status_code == 422
