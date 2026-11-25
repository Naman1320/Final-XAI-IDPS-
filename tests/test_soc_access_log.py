"""The access log: who looked at personal data, as fingerprints; the admin lookup; retention."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import TEST_SECRET, alert_payload, ingest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from soc.api import access_log
from soc.api.models import AccessLog, Block, BlockSource, SensorToken, WouldBlock
from soc.api.retention import prune
from soc.api.settings import SocSettings

SRC, DST = "203.0.113.7", "10.10.1.5"


def fp(app, ip):
    return access_log.fingerprint(app.state.settings, ip)


def rows(app, **where):
    with app.state.session_factory() as db:
        q = select(AccessLog).order_by(AccessLog.id)
        for k, v in where.items():
            q = q.where(getattr(AccessLog, k) == v)
        return list(db.scalars(q))


def whole_table(app) -> str:
    return json.dumps([{c.name: str(getattr(r, c.name)) for c in AccessLog.__table__.columns}
                       for r in rows(app)])


@pytest.fixture
def alert_id(client, sensor_headers):
    return ingest(client, sensor_headers, alert_payload(src_ip=SRC, dst_ip=DST))[0]


# --- fingerprints -----------------------------------------------------------------------------

def test_fingerprint_is_a_keyed_hmac_of_the_normalised_address(soc_settings):
    a = access_log.fingerprint(soc_settings, "2001:db8::1")
    assert len(a) == 64 and int(a, 16) >= 0
    assert a == access_log.fingerprint(soc_settings, "2001:0DB8:0:0:0:0:0:1")  # any spelling
    assert access_log.fingerprint(soc_settings, "::ffff:1.2.3.4") == \
        access_log.fingerprint(soc_settings, "1.2.3.4")  # IPv4-mapped is the IPv4 address
    assert access_log.fingerprint(soc_settings, "1.2.3.4") != \
        access_log.fingerprint(soc_settings, "1.2.3.5")
    assert access_log.fingerprint(soc_settings, "1.2.3.4") != hashlib.sha256(b"1.2.3.4").hexdigest()


def test_fingerprint_key_comes_from_the_mfa_key_else_the_jwt_secret():
    jwt_only = SocSettings(jwt_secret=TEST_SECRET)
    same = SocSettings(jwt_secret="another-secret-" + "y" * 40, mfa_key=TEST_SECRET)
    other = SocSettings(jwt_secret=TEST_SECRET, mfa_key="m" * 40)
    assert access_log.fingerprint(jwt_only, "1.2.3.4") == access_log.fingerprint(same, "1.2.3.4")
    assert access_log.fingerprint(jwt_only, "1.2.3.4") != access_log.fingerprint(other, "1.2.3.4")


@pytest.mark.parametrize("bad", ["", "nope", "1.2.3.0/24"])
def test_normalise_refuses_what_is_not_an_address(bad):
    with pytest.raises(ValueError):
        access_log.normalise_ip(bad)


# --- what is logged ---------------------------------------------------------------------------

def test_viewing_an_alert_logs_source_and_destination(client, soc_app, analyst_headers, alert_id):
    assert client.get(f"/alerts/{alert_id}", headers=analyst_headers).status_code == 200
    got = rows(soc_app)
    assert [(r.username, r.action, r.target_type, r.target) for r in got] == \
        [("analyst", "alert_view", "alert", str(alert_id))] * 2
    assert {r.subject_fp for r in got} == {fp(soc_app, SRC), fp(soc_app, DST)}
    assert all(r.user_id and r.at for r in got)
    assert SRC not in whole_table(soc_app) and DST not in whole_table(soc_app)


def test_a_failed_lookup_is_not_logged(client, soc_app, analyst_headers):
    assert client.get("/alerts/9999", headers=analyst_headers).status_code == 404
    assert rows(soc_app) == []


def test_searching_alerts_by_address_logs_the_address_searched(client, soc_app, analyst_headers,
                                                               alert_id):
    assert client.get(f"/alerts?ip={SRC}", headers=analyst_headers).status_code == 200
    (row,) = rows(soc_app)
    assert row.action == "alert_search_by_ip" and row.subject_fp == fp(soc_app, SRC)
    # the filter is normalised: another spelling is the same subject
    client.get("/alerts?ip=::ffff:203.0.113.7", headers=analyst_headers)
    assert [r.subject_fp for r in rows(soc_app)] == [fp(soc_app, SRC)] * 2
    assert SRC not in whole_table(soc_app)


def test_listing_alerts_without_an_address_filter_logs_nothing(client, soc_app, analyst_headers,
                                                               alert_id):
    for path in ("/alerts", "/alerts?severity=high", "/blocks", "/blocks/would", "/cases"):
        assert client.get(path, headers=analyst_headers).status_code == 200
    assert rows(soc_app) == []


def test_searching_blocks_and_would_blocks_by_address(client, soc_app, analyst_headers,
                                                      sensor_token):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(Block(sensor_id=sensor.id, ip=SRC, reason="r", source=BlockSource.AUTO,
                     blocked_at=now))
        db.add(WouldBlock(sensor_id=sensor.id, ip=SRC, reason="r", source=BlockSource.AUTO, at=now))
        db.commit()
    assert client.get(f"/blocks?ip={SRC}", headers=analyst_headers).json()["items"]
    assert client.get(f"/blocks/would?ip={SRC}", headers=analyst_headers).json()["items"]
    assert [(r.action, r.subject_fp) for r in rows(soc_app)] == [
        ("block_search_by_ip", fp(soc_app, SRC)), ("would_block_search_by_ip", fp(soc_app, SRC))]


def test_reputation_view_logs_the_source_address(client, soc_app, analyst_headers, alert_id):
    r = client.get(f"/alerts/{alert_id}/reputation", headers=analyst_headers)
    assert r.status_code == 200
    (row,) = rows(soc_app)
    assert row.action == "reputation_view" and row.subject_fp == fp(soc_app, SRC)
    assert row.target == str(alert_id)


def test_viewing_a_case_logs_the_case_and_its_alerts_addresses(client, soc_app, analyst_headers,
                                                               sensor_headers):
    ids = ingest(client, sensor_headers, alert_payload(src_ip=SRC, dst_ip=DST),
                 alert_payload(src_ip="198.51.100.9", dst_ip=DST))
    case = client.post("/cases", json={"title": "c", "alert_ids": ids}, headers=analyst_headers)
    assert case.status_code == 201
    cid = case.json()["id"]
    assert rows(soc_app) == []  # creating it is audited, not an access
    assert client.get(f"/cases/{cid}", headers=analyst_headers).status_code == 200
    got = rows(soc_app)
    assert all(r.action == "case_view" and r.target == str(cid) for r in got)
    assert got[0].subject_fp is None  # the case itself
    assert {r.subject_fp for r in got[1:]} == {fp(soc_app, ip)
                                              for ip in (SRC, DST, "198.51.100.9")}
    assert len(got) == 4  # one row per distinct address, DST once


def test_a_case_with_many_addresses_is_capped(client, soc_app, analyst_headers, sensor_headers):
    alerts = [alert_payload(src_ip=f"192.0.2.{i}", dst_ip=f"198.51.100.{i}") for i in range(1, 61)]
    ids = ingest(client, sensor_headers, *alerts)
    cid = client.post("/cases", json={"title": "big", "alert_ids": ids},
                      headers=analyst_headers).json()["id"]
    assert client.get(f"/cases/{cid}", headers=analyst_headers).status_code == 200
    assert len(rows(soc_app)) == access_log.MAX_SUBJECTS + 1  # the case row and 100 addresses


def test_training_export_and_report_download_are_logged_without_a_subject(
        client, soc_app, admin_headers):
    assert client.get("/training/feedback", headers=admin_headers).status_code == 200
    assert client.get("/reports/weekly", headers=admin_headers).status_code == 200
    got = rows(soc_app)
    assert [(r.action, r.subject_fp) for r in got] == [("training_feedback_export", None),
                                                       ("report_download", None)]
    assert got[1].target_type == "report" and got[1].target.count("-W") == 1


def test_a_sensor_reading_nothing_and_ingest_are_not_accesses(client, soc_app, sensor_headers):
    ingest(client, sensor_headers, alert_payload())
    assert rows(soc_app) == []


# --- fail closed ------------------------------------------------------------------------------

def test_if_logging_fails_the_request_fails_and_serves_nothing(soc_app, analyst_headers, alert_id,
                                                               monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("log disk full")

    monkeypatch.setattr(access_log, "fingerprint", broken)
    c = TestClient(soc_app, raise_server_exceptions=False)
    for path in (f"/alerts/{alert_id}", f"/alerts?ip={SRC}"):
        r = c.get(path, headers=analyst_headers)
        assert r.status_code == 500, path
        assert SRC not in r.text and DST not in r.text and "predicted_class" not in r.text
    monkeypatch.undo()
    assert rows(soc_app) == []


def test_if_the_commit_fails_nothing_is_served(soc_app, analyst_headers, alert_id, monkeypatch):
    from sqlalchemy.orm import Session

    real = Session.commit

    def failing(self):
        if any(isinstance(o, AccessLog) for o in self.new):
            raise RuntimeError("commit failed")
        return real(self)

    monkeypatch.setattr(Session, "commit", failing)
    r = TestClient(soc_app, raise_server_exceptions=False).get(
        f"/alerts/{alert_id}", headers=analyst_headers)
    assert r.status_code == 500 and SRC not in r.text
    monkeypatch.undo()
    assert rows(soc_app) == []


# --- the admin lookup -------------------------------------------------------------------------

def test_lookup_by_address_username_action_and_time(client, soc_app, admin_headers,
                                                    analyst_headers, alert_id):
    client.get(f"/alerts/{alert_id}", headers=analyst_headers)
    client.get(f"/alerts?ip={SRC}", headers=admin_headers)
    client.get("/reports/weekly", headers=admin_headers)

    def items(qs):
        r = client.get(f"/admin/privacy/access-log?{qs}", headers=admin_headers)
        assert r.status_code == 200, r.text
        return r.json()["items"]

    who = items(f"ip={SRC}")
    assert sorted((i["username"], i["action"]) for i in who) == [
        ("admin", "alert_search_by_ip"), ("analyst", "alert_view")]
    assert all(i["subject_fp"] == fp(soc_app, SRC) for i in who)
    assert [i["username"] for i in items(f"ip={DST}")] == ["analyst"]
    assert items("ip=::ffff:203.0.113.7") == who  # any spelling of the address
    assert items("ip=192.0.2.99") == []
    assert {i["username"] for i in items("username=analyst")} == {"analyst"}
    assert {i["action"] for i in items("action=report_download")} == {"report_download"}
    now = datetime.now(UTC)
    past = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    future = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    assert len(items(f"since={past}")) == 4 and items(f"since={future}") == []
    assert len(items(f"until={future}")) == 4 and items(f"until={past}") == []
    assert items(f"ip={SRC}&username=analyst")[0]["action"] == "alert_view"
    assert set(who[0]) == {"id", "at", "user_id", "username", "action", "target_type", "target",
                           "subject_fp"}
    assert SRC not in json.dumps(who)


def test_lookup_paginates_newest_first(client, soc_app, admin_headers, analyst_headers, alert_id):
    for _ in range(3):
        client.get(f"/alerts?ip={SRC}", headers=analyst_headers)
    page = client.get(f"/admin/privacy/access-log?ip={SRC}&limit=2", headers=admin_headers).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    assert page["items"][0]["id"] > page["items"][1]["id"]
    rest = client.get(f"/admin/privacy/access-log?ip={SRC}&limit=2&cursor={page['next_cursor']}",
                      headers=admin_headers).json()
    assert len(rest["items"]) == 1 and rest["next_cursor"] is None
    seen = [i["id"] for i in page["items"] + rest["items"]]
    assert seen == sorted(seen, reverse=True) and len(set(seen)) == 3


@pytest.mark.parametrize("qs", ["ip=nope", "ip=10.0.0.0/24", "since=2026-01-01T00:00:00",
                                "until=2026-01-01T00:00:00", "limit=0", "limit=501"])
def test_lookup_validates_its_filters(client, admin_headers, qs):
    assert client.get(f"/admin/privacy/access-log?{qs}", headers=admin_headers).status_code == 422


# --- retention --------------------------------------------------------------------------------

def test_access_log_retention(soc_app):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        for days in (400, 366, 364, 1):
            db.add(AccessLog(at=now - timedelta(days=days), user_id=1, username="u",
                             action="alert_view", subject_fp=None))
        db.commit()
        settings = soc_app.state.settings
        assert settings.access_log_retention_days == 365
        dry = prune(db, settings, now, dry_run=True)
        assert dry["access_log"] == 2
        done = prune(db, settings, now)
        assert done["access_log"] == 2
        assert db.scalar(select(func.count()).select_from(AccessLog)) == 2


def test_access_log_retention_zero_keeps_everything(soc_app):
    now = datetime.now(UTC)
    settings = soc_app.state.settings.model_copy(update={"access_log_retention_days": 0})
    with soc_app.state.session_factory() as db:
        db.add(AccessLog(at=now - timedelta(days=5000), user_id=1, username="u", action="a"))
        db.commit()
        assert prune(db, settings, now)["access_log"] == 0
        assert db.scalar(select(func.count()).select_from(AccessLog)) == 1


def test_retention_policy_lists_the_access_log(soc_app):
    from soc.api import retention

    assert retention.policy(soc_app.state.settings)["access_log_retention_days"] == 365
    assert "access_log" in retention.TABLES
