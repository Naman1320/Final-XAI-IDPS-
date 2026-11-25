"""SOC API: sensor status reports (POST /sensor/status, GET /sensors/status)."""

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from soc.api import auth
from soc.api.models import SensorStatus, SensorToken


def report(**overrides) -> dict:
    base = {
        "dry_run": True, "blocking_enabled": False, "interface": "eth1", "mode": "live",
        "model": {"name": "xgboost", "checksum_ok": True},
        "policy": {"confidence_threshold": 0.9, "min_flows": 5, "window_seconds": 60.0,
                   "min_alert_confidence": 0.5, "block_ttl_seconds": 900,
                   "unblock_grace_seconds": 3600, "max_analyst_blocks": 1000},
        "allowlist": ["10.10.1.1/32", "10.10.2.0/24"], "allowlist_total": 2,
        "outbox_pending": 3, "shap_p95_ms": 12.5,
        "heartbeat": {"enabled": True, "ok": True},
        "counters": {"flows": 100, "alerts": 7, "blocked": 0, "would_block": 2},
        "sensor_version": "0.1.0", "sent_at": "2026-11-13T10:00:00+00:00",
    }
    return base | overrides


def post(client, headers, body):
    return client.post("/sensor/status", headers=headers, json=body)


def test_a_sensor_can_post_status_and_admins_can_read_all_of_it(client, sensor_headers,
                                                                admin_headers):
    analyst_headers = admin_headers  # admins see everything; analysts: see the redaction tests
    r = post(client, sensor_headers, report())
    assert r.status_code == 200 and "last_seen_at" in r.json()
    got = client.get("/sensors/status", headers=analyst_headers)
    assert got.status_code == 200
    (s,) = got.json()["sensors"]
    assert s["name"] == "sensor-1" and s["online"] is True and s["revoked"] is False
    assert s["status"]["policy"]["confidence_threshold"] == 0.9
    assert s["status"]["allowlist"] == ["10.10.1.1/32", "10.10.2.0/24"]
    assert s["status"]["counters"] == {"flows": 100, "alerts": 7, "blocked": 0, "would_block": 2}
    assert set(s) == {"sensor_id", "name", "revoked", "last_seen_at", "online", "status"}


def test_the_get_includes_the_socs_own_allowlist_for_admins(client, admin_headers):
    body = client.get("/sensors/status", headers=admin_headers).json()
    assert body["redacted"] is False
    assert body["soc_allowlist"] == ["10.10.1.1/32", "10.10.2.1/32", "10.10.1.2/32", "10.10.2.2/32"]
    assert body["sensors"] == []


def test_a_sensor_never_seen_has_null_status_and_is_offline(client, sensor_token, analyst_headers):
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"] is None and s["last_seen_at"] is None and s["online"] is False


def test_auth(client, sensor_headers, analyst_headers, admin_headers):
    assert client.post("/sensor/status", json=report()).status_code == 401
    bad = {"Authorization": "Bearer idps_sensor_nope"}
    assert post(client, bad, report()).status_code == 401
    # a user's token is not a sensor token
    assert post(client, analyst_headers, report()).status_code == 401
    assert post(client, admin_headers, report()).status_code == 401
    # and a sensor token is not a user token
    assert client.get("/sensors/status", headers=sensor_headers).status_code == 401
    assert client.get("/sensors/status").status_code == 401


def test_a_revoked_sensor_cannot_post(client, soc_app, sensor_headers):
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).update({"revoked": True})
        db.commit()
    assert post(client, sensor_headers, report()).status_code == 401


def test_status_is_an_upsert_one_row_per_sensor(client, soc_app, sensor_headers, analyst_headers):
    post(client, sensor_headers, report(outbox_pending=1))
    post(client, sensor_headers, report(outbox_pending=9))
    with soc_app.state.session_factory() as db:
        assert db.query(SensorStatus).count() == 1
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["outbox_pending"] == 9


def test_two_sensors_keep_separate_status(client, soc_app, sensor_headers, analyst_headers):
    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, sensor_headers, report(interface="eth1"))
    post(client, {"Authorization": f"Bearer {other}"}, report(interface=None, mode="replay"))
    by_name = {s["name"]: s for s in
               client.get("/sensors/status", headers=analyst_headers).json()["sensors"]}
    assert by_name["sensor-1"]["status"]["interface"] == "eth1"
    assert by_name["sensor-2"]["status"]["mode"] == "replay"


def test_online_means_seen_within_two_minutes(client, soc_app, sensor_headers, analyst_headers):
    post(client, sensor_headers, report())

    def age(seconds):
        with soc_app.state.session_factory() as db:
            row = db.query(SensorStatus).one()
            row.last_seen_at = datetime.now(UTC) - timedelta(seconds=seconds)
            db.commit()
        return client.get("/sensors/status", headers=analyst_headers).json()["sensors"][0]

    assert age(60)["online"] is True
    stale = age(121)
    assert stale["online"] is False and stale["status"] is not None  # last report still shown


def test_a_revoked_sensor_is_listed_but_never_online(client, soc_app, sensor_headers,
                                                     analyst_headers):
    post(client, sensor_headers, report())
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).update({"revoked": True})
        db.commit()
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["revoked"] is True and s["online"] is False


def test_last_seen_is_the_servers_clock_not_the_sensors(client, sensor_headers, analyst_headers):
    post(client, sensor_headers, report(sent_at="2001-01-01T00:00:00+00:00"))
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    seen = datetime.fromisoformat(s["last_seen_at"])
    assert abs(datetime.now(UTC) - seen) < timedelta(seconds=30) and s["online"] is True


def test_no_tokens_or_hashes_in_the_listing(client, sensor_token, sensor_headers, analyst_headers):
    post(client, sensor_headers, report())
    text = client.get("/sensors/status", headers=analyst_headers).text
    assert sensor_token not in text and "token_hash" not in text and "idps_sensor_" not in text
    from soc.api import security
    assert security.hash_sensor_token(sensor_token) not in text


def _mut(path, value):
    body = copy.deepcopy(report())
    target = body
    *head, last = path
    for key in head:
        target = target[key]
    target[last] = value
    return body


@pytest.mark.parametrize("body", [
    {**report(), "extra": 1},                                  # unknown top-level field
    _mut(["policy", "extra"], 1),                              # unknown nested field
    _mut(["mode"], "other"),
    _mut(["interface"], "x" * 65),
    _mut(["model", "name"], "x" * 65),
    _mut(["allowlist"], ["10.0.0.1"] * 101),                   # too many entries
    _mut(["allowlist"], ["x" * 65]),                           # entry too long
    _mut(["allowlist"], "10.0.0.1"),                           # not a list
    _mut(["sensor_version"], "v" * 33),
    _mut(["outbox_pending"], -1),
    _mut(["outbox_pending"], 10**9),
    _mut(["shap_p95_ms"], -1),
    _mut(["policy", "confidence_threshold"], 1.5),
    _mut(["policy", "window_seconds"], 0),
    _mut(["counters", "flows"], -1),
    _mut(["counters", "flows"], 2**60),
    _mut(["counters", "extra"], 1),
    _mut(["dry_run"], "maybe"),
    {k: v for k, v in report().items() if k != "policy"},      # missing required block
])
def test_invalid_reports_are_refused(client, sensor_headers, body):
    assert post(client, sensor_headers, body).status_code == 422


def test_nan_is_refused(client, sensor_headers):
    text = json.dumps(report()).replace('"shap_p95_ms": 12.5', '"shap_p95_ms": NaN')
    assert "NaN" in text
    r = client.post("/sensor/status", headers={**sensor_headers, "Content-Type": "application/json"},
                    content=text)
    assert r.status_code == 422


def test_boundary_values_are_accepted(client, sensor_headers):
    ok = report(allowlist=["10.0.0.0/8"] * 100, allowlist_total=100, interface=None, shap_p95_ms=None,
                sensor_version=None, sent_at=None)
    assert post(client, sensor_headers, ok).status_code == 200


def test_posting_status_does_not_fill_the_audit_log(client, sensor_headers, admin_headers):
    for _ in range(3):
        post(client, sensor_headers, report())
    entries = client.get("/admin/audit", headers=admin_headers).json()
    items = entries["items"] if isinstance(entries, dict) else entries
    status = [e["action"] for e in items if "status" in e["action"]]
    assert status == ["sensor_status_first"]  # one row for the first report, none for the repeats


def test_allowlist_total_is_optional_and_bounded(client, sensor_headers, analyst_headers):
    body = report()
    del body["allowlist_total"]  # an older sensor
    assert post(client, sensor_headers, body).status_code == 200
    assert post(client, sensor_headers, report(allowlist_total=-1)).status_code == 422
    assert post(client, sensor_headers, report(allowlist_total=250)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["allowlist_total"] == 250


def test_the_upsert_retries_once_after_an_integrity_error(client, soc_app, sensor_headers,
                                                          monkeypatch):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    real, calls = Session.commit, []

    def flaky(self):
        calls.append(1)
        if len(calls) == 1:  # another first report won the race
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return real(self)

    monkeypatch.setattr(Session, "commit", flaky)
    assert post(client, sensor_headers, report(outbox_pending=4)).status_code == 200
    assert len(calls) == 2
    with soc_app.state.session_factory() as db:
        (row,) = db.query(SensorStatus).all()
        assert row.payload["outbox_pending"] == 4


def test_a_second_integrity_error_is_not_swallowed(client, sensor_headers, monkeypatch):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    def always(self):
        raise IntegrityError("insert", {}, Exception("duplicate"))

    monkeypatch.setattr(Session, "commit", always)
    with pytest.raises(IntegrityError):
        post(client, sensor_headers, report())


def test_a_stored_row_that_no_longer_validates_does_not_break_the_listing(
        client, soc_app, sensor_headers, analyst_headers, caplog):
    import logging

    from soc.api.routes import sensors

    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, sensor_headers, report())
    post(client, {"Authorization": f"Bearer {other}"}, report())
    with soc_app.state.session_factory() as db:
        row = db.query(SensorStatus).filter_by(sensor_id=1).one()
        row.payload = {"dry_run": "garbage", "unknown": 1}
        db.commit()
    sensors._warned_bad_row = False
    with caplog.at_level(logging.WARNING, logger="soc.api"):
        r = client.get("/sensors/status", headers=analyst_headers)
        client.get("/sensors/status", headers=analyst_headers)
    assert r.status_code == 200
    by_name = {s["name"]: s for s in r.json()["sensors"]}
    assert by_name["sensor-1"]["status"] is None and by_name["sensor-1"]["last_seen_at"]
    assert by_name["sensor-2"]["status"] is not None
    assert len([m for m in caplog.records if "no longer validates" in m.message]) == 1


def test_every_policy_value_the_sensor_can_have_is_accepted(client, sensor_headers):
    """The sensor's own limits (idps/config.py) must fit the SOC's, or its status always 422s."""
    from idps.config import Settings

    fields = Settings.model_fields
    grace = next(m.le for m in fields["unblock_grace_seconds"].metadata if hasattr(m, "le"))
    ttl = next(m.le for m in fields["block_ttl_seconds"].metadata if hasattr(m, "le"))
    cap = next(m.le for m in fields["max_analyst_blocks"].metadata if hasattr(m, "le"))
    policy = report()["policy"] | {"unblock_grace_seconds": grace, "block_ttl_seconds": ttl,
                                   "max_analyst_blocks": cap}
    assert post(client, sensor_headers, report(policy=policy)).status_code == 200
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(unblock_grace_seconds=grace + 1)


# --- faithfulness ---------------------------------------------------------------------------

METHOD = {"mean_drop": 0.377, "ratio_to_random": 38.6, "label_flip_rate": 0.42,
          "share_flows_beating_random": 1.0}


def faith(**overrides):
    base = {"model": "xgboost", "model_matches": True, "flows": 100, "top_k": 5,
            "random_mean_drop": 0.0097, "methods": {"shap": METHOD, "lime": METHOD}}
    return base | overrides


def test_faithfulness_is_accepted_and_returned(client, sensor_headers, analyst_headers):
    assert post(client, sensor_headers, report(faithfulness=faith())).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"] == faith() | {"model_check": None}  # none sent


def test_faithfulness_may_have_one_method_and_is_optional(client, sensor_headers, analyst_headers):
    only = faith(methods={"shap": METHOD})
    assert post(client, sensor_headers, report(faithfulness=only)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"]["methods"] == {"shap": METHOD}
    assert post(client, sensor_headers, report()).status_code == 200  # older sensor
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"] is None
    assert post(client, sensor_headers, report(faithfulness=None)).status_code == 200


@pytest.mark.parametrize("bad", [
    faith(extra=1),
    faith(model=""),
    faith(model="x" * 65),
    faith(model_matches="maybe"),
    faith(flows=0),
    faith(top_k=0),
    faith(top_k=1001),
    faith(random_mean_drop=2),
    faith(methods={}),
    faith(methods={"other": METHOD}),
    faith(methods={"shap": {**METHOD, "extra": 1}}),
    faith(methods={"shap": {**METHOD, "ratio_to_random": -1e10}}),
    faith(model_check="other"),
    faith(methods={"shap": {**METHOD, "label_flip_rate": 1.5}}),
    faith(methods={"shap": {**METHOD, "share_flows_beating_random": -0.1}}),
    faith(methods={"shap": {**METHOD, "mean_drop": 5}}),
    faith(methods={"shap": {k: v for k, v in METHOD.items() if k != "mean_drop"}}),
    faith(methods={"shap": METHOD, "lime": "x"}),
])
def test_faithfulness_bounds(client, sensor_headers, bad):
    assert post(client, sensor_headers, report(faithfulness=bad)).status_code == 422


def test_null_and_negative_ratios_and_model_check_are_accepted(client, sensor_headers,
                                                               analyst_headers):
    worst = faith(model_check="digest", methods={
        "shap": {**METHOD, "ratio_to_random": None, "mean_drop": -0.3},
        "lime": {**METHOD, "ratio_to_random": -4.2}})
    assert post(client, sensor_headers, report(faithfulness=worst)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    f = s["status"]["faithfulness"]
    assert f["model_check"] == "digest"
    assert f["methods"]["shap"]["ratio_to_random"] is None
    assert f["methods"]["lime"]["ratio_to_random"] == -4.2
    assert post(client, sensor_headers, report(faithfulness=faith(model_check="name"))
                ).status_code == 200


# --- redaction for analysts (L3) ------------------------------------------------------------

def test_analysts_get_a_redacted_listing(client, sensor_headers, analyst_headers):
    post(client, sensor_headers, report(faithfulness=faith()))
    body = client.get("/sensors/status", headers=analyst_headers).json()
    assert body["redacted"] is True and body["soc_allowlist"] is None
    (s,) = body["sensors"]
    st = s["status"]
    assert st["allowlist"] is None and st["policy"] is None
    # everything else the dashboard needs is still there
    assert st["allowlist_total"] == 2 and st["mode"] == "live" and st["dry_run"] is True
    assert st["blocking_enabled"] is False and st["model"] == {
        "name": "xgboost", "sha256": None, "version": None, "checksum_ok": True,
        "signed_by": None}
    assert st["heartbeat"] == {"enabled": True, "ok": True} and st["outbox_pending"] == 3
    assert st["counters"]["would_block"] == 2 and st["faithfulness"]["model"] == "xgboost"
    text = client.get("/sensors/status", headers=analyst_headers).text
    assert "10.10.1.1" not in text and "confidence_threshold" not in text


def test_admins_get_the_full_listing(client, sensor_headers, admin_headers):
    post(client, sensor_headers, report())
    body = client.get("/sensors/status", headers=admin_headers).json()
    assert body["redacted"] is False and body["soc_allowlist"]
    st = body["sensors"][0]["status"]
    assert st["allowlist"] == ["10.10.1.1/32", "10.10.2.0/24"]
    assert st["policy"]["min_flows"] == 5


def test_a_revoked_sensors_status_is_hidden_from_analysts_only(
        client, soc_app, sensor_headers, analyst_headers, admin_headers):
    post(client, sensor_headers, report())
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).update({"revoked": True})
        db.commit()
    (a,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert a["revoked"] is True and a["status"] is None and a["online"] is False
    (adm,) = client.get("/sensors/status", headers=admin_headers).json()["sensors"]
    assert adm["status"] is not None


# --- audit of status changes (L4) -----------------------------------------------------------

def status_audit(client, admin_headers):
    r = client.get("/admin/audit?limit=200", headers=admin_headers).json()
    items = r["items"] if isinstance(r, dict) else r
    return [e for e in items if e["action"].startswith("sensor_status")][::-1]  # oldest first


def test_the_first_report_is_audited_and_unchanged_reports_are_not(client, sensor_headers,
                                                                   admin_headers):
    for _ in range(3):
        post(client, sensor_headers, report())
    (first,) = status_audit(client, admin_headers)
    assert first["action"] == "sensor_status_first" and first["actor_name"] == "sensor-1"
    assert first["details"] == {"mode": "live", "dry_run": True, "blocking_enabled": False}


@pytest.mark.parametrize("change, expected", [
    ({"dry_run": False}, {"dry_run": [True, False]}),
    ({"blocking_enabled": True}, {"blocking_enabled": [False, True]}),
    ({"mode": "replay", "interface": None}, {"mode": ["live", "replay"]}),
    ({"model": {"name": "rf", "checksum_ok": True}},
     {"model": [{"name": "xgboost", "sha256": None, "version": None, "checksum_ok": True},
                {"name": "rf", "sha256": None, "version": None, "checksum_ok": True}]}),
])
def test_a_change_of_a_watched_field_is_audited(client, sensor_headers, admin_headers, change,
                                                expected):
    post(client, sensor_headers, report())
    post(client, sensor_headers, report(**change))
    _, changed = status_audit(client, admin_headers)
    assert changed["action"] == "sensor_status_changed"
    assert changed["details"] == {"changed": expected}


def test_a_policy_change_names_the_fields(client, sensor_headers, admin_headers):
    post(client, sensor_headers, report())
    policy = report()["policy"] | {"confidence_threshold": 0.6, "min_flows": 1}
    post(client, sensor_headers, report(policy=policy))
    _, changed = status_audit(client, admin_headers)
    assert changed["details"]["changed"]["policy"] == {
        "confidence_threshold": [0.9, 0.6], "min_flows": [5, 1]}


@pytest.fixture
def audit_clock(monkeypatch):
    """The throttle's clock (seconds), so a test can step past or stay inside the window."""
    from soc.api.routes import sensors

    now = [1000.0]
    monkeypatch.setattr(sensors, "_clock", lambda: now[0])
    return now


def test_an_allowlist_change_logs_counts_and_entries_capped(client, sensor_headers, admin_headers,
                                                            audit_clock):
    post(client, sensor_headers, report())
    many = [f"10.{i // 250}.{i % 250}.0/24" for i in range(60)]
    post(client, sensor_headers, report(allowlist=["10.10.1.1/32", *many], allowlist_total=61))
    _, changed = status_audit(client, admin_headers)
    al = changed["details"]["changed"]["allowlist"]
    assert al["count"] == [2, 61] and al["total"] == [2, 61]
    assert len(al["added"]) == 20 and al["removed"] == ["10.10.2.0/24"] and al["more"] == 40
    audit_clock[0] += 601  # past the throttle window
    post(client, sensor_headers, report(allowlist=["10.10.1.1/32", *many], allowlist_total=70))
    third = status_audit(client, admin_headers)[-1]  # only allowlist_total changed
    assert third["details"]["changed"]["allowlist"]["total"] == [61, 70]
    assert third["details"]["changed"]["allowlist"]["added"] == []


def test_faithfulness_model_match_changes_are_audited_but_other_numbers_are_not(
        client, sensor_headers, admin_headers):
    post(client, sensor_headers, report(faithfulness=faith(model_matches=True)))
    post(client, sensor_headers, report(faithfulness=faith(model_matches=True, flows=999)))
    assert len(status_audit(client, admin_headers)) == 1  # flows changed: not audited
    post(client, sensor_headers, report(faithfulness=faith(model_matches=False)))
    changed = status_audit(client, admin_headers)[-1]
    assert changed["details"]["changed"] == {"faithfulness.model_matches": [True, False]}


def test_counters_outbox_and_time_never_cause_an_audit_row(client, sensor_headers, admin_headers):
    post(client, sensor_headers, report())
    post(client, sensor_headers, report(
        outbox_pending=99, shap_p95_ms=1.0, sent_at="2030-01-01T00:00:00+00:00",
        counters={"flows": 5, "alerts": 5, "blocked": 5, "would_block": 5},
        heartbeat={"enabled": False, "ok": False}))
    assert len(status_audit(client, admin_headers)) == 1


# --- semantic validation (L5) ---------------------------------------------------------------

def test_allowlist_entries_are_normalised_and_garbage_is_refused(client, sensor_headers,
                                                                 admin_headers):
    ok = report(allowlist=["10.10.1.1", "10.10.2.5/24", "2001:DB8::1"], allowlist_total=3)
    assert post(client, sensor_headers, ok).status_code == 200
    (s,) = client.get("/sensors/status", headers=admin_headers).json()["sensors"]
    assert s["status"]["allowlist"] == ["10.10.1.1/32", "10.10.2.0/24", "2001:db8::1/128"]
    for bad in ("not-an-ip", "10.0.0.256", "fe80::1%eth0", "10.0.0.0/33", "", "1.2.3.4; drop"):
        assert post(client, sensor_headers, report(allowlist=[bad], allowlist_total=1)
                    ).status_code == 422, bad


def test_allowlist_total_must_cover_the_list(client, sensor_headers):
    assert post(client, sensor_headers, report(allowlist_total=1)).status_code == 422  # 2 entries
    assert post(client, sensor_headers, report(allowlist_total=2)).status_code == 200
    body = report()
    del body["allowlist_total"]
    assert post(client, sensor_headers, body).status_code == 200  # older sensors


@pytest.mark.parametrize("change", [
    {"dry_run": "yes"}, {"dry_run": 1}, {"blocking_enabled": "false"},
    {"heartbeat": {"enabled": 1, "ok": True}},
    {"model": {"name": "x", "checksum_ok": "true"}},
    {"outbox_pending": "3"}, {"outbox_pending": 3.0}, {"outbox_pending": True},
    {"counters": {"flows": "1", "alerts": 0, "blocked": 0, "would_block": 0}},
    {"counters": {"flows": 1.5, "alerts": 0, "blocked": 0, "would_block": 0}},
    {"allowlist_total": "2"},
])
def test_booleans_and_integers_are_strict(client, sensor_headers, change):
    assert post(client, sensor_headers, report(**change)).status_code == 422


def test_policy_integers_are_strict(client, sensor_headers):
    for key in ("min_flows", "block_ttl_seconds", "unblock_grace_seconds", "max_analyst_blocks"):
        policy = report()["policy"] | {key: str(report()["policy"][key])}
        assert post(client, sensor_headers, report(policy=policy)).status_code == 422, key
    assert post(client, sensor_headers, report(faithfulness=faith(flows="100"))).status_code == 422
    assert post(client, sensor_headers, report(faithfulness=faith(model_matches=1))
                ).status_code == 422


UNSAFE = ["eth\x00", "eth\n1", "eth\u202e1", "eth\u200b1", "eth\x1b[31m", "eth\u2028"]


@pytest.mark.parametrize("bad", UNSAFE)
def test_control_and_direction_override_characters_are_refused(client, sensor_headers, bad):
    assert post(client, sensor_headers, report(interface=bad)).status_code == 422
    assert post(client, sensor_headers, report(model={"name": bad, "checksum_ok": True})
                ).status_code == 422
    assert post(client, sensor_headers, report(faithfulness=faith(model=bad))).status_code == 422
    assert post(client, sensor_headers, report(sensor_version=bad)).status_code == 422


def test_ordinary_unicode_names_are_fine(client, sensor_headers):
    assert post(client, sensor_headers, report(interface="enp0s3", model={
        "name": "xgboost-é", "checksum_ok": True})).status_code == 200


def test_a_lone_surrogate_escape_is_refused(client, sensor_headers):
    text = json.dumps(report()).replace('"interface": "eth1"', '"interface": "a\\ud800"')
    assert "\\ud800" in text
    r = client.post("/sensor/status", content=text,
                    headers={**sensor_headers, "Content-Type": "application/json"})
    assert r.status_code == 422


# --- throttled audit (flapping) ---------------------------------------------------------------

def test_a_flapping_setting_cannot_flood_the_audit_log(client, sensor_headers, admin_headers,
                                                       audit_clock):
    post(client, sensor_headers, report())
    for i in range(40):  # dry_run toggles on every 30 s post
        audit_clock[0] += 30
        post(client, sensor_headers, report(dry_run=bool(i % 2)))
    rows = status_audit(client, admin_headers)
    # 1 first + the rows the 10 minute window allows in 20 minutes of flapping (a few), not 41
    assert 2 <= len(rows) <= 4
    assert rows[0]["action"] == "sensor_status_first"


def test_changes_inside_the_window_are_folded_into_the_next_row(client, sensor_headers,
                                                                 admin_headers, audit_clock):
    post(client, sensor_headers, report(dry_run=True))
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=False))           # logged now: [True, False]
    for value in (True, False, True):                             # three changes, all folded
        audit_clock[0] += 30
        post(client, sensor_headers, report(dry_run=value))
    assert len(status_audit(client, admin_headers)) == 2
    audit_clock[0] += 600
    post(client, sensor_headers, report(dry_run=True))            # window over: one summary row
    rows = status_audit(client, admin_headers)
    assert len(rows) == 3
    last = rows[-1]
    assert last["details"]["changed"]["dry_run"] == [False, True]  # first audited old -> latest
    assert last["details"]["folded"]["dry_run"] == 3


def test_the_final_state_is_logged_after_the_window_even_if_nothing_else_changes(
        client, sensor_headers, admin_headers, audit_clock):
    post(client, sensor_headers, report(dry_run=True))
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=False))           # logged
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=True))            # throttled (back to the first)
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=False))           # throttled
    audit_clock[0] += 700
    post(client, sensor_headers, report(dry_run=False))
    rows = status_audit(client, admin_headers)
    # the audited baseline is dry_run=False and the sensor is at False: nothing to add
    assert [r["action"] for r in rows] == ["sensor_status_first", "sensor_status_changed"]
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=True))            # a real new change, window over
    assert status_audit(client, admin_headers)[-1]["details"]["changed"]["dry_run"] == [False, True]


def test_the_throttle_is_per_field(client, sensor_headers, admin_headers, audit_clock):
    post(client, sensor_headers, report())
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=False))
    audit_clock[0] += 30
    post(client, sensor_headers, report(dry_run=False, blocking_enabled=True))  # other field: logged
    rows = status_audit(client, admin_headers)
    assert [list(r["details"].get("changed", {})) for r in rows[1:]] == [
        ["dry_run"], ["blocking_enabled"]]


def test_the_throttle_is_per_sensor(client, soc_app, sensor_headers, admin_headers, audit_clock):
    with soc_app.state.session_factory() as db:
        other = {"Authorization": f"Bearer {auth.create_sensor_token(db, 'sensor-2')}"}
    for headers in (sensor_headers, other):
        post(client, headers, report())
        audit_clock[0] += 30
        post(client, headers, report(dry_run=False))
    changed = [r for r in status_audit(client, admin_headers) if r["action"].endswith("changed")]
    assert sorted(r["actor_name"] for r in changed) == ["sensor-1", "sensor-2"]


def test_after_a_restart_the_stored_status_is_the_baseline(client, soc_app, sensor_headers,
                                                          admin_headers, audit_clock):
    from soc.api.routes.sensors import SensorAuditState

    post(client, sensor_headers, report(dry_run=True))
    soc_app.state.sensor_audit = SensorAuditState()  # a new process
    post(client, sensor_headers, report(dry_run=False))
    assert status_audit(client, admin_headers)[-1]["details"]["changed"]["dry_run"] == [True, False]


# --- upgrade: old unnormalised allowlist rows -------------------------------------------------

def test_an_old_unnormalised_allowlist_is_not_a_change(client, soc_app, sensor_headers,
                                                       admin_headers):
    post(client, sensor_headers, report(allowlist=["10.10.1.1/32", "10.10.2.0/24"],
                                        allowlist_total=2))
    with soc_app.state.session_factory() as db:  # the row as an older SOC stored it
        row = db.query(SensorStatus).one()
        row.payload = {**row.payload, "allowlist": ["10.10.1.1", "10.10.2.0/24"]}
        db.commit()
    from soc.api.routes.sensors import SensorAuditState

    soc_app.state.sensor_audit = SensorAuditState()
    post(client, sensor_headers, report(allowlist=["10.10.1.1/32", "10.10.2.0/24"],
                                        allowlist_total=2))
    assert [r["action"] for r in status_audit(client, admin_headers)] == ["sensor_status_first"]


def test_status_changes_normalises_the_old_side():
    from soc.api.routes.sensors import status_changes

    old = {"allowlist": ["10.10.1.1", "2001:DB8::1"], "allowlist_total": 2}
    new = {"allowlist": ["10.10.1.1/32", "2001:db8::1/128"], "allowlist_total": 2}
    assert status_changes(old, new) == {}
    new = {"allowlist": ["10.10.1.1/32", "10.9.0.0/16"], "allowlist_total": 2}
    al = status_changes(old, new)["allowlist"]
    assert al["added"] == ["10.9.0.0/16"] and al["removed"] == ["2001:db8::1/128"]
