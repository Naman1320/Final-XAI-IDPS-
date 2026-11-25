"""SOC side of 'learning from analysts': alert features, verdicts, model versions, export."""

import json

import pandas as pd
import pytest
from conftest import alert_payload, ingest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session
from test_soc_sensor_status import post, report

from idps.detect.bundle import read_digest, save_bundle
from idps.features import FEATURE_COLUMNS, MODEL_FEATURES, extraction_meta, read_features
from soc.api import auth
from soc.api.migrate import baseline_metadata
from soc.api.db import Base, init_db, upgrade_schema
from soc.api.export_feedback import build_feedback
from soc.api.export_feedback import main as export_main
from soc.api.models import Alert, AlertStatus, AuditEntry, ModelVersion, SensorToken

SHA_A, SHA_B = "a" * 64, "b" * 64
FEATS = {n: float(i) for i, n in enumerate(MODEL_FEATURES)}


def with_model(**kw):
    return alert_payload(features=FEATS, model_sha256=SHA_A, model_version="xgboost-202611150000-abcd1234",
                         **kw)


# --- ingest: fields, validation, caps -------------------------------------------------------

def test_ingest_stores_features_and_model_identity(client, sensor_headers, soc_app,
                                                   analyst_headers):
    (aid,) = ingest(client, sensor_headers, with_model())
    with soc_app.state.session_factory() as db:
        a = db.get(Alert, aid)
        assert a.features == FEATS and a.model_sha256 == SHA_A and a.true_class is None
        assert a.model_version == "xgboost-202611150000-abcd1234"
    detail = client.get(f"/alerts/{aid}", headers=analyst_headers).json()
    assert detail["model_sha256"] == SHA_A and detail["has_features"] is True
    assert "features" not in detail and detail["true_class"] is None


def test_old_sensors_without_the_fields_still_ingest(client, sensor_headers, soc_app,
                                                     analyst_headers):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    with soc_app.state.session_factory() as db:
        assert db.get(Alert, aid).features is None
    assert client.get(f"/alerts/{aid}", headers=analyst_headers).json()["has_features"] is False


def stored(soc_app, aid):
    with soc_app.state.session_factory() as db:
        a = db.get(Alert, aid)
        return a.features, a.model_sha256, a.model_version


@pytest.mark.parametrize("bad", [
    {"not_a_feature": 1.0},
    FEATS | {"extra": 1.0},  # unknown key (a newer sensor)
    {},  # empty
    {"fwd_packets": 1.0},  # partial
    FEATS | {"fwd_packets": "7"},
    FEATS | {"fwd_packets": True},
    FEATS | {"fwd_packets": [1]},
    FEATS | {"fwd_packets": 10**400},  # float() overflows
    [1, 2],
    "text",
])
def test_unusable_features_are_dropped_not_the_batch(client, sensor_headers, soc_app, bad):
    r = client.post("/ingest/alerts", headers=sensor_headers, json={"alerts": [
        alert_payload(features=bad, model_sha256=SHA_A), alert_payload()]})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["accepted"] == 2 and body["features_dropped"] == 1
    features, sha, _ = stored(soc_app, body["ids"][0])
    assert features is None and sha == SHA_A  # the alert and its model identity are kept
    assert audit_rows(soc_app, "ingest_alerts")[0]["features_dropped"] == 1


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_features_are_dropped(client, sensor_headers, soc_app, bad):
    body = json.dumps({"alerts": [alert_payload(features=FEATS | {"fwd_packets": "X"})]}
                      ).replace('"X"', bad)
    r = client.post("/ingest/alerts", content=body,
                    headers=sensor_headers | {"Content-Type": "application/json"})
    assert r.status_code == 201 and r.json()["features_dropped"] == 1
    assert stored(soc_app, r.json()["ids"][0])[0] is None


@pytest.mark.parametrize("override", [
    {"model_sha256": "xyz"}, {"model_sha256": "a" * 63}, {"model_sha256": 5},
    {"model_version": ""}, {"model_version": "v" * 81}, {"model_version": 7},
    {"model_version": "bad\u202eversion"},
])
def test_odd_model_identity_is_dropped_not_the_batch(client, sensor_headers, soc_app, override):
    r = client.post("/ingest/alerts", headers=sensor_headers,
                    json={"alerts": [alert_payload(features=FEATS, model_sha256=SHA_A,
                                                   model_version="v1") | override]})
    assert r.status_code == 201 and r.json()["model_info_dropped"] == 1
    features, sha, version = stored(soc_app, r.json()["ids"][0])
    assert features == FEATS  # only the odd field goes
    assert (sha is None) == ("model_sha256" in override)  # the other one is kept
    assert (version is None) == ("model_version" in override)
    assert (sha, version)[0 if "model_version" in override else 1] in (SHA_A, "v1")


def test_a_good_alert_reports_nothing_dropped(client, sensor_headers):
    r = client.post("/ingest/alerts", headers=sensor_headers, json={"alerts": [with_model()]})
    assert r.json()["features_dropped"] == 0 and r.json()["model_info_dropped"] == 0


def test_features_size_cap_drops_them(client, sensor_headers, monkeypatch, soc_app):
    from soc.api.routes import alerts

    monkeypatch.setattr(alerts, "MAX_FEATURES_BYTES", 100)
    r = client.post("/ingest/alerts", headers=sensor_headers, json={"alerts": [with_model()]})
    assert r.status_code == 201 and r.json()["features_dropped"] == 1


def test_sha_is_stored_lowercase(client, sensor_headers, soc_app):
    (aid,) = ingest(client, sensor_headers, alert_payload(model_sha256="AB" * 32))
    with soc_app.state.session_factory() as db:
        assert db.get(Alert, aid).model_sha256 == "ab" * 32


# --- PATCH: confirmed + true_class ---------------------------------------------------------

def audit_rows(soc_app, action):
    with soc_app.state.session_factory() as db:
        return [r.details for r in db.query(AuditEntry).filter_by(action=action)]


def test_confirm_with_true_class_is_audited(client, sensor_headers, analyst_headers, soc_app):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    r = client.patch(f"/alerts/{aid}", headers=analyst_headers,
                     json={"status": "confirmed", "true_class": "PortScan"})
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed" and r.json()["true_class"] == "PortScan"
    assert audit_rows(soc_app, "alert_status") == [
        {"from": "new", "to": "confirmed", "true_class": [None, "PortScan"]}]


def test_patch_without_true_class_leaves_it_alone_and_null_clears_it(client, sensor_headers,
                                                                      analyst_headers):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    url = f"/alerts/{aid}"
    client.patch(url, headers=analyst_headers, json={"status": "confirmed", "true_class": "Bot"})
    r = client.patch(url, headers=analyst_headers, json={"status": "resolved"})
    assert r.json()["true_class"] == "Bot"
    r = client.patch(url, headers=analyst_headers, json={"status": "resolved", "true_class": None})
    assert r.json()["true_class"] is None


@pytest.mark.parametrize("body", [
    {"status": "confirmed", "true_class": "Not A Class"},
    {"status": "confirmed", "true_class": "benign"},  # exact names only
    {"status": "confirmed", "true_class": "BENIGN"},  # a true positive is not benign
    {"status": "false_positive", "true_class": "DDoS"},
    {"status": "confirmed", "true_class": "x" * 65},
])
def test_patch_rejects_unknown_or_contradicting_true_class(client, sensor_headers,
                                                          analyst_headers, body):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    assert client.patch(f"/alerts/{aid}", headers=analyst_headers, json=body).status_code == 422


def test_false_positive_may_carry_benign(client, sensor_headers, analyst_headers):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    r = client.patch(f"/alerts/{aid}", headers=analyst_headers,
                     json={"status": "false_positive", "true_class": "BENIGN"})
    assert r.status_code == 200 and r.json()["true_class"] == "BENIGN"


# --- migration -----------------------------------------------------------------------------

NEW_ALERT_COLUMNS = ("features", "model_sha256", "model_version", "true_class")


def old_schema_db(path):
    """A database as the previous release made it: no feedback columns, no model_versions."""
    engine = create_engine(f"sqlite:///{path}")
    from soc.api import models  # noqa: F401

    baseline_metadata().create_all(engine)  # the frozen pre-migration schema (0001)
    with engine.begin() as c:
        c.execute(text("DROP TABLE model_versions"))
        c.execute(text("DROP INDEX ix_alerts_model_sha256"))
        for col in NEW_ALERT_COLUMNS:
            c.execute(text(f"ALTER TABLE alerts DROP COLUMN {col}"))
        c.execute(text("INSERT INTO sensor_tokens (id, name, token_hash, revoked, created_at) "
                       "VALUES (1, 's', 'h', 0, '2026-01-01 00:00:00')"))
        c.execute(text(
            "INSERT INTO alerts (sensor_id, received_at, src_ip, src_port, dst_ip, dst_port, "
            "protocol, start_ms, end_ms, predicted_class, confidence, severity, explanation, "
            "status) VALUES (1, '2026-01-01 00:00:00', '1.2.3.4', 1, '5.6.7.8', 2, 6, 1, 2, "
            "'DDoS', 0.9, 'high', '{}', 'new')"))
    return engine


def test_init_db_upgrades_an_old_database_and_is_idempotent(tmp_path):
    engine = old_schema_db(tmp_path / "old.db")
    assert not set(NEW_ALERT_COLUMNS) & {c["name"] for c in inspect(engine).get_columns("alerts")}
    init_db(engine)
    cols = {c["name"] for c in inspect(engine).get_columns("alerts")}
    assert set(NEW_ALERT_COLUMNS) <= cols
    assert inspect(engine).has_table("model_versions")
    with Session(engine) as db:  # old rows survive, with NULLs in the new columns
        a = db.query(Alert).one()
        assert a.predicted_class == "DDoS" and a.features is None and a.true_class is None
        a.features, a.status = FEATS, AlertStatus.CONFIRMED
        db.commit()
    assert upgrade_schema(engine, baseline_metadata()) == []  # second run: nothing to do
    init_db(engine)


def test_upgrade_reports_what_it_added(tmp_path):
    engine = old_schema_db(tmp_path / "old2.db")
    Base.metadata.create_all(engine)
    assert sorted(upgrade_schema(engine, baseline_metadata())) == sorted(f"alerts.{c}" for c in NEW_ALERT_COLUMNS)


def test_the_app_starts_on_an_old_database_and_serves_it(tmp_path, soc_settings):
    from fastapi.testclient import TestClient

    from soc.api.main import create_app

    old_schema_db(tmp_path / "app.db")
    settings = soc_settings.model_copy(update={"database_url": f"sqlite:///{tmp_path / 'app.db'}"})
    app = create_app(settings)
    with app.state.session_factory() as db:
        from soc.api.models import Role
        auth.create_user(db, "admin", "admin-password-123", Role.ADMIN)
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "admin", "password": "admin-password-123"}
                 ).json()["access_token"]
    got = c.get("/alerts/1", headers={"Authorization": f"Bearer {tok}"})
    assert got.status_code == 200 and got.json()["has_features"] is False


# --- model versions ------------------------------------------------------------------------

def model_report(sha, version, name="xgboost", **extra):
    return report(model={"name": name, "sha256": sha, "version": version, "checksum_ok": True},
                  **extra)


def test_status_records_model_versions_and_moves_last_seen(client, sensor_headers, soc_app):
    assert post(client, sensor_headers, model_report(SHA_A, "v1")).status_code == 200
    with soc_app.state.session_factory() as db:
        (mv,) = db.query(ModelVersion).all()
        first, seen1 = mv.first_seen, mv.last_seen
        assert (mv.sha256, mv.version, mv.name) == (SHA_A, "v1", "xgboost")
    post(client, sensor_headers, model_report(SHA_A, "v1"))
    with soc_app.state.session_factory() as db:
        (mv,) = db.query(ModelVersion).all()
        assert mv.first_seen == first and mv.last_seen >= seen1
    post(client, sensor_headers, model_report(SHA_B, "v2"))
    with soc_app.state.session_factory() as db:
        assert sorted(m.sha256 for m in db.query(ModelVersion)) == [SHA_A, SHA_B]


def test_old_sensor_reports_without_a_digest_record_nothing(client, sensor_headers, soc_app):
    post(client, sensor_headers, report())
    with soc_app.state.session_factory() as db:
        assert db.query(ModelVersion).count() == 0


def test_models_endpoint_lists_versions_and_who_runs_them_now(client, sensor_headers,
                                                              analyst_headers, soc_app):
    post(client, sensor_headers, model_report(SHA_A, "v1"))
    post(client, sensor_headers, model_report(SHA_B, "v2"))  # the sensor moved on to v2
    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, {"Authorization": f"Bearer {other}"}, model_report(SHA_B, "v2"))
    body = client.get("/models", headers=analyst_headers).json()
    by = {m["sha256"]: m for m in body["models"]}
    assert set(by) == {SHA_A, SHA_B}
    assert by[SHA_B]["running_now"] == 2 and by[SHA_A]["running_now"] == 0
    assert {s["name"]: s["running_now"] for s in by[SHA_A]["sensors"]} == {"sensor-1": False}
    assert {s["name"] for s in by[SHA_B]["sensors"]} == {"sensor-1", "sensor-2"}
    assert set(by[SHA_B]) == {"sha256", "version", "name", "first_seen", "last_seen",
                              "running_now", "sensors"}
    assert set(by[SHA_B]["sensors"][0]) == {"sensor_id", "name", "first_seen", "last_seen",
                                            "running_now", "online"}
    assert client.get("/models").status_code == 401


def test_revoked_sensors_are_hidden_from_analysts_but_not_admins(
        client, sensor_headers, analyst_headers, admin_headers, soc_app):
    post(client, sensor_headers, model_report(SHA_A, "v1"))  # only the sensor we revoke ran v1
    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, {"Authorization": f"Bearer {other}"}, model_report(SHA_A, "v1"))
    post(client, {"Authorization": f"Bearer {other}"}, model_report(SHA_B, "v2"))  # now on v2
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).filter_by(name="sensor-1").update({"revoked": True})
        db.commit()
    mine = {m["sha256"]: m for m in client.get("/models", headers=analyst_headers).json()["models"]}
    assert {s["name"] for m in mine.values() for s in m["sensors"]} == {"sensor-2"}
    assert mine[SHA_B]["running_now"] == 1 and mine[SHA_A]["running_now"] == 0
    full = {m["sha256"]: m for m in client.get("/models", headers=admin_headers).json()["models"]}
    assert {s["name"] for s in full[SHA_A]["sensors"]} == {"sensor-1", "sensor-2"}
    assert all(not s["running_now"] for s in full[SHA_A]["sensors"] if s["name"] == "sensor-1")
    # a model only a revoked sensor ran disappears for analysts
    with soc_app.state.session_factory() as db:
        db.query(ModelVersion).filter_by(sensor_id=2).delete()
        db.commit()
    assert [m["sha256"] for m in client.get("/models", headers=analyst_headers).json()["models"]] == []
    assert len(client.get("/models", headers=admin_headers).json()["models"]) == 1


def test_sensors_status_shows_model_and_drift(client, sensor_headers, analyst_headers):
    drift = {"window": 5000, "psi_max": 0.31, "level": "drift", "reference_sha256": SHA_A,
             "top": [{"feature": "fwd_packets", "psi": 0.31}, {"feature": "dst_port", "psi": 0.2}]}
    assert post(client, sensor_headers, model_report(SHA_A, "v1", drift=drift)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["model"] == {"name": "xgboost", "sha256": SHA_A, "version": "v1",
                                    "checksum_ok": True, "signed_by": None}
    assert s["status"]["drift"] == drift | {"reason": None}


def test_unknown_drift_carries_a_reason(client, sensor_headers, analyst_headers):
    drift = {"level": "unknown", "reason": "no drift reference"}
    assert post(client, sensor_headers, model_report(SHA_A, "v1", drift=drift)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["drift"] == {"level": "unknown", "reason": "no drift reference",
                                    "window": None, "psi_max": None, "top": [],
                                    "reference_sha256": None}


@pytest.mark.parametrize("drift", [
    {"level": "bad"}, {"level": "ok", "top": [{"feature": "f", "psi": 0.1}] * 6},
    {"level": "ok", "psi_max": -1}, {"level": "ok", "extra": 1},
])
def test_bad_drift_is_rejected(client, sensor_headers, drift):
    assert post(client, sensor_headers, model_report(SHA_A, "v1", drift=drift)).status_code == 422


# --- export --------------------------------------------------------------------------------

@pytest.fixture
def model(tmp_path):
    from test_live import _train

    path = save_bundle(_train(extraction_meta("nfstream", 120, 120)), tmp_path / "m.joblib")
    return path, read_digest(path)


_PORT = iter(range(1000, 10**6))


def add_alert(db, status, sha, *, features=FEATS, true_class=None, cls="DDoS", sensor_id=1,
              src_port=None):
    a = Alert(sensor_id=sensor_id, src_ip="1.2.3.4", src_port=src_port or next(_PORT), dst_ip="5.6.7.8", dst_port=80,
              protocol=6, start_ms=1_000, end_ms=2_000, predicted_class=cls, confidence=0.9,
              severity="high", explanation={}, status=status, features=features,
              model_sha256=sha, true_class=true_class)
    db.add(a)
    db.flush()
    return a.id


@pytest.fixture
def seeded(tmp_path, model):
    """A database file with judged alerts of several kinds; returns (url, ids)."""
    _, sha = model
    url = f"sqlite:///{tmp_path / 'soc.db'}"
    engine = create_engine(url)
    init_db(engine)
    ids = {}
    with Session(engine) as db:
        db.add(SensorToken(id=1, name="s", token_hash="h"))
        db.flush()
        ids["fp"] = add_alert(db, AlertStatus.FALSE_POSITIVE, sha)
        ids["conf_true"] = add_alert(db, AlertStatus.CONFIRMED, sha, true_class="PortScan")
        ids["conf_pred"] = add_alert(db, AlertStatus.CONFIRMED, sha, cls="Bot")
        ids["no_feat"] = add_alert(db, AlertStatus.CONFIRMED, sha, features=None)
        ids["other"] = add_alert(db, AlertStatus.CONFIRMED, SHA_B)
        ids["no_sha"] = add_alert(db, AlertStatus.FALSE_POSITIVE, None)
        ids["partial"] = add_alert(db, AlertStatus.CONFIRMED, sha, features={"dst_port": 1.0})
        ids["new"] = add_alert(db, AlertStatus.NEW, sha)
        ids["ack"] = add_alert(db, AlertStatus.ACKNOWLEDGED, sha)
        db.commit()
    return url, ids


def test_export_filters_labels_and_metadata(seeded, model, tmp_path, capsys):
    url, ids = seeded
    path, sha = model
    out = tmp_path / "feedback.parquet"
    assert export_main(["--db", url, "--model", str(path), "-o", str(out)]) == 0
    df, meta = read_features(out)
    assert dict(zip(df["alert_id"], df["label"], strict=True)) == {
        ids["fp"]: "BENIGN", ids["conf_true"]: "PortScan", ids["conf_pred"]: "Bot"}
    assert list(df.columns) == [*FEATURE_COLUMNS, "label", "alert_id"]
    assert df["alert_id"].is_unique
    assert df.loc[0, "fwd_packets"] == FEATS["fwd_packets"] and df.loc[0, "src_ip"] == "1.2.3.4"
    # the model's extraction metadata, so the retrainer's check passes
    from idps.detect.bundle import load_bundle
    from idps.features import check_same_extraction

    check_same_extraction(load_bundle(path).extraction_meta, meta)
    assert meta["feedback"]["model_sha256"] == sha
    err = capsys.readouterr().err
    assert "judged 7" in err and "no_features 1" in err and "other_model 2" in err
    assert "bad_features 1" in err and "exported 3" in err


def test_export_with_nothing_to_export_writes_no_file(tmp_path, model, capsys):
    path, _ = model
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    init_db(create_engine(url))
    out = tmp_path / "f.parquet"
    assert export_main(["--db", url, "--model", str(path), "-o", str(out)]) == 1
    assert not out.exists() and "nothing to export" in capsys.readouterr().err


def test_export_refuses_a_database_without_the_new_columns(tmp_path, model, capsys):
    path, _ = model
    engine = old_schema_db(tmp_path / "old.db")
    code = export_main(["--db", str(engine.url), "--model", str(path),
                        "-o", str(tmp_path / "f.parquet")])
    assert code == 2 and "start the SOC once" in capsys.readouterr().err


def test_export_counts_other_model_alerts(seeded, model):
    url, _ = seeded
    path, _ = model
    from idps.detect.bundle import load_bundle

    with Session(create_engine(url)) as db:
        df, counts = build_feedback(db, load_bundle(path), "c" * 64)
    assert df.empty and counts["other_model"] == 6 and counts["exported"] == 0
    assert isinstance(df, pd.DataFrame)


# --- GET /training/feedback ----------------------------------------------------------------

def test_training_feedback_endpoint_admin_only_with_audit(client, sensor_headers, analyst_headers,
                                                          admin_headers, soc_app):
    a, b, c = (ingest(client, sensor_headers, with_model(src_port=2000 + i))[0] for i in range(3))
    for aid, body in ((a, {"status": "false_positive"}),
                      (b, {"status": "confirmed", "true_class": "Bot"}),
                      (c, {"status": "acknowledged"})):
        client.patch(f"/alerts/{aid}", headers=analyst_headers, json=body)
    assert client.get("/training/feedback", headers=analyst_headers).status_code == 403
    assert client.get("/training/feedback", headers=sensor_headers).status_code in (401, 403)
    body = client.get("/training/feedback", headers=admin_headers).json()
    assert [(r["alert_id"], r["label"]) for r in body["rows"]] == [(a, "BENIGN"), (b, "Bot")]
    assert body["rows"][0]["features"] == FEATS and body["next_after_id"] is None
    page = client.get("/training/feedback?limit=1", headers=admin_headers).json()
    assert len(page["rows"]) == 1 and page["next_after_id"] == a
    rest = client.get(f"/training/feedback?after_id={a}", headers=admin_headers).json()
    assert [r["alert_id"] for r in rest["rows"]] == [b]
    assert client.get(f"/training/feedback?model_sha256={SHA_B}",
                      headers=admin_headers).json()["rows"] == []
    assert len(audit_rows(soc_app, "training_feedback_read")) == 4


# --- review fixes: PATCH sequences ----------------------------------------------------------

def patch(client, headers, aid, **body):
    r = client.patch(f"/alerts/{aid}", headers=headers, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_a_stored_benign_does_not_survive_a_confirmation(client, sensor_headers, analyst_headers,
                                                         soc_app):
    from soc.api.feedback import feedback_label

    (aid,) = ingest(client, sensor_headers, alert_payload())
    patch(client, analyst_headers, aid, status="false_positive", true_class="BENIGN")
    r = patch(client, analyst_headers, aid, status="confirmed")  # true_class left out
    assert r["status"] == "confirmed" and r["true_class"] is None
    with soc_app.state.session_factory() as db:
        assert feedback_label(db.get(Alert, aid)) == "SSH-Patator"  # the predicted class
    assert audit_rows(soc_app, "alert_status")[-1]["true_class"] == ["BENIGN", None]


def test_a_stored_attack_class_does_not_survive_a_false_positive(client, sensor_headers,
                                                                 analyst_headers):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    patch(client, analyst_headers, aid, status="confirmed", true_class="Bot")
    assert patch(client, analyst_headers, aid, status="false_positive")["true_class"] is None


def test_a_consistent_class_is_kept_when_omitted(client, sensor_headers, analyst_headers):
    (aid,) = ingest(client, sensor_headers, alert_payload())
    patch(client, analyst_headers, aid, status="confirmed", true_class="Bot")
    assert patch(client, analyst_headers, aid, status="confirmed")["true_class"] == "Bot"
    assert patch(client, analyst_headers, aid, status="resolved")["true_class"] == "Bot"
    patch(client, analyst_headers, aid, status="false_positive", true_class="BENIGN")
    assert patch(client, analyst_headers, aid, status="false_positive")["true_class"] == "BENIGN"
    assert patch(client, analyst_headers, aid, status="acknowledged")["true_class"] == "BENIGN"


def test_feedback_label_is_defensive(soc_app):
    from soc.api.feedback import feedback_label

    def label(status, true_class):
        return feedback_label(Alert(status=status, true_class=true_class, predicted_class="DDoS"))

    assert label(AlertStatus.CONFIRMED, "BENIGN") == "DDoS"  # never BENIGN when confirmed
    assert label(AlertStatus.CONFIRMED, None) == "DDoS"
    assert label(AlertStatus.CONFIRMED, "Bot") == "Bot"
    assert label(AlertStatus.FALSE_POSITIVE, "Bot") == "BENIGN"  # always BENIGN
    assert label(AlertStatus.FALSE_POSITIVE, None) == "BENIGN"


# --- review fixes: autoflush race on the first report ---------------------------------------

def test_a_lost_first_report_race_surfaces_at_flush_and_is_retried(client, sensor_headers,
                                                                   monkeypatch, soc_app):
    """The other first report committed after our read: the duplicate row fails when the next
    query autoflushes it (not at commit). The retry must update the existing row."""
    from soc.api.models import SensorStatus

    body = model_report(SHA_A, "v1")
    assert post(client, sensor_headers, body).status_code == 200
    real, calls = Session.get, []

    def fake(self, cls, ident, *a, **k):
        if cls is SensorStatus and not calls:
            calls.append(1)
            return None  # "no row yet", although the other process just wrote it
        return real(self, cls, ident, *a, **k)

    monkeypatch.setattr(Session, "get", fake)
    r = post(client, sensor_headers, model_report(SHA_B, "v2"))
    assert r.status_code == 200 and calls == [1]
    with soc_app.state.session_factory() as db:
        assert db.get(SensorStatus, 1).payload["model"]["sha256"] == SHA_B
        assert sorted(m.sha256 for m in db.query(ModelVersion)) == [SHA_A, SHA_B]


# --- review fixes: duplicate ingests, pagination ---------------------------------------------

def test_a_flow_ingested_twice_counts_once_in_export_and_endpoint(
        client, sensor_headers, analyst_headers, admin_headers, soc_app, model, tmp_path, capsys):
    path, sha = model
    twin = alert_payload(features=FEATS, model_sha256=sha)
    a, b, other = (ingest(client, sensor_headers, twin)[0], ingest(client, sensor_headers, twin)[0],
                   ingest(client, sensor_headers, alert_payload(features=FEATS, model_sha256=sha,
                                                                src_port=9))[0])
    for aid in (a, b, other):
        patch(client, analyst_headers, aid, status="false_positive")
    rows = client.get("/training/feedback", headers=admin_headers).json()["rows"]
    assert [r["alert_id"] for r in rows] == [a, other]  # the first one wins
    out = tmp_path / "f.parquet"
    url = str(soc_app.state.engine.url)
    with soc_app.state.session_factory() as db:
        from idps.detect.bundle import load_bundle
        df, counts = build_feedback(db, load_bundle(path), sha)
    assert sorted(df["alert_id"]) == [a, other] and counts["duplicates"] == 1
    assert url and not out.exists()


def test_feedback_pages_cover_every_row_once(client, sensor_headers, analyst_headers,
                                             admin_headers):
    ids = [ingest(client, sensor_headers, with_model(src_port=3000 + i))[0] for i in range(5)]
    for aid in ids:
        patch(client, analyst_headers, aid, status="false_positive")
    seen, after = [], 0
    for _ in range(10):
        page = client.get(f"/training/feedback?limit=2&after_id={after}", headers=admin_headers
                          ).json()
        seen += [r["alert_id"] for r in page["rows"]]
        if page["next_after_id"] is None:
            break
        assert len(page["rows"]) == 2
        after = page["next_after_id"]
    assert seen == ids
    exact = client.get("/training/feedback?limit=5", headers=admin_headers).json()
    assert len(exact["rows"]) == 5 and exact["next_after_id"] is None  # no phantom next page


# --- review fixes: schema upgrade ------------------------------------------------------------

def test_upgrade_creates_the_index_on_the_new_column(tmp_path):
    engine = old_schema_db(tmp_path / "idx.db")
    init_db(engine)
    names = {i["name"] for i in inspect(engine).get_indexes("alerts")}
    assert "ix_alerts_model_sha256" in names


def test_upgrade_tolerates_a_concurrent_duplicate_column(tmp_path, monkeypatch):
    """Another process adds the column between our inspection and our ALTER."""
    engine = old_schema_db(tmp_path / "race.db")
    from sqlalchemy.engine import Connection
    from sqlalchemy.exc import OperationalError

    real, state = Connection.execute, {"raced": False}

    def racing(self, statement, *a, **k):
        sql = str(statement)
        if "ADD COLUMN" in sql and "features" in sql and not state["raced"]:
            state["raced"] = True
            real(self, statement, *a, **k)  # the "other process" wins
            raise OperationalError(sql, {}, Exception("duplicate column name: features"))
        return real(self, statement, *a, **k)

    monkeypatch.setattr(Connection, "execute", racing)
    added = upgrade_schema(engine, baseline_metadata())
    assert state["raced"] and "alerts.features" not in added
    assert "alerts.true_class" in added
    monkeypatch.undo()
    assert {"features", "true_class"} <= {c["name"] for c in inspect(engine).get_columns("alerts")}


def test_upgrade_quotes_identifiers_with_the_dialect(tmp_path, monkeypatch):
    engine = old_schema_db(tmp_path / "q.db")
    prep = engine.dialect.identifier_preparer
    quoted = []
    real = prep.quote
    monkeypatch.setattr(prep, "quote", lambda name, *a: quoted.append(name) or f"<{real(name)}>")
    # the made-up quoting would break the SQL, which proves the statement is built from it
    with pytest.raises(Exception, match="syntax|unrecognized|near"):
        upgrade_schema(engine, baseline_metadata())
    assert "alerts" in quoted and "features" in quoted


def test_a_missing_non_nullable_column_needs_a_real_migration(tmp_path):
    engine = old_schema_db(tmp_path / "nn.db")
    with engine.begin() as c:
        c.execute(text("DROP INDEX ix_alerts_src_ip"))
        c.execute(text("ALTER TABLE alerts DROP COLUMN src_ip"))
    with pytest.raises(RuntimeError, match="real migration"):
        upgrade_schema(engine, baseline_metadata())
