"""Regression tests for the SOC review findings (throttle race, explanations, timestamps, seeding)."""

import os
import subprocess
import sys
import threading
from pathlib import Path

from conftest import alert_payload

from soc.api import security

ROOT = Path(__file__).resolve().parents[1]


def test_parallel_wrong_passwords_cannot_exceed_the_limit():
    throttle = security.LoginThrottle(5, 100, lockout_seconds=900)
    passed = []
    lock = threading.Lock()
    barrier = threading.Barrier(30)

    def attempt():
        barrier.wait()
        for _ in range(3):
            ticket = throttle.begin_attempt("analyst", "1.2.3.4")
            if ticket is not None:
                with lock:
                    passed.append(ticket)  # would reach the password check

    threads = [threading.Thread(target=attempt) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(passed) == 5


def test_successful_login_takes_its_attempt_back():
    throttle = security.LoginThrottle(2, 3, lockout_seconds=900)
    for _ in range(10):  # many good logins from one IP never lock it
        ticket = throttle.begin_attempt("admin", "1.2.3.4")
        assert ticket is not None
        throttle.succeeded("admin", "1.2.3.4", ticket)


def test_malformed_explanations_are_rejected(client, sensor_headers):
    for bad in ({"method": 5}, {"top_features": {"a": 1}}, {"top_features": [{"feature": 3}]},
                {"top_features": [{"feature": "x", "contribution": "big"}]}, ["not", "a", "dict"]):
        r = client.post("/ingest/alerts", headers=sensor_headers,
                        json={"alerts": [alert_payload(explanation=bad)]})
        assert r.status_code == 422, bad


def test_explanations_keep_known_fields_and_drop_unknown_ones(client, sensor_headers,
                                                              analyst_headers):
    exp = {"method": "shap", "predicted_class": "X", "extra": "dropped",
           "top_features": [{"feature": "syn_count", "value": 4, "contribution": 0.5, "zz": 1}]}
    r = client.post("/ingest/alerts", headers=sensor_headers,
                    json={"alerts": [alert_payload(explanation=exp)]})
    stored = client.get(f"/alerts/{r.json()['ids'][0]}", headers=analyst_headers).json()
    assert "extra" not in stored["explanation"]
    assert stored["explanation"]["top_features"][0] == {
        "feature": "syn_count", "value": 4.0, "contribution": 0.5}


def test_user_and_sensor_timestamps_carry_utc_offset(client, admin_headers):
    users = client.get("/admin/users", headers=admin_headers).json()
    assert all(u["created_at"].endswith(("+00:00", "Z")) for u in users)
    client.post("/admin/sensors", headers=admin_headers, json={"name": "tz-check"})
    sensors = client.get("/admin/sensors", headers=admin_headers).json()
    assert all(s["created_at"].endswith(("+00:00", "Z")) for s in sensors)


def _seed(args, env_extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("IDPS_")}
    env.update({"IDPS_SOC_JWT_SECRET": "s" * 40, "PYTHONPATH": str(ROOT)}, **env_extra)
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "dev_seed.py"), *args],
                          env=env, capture_output=True, text=True, cwd=ROOT, check=False)


def test_dev_seed_needs_the_flag_and_a_named_dev_database(tmp_path):
    db = f"sqlite:///{tmp_path / 'dev.db'}"
    assert _seed([], {"IDPS_SOC_DATABASE_URL": db}).returncode == 1  # no flag
    flag = "--i-understand-this-adds-demo-logins"
    assert _seed([flag], {}).returncode == 1  # default database
    assert _seed([flag], {"IDPS_SOC_DATABASE_URL": "sqlite:///./soc.db"}).returncode == 1
    assert _seed([flag], {"IDPS_SOC_DATABASE_URL": db}).returncode == 1
    import secrets
    ok = _seed([flag], {"IDPS_SOC_DATABASE_URL": db,
                        "IDPS_DEMO_ADMIN_PASSWORD": secrets.token_urlsafe(24),
                        "IDPS_DEMO_ANALYST_PASSWORD": secrets.token_urlsafe(24)})
    assert ok.returncode == 0, ok.stderr
    assert not (ROOT / "soc.db").exists()  # the refused runs wrote nothing to the default DB
