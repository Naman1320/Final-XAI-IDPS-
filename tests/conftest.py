"""Shared fixtures for the SOC API tests."""

import pytest
from fastapi.testclient import TestClient

from soc.api import auth
from soc.api.main import create_app
from soc.api.models import Role
from soc.api.settings import SocSettings

TEST_SECRET = "test-secret-" + "x" * 40
ADMIN_PW = "admin-password-123"
ANALYST_PW = "analyst-password-123"


@pytest.fixture
def soc_settings(monkeypatch):
    url = __import__("os").environ.get("IDPS_TEST_DATABASE_URL", "sqlite://")  # read before the purge
    # Tests must not depend on IDPS_* variables in the developer's shell.
    for name in [n for n in __import__("os").environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)
    # The block allowlist is required for blocking; tests use the lab's gateways and sensor.
    if not url.startswith("sqlite"):
        # Run the SOC tests against a real PostgreSQL (a throwaway one: this wipes its schema).
        from sqlalchemy import create_engine, text

        engine = create_engine(url)
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    # MFA for admins is on by default in the SOC; the suite logs in as admin with a password only,
    # so it is off here. tests/test_soc_mfa.py turns it on.
    return SocSettings(jwt_secret=TEST_SECRET, database_url=url, mfa_required_for_admins=False,
                       block_allowlist=["10.10.1.1", "10.10.2.1", "10.10.1.2", "10.10.2.2"])


@pytest.fixture
def soc_app(soc_settings):
    app = create_app(soc_settings)
    app.state.assistant_llm = None  # tests never call the real model; they install a fake
    with app.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
    return app


@pytest.fixture
def client(soc_app):
    return TestClient(soc_app)


def login(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin_headers(client):
    return login(client, "admin", ADMIN_PW)


@pytest.fixture
def analyst_headers(client):
    return login(client, "analyst", ANALYST_PW)


@pytest.fixture
def sensor_token(soc_app):
    with soc_app.state.session_factory() as db:
        return auth.create_sensor_token(db, "sensor-1")


@pytest.fixture
def sensor_headers(sensor_token):
    return {"Authorization": f"Bearer {sensor_token}"}


def alert_payload(**overrides) -> dict:
    """A valid alert as a sensor would send it."""
    base = {
        "src_ip": "203.0.113.7", "src_port": 51514, "dst_ip": "10.10.1.5", "dst_port": 22,
        "protocol": 6, "start_ms": 1_700_000_000_000, "end_ms": 1_700_000_005_000,
        "predicted_class": "SSH-Patator", "confidence": 0.93, "anomaly_score": 0.12,
        "explanation": {"method": "shap", "predicted_class": "SSH-Patator", "confidence": 0.93,
                        "base_value": 0.1, "output_space": "margin",
                        "top_features": [{"feature": "dst_port", "value": 22.0,
                                          "contribution": 0.4}]},
    }
    return base | overrides


def ingest(client, sensor_headers, *alerts) -> list[int]:
    r = client.post("/ingest/alerts", json={"alerts": list(alerts)}, headers=sensor_headers)
    assert r.status_code == 201, r.text
    return r.json()["ids"]


@pytest.fixture(autouse=True)
def _fresh_class_day_cache():
    """The class-by-day result is cached in-process; every test starts without it."""
    from soc.api.routes import metrics

    metrics.clear_class_per_day_cache()
    yield
    metrics.clear_class_per_day_cache()
