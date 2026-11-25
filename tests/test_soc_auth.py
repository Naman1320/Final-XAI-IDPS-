"""SOC API authentication and authorisation."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from conftest import ADMIN_PW, ANALYST_PW, TEST_SECRET, login
from fastapi.testclient import TestClient
from pydantic import ValidationError

from soc.api import auth, security
from soc.api.auth import AdminUser, Sensor
from soc.api.models import User
from soc.api.settings import SocSettings


def _with_test_routes(app):
    @app.get("/test/admin-only")
    def admin_only(user: AdminUser):
        return {"user": user.username}

    @app.get("/test/sensor-only")
    def sensor_only(sensor: Sensor):
        return {"sensor": sensor.name}

    return app


def test_settings_require_a_long_secret(monkeypatch):
    monkeypatch.delenv("IDPS_SOC_JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        SocSettings()
    with pytest.raises(ValidationError):
        SocSettings(jwt_secret="short")


def test_login_and_me(client):
    headers = login(client, "analyst", ANALYST_PW)
    r = client.get("/auth/me", headers=headers)
    assert r.status_code == 200 and r.json()["role"] == "analyst"


@pytest.mark.parametrize("username,password", [("analyst", "wrong-password-xx"),
                                               ("nobody", "whatever-password")])
def test_login_failures_look_the_same(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 401
    assert r.json()["detail"] == "incorrect username or password"


def test_me_requires_a_valid_token(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401


def _forge(claims, secret=TEST_SECRET, alg="HS256"):
    base = {"sub": "1", "ver": 0, "iss": "idps-soc", "aud": "idps-soc",
            "iat": datetime.now(UTC), "exp": datetime.now(UTC) + timedelta(minutes=5)}
    return jwt.encode({**base, **claims}, secret, algorithm=alg)


@pytest.mark.parametrize("token", [
    _forge({}, secret="another-secret-" + "y" * 40),  # wrong key
    _forge({"exp": datetime.now(UTC) - timedelta(seconds=1)}),  # expired
    _forge({"aud": "someone-else"}),  # wrong audience
    _forge({"iss": "someone-else"}),  # wrong issuer
    _forge({"ver": 1}),  # stale token version
    _forge({"sub": "999"}),  # no such user
    jwt.encode({"sub": "1", "ver": 0}, key=None, algorithm="none"),  # unsigned
])
def test_bad_tokens_are_rejected(client, token):
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_role_comes_from_database_not_token(soc_app):
    app = _with_test_routes(soc_app)
    client = TestClient(app)
    analyst = login(client, "analyst", ANALYST_PW)
    admin = login(client, "admin", ADMIN_PW)
    assert client.get("/test/admin-only", headers=analyst).status_code == 403
    assert client.get("/test/admin-only", headers=admin).status_code == 200


def test_password_change_and_disable_revoke_tokens(soc_app, client):
    headers = login(client, "analyst", ANALYST_PW)
    with soc_app.state.session_factory() as db:
        user = db.query(User).filter_by(username="analyst").one()
        auth.set_password(db, user, "a-brand-new-password")
    assert client.get("/auth/me", headers=headers).status_code == 401
    headers = login(client, "analyst", "a-brand-new-password")
    with soc_app.state.session_factory() as db:
        auth.set_disabled(db, db.query(User).filter_by(username="analyst").one(), True)
    assert client.get("/auth/me", headers=headers).status_code == 401
    r = client.post("/auth/login", json={"username": "analyst", "password": "a-brand-new-password"})
    assert r.status_code == 401


def test_lockout_after_repeated_failures(client, soc_settings):
    for _ in range(soc_settings.login_max_failures):
        client.post("/auth/login", json={"username": "analyst", "password": "wrong-password-xx"})
    r = client.post("/auth/login", json={"username": "analyst", "password": ANALYST_PW})
    assert r.status_code == 429  # locked even with the right password
    # another user from the same IP isn't affected by this username's lockout
    assert client.post("/auth/login", json={"username": "admin",
                                            "password": ADMIN_PW}).status_code == 200


def test_throttle_window_expires():
    now = [0.0]
    t = security.LoginThrottle(2, 100, lockout_seconds=60, clock=lambda: now[0])
    t.record_failure("u", "1.2.3.4")
    t.record_failure("u", "1.2.3.4")
    assert t.is_locked("u", "1.2.3.4") and not t.is_locked("u", "5.6.7.8")
    now[0] = 61
    assert not t.is_locked("u", "1.2.3.4")


def test_password_policy_and_hashing():
    with pytest.raises(security.PasswordPolicyError):
        security.hash_password("short")
    h = security.hash_password("long-enough-password")
    assert h.startswith("$argon2id$")
    assert security.verify_password("long-enough-password", h)
    assert not security.verify_password("wrong", h)
    assert not security.verify_password("anything", None)
    assert not security.verify_password("x" * 10_000, h)


def test_duplicate_user_refused(soc_app):
    with soc_app.state.session_factory() as db, pytest.raises(ValueError):
        auth.create_user(db, "admin", "another-password-1", "admin")


def test_sensor_tokens(soc_app):
    app = _with_test_routes(soc_app)
    client = TestClient(app)
    with app.state.session_factory() as db:
        token = auth.create_sensor_token(db, "lab-sensor")
    ok = client.get("/test/sensor-only", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200 and ok.json() == {"sensor": "lab-sensor"}
    # a user token is not a sensor token, and a wrong sensor token fails
    user = login(client, "admin", ADMIN_PW)
    assert client.get("/test/sensor-only", headers=user).status_code == 401
    bad = {"Authorization": "Bearer " + security.SENSOR_TOKEN_PREFIX + "x" * 43}
    assert client.get("/test/sensor-only", headers=bad).status_code == 401
    with app.state.session_factory() as db:
        from soc.api.models import SensorToken

        db.query(SensorToken).filter_by(name="lab-sensor").one().revoked = True
        db.commit()
    assert client.get("/test/sensor-only",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_sensor_token_stored_hashed(soc_app):
    with soc_app.state.session_factory() as db:
        token = auth.create_sensor_token(db, "s1")
        from soc.api.models import SensorToken

        stored = db.query(SensorToken).filter_by(name="s1").one().token_hash
    assert token not in stored and stored == security.hash_sensor_token(token)

