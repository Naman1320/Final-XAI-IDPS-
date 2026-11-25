"""Login history: rows written by the existing login flow, and GET /iam/logins."""

import pytest
from conftest import ADMIN_PW, ANALYST_PW
from iam_helpers import PW, add_user, headers
from sqlalchemy import select

from soc.api import mfa
from soc.api.iam import history
from soc.api.models import LoginHistory, User


@pytest.fixture(autouse=True)
def _forget_locked_rows():
    history._recent_locked.clear()
    history._recent_fails.clear()
    yield
    history._recent_locked.clear()
    history._recent_fails.clear()


def rows(app, **where) -> list[LoginHistory]:
    with app.state.session_factory() as db:
        query = select(LoginHistory).order_by(LoginHistory.id)
        for key, value in where.items():
            query = query.where(getattr(LoginHistory, key) == value)
        return list(db.scalars(query))


def attempt(client, username, password, **kw):
    return client.post("/auth/login", json={"username": username, "password": password}, **kw)


def test_a_good_login_is_recorded(client, soc_app):
    r = attempt(client, "analyst", ANALYST_PW, headers={"User-Agent": "pytest-agent/1.0"})
    assert r.status_code == 200
    (row,) = rows(soc_app)
    assert (row.username, row.success, row.reason, row.mfa_used) == ("analyst", True, "ok", False)
    assert row.user_id and row.ip == "testclient" and row.user_agent == "pytest-agent/1.0"
    assert row.at is not None


def test_a_wrong_password_and_an_unknown_user_are_recorded(client, soc_app):
    assert attempt(client, "analyst", "wrong-password-1").status_code == 401
    assert attempt(client, "ghost", "whatever-password-1").status_code == 401
    bad, ghost = rows(soc_app)
    assert (bad.reason, bad.success, bad.user_id is not None) == ("bad_password", False, True)
    assert (ghost.reason, ghost.success, ghost.user_id) == ("unknown_user", False, None)
    assert ghost.username != "ghost" and ghost.username.startswith("?")  # never the raw name


def test_the_response_does_not_tell_the_causes_apart(client, soc_app):
    add_user(soc_app, "off", disabled=True)
    bodies = {attempt(client, n, p).text for n, p in (("analyst", "wrong-password-1"),
                                                      ("ghost", "whatever-password-1"),
                                                      ("off", PW))}
    assert len(bodies) == 1


def test_a_disabled_account_is_recorded_as_disabled(client, soc_app):
    add_user(soc_app, "off", disabled=True)
    assert attempt(client, "off", PW).status_code == 401
    assert attempt(client, "off", "wrong-password-1").status_code == 401
    first, second = rows(soc_app, username="off")
    assert first.reason == "disabled" and second.reason == "bad_password"


def test_a_throttled_attempt_is_recorded_once_per_minute(client, soc_app):
    for _ in range(5):
        assert attempt(client, "analyst", "wrong-password-1").status_code == 401
    for _ in range(4):
        assert attempt(client, "analyst", ANALYST_PW).status_code == 429
    reasons = [r.reason for r in rows(soc_app)]
    assert reasons == ["bad_password"] * 5 + ["locked"]  # the flood is one row, not four


def test_mfa_failure_and_success_are_recorded(client, soc_app):
    secret = mfa.new_secret()
    with soc_app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "analyst"))
        user.mfa_enabled = True
        user.totp_secret = mfa.MfaKeys(soc_app.state.settings.mfa_master_key).encrypt(
            secret, user.id)
        db.commit()
    challenge = attempt(client, "analyst", ANALYST_PW).json()
    assert challenge["mfa"] == "verify" and not challenge["access_token"]
    assert rows(soc_app) == []  # the password alone is not a sign-in
    bad = client.post("/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"],
                                                "code": "000000"})
    assert bad.status_code == 401
    good = client.post("/auth/mfa/verify", json={
        "mfa_token": challenge["mfa_token"], "code": mfa.code_at(secret, mfa.current_step())})
    assert good.status_code == 200
    failed, ok = rows(soc_app)
    assert (failed.success, failed.reason, failed.mfa_used) == (False, "mfa_failed", True)
    assert (ok.success, ok.reason, ok.mfa_used) == (True, "ok", True)


def test_mfa_lockout_is_recorded_as_locked(client, soc_app):
    secret = mfa.new_secret()
    with soc_app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "analyst"))
        user.mfa_enabled = True
        user.totp_secret = mfa.MfaKeys(soc_app.state.settings.mfa_master_key).encrypt(
            secret, user.id)
        db.commit()
    challenge = attempt(client, "analyst", ANALYST_PW).json()["mfa_token"]
    codes = [client.post("/auth/mfa/verify", json={"mfa_token": challenge, "code": "000000"}
                         ).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    reasons = [r.reason for r in rows(soc_app)]
    assert reasons == ["mfa_failed"] * 5 + ["locked"]


def test_nothing_secret_is_stored(client, soc_app):
    attempt(client, "analyst", "super-secret-attempt-1")
    r = attempt(client, "analyst", ANALYST_PW)
    token = r.json()["access_token"]
    with soc_app.state.engine.connect() as conn:
        dump = " ".join(str(v) for row in conn.exec_driver_sql("SELECT * FROM login_history")
                        for v in row)
    assert "super-secret" not in dump and ANALYST_PW not in dump and token not in dump
    assert "argon2" not in dump


def test_user_agent_is_truncated_and_text_is_cleaned(client, soc_app):
    attempt(client, "analyst", ANALYST_PW, headers={"User-Agent": "A" * 1000})
    attempt(client, "bad" + chr(0x202E) + "user", "whatever-password-1")
    first, second = rows(soc_app)
    assert first.user_agent == "A" * 255
    assert second.username == history.unknown_label(soc_app.state.settings, "bad" + chr(0x202E) + "user")


def test_a_failing_history_write_never_breaks_login(client, soc_app, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(history, "LoginHistory", boom)
    assert attempt(client, "analyst", ANALYST_PW).status_code == 200
    assert attempt(client, "analyst", "wrong-password-1").status_code == 401
    monkeypatch.undo()
    assert rows(soc_app) == []
    assert attempt(client, "analyst", ANALYST_PW).status_code == 200  # and recovers
    assert len(rows(soc_app)) == 1


def test_endpoint_lists_and_filters(client, soc_app, admin_headers):
    attempt(client, "analyst", ANALYST_PW)
    attempt(client, "analyst", "wrong-password-1")
    attempt(client, "ghost", "whatever-password-1")
    r = client.get("/iam/logins", headers=admin_headers)
    items = r.json()["items"]
    assert [i["reason"] for i in items][:4] == ["unknown_user", "bad_password", "ok", "ok"]
    assert set(items[0]) == {"id", "at", "user_id", "username", "success", "reason", "ip",
                             "user_agent", "mfa_used"}
    analyst_id = next(i["user_id"] for i in items if i["username"] == "analyst")

    def reasons(**params):
        return [i["reason"] for i in client.get("/iam/logins", params=params,
                                                headers=admin_headers).json()["items"]]

    assert reasons(success="false") == ["unknown_user", "bad_password"]
    assert reasons(user_id=analyst_id, success="true") == ["ok"]  # not the admin's own login
    assert reasons(username="ghost") == []
    assert reasons(username=items[0]["username"]) == ["unknown_user"]
    assert reasons(reason="bad_password") == ["bad_password"]
    assert reasons(since="2999-01-01T00:00:00Z") == []
    assert len(reasons(until="2999-01-01T00:00:00Z")) == len(items)
    assert reasons(since="2000-01-01T00:00:00Z", until="2999-01-01T00:00:00Z")
    assert client.get("/iam/logins", params={"since": "2026-01-01T00:00:00"},
                      headers=admin_headers).status_code == 422
    page = client.get("/iam/logins", params={"limit": 2}, headers=admin_headers).json()
    assert len(page["items"]) == 2 and page["next_cursor"]


def test_a_users_last_login_shows_in_the_user_list(client, soc_app, admin_headers):
    attempt(client, "analyst", ANALYST_PW)
    attempt(client, "analyst", "wrong-password-1")
    users = {u["username"]: u for u in client.get("/iam/users", headers=admin_headers
                                                   ).json()["items"]}
    assert users["analyst"]["last_login"] and users["admin"]["last_login"]
    assert users["analyst"]["last_login"] > users["admin"]["last_login"]


def test_the_admin_login_used_by_the_fixtures_is_recorded(client, admin_headers, soc_app):
    assert [r.username for r in rows(soc_app)] == ["admin"] and ADMIN_PW
    assert headers  # the helper is shared with the other IAM tests


def test_an_unknown_username_is_stored_as_a_keyed_hash(client, soc_app):
    pasted = "My-Secret-Passw0rd!"  # someone typed their password into the username box
    assert attempt(client, pasted, "x-whatever-1").status_code == 401
    (row,) = rows(soc_app)
    assert row.reason == "unknown_user" and pasted not in row.username
    assert row.username == history.unknown_label(soc_app.state.settings, pasted)
    assert len(row.username) == 17  # "?" and 16 hex characters


def test_a_label_depends_on_the_key(soc_app):
    a = history.unknown_label(soc_app.state.settings, "ghost")
    assert a == history.unknown_label(soc_app.state.settings, "ghost")
    history._key.cache_clear()

    class Other:
        mfa_master_key = "another-master-key-entirely"

    assert history.unknown_label(Other, "ghost") != a


def test_repeated_unknown_user_attempts_are_one_row_a_minute(client, soc_app):
    for _ in range(4):
        assert attempt(client, "ghost", "whatever-password-1").status_code == 401
    assert attempt(client, "ghost2", "whatever-password-1").status_code == 401  # another name
    assert [r.reason for r in rows(soc_app)] == ["unknown_user", "unknown_user"]


def test_a_locked_row_for_an_unknown_name_is_hashed_too(client, soc_app):
    for _ in range(5):
        attempt(client, "ghost-lock", "whatever-password-1")
    assert attempt(client, "ghost-lock", "whatever-password-1").status_code == 429
    locked = [r for r in rows(soc_app) if r.reason == "locked"]
    assert len(locked) == 1 and "ghost-lock" not in locked[0].username
    assert locked[0].username.startswith("?")


def test_failure_rows_are_capped_per_address(soc_app, monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(history.time, "monotonic", lambda: t[0])
    with soc_app.state.session_factory() as db:
        for i in range(history._FAILS_PER_MINUTE + 20):
            history.record_login(db, username="analyst", user_id=None, success=False,
                                 reason="bad_password", ip="203.0.113.9", user_agent="x")
        history.record_login(db, username="analyst", user_id=None, success=True, reason="ok",
                             ip="203.0.113.9", user_agent="x")  # successes are never dropped
        assert len(rows(soc_app)) == history._FAILS_PER_MINUTE + 1
        t[0] += 61
        history.record_login(db, username="analyst", user_id=None, success=False,
                             reason="bad_password", ip="203.0.113.9", user_agent="x")
    assert len(rows(soc_app)) == history._FAILS_PER_MINUTE + 2


def test_login_history_retention(soc_app):
    from datetime import UTC, datetime, timedelta

    from soc.api.retention import prune

    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        for days in (400, 366, 364, 1):
            db.add(LoginHistory(at=now - timedelta(days=days), username="u", success=True,
                                reason="ok"))
        db.commit()
        settings = soc_app.state.settings
        assert settings.login_history_retention_days == 365
        assert prune(db, settings, now, dry_run=True)["login_history"] == 2
        assert prune(db, settings, now)["login_history"] == 2
        assert db.query(LoginHistory).count() == 2
        off = settings.model_copy(update={"login_history_retention_days": 0})
        db.add(LoginHistory(at=now - timedelta(days=5000), username="u", success=True,
                            reason="ok"))
        db.commit()
        assert prune(db, off, now)["login_history"] == 0
        assert db.query(LoginHistory).count() == 3
