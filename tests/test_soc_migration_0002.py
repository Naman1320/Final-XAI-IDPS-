"""Migration 0002 (MFA and single sign-on columns on users): upgrade, downgrade, upgrade again."""

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text
from step10_helpers import any_engine  # noqa: F401

from soc.api import migrate

NEW_COLUMNS = {"mfa_enabled", "totp_secret", "totp_pending", "totp_last_step", "recovery_codes",
               "oidc_issuer", "oidc_subject"}
OLD_COLUMNS = ["id", "username", "password_hash", "role", "disabled", "token_version", "created_at"]


def _columns(engine):
    return {c["name"] for c in inspect(engine).get_columns("users")}


def _index_names(engine):
    return {i["name"] for i in inspect(engine).get_indexes("users")}


def _step(engine, op, target):
    with engine.begin() as conn:
        getattr(migrate.command, op)(migrate.alembic_config(conn), target)


def _revision(engine):
    with engine.connect() as conn:
        rev = migrate.current_revision(conn)
        conn.rollback()
    return rev


def _at_0001_with_users(engine):
    _step(engine, "upgrade", "0001_initial")
    with engine.begin() as conn:
        for i, (name, role, disabled, ver) in enumerate(
                [("root", "admin", False, 4), ("ana", "analyst", True, 0), ("bo", "analyst", False, 9)],
                start=1):
            conn.execute(text(
                "INSERT INTO users (id, username, password_hash, role, disabled, token_version, "
                "created_at) VALUES (:i, :n, :h, :r, :d, :v, :t)"),
                {"i": i, "n": name, "h": f"hash-{name}", "r": role, "d": disabled, "v": ver,
                 "t": "2026-01-02 03:04:05.000000"})


def _old_rows(engine):
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT {', '.join(OLD_COLUMNS)} FROM users ORDER BY id")).all()
        conn.rollback()
    return [tuple(r) for r in rows]


def test_the_chain_is_0001_0002_0003():
    assert migrate.head_revision() == "0007_email_mfa"
    script = migrate._script()
    assert script.get_revision("0003_privacy_reports").down_revision == "0002_mfa_oidc"
    assert script.get_revision("0002_mfa_oidc").down_revision == "0001_initial"


def test_upgrade_adds_the_columns_and_existing_users_get_mfa_off(any_engine):
    _at_0001_with_users(any_engine)
    assert _revision(any_engine) == "0001_initial"
    assert not NEW_COLUMNS & _columns(any_engine)
    before = _old_rows(any_engine)
    _step(any_engine, "upgrade", "0002_mfa_oidc")
    assert _revision(any_engine) == "0002_mfa_oidc"
    assert NEW_COLUMNS <= _columns(any_engine)
    assert "ux_users_oidc" in _index_names(any_engine)
    assert _old_rows(any_engine) == before
    with any_engine.connect() as conn:
        rows = conn.execute(text("SELECT mfa_enabled, totp_secret, totp_pending, totp_last_step, "
                                 "recovery_codes, oidc_issuer, oidc_subject FROM users")).all()
        conn.rollback()
    assert len(rows) == 3
    for row in rows:
        assert not row[0]  # mfa_enabled false
        assert row[1:] == (None,) * 6
    _step(any_engine, "upgrade", "head")
    assert migrate.check(any_engine) == []


def test_new_columns_are_usable_and_the_unique_index_holds(any_engine):
    _at_0001_with_users(any_engine)
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        conn.execute(text("UPDATE users SET oidc_issuer = 'https://i', oidc_subject = 's' "
                          "WHERE id = 1"))
        conn.execute(text("UPDATE users SET totp_last_step = 9999999999 WHERE id = 2"))  # > int32
    with pytest.raises(sa.exc.IntegrityError):
        with any_engine.begin() as conn:
            conn.execute(text("UPDATE users SET oidc_issuer = 'https://i', oidc_subject = 's' "
                              "WHERE id = 3"))
    # several users with no link are fine (NULLs are distinct)
    with any_engine.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM users WHERE oidc_subject IS NULL")).scalar()
        conn.rollback()
    assert n == 2


def test_downgrade_removes_the_columns_and_keeps_the_other_data(any_engine):
    _at_0001_with_users(any_engine)
    before = _old_rows(any_engine)
    _step(any_engine, "upgrade", "head")
    with any_engine.begin() as conn:
        conn.execute(text("UPDATE users SET mfa_enabled = :t, totp_secret = 'v1:x', "
                          "oidc_issuer = 'https://i', oidc_subject = 's', token_version = 5 "
                          "WHERE id = 1"), {"t": True})
    _step(any_engine, "downgrade", "0001_initial")
    assert _revision(any_engine) == "0001_initial"
    assert not NEW_COLUMNS & _columns(any_engine)
    assert "ux_users_oidc" not in _index_names(any_engine)
    after = _old_rows(any_engine)
    assert [r[:5] + r[6:] for r in after] == [r[:5] + r[6:] for r in before]  # all but token_version
    assert after[0][5] == 5  # the data written at head in an old column survives too
    # the rest of the table's shape survived the rebuild (SQLite batch mode)
    assert "ix_users_username" in _index_names(any_engine)
    with pytest.raises(sa.exc.IntegrityError):
        with any_engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO users (username, password_hash, role, disabled, token_version, "
                "created_at) VALUES ('root', 'h', 'admin', :f, 0, '2026-01-02 03:04:05.000000')"),
                {"f": False})


def test_upgrade_again_after_a_downgrade(any_engine):
    _at_0001_with_users(any_engine)
    _step(any_engine, "upgrade", "head")
    _step(any_engine, "downgrade", "0001_initial")
    before = _old_rows(any_engine)
    _step(any_engine, "upgrade", "head")
    assert NEW_COLUMNS <= _columns(any_engine) and "ux_users_oidc" in _index_names(any_engine)
    assert _old_rows(any_engine) == before
    assert migrate.check(any_engine) == []


def test_fresh_database_goes_straight_to_head_with_the_columns(any_engine):
    with any_engine.begin() as conn:
        migrate.upgrade(conn)
    assert NEW_COLUMNS <= _columns(any_engine)
    assert _revision(any_engine) == migrate.head_revision()
