"""MFA (TOTP + recovery codes): unit tests, the API flow, admin reset and the CLI."""

import base64
import os
import stat
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from conftest import ADMIN_PW, ANALYST_PW, TEST_SECRET
from fastapi.testclient import TestClient
from sqlalchemy import select

from soc.api import __main__ as cli
from soc.api import auth, mfa, security
from soc.api.main import create_app
from soc.api.models import AuditEntry, Role, User
from soc.api.settings import SocSettings, get_settings

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


# --- TOTP unit tests ---------------------------------------------------------------------------

def test_rfc6238_sha1_vector():
    # RFC 6238 appendix B, T=59: 8-digit 94287082, so the 6-digit code is 287082.
    assert mfa.code_at(RFC_SECRET, 59 // 30) == "287082"
    assert mfa.matching_step(RFC_SECRET, "287082", None, now=59) == 1
    # Another vector from the RFC: T=1111111109 -> 07081804 -> 081804.
    assert mfa.code_at(RFC_SECRET, 1111111109 // 30) == "081804"


def test_skew_of_one_step_is_accepted_two_is_refused():
    now = 10 * 30 + 5  # step 10
    assert mfa.current_step(now) == 10
    for step in (9, 10, 11):
        assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step), None, now=now) == step
    for step in (7, 8, 12, 13):
        assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step), None, now=now) is None


def test_last_step_blocks_replay_and_older_codes():
    now = 10 * 30
    code10 = mfa.code_at(RFC_SECRET, 10)
    assert mfa.matching_step(RFC_SECRET, code10, 9, now=now) == 10
    assert mfa.matching_step(RFC_SECRET, code10, 10, now=now) is None  # same step: replay
    assert mfa.matching_step(RFC_SECRET, code10, 11, now=now) is None
    assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, 9), 9, now=now) is None
    assert mfa.matching_step(RFC_SECRET, mfa.code_at(RFC_SECRET, 11), 10, now=now) == 11


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "28708a", "-28708", "28.082",
                                  "287082\n287082"])
def test_malformed_codes_are_refused(code):
    assert mfa.matching_step(RFC_SECRET, code, None, now=59) is None


def test_surrounding_whitespace_in_a_code_is_tolerated():
    assert mfa.matching_step(RFC_SECRET, " 287 082 ", None, now=59) == 1


@pytest.mark.parametrize("code", ["١٢٣٤٥٦",  # Arabic-Indic digits
                                  "１２３４５６",  # fullwidth digits
                                  "²²²²²²"])  # superscript two
def test_non_ascii_digits_are_refused_not_crashed(code):
    # str.isdigit() is true for these, and hmac.compare_digest raises TypeError on non-ASCII str.
    assert mfa.matching_step(RFC_SECRET, code, None, now=59) is None


def test_new_secret_is_base32_of_20_bytes_and_unique():
    a, b = mfa.new_secret(), mfa.new_secret()
    assert a != b and "=" not in a
    assert len(base64.b32decode(a + "=" * (-len(a) % 8))) == mfa.SECRET_BYTES


def test_otpauth_uri_and_qr():
    uri = mfa.otpauth_uri("ABC234", "ana@example.com", "IDPS SOC")
    assert uri.startswith("otpauth://totp/IDPS%20SOC%3Aana%40example.com?")
    for part in ("secret=ABC234", "issuer=IDPS%20SOC", "algorithm=SHA1", "digits=6", "period=30"):
        assert part in uri
    svg = mfa.qr_svg(uri)
    assert "<svg" in svg and "ABC234" not in svg


# --- keys and recovery codes -------------------------------------------------------------------

MASTER = "m" * 40


def test_keys_round_trip_and_are_randomised():
    keys = mfa.MfaKeys(MASTER)
    a, b = keys.encrypt("SECRET234", 7), keys.encrypt("SECRET234", 7)
    assert a != b and a.startswith("v1:") and "SECRET234" not in a
    assert keys.decrypt(a, 7) == keys.decrypt(b, 7) == "SECRET234"


def test_wrong_user_id_or_master_key_is_an_mfa_error():
    keys = mfa.MfaKeys(MASTER)
    blob = keys.encrypt("SECRET234", 7)
    with pytest.raises(mfa.MfaError):
        keys.decrypt(blob, 8)  # the ciphertext copied onto another user
    with pytest.raises(mfa.MfaError):
        mfa.MfaKeys("n" * 40).decrypt(blob, 7)


@pytest.mark.parametrize("blob", ["", "SECRET234", "v2:abcd", "v1:", "v1:!!!!", "v1:AAAA",
                                  "v1:" + "A" * 60])
def test_garbage_ciphertext_is_an_mfa_error(blob):
    with pytest.raises(mfa.MfaError):
        mfa.MfaKeys(MASTER).decrypt(blob, 1)


def test_tampered_ciphertext_is_refused():
    keys = mfa.MfaKeys(MASTER)
    raw = bytearray(base64.urlsafe_b64decode(keys.encrypt("SECRET234", 1)[3:]))
    raw[-1] ^= 1
    with pytest.raises(mfa.MfaError):
        keys.decrypt("v1:" + base64.urlsafe_b64encode(bytes(raw)).decode(), 1)


def test_master_key_must_be_long_enough():
    with pytest.raises(ValueError):
        mfa.MfaKeys("short")


def test_recovery_code_format_and_normalisation():
    codes = mfa.new_recovery_codes()
    assert len(codes) == 10 == mfa.RECOVERY_CODES and len(set(codes)) == 10
    for c in codes:
        assert len(c) == 11 and c[5] == "-"
        assert set(c.replace("-", "")) <= set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        assert mfa.looks_like_recovery(c)
    assert mfa.normalise_recovery(" abcde-fghjk ") == "ABCDEFGHJK"
    keys = mfa.MfaKeys(MASTER)
    c = codes[0]
    assert (keys.recovery_hash(c) == keys.recovery_hash(c.lower())
            == keys.recovery_hash(c.replace("-", "")) == keys.recovery_hash(f" {c[:3]} {c[3:]} "))
    assert keys.recovery_hash(codes[0]) != keys.recovery_hash(codes[1])
    assert mfa.MfaKeys("n" * 40).recovery_hash(c) != keys.recovery_hash(c)  # keyed


@pytest.mark.parametrize("code", ["123456", "ABCDE-FGHJ", "ABCDE-FGHJKL", "ABCDE-FGHJ0", "ABCDE-FGHJI",
                                  ""])
def test_things_that_are_not_recovery_codes(code):
    assert not mfa.looks_like_recovery(code)


# --- API flow ----------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.step = mfa.current_step()

    def advance(self, n=2):
        self.step += n
        return self.step


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(mfa, "current_step", lambda now=None: c.step)
    return c


@pytest.fixture
def app(soc_settings):
    settings = soc_settings.model_copy(update={"mfa_required_for_admins": True})
    application = create_app(settings)
    application.state.assistant_llm = None
    with application.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
    return application


@pytest.fixture
def c(app):
    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def password_login(c, name="admin", pw=ADMIN_PW):
    r = c.post("/auth/login", json={"username": name, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()


def get_user(app, name):
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == name))
        db.expunge(user)
        return user


def audits(app, action):
    with app.state.session_factory() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action)))


def bad_code(secret, step):
    near = {mfa.code_at(secret, step + i) for i in range(-3, 4)}
    return next(f"{n:06d}" for n in range(1000, 5000) if f"{n:06d}" not in near)


def enrol_admin(c, clock):
    """Log in as admin, enrol with the challenge. Returns (secret, confirm response json)."""
    challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).json()["secret"]
    r = c.post("/auth/mfa/enrol/confirm",
               json={"mfa_token": challenge, "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 200, r.text
    return secret, r.json()


def enrol_analyst(c, clock):
    """An analyst opts in with a bearer token. Returns (secret, confirm json)."""
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"password": ANALYST_PW},
                    headers=bearer(token)).json()["secret"]
    r = c.post("/auth/mfa/enrol/confirm", json={"code": mfa.code_at(secret, clock.step)},
               headers=bearer(token))
    assert r.status_code == 200, r.text
    return secret, r.json()


def verify(c, secret, clock, name="admin", pw=ADMIN_PW, advance=True):
    """Password login then app code. Returns the verify response."""
    login = password_login(c, name, pw)
    assert login["mfa"] == "verify" and login["access_token"] is None
    if advance:
        clock.advance()
    return c.post("/auth/mfa/verify",
                  json={"mfa_token": login["mfa_token"], "code": mfa.code_at(secret, clock.step)})


def test_admin_password_login_needs_enrolment_and_gives_no_access_token(c):
    body = password_login(c)
    assert body["mfa"] == "enrol" and body["access_token"] is None and body["mfa_token"]
    assert body["expires_in"] == 600
    assert c.get("/auth/me").status_code == 401
    assert c.get("/admin/users").status_code == 401


def test_enrol_start_returns_secret_uri_and_qr(c):
    challenge = password_login(c)["mfa_token"]
    r = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge})
    assert r.status_code == 200
    body = r.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/") and body["secret"] in body["otpauth_uri"]
    assert "<svg" in body["qr_svg"] and body["issuer"] == "IDPS SOC"
    assert len(base64.b32decode(body["secret"] + "=" * (-len(body["secret"]) % 8))) == 20


def test_confirm_with_a_wrong_code_is_401_and_changes_nothing(app, c, clock):
    challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).json()["secret"]
    r = c.post("/auth/mfa/enrol/confirm",
               json={"mfa_token": challenge, "code": bad_code(secret, clock.step)})
    assert r.status_code == 401 and r.json()["detail"] == "incorrect code"
    user = get_user(app, "admin")
    assert user.mfa_enabled is False and user.totp_secret is None and user.totp_pending


def test_confirm_needs_start_first_and_a_six_digit_code(c, clock):
    challenge = password_login(c)["mfa_token"]
    r = c.post("/auth/mfa/enrol/confirm", json={"mfa_token": challenge, "code": "123456"})
    assert r.status_code == 409
    c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge})
    r = c.post("/auth/mfa/enrol/confirm", json={"mfa_token": challenge, "code": "12"})
    assert r.status_code == 422
    # unauthenticated: 401 (not 422) even for an empty code
    assert c.post("/auth/mfa/enrol/confirm", json={}).status_code == 401


def test_enrolment_returns_token_and_ten_recovery_codes_and_bumps_token_version(app, c, clock):
    before = get_user(app, "admin").token_version
    challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).json()["secret"]
    r = c.post("/auth/mfa/enrol/confirm",
               json={"mfa_token": challenge, "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] and len(body["recovery_codes"]) == 10
    assert all(mfa.looks_like_recovery(x) for x in body["recovery_codes"])
    user = get_user(app, "admin")
    assert user.token_version == before + 1 and user.mfa_enabled and user.totp_pending is None
    assert user.totp_last_step == clock.step
    # the secret and the recovery codes are not stored in the clear
    assert secret not in (user.totp_secret or "")
    assert not set(body["recovery_codes"]) & set(user.recovery_codes)
    # the old challenge is dead
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).status_code == 401
    assert audits(app, "mfa_enable")
    # the new token works
    assert c.get("/auth/me", headers=bearer(body["access_token"])).status_code == 200


def test_me_shows_mfa_state(c, clock):
    _, body = enrol_admin(c, clock)
    me = c.get("/auth/me", headers=bearer(body["access_token"])).json()
    assert me["mfa_enabled"] is True and me["mfa_required"] is True


def test_next_login_asks_for_a_code_and_replay_is_refused(c, clock):
    secret, _ = enrol_admin(c, clock)
    r = verify(c, secret, clock)
    assert r.status_code == 200 and r.json()["access_token"]
    code = mfa.code_at(secret, clock.step)
    challenge = password_login(c)["mfa_token"]
    r = c.post("/auth/mfa/verify", json={"mfa_token": challenge, "code": code})  # same code again
    assert r.status_code == 401 and r.json()["detail"] == "incorrect code"
    # a later step works
    clock.advance()
    r = c.post("/auth/mfa/verify",
               json={"mfa_token": challenge, "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 200


def test_the_enrolment_code_cannot_be_replayed_at_login(c, clock):
    secret, _ = enrol_admin(c, clock)  # used the code of clock.step
    login = password_login(c)
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                         "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 401


def test_wrong_code_is_401_and_a_code_from_two_steps_away_too(c, clock):
    secret, _ = enrol_admin(c, clock)
    login = password_login(c)
    clock.advance()
    for code in (bad_code(secret, clock.step), mfa.code_at(secret, clock.step - 2),
                 mfa.code_at(secret, clock.step + 2)):
        r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"], "code": code})
        assert r.status_code == 401


def test_non_ascii_digit_code_at_the_endpoint_is_401_not_500(app, c, clock):
    secret, _ = enrol_admin(c, clock)
    login = password_login(c)
    quiet = TestClient(app, raise_server_exceptions=False)
    r = quiet.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                             "code": "١٢٣٤٥٦"})
    assert r.status_code == 401


def test_recovery_code_works_once_is_forgiving_and_logs_out_other_sessions(app, c, clock):
    secret, body = enrol_admin(c, clock)
    first_token = verify(c, secret, clock).json()["access_token"]
    assert c.get("/auth/me", headers=bearer(first_token)).status_code == 200
    code = body["recovery_codes"][0]
    messy = code.lower().replace("-", "")
    login = password_login(c)
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"], "code": messy})
    assert r.status_code == 200, r.text
    # other sessions are logged out, the new one works
    assert c.get("/auth/me", headers=bearer(first_token)).status_code == 401
    assert c.get("/auth/me", headers=bearer(r.json()["access_token"])).status_code == 200
    (entry,) = audits(app, "mfa_recovery_code_used")
    assert entry.actor_name == "admin" and entry.details == {"left": 9}
    assert code not in str(entry.details)
    # once only (a new challenge: the old one died with the token_version bump)
    login = password_login(c)
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"], "code": code})
    assert r.status_code == 401
    assert len(get_user(app, "admin").recovery_codes) == 9


def test_recovery_code_with_dash_and_uppercase_also_works(c, clock):
    _, body = enrol_admin(c, clock)
    login = password_login(c)
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                         "code": body["recovery_codes"][3]})
    assert r.status_code == 200


def test_five_wrong_codes_lock_the_user_out_from_any_address(app, c, clock):
    secret, _ = enrol_admin(c, clock)
    login = password_login(c)
    clock.advance()
    wrong = bad_code(secret, clock.step)
    other = TestClient(app, client=("203.0.113.9", 4444))
    clients = [c, other, c, other, c]
    for client in clients:
        r = client.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"], "code": wrong})
        assert r.status_code == 401
    good = {"mfa_token": login["mfa_token"], "code": mfa.code_at(secret, clock.step)}
    for client in (c, other):
        assert client.post("/auth/mfa/verify", json=good).status_code == 429


def test_a_challenge_is_not_an_access_token_and_vice_versa(c, clock):
    secret, body = enrol_admin(c, clock)
    login = password_login(c)  # a "verify" challenge
    assert c.get("/auth/me", headers=bearer(login["mfa_token"])).status_code == 401
    assert c.get("/admin/users", headers=bearer(login["mfa_token"])).status_code == 401
    clock.advance()
    r = c.post("/auth/mfa/verify", json={"mfa_token": body["access_token"],
                                         "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 401
    r = c.post("/auth/mfa/enrol/start", json={"mfa_token": body["access_token"]})
    assert r.status_code == 401


def test_a_verify_challenge_cannot_enrol_and_an_enrol_challenge_cannot_verify(c, clock):
    secret, _ = enrol_admin(c, clock)
    verify_challenge = password_login(c)["mfa_token"]
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": verify_challenge}).status_code == 401
    assert c.post("/auth/mfa/enrol/confirm",
                  json={"mfa_token": verify_challenge, "code": "123456"}).status_code == 401


def test_an_enrol_challenge_cannot_verify(c, clock):
    enrol_challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": enrol_challenge}).json()["secret"]
    r = c.post("/auth/mfa/verify", json={"mfa_token": enrol_challenge,
                                         "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 401


def _forged_challenge(user, purpose, *, exp=None, secret=TEST_SECRET):
    now = datetime.now(UTC)
    claims = {"sub": str(user.id), "ver": user.token_version, "account_created": user.created_at.isoformat(),
              "purpose": purpose, "iss": security.ISSUER,
              "aud": security.CHALLENGE_AUDIENCE, "iat": now - timedelta(minutes=30),
              "nbf": now - timedelta(minutes=30), "exp": exp or now + timedelta(minutes=5)}
    return jwt.encode(claims, secret, algorithm="HS256")


def test_expired_challenge_is_refused_but_a_forged_fresh_one_is_accepted(app, c):
    user = get_user(app, "admin")
    fresh = _forged_challenge(user, "enrol")
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": fresh}).status_code == 200
    expired = _forged_challenge(user, "enrol",
                                exp=datetime.now(UTC) - timedelta(minutes=1))
    r = c.post("/auth/mfa/enrol/start", json={"mfa_token": expired})
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_challenge_signed_with_another_secret_is_refused(app, c):
    user = get_user(app, "admin")
    forged = _forged_challenge(user, "enrol", secret="z" * 48)
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": forged}).status_code == 401


def test_disabled_users_challenge_is_refused(app, c):
    challenge = password_login(c)["mfa_token"]
    with app.state.session_factory() as db:  # disabled without bumping token_version
        db.scalar(select(User).where(User.username == "admin")).disabled = True
        db.commit()
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).status_code == 401


def test_disabled_user_with_mfa_cannot_verify(app, c, clock):
    secret, _ = enrol_admin(c, clock)
    login = password_login(c)
    with app.state.session_factory() as db:
        db.scalar(select(User).where(User.username == "admin")).disabled = True
        db.commit()
    clock.advance()
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                         "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 401


def test_an_admin_without_mfa_whose_role_was_granted_after_login_loses_access(app, c):
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    assert c.get("/auth/me", headers=bearer(token)).status_code == 200
    with app.state.session_factory() as db:  # promoted without a token_version bump
        db.scalar(select(User).where(User.username == "analyst")).role = Role.ADMIN
        db.commit()
    assert c.get("/auth/me", headers=bearer(token)).status_code == 401
    assert c.get("/admin/users", headers=bearer(token)).status_code == 401
    assert c.post("/auth/mfa/enrol/start", json={}, headers=bearer(token)).status_code == 401
    # logging in again asks them to enrol
    assert password_login(c, "analyst", ANALYST_PW)["mfa"] == "enrol"


def test_a_challenge_for_a_missing_user_is_refused(c):
    user = User(id=9999, token_version=0, created_at=datetime.now(UTC))
    assert c.post("/auth/mfa/enrol/start",
                  json={"mfa_token": _forged_challenge(user, "enrol")}).status_code == 401


def test_analysts_log_in_with_password_only(c):
    body = password_login(c, "analyst", ANALYST_PW)
    assert body["access_token"] and body["mfa"] is None
    me = c.get("/auth/me", headers=bearer(body["access_token"])).json()
    assert me["mfa_enabled"] is False and me["mfa_required"] is False


def test_analyst_can_opt_in_with_a_bearer_token(app, c, clock):
    secret, body = enrol_analyst(c, clock)
    assert len(body["recovery_codes"]) == 10
    me = c.get("/auth/me", headers=bearer(body["access_token"])).json()
    assert me["mfa_enabled"] is True and me["mfa_required"] is False
    # now a login asks for the code
    r = verify(c, secret, clock, "analyst", ANALYST_PW)
    assert r.status_code == 200 and r.json()["access_token"]
    # a second enrolment is refused
    r = c.post("/auth/mfa/enrol/start", json={"password": ANALYST_PW},
               headers=bearer(body["access_token"]))
    assert r.status_code == 409


def test_enrolment_without_any_credential_is_401(c):
    assert c.post("/auth/mfa/enrol/start", json={}).status_code == 401
    assert c.post("/auth/mfa/enrol/start", json={},
                  headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": "nonsense"}).status_code == 401


def test_analyst_can_disable_with_password_and_code(app, c, clock):
    secret, body = enrol_analyst(c, clock)
    token = body["access_token"]
    clock.advance()
    r = c.post("/auth/mfa/disable", headers=bearer(token),
               json={"password": ANALYST_PW, "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 200 and r.json()["access_token"]
    user = get_user(app, "analyst")
    assert (user.mfa_enabled, user.totp_secret, user.recovery_codes, user.totp_last_step) == (
        False, None, None, None)
    assert audits(app, "mfa_disable")
    assert c.get("/auth/me", headers=bearer(token)).status_code == 401  # old session ended
    assert password_login(c, "analyst", ANALYST_PW)["access_token"]


def test_disable_with_a_recovery_code_works(c, clock):
    _, body = enrol_analyst(c, clock)
    r = c.post("/auth/mfa/disable", headers=bearer(body["access_token"]),
               json={"password": ANALYST_PW, "code": body["recovery_codes"][0]})
    assert r.status_code == 200


def test_disable_when_mfa_is_off_is_409(c):
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    r = c.post("/auth/mfa/disable", headers=bearer(token),
               json={"password": ANALYST_PW, "code": "123456"})
    assert r.status_code == 409


def test_wrong_password_on_disable_counts_toward_the_lockout(c, clock):
    secret, body = enrol_analyst(c, clock)
    token = body["access_token"]
    clock.advance()
    good = {"password": ANALYST_PW, "code": mfa.code_at(secret, clock.step)}
    for _ in range(5):
        r = c.post("/auth/mfa/disable", headers=bearer(token),
                   json={"password": "wrong-password-xx", "code": good["code"]})
        assert r.status_code == 403  # signed in: 403, so the dashboard does not log out
    assert c.post("/auth/mfa/disable", headers=bearer(token), json=good).status_code == 429


def test_admins_cannot_disable_mfa(c, clock):
    secret, body = enrol_admin(c, clock)
    clock.advance()
    r = c.post("/auth/mfa/disable", headers=bearer(body["access_token"]),
               json={"password": ADMIN_PW, "code": mfa.code_at(secret, clock.step)})
    assert r.status_code == 403


def test_new_recovery_codes_replace_the_old_ones(app, c, clock):
    secret, body = enrol_admin(c, clock)
    clock.advance()
    code = mfa.code_at(secret, clock.step)
    r = c.post("/auth/mfa/recovery-codes", headers=bearer(body["access_token"]),
               json={"code": code})
    assert r.status_code == 200
    new = r.json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(body["recovery_codes"])
    assert audits(app, "mfa_recovery_codes_replaced")
    # the same app code cannot be used again (replay), and old recovery codes are dead
    assert c.post("/auth/mfa/recovery-codes", headers=bearer(body["access_token"]),
                  json={"code": code}).status_code == 403
    login = password_login(c)
    assert c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                            "code": body["recovery_codes"][0]}).status_code == 401
    assert c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                            "code": new[0]}).status_code == 200


def test_new_recovery_codes_need_an_app_code_not_a_recovery_code_and_mfa_on(c, clock):
    secret, body = enrol_admin(c, clock)
    r = c.post("/auth/mfa/recovery-codes", headers=bearer(body["access_token"]),
               json={"code": "ABCDEFGH"})
    assert r.status_code == 403
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    assert c.post("/auth/mfa/recovery-codes", headers=bearer(token),
                  json={"code": "123456"}).status_code == 409
    assert c.post("/auth/mfa/recovery-codes", json={"code": "123456"}).status_code == 401


# --- admin: reset MFA, user listing ------------------------------------------------------------

def _user_id(c, token, name):
    users = c.get("/admin/users", headers=bearer(token)).json()
    return next(u["id"] for u in users if u["username"] == name)


def test_admin_reset_clears_mfa_logs_the_user_out_and_is_audited(app, c, clock):
    _, admin_body = enrol_admin(c, clock)
    admin_token = admin_body["access_token"]
    clock.advance()
    _, analyst_body = enrol_analyst(c, clock)
    uid = _user_id(c, admin_token, "analyst")
    r = c.post(f"/admin/users/{uid}/mfa/reset", headers=bearer(admin_token))
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    user = get_user(app, "analyst")
    assert (user.mfa_enabled, user.totp_secret, user.totp_pending, user.recovery_codes) == (
        False, None, None, None)
    assert c.get("/auth/me", headers=bearer(analyst_body["access_token"])).status_code == 401
    (entry,) = audits(app, "user_mfa_reset")
    assert entry.actor_name == "admin" and entry.target == "user:analyst"
    assert password_login(c, "analyst", ANALYST_PW)["access_token"]  # back to password only
    # MFA is off now: 409
    assert c.post(f"/admin/users/{uid}/mfa/reset", headers=bearer(admin_token)).status_code == 409


def test_admin_reset_of_an_admin_asks_them_to_enrol_again(app, c, clock):
    # Two admins: the first resets the second.
    with app.state.session_factory() as db:
        auth.create_user(db, "admin2", ADMIN_PW, Role.ADMIN)
    _, body = enrol_admin(c, clock)
    clock.advance()
    ch = password_login(c, "admin2")["mfa_token"]
    secret2 = c.post("/auth/mfa/enrol/start", json={"mfa_token": ch}).json()["secret"]
    assert c.post("/auth/mfa/enrol/confirm", json={
        "mfa_token": ch, "code": mfa.code_at(secret2, clock.step)}).status_code == 200
    uid = _user_id(c, body["access_token"], "admin2")
    assert c.post(f"/admin/users/{uid}/mfa/reset",
                  headers=bearer(body["access_token"])).status_code == 200
    assert password_login(c, "admin2")["mfa"] == "enrol"


def test_reset_of_a_pending_enrolment_is_allowed(app, c, clock):
    _, body = enrol_admin(c, clock)
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    c.post("/auth/mfa/enrol/start", json={"password": ANALYST_PW}, headers=bearer(token))  # pending only
    uid = _user_id(c, body["access_token"], "analyst")
    assert c.post(f"/admin/users/{uid}/mfa/reset",
                  headers=bearer(body["access_token"])).status_code == 200
    assert get_user(app, "analyst").totp_pending is None


def test_reset_needs_an_admin_and_a_real_user(c, clock):
    _, admin_body = enrol_admin(c, clock)
    analyst_token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    assert c.post("/admin/users/1/mfa/reset", headers=bearer(analyst_token)).status_code == 403
    assert c.post("/admin/users/1/mfa/reset").status_code == 401
    assert c.post("/admin/users/9999/mfa/reset",
                  headers=bearer(admin_body["access_token"])).status_code == 404


def test_admin_users_never_returns_secrets(c, clock):
    secret, body = enrol_admin(c, clock)
    clock.advance()
    enrol_analyst(c, clock)
    r = c.get("/admin/users", headers=bearer(body["access_token"]))
    assert r.status_code == 200
    for item in r.json():
        assert set(item) == {"id", "username", "role", "disabled", "created_at", "mfa_enabled",
                             "sso_linked"}
    assert any(u["mfa_enabled"] for u in r.json())
    for needle in ("totp_secret", "totp_pending", "recovery_codes", "oidc_subject", "oidc_issuer",
                   secret, "v1:"):
        assert needle not in r.text


# --- CLI ---------------------------------------------------------------------------------------

@pytest.fixture
def cli_app(tmp_path, soc_settings, monkeypatch):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("IDPS_SOC_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("IDPS_SOC_DATABASE_URL", url)
    get_settings.cache_clear()
    settings = SocSettings(jwt_secret=TEST_SECRET, database_url=url, mfa_required_for_admins=True)
    application = create_app(settings)
    application.state.assistant_llm = None
    with application.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
    yield application
    get_settings.cache_clear()


def test_cli_mfa_enrol_writes_the_secret_0600_never_prints_it_and_the_code_works(
        cli_app, tmp_path, capsys):
    path = tmp_path / "check.secret"
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(path)]) == 0
    out = capsys.readouterr()
    secret = path.read_text().strip()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(base64.b32decode(secret + "=" * (-len(secret) % 8))) == 20
    assert secret not in out.out and secret not in out.err
    assert str(path) in out.out  # says where it went
    c = TestClient(cli_app)
    login = password_login(c, "analyst", ANALYST_PW)
    assert login["mfa"] == "verify" and login["access_token"] is None
    r = c.post("/auth/mfa/verify", json={"mfa_token": login["mfa_token"],
                                         "code": mfa.code_at(secret, mfa.current_step())})
    assert r.status_code == 200 and r.json()["access_token"]
    assert any(e.details == {"by": "cli"} for e in audits(cli_app, "mfa_enable"))
    # enrolling again needs --replace
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(tmp_path / "again")]) == 1
    assert not (tmp_path / "again").exists()
    assert "already on" in capsys.readouterr().err


def test_cli_mfa_enrol_fixes_the_mode_of_an_existing_file(cli_app, tmp_path):
    path = tmp_path / "old.secret"
    path.write_text("old")
    os.chmod(path, 0o644)
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(path)]) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text().strip() != "old"


def test_cli_mfa_enrol_replace_changes_the_secret(cli_app, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(a)]) == 0
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(b), "--replace"]) == 0
    assert a.read_text() != b.read_text()


def test_cli_mfa_enrol_errors(cli_app, tmp_path, capsys):
    assert cli.main(["mfa-enrol", "nobody", "--secret-file", str(tmp_path / "s")]) == 1
    assert "no user" in capsys.readouterr().err and not (tmp_path / "s").exists()
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(tmp_path / "no" / "s")]) == 1
    assert "cannot write" in capsys.readouterr().err
    assert get_user(cli_app, "analyst").mfa_enabled is False  # nothing half-done


def test_cli_mfa_reset_removes_mfa_and_audits(cli_app, tmp_path, capsys):
    path = tmp_path / "s"
    assert cli.main(["mfa-enrol", "analyst", "--secret-file", str(path)]) == 0
    before = get_user(cli_app, "analyst").token_version
    assert cli.main(["mfa-reset", "analyst"]) == 0
    user = get_user(cli_app, "analyst")
    assert (user.mfa_enabled, user.totp_secret, user.recovery_codes) == (False, None, None)
    assert user.token_version == before + 1
    c = TestClient(cli_app)
    assert password_login(c, "analyst", ANALYST_PW)["access_token"]
    assert any(e.details == {"by": "cli"} for e in audits(cli_app, "user_mfa_reset"))
    assert cli.main(["mfa-reset", "nobody"]) == 1
    assert "no user" in capsys.readouterr().err


def test_cli_mfa_reset_makes_an_admin_enrol_again(cli_app, tmp_path):
    assert cli.main(["mfa-enrol", "admin", "--secret-file", str(tmp_path / "s")]) == 0
    c = TestClient(cli_app)
    assert password_login(c)["mfa"] == "verify"
    assert cli.main(["mfa-reset", "admin"]) == 0
    assert password_login(c)["mfa"] == "enrol"


@pytest.mark.parametrize("expired", [False, True])
def test_email_sign_in_is_bound_to_mailbox_and_challenge(app, c, clock, monkeypatch, expired):
    import re

    from soc.api import email_mfa

    enrol_admin(c, clock)
    settings = app.state.settings
    settings.smtp_host, settings.smtp_from = "smtp.lab.test", "soc@lab.test"
    settings.smtp_security = "starttls"
    mailbox = "owner@lab.test"
    with app.state.session_factory() as db:
        db.scalar(select(User).where(User.username == "admin")).mfa_email = mailbox
        db.commit()
    messages = []
    monkeypatch.setattr(email_mfa, "send_email", lambda s, msg, to, timeout: messages.append((msg, to)))
    credentials = {"username": "admin", "password": ADMIN_PW, "request_email_code": True}
    challenge = c.post("/auth/login", json=credentials).json()
    assert challenge["email_status"] == "sent" and challenge["access_token"] is None
    other = c.post("/auth/login", json=credentials).json()
    assert other["email_status"] == "cooldown"
    (msg, recipients), = messages
    assert recipients == [mailbox] and msg["To"] == mailbox
    code = re.search(r"\b[0-9]{8}\b", msg.get_content()).group()
    def submit(token):
        return c.post("/auth/mfa/verify", json={"mfa_token": token, "code": code})
    assert submit(other["mfa_token"]).status_code == 401
    if expired:
        with app.state.session_factory() as db:
            user = db.scalar(select(User).where(User.username == "admin"))
            user.email_sent_at -= timedelta(minutes=6)
            db.commit()
        assert submit(challenge["mfa_token"]).status_code == 401
    else:
        assert submit(challenge["mfa_token"]).json()["access_token"]
        assert submit(challenge["mfa_token"]).status_code == 401
