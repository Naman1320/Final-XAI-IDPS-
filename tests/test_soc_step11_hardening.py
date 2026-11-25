"""Fixes from the step 11 security audit: enrolment needs the password from a session, races on
codes and enrolment, provider network errors, SSO linking rules, mTLS keep-alive, the lab's
sensor certificate, and the cloud SOC's package list."""

import http.client
import importlib.util
import re
import stat
import threading
from pathlib import Path

import pytest
from conftest import ADMIN_PW, ANALYST_PW
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_soc_mfa import bearer, password_login
from test_soc_oidc import begin, make_app, make_settings, refused, signin  # noqa: F401
from test_soc_oidc import provider, rsa_keys  # noqa: F401  (fixtures)

from soc.api import auth, mfa, oidc
from soc.api.main import create_app
from soc.api.models import Role, User
from soc.api.settings import SocSettings

ROOT = Path(__file__).resolve().parent.parent


def _file_app(tmp_path, **kw):
    """A SOC on a file SQLite database, so threads really run concurrently."""
    settings = SocSettings(jwt_secret="t" * 40, database_url=f"sqlite:///{tmp_path / 'r.db'}",
                           mfa_required_for_admins=True, **kw)
    app = create_app(settings)
    app.state.assistant_llm = None
    with app.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
    return app


def _parallel(n, fn):
    barrier, out = threading.Barrier(n), []

    def run():
        barrier.wait()
        out.append(fn())

    threads = [threading.Thread(target=run) for _ in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return out


# --- enrolment from a session needs the password -----------------------------------------------

def test_bearer_enrolment_needs_the_password(tmp_path):
    c = TestClient(_file_app(tmp_path))
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    # 403, not 401: a typo must not end the session (the dashboard logs out on any 401)
    assert c.post("/auth/mfa/enrol/start", json={}, headers=bearer(token)).status_code == 403
    assert c.post("/auth/mfa/enrol/start", json={"password": "wrong-password-xx"},
                  headers=bearer(token)).status_code == 403
    assert c.post("/auth/mfa/enrol/start", json={"password": ANALYST_PW}).status_code == 401
    r = c.post("/auth/mfa/enrol/start", json={"password": ANALYST_PW}, headers=bearer(token))
    assert r.status_code == 200 and r.json()["secret"]


def test_wrong_passwords_at_enrolment_count_toward_the_lockout(tmp_path):
    c = TestClient(_file_app(tmp_path, mfa_max_failures=3))
    token = password_login(c, "analyst", ANALYST_PW)["access_token"]
    codes = [c.post("/auth/mfa/enrol/start", json={"password": "wrong-password-xx"},
                    headers=bearer(token)).status_code for _ in range(4)]
    assert codes == [403, 403, 403, 429]


def test_the_enrol_step_token_needs_no_second_password(tmp_path):
    c = TestClient(_file_app(tmp_path))
    challenge = password_login(c)["mfa_token"]
    assert c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).status_code == 200


# --- races ---------------------------------------------------------------------------------------

def _enrolled_admin(c):
    challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).json()["secret"]
    step = mfa.current_step() - 1  # leave the current step free for the test
    r = c.post("/auth/mfa/enrol/confirm",
               json={"mfa_token": challenge, "code": mfa.code_at(secret, step)})
    assert r.status_code == 200, r.text
    return secret, r.json()


def test_the_same_code_wins_once_under_concurrency(tmp_path):
    app = _file_app(tmp_path)
    c = TestClient(app)
    secret, _ = _enrolled_admin(c)
    challenge = password_login(c)["mfa_token"]
    code = mfa.code_at(secret, mfa.current_step())
    results = _parallel(8, lambda: TestClient(app).post(
        "/auth/mfa/verify", json={"mfa_token": challenge, "code": code}).status_code)
    assert sorted(results).count(200) == 1, results


def test_a_recovery_code_wins_once_under_concurrency(tmp_path):
    app = _file_app(tmp_path)
    c = TestClient(app)
    _, enrolled = _enrolled_admin(c)
    challenge = password_login(c)["mfa_token"]
    code = enrolled["recovery_codes"][0]
    results = _parallel(8, lambda: TestClient(app).post(
        "/auth/mfa/verify", json={"mfa_token": challenge, "code": code}).status_code)
    assert results.count(200) == 1, results


def test_concurrent_confirms_store_the_codes_that_were_shown(tmp_path):
    app = _file_app(tmp_path)
    c = TestClient(app)
    challenge = password_login(c)["mfa_token"]
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": challenge}).json()["secret"]
    code = mfa.code_at(secret, mfa.current_step())
    responses = _parallel(6, lambda: TestClient(app).post(
        "/auth/mfa/enrol/confirm", json={"mfa_token": challenge, "code": code}))
    winners = [r for r in responses if r.status_code == 200]
    assert len(winners) == 1, [r.status_code for r in responses]
    keys = mfa.MfaKeys(app.state.settings.mfa_master_key)
    with app.state.session_factory() as db:
        stored = db.scalar(select(User).where(User.username == "admin")).recovery_codes
    assert sorted(stored) == sorted(keys.recovery_hash(x) for x in winners[0].json()["recovery_codes"])


# --- single sign-on ------------------------------------------------------------------------------

@pytest.mark.parametrize("error", [http.client.IncompleteRead(b"x"), http.client.BadStatusLine("?"),
                                   http.client.RemoteDisconnected("gone")])
def test_http_client_errors_become_oidc_errors(monkeypatch, error):
    def opener(*a, **k):
        class O:
            def open(self, *a, **k):
                raise error
        return O()

    monkeypatch.setattr(oidc.urllib.request, "build_opener", opener)
    with pytest.raises(oidc.OidcError):
        oidc.http_json("https://idp.test/x")


def test_start_is_503_not_500_when_the_provider_breaks_mid_answer(soc_settings, monkeypatch):
    app = make_app(make_settings(soc_settings))

    def broken(*a, **k):
        raise oidc.OidcError("provider unreachable: IncompleteRead")

    monkeypatch.setattr(oidc, "http_json", broken)
    assert TestClient(app).post("/auth/oidc/start").status_code == 503


def test_a_disabled_user_is_not_linked(soc_settings, provider):  # noqa: F811
    app = make_app(make_settings(soc_settings))
    with app.state.session_factory() as db:
        db.scalar(select(User).where(User.username == "analyst")).disabled = True
        db.commit()
    refused(signin(TestClient(app), provider))
    with app.state.session_factory() as db:
        assert db.scalar(select(User).where(User.username == "analyst")).oidc_subject is None


def test_an_admin_with_mfa_is_linked_and_still_asked_for_a_code(soc_settings, provider):  # noqa: F811
    app = make_app(make_settings(soc_settings))
    with app.state.session_factory() as db:
        db.scalar(select(User).where(User.username == "admin")).mfa_enabled = True
        db.commit()
    r = signin(TestClient(app), provider, preferred_username="admin", sub="adm")
    assert r.status_code == 200 and r.json()["mfa"] == "verify"


@pytest.mark.parametrize("key", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
def test_discovery_endpoints_must_be_https(soc_settings, provider, key, monkeypatch):  # noqa: F811
    real = provider.http_json

    def served(url, **kw):
        doc = real(url, **kw)
        return doc | {key: "http://idp.test/plain"} if url.endswith("openid-configuration") else doc

    monkeypatch.setattr(oidc, "http_json", served)
    app = make_app(make_settings(soc_settings))
    assert TestClient(app).post("/auth/oidc/start").status_code == 503


def test_pending_sign_ins_per_address_are_capped(soc_settings, provider):  # noqa: F811
    app = make_app(make_settings(soc_settings))
    c = TestClient(app)
    for _ in range(oidc.MAX_PENDING_PER_CLIENT + 5):
        begin(c)
    assert len(app.state.oidc._pending) == oidc.MAX_PENDING_PER_CLIENT


def test_otpauth_issuer_is_percent_encoded():
    uri = mfa.otpauth_uri("ABC234", "ana", "IDPS SOC")
    assert "issuer=IDPS%20SOC" in uri and "+" not in uri


# --- mutual TLS: every request on a kept-alive connection carries the certificate ---------------

def test_keep_alive_requests_all_carry_the_certificate(tmp_path):
    import json
    import ssl

    from test_soc_mtls import ALERT, Lab

    lab = Lab(tmp_path, required=True)
    try:
        ctx = ssl.create_default_context(cafile=str(lab.server_ca))
        ctx.load_cert_chain(str(tmp_path / "sensor-a.pem"), str(tmp_path / "sensor-a.key"))
        conn = http.client.HTTPSConnection("127.0.0.1", lab.sensor_port, context=ctx, timeout=10)
        statuses = []
        for _ in range(3):  # one TLS connection, three requests
            conn.request("POST", "/ingest/alerts", body=json.dumps({"alerts": [ALERT]}),
                         headers={"Authorization": f"Bearer {lab.tokens['sensor-a']}",
                                  "Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            statuses.append(resp.status)
        conn.close()
        assert statuses == [201, 201, 201]
    finally:
        lab.stop()


# --- lab: the sensor certificate ---------------------------------------------------------------

def _bootstrap():
    spec = importlib.util.spec_from_file_location("lab_bootstrap", ROOT / "lab/soc/bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_lab_sensor_certificate_is_issued_once_and_reissued_when_needed(tmp_path):
    from cryptography import x509

    from soc.api import pki

    b = _bootstrap()
    shared, data = tmp_path / "shared", tmp_path / "data"
    shared.mkdir()
    data.mkdir()
    assert b.ensure_sensor_cert(shared, data, "lab-sensor-1") is True
    assert stat.S_IMODE((shared / "sensor.key").stat().st_mode) == 0o600
    cert = x509.load_pem_x509_certificate((shared / "sensor.pem").read_bytes())
    assert pki.common_name(cert) == "lab-sensor-1"
    files = {p.name for p in shared.iterdir()} | {p.name for p in data.iterdir()}
    assert files == {"sensor.pem", "sensor.key", "sensor-ca.pem"}  # the CA key is never written
    assert b.ensure_sensor_cert(shared, data, "lab-sensor-1") is False  # still good
    assert b.ensure_sensor_cert(shared, data, "lab-sensor-2") is True  # a new sensor name
    (shared / "sensor.key").unlink()
    assert b.ensure_sensor_cert(shared, data, "lab-sensor-2") is True  # key gone
    other_key, other_ca = pki.make_ca("other")
    pki.write_public(data / "sensor-ca.pem", pki.cert_pem(other_ca))
    assert b.ensure_sensor_cert(shared, data, "lab-sensor-2") is True  # CA no longer matches


# --- the cloud SOC installs what soc.api imports ------------------------------------------------

def test_cloud_soc_installs_the_security_packages():
    text = (ROOT / "infra/templates/soc-user-data.sh.tftpl").read_text()
    install = re.search(r"pip install[^&]*", text).group(0)
    for package in ("cryptography", "segno", "alembic", "pyjwt", "argon2-cffi", "pandas",
                    "reportlab"):
        assert package in install, package
