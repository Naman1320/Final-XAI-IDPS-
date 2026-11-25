"""Single sign-on (OpenID Connect) against a fake provider; nothing touches the network."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from conftest import ADMIN_PW, ANALYST_PW, TEST_SECRET
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from soc.api import auth, mfa, oidc
from soc.api.main import create_app
from soc.api.models import AuditEntry, Role, User
from soc.api.settings import SocSettings

ISSUER = "https://idp.test/realms/soc"
CLIENT_ID = "idps-soc"
CLIENT_SECRET = "client-secret-" + "s" * 30
REDIRECT = "https://soc.test/auth/callback"
GENERIC = "single sign-on failed; try again or ask an admin"
ALLOWLIST = ["10.10.1.1", "10.10.2.1", "10.10.1.2", "10.10.2.2"]


@pytest.fixture(scope="module")
def rsa_keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]


class Provider:
    """A fake identity provider: discovery, JWKS and the token endpoint."""

    def __init__(self, keys):
        self.keys = keys
        self.current = 0
        self.discovery_issuer = ISSUER
        self.jwks_fetches = 0
        self.token_posts = []  # (url, data, auth_header)
        self.next_id_token = None
        self.published = [0]  # indexes of keys in the JWKS

    def kid(self, i=None):
        return f"kid-{self.current if i is None else i}"

    def jwks(self):
        self.jwks_fetches += 1
        keys = []
        for i in self.published:
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.keys[i].public_key()))
            jwk.update(kid=self.kid(i), use="sig", alg="RS256")
            keys.append(jwk)
        return {"keys": keys}

    def rotate(self):
        self.current += 1
        self.published = [self.current]

    def http_json(self, url, *, data=None, auth_header=None, timeout=5.0, allow_http=False):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return {"issuer": self.discovery_issuer,
                    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs"}
        if url.endswith("/certs"):
            return self.jwks()
        if url.endswith("/token"):
            self.token_posts.append((url, data, auth_header))
            return {"id_token": self.next_id_token, "access_token": "unused", "token_type": "Bearer"}
        raise AssertionError(f"unexpected provider request {url}")

    def issue(self, _nonce, /, *, alg="RS256", key=None, kid="default", headers=None, **overrides):
        """An ID token; a None override removes the claim."""
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "sub-1", "aud": CLIENT_ID, "exp": now + 300, "iat": now,
                  "nonce": _nonce, "preferred_username": "analyst"}
        for k, v in overrides.items():
            if v is None:
                claims.pop(k, None)
            else:
                claims[k] = v
        hdr = {"kid": self.kid() if kid == "default" else kid, **(headers or {})}
        if hdr["kid"] is None:
            del hdr["kid"]
        if alg == "none":
            return jwt.encode(claims, None, algorithm="none", headers=hdr)
        if alg == "RS256" and key is None:
            key = self.keys[self.current]
        return jwt.encode(claims, key, algorithm=alg, headers=hdr)


@pytest.fixture
def provider(rsa_keys, monkeypatch):
    p = Provider(rsa_keys)
    monkeypatch.setattr(oidc, "http_json", p.http_json)
    return p


def make_settings(soc_settings, **kw):
    base = dict(jwt_secret=TEST_SECRET, database_url=soc_settings.database_url,
                mfa_required_for_admins=False, block_allowlist=ALLOWLIST, oidc_issuer=ISSUER,
                oidc_client_id=CLIENT_ID, oidc_client_secret=CLIENT_SECRET,
                oidc_redirect_uri=REDIRECT)
    return SocSettings(**(base | kw))


def make_app(settings):
    app = create_app(settings)
    app.state.assistant_llm = None
    with app.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
        auth.create_user(db, "analyst", ANALYST_PW, Role.ANALYST)
    return app


@pytest.fixture
def app(soc_settings, provider):
    return make_app(make_settings(soc_settings))


@pytest.fixture
def c(app):
    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def begin(c):
    r = c.post("/auth/oidc/start")
    assert r.status_code == 200, r.text
    url = r.json()["authorization_url"]
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}, r.json()["binding"]


def signin(c, provider, *, binding=None, code="auth-code-1", **token_kw):
    """Start, have the provider issue a token for this nonce, call back. Returns the response."""
    q, bind = begin(c)
    provider.next_id_token = provider.issue(q["nonce"], **token_kw)
    return c.post("/auth/oidc/callback", json={"code": code, "state": q["state"],
                                               "binding": binding or bind})


def get_user(app, name):
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == name))
        db.expunge(user)
        return user


def audits(app, action):
    with app.state.session_factory() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action)))


def refused(r):
    assert r.status_code == 401, r.text
    assert r.json() == {"detail": GENERIC}
    assert "access_token" not in r.text


# --- configuration and start -------------------------------------------------------------------

def test_not_configured(soc_settings):
    app = create_app(soc_settings)
    c = TestClient(app)
    assert c.get("/auth/oidc/config").json() == {"enabled": False, "label": None}
    assert c.post("/auth/oidc/start").status_code == 404
    assert c.post("/auth/oidc/callback", json={"code": "a", "state": "b", "binding": "c"}
                  ).status_code == 404


def test_config_reports_enabled_and_the_label(soc_settings, provider):
    c = TestClient(make_app(make_settings(soc_settings, oidc_button_label="Company login")))
    assert c.get("/auth/oidc/config").json() == {"enabled": True, "label": "Company login"}
    assert TestClient(make_app(make_settings(soc_settings))).get("/auth/oidc/config").json()[
        "label"] == "Sign in with single sign-on"


def test_start_builds_the_authorization_url(c, provider):
    r = c.post("/auth/oidc/start")
    body = r.json()
    url = urlparse(body["authorization_url"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == f"{ISSUER}/protocol/openid-connect/auth"
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert q["response_type"] == "code" and q["client_id"] == CLIENT_ID
    assert q["redirect_uri"] == REDIRECT and q["scope"] == "openid profile email"
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    assert len(q["state"]) >= 32 and len(q["nonce"]) >= 32
    assert body["binding"] and body["binding"] not in body["authorization_url"]
    assert CLIENT_SECRET not in body["authorization_url"]
    q2, b2 = begin(c)
    assert q2["state"] != q["state"] and q2["nonce"] != q["nonce"] and b2 != body["binding"]


def test_discovery_for_a_different_issuer_is_refused(c, provider):
    provider.discovery_issuer = "https://evil.test/realms/soc"
    r = c.post("/auth/oidc/start")
    assert r.status_code == 503 and "evil" not in r.text


def test_discovery_missing_endpoints_is_refused(c, provider, monkeypatch):
    real = provider.http_json

    def broken(url, **kw):
        meta = real(url, **kw)
        meta.pop("jwks_uri", None)
        return meta

    monkeypatch.setattr(oidc, "http_json", broken)
    assert c.post("/auth/oidc/start").status_code == 503


# --- the happy path ----------------------------------------------------------------------------

def test_callback_signs_in_links_and_exchanges_the_code_correctly(app, c, provider):
    q, binding = begin(c)
    provider.next_id_token = provider.issue(q["nonce"])
    r = c.post("/auth/oidc/callback", json={"code": "the-code", "state": q["state"],
                                            "binding": binding})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    assert c.get("/auth/me", headers=bearer(token)).json()["username"] == "analyst"
    user = get_user(app, "analyst")
    assert (user.oidc_issuer, user.oidc_subject) == (ISSUER, "sub-1")
    (entry,) = audits(app, "sso_link")
    assert entry.target == "user:analyst" and entry.details == {"issuer": ISSUER}
    # what the SOC posted to the token endpoint
    ((url, data, auth_header),) = provider.token_posts
    assert url == f"{ISSUER}/protocol/openid-connect/token"
    assert data["grant_type"] == "authorization_code" and data["code"] == "the-code"
    assert data["redirect_uri"] == REDIRECT
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(data["code_verifier"].encode()).digest()).decode().rstrip("=")
    assert challenge == q["code_challenge"]
    assert set(data) == {"grant_type", "code", "redirect_uri", "code_verifier"}  # no secret in body
    assert auth_header == "Basic " + base64.b64encode(
        f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()


def test_later_sign_in_matches_by_subject_even_if_the_username_changes(app, c, provider):
    assert signin(c, provider).status_code == 200
    r = signin(c, provider, preferred_username="someone-else")
    assert r.status_code == 200
    assert c.get("/auth/me", headers=bearer(r.json()["access_token"])).json()[
        "username"] == "analyst"
    assert len(audits(app, "sso_link")) == 1  # linked once


def test_an_admin_without_mfa_is_never_linked_by_a_first_sso(app, c, provider):
    """Linking trusts the provider's usernames: an unenrolled admin would be one provider account
    named "admin" away from an attacker enrolling their own authenticator."""
    refused(signin(c, provider, preferred_username="admin", sub="admin-sub"))
    assert get_user(app, "admin").oidc_subject is None


# --- refusals ----------------------------------------------------------------------------------

REFUSALS = {
    "unknown user": dict(preferred_username="nobody"),
    "no username claim": dict(preferred_username=None),
    "wrong nonce": dict(nonce="not-the-nonce"),
    "missing nonce": dict(nonce=None),
    "wrong audience": dict(aud="another-client"),
    "wrong issuer": dict(iss="https://other.test/realms/soc"),
    "expired token": dict(exp=int(time.time()) - 3600),
    "issued in the far future": dict(iat=int(time.time()) + 3600, nbf=int(time.time()) + 3600),
    "missing exp": dict(exp=None),
    "missing sub": dict(sub=None),
    "empty sub": dict(sub=""),
    "numeric sub": dict(sub=12345),
    "huge sub": dict(sub="x" * 300),
    "alg none": dict(alg="none"),
    "HS256 with the client secret": dict(alg="HS256", key=CLIENT_SECRET),
    "HS256 with the jwt secret": dict(alg="HS256", key=TEST_SECRET),
    "unknown kid": dict(kid="no-such-kid"),
    "azp mismatch": dict(azp="another-client"),
    "several audiences without azp": dict(aud=[CLIENT_ID, "another-client"]),
    "several audiences with a wrong azp": dict(aud=[CLIENT_ID, "x"], azp="x"),
}


@pytest.mark.parametrize("name", REFUSALS)
def test_refusals_are_401_generic_and_link_nothing(app, c, provider, name):
    r = signin(c, provider, **REFUSALS[name])
    refused(r)
    user = get_user(app, "analyst")
    assert user.oidc_subject is None and not audits(app, "sso_link")


def test_azp_matching_and_several_audiences_with_azp_are_accepted(c, provider):
    assert signin(c, provider, azp=CLIENT_ID).status_code == 200
    assert signin(c, provider, aud=[CLIENT_ID, "other"], azp=CLIENT_ID).status_code == 200


def test_token_signed_by_an_unpublished_key_is_refused(c, provider):
    refused(signin(c, provider, key=provider.keys[2], kid=provider.kid(0)))


def test_token_without_a_kid_is_matched_only_when_there_is_one_key(c, provider):
    assert signin(c, provider, kid=None).status_code == 200
    provider.published = [0, 1]  # two keys: ambiguous without a kid
    c.app.state.oidc._keys = None  # drop the cached key set
    refused(signin(c, provider, kid=None))


def test_disabled_user_is_refused(app, c, provider):
    with app.state.session_factory() as db:
        auth.set_disabled(db, db.scalar(select(User).where(User.username == "analyst")), True)
    refused(signin(c, provider))


def test_a_user_disabled_after_linking_is_refused_even_by_subject(app, c, provider):
    assert signin(c, provider).status_code == 200
    with app.state.session_factory() as db:
        auth.set_disabled(db, db.scalar(select(User).where(User.username == "analyst")), True)
    refused(signin(c, provider))


def test_wrong_binding_is_refused_and_burns_the_state(app, c, provider):
    q, binding = begin(c)
    provider.next_id_token = provider.issue(q["nonce"])
    body = {"code": "c", "state": q["state"], "binding": "x" * 20}
    refused(c.post("/auth/oidc/callback", json=body))
    # the real browser's binding no longer helps: each state works once
    refused(c.post("/auth/oidc/callback", json=body | {"binding": binding}))
    assert provider.token_posts == []  # the code was never sent to the provider
    assert get_user(app, "analyst").oidc_subject is None


def test_unknown_state_is_refused_without_calling_the_provider(c, provider):
    refused(c.post("/auth/oidc/callback", json={"code": "c", "state": "nope", "binding": "b"}))
    assert provider.token_posts == []


def test_reused_state_is_refused(c, provider):
    q, binding = begin(c)
    provider.next_id_token = provider.issue(q["nonce"])
    body = {"code": "c", "state": q["state"], "binding": binding}
    assert c.post("/auth/oidc/callback", json=body).status_code == 200
    refused(c.post("/auth/oidc/callback", json=body))


def test_expired_state_is_refused(c, provider):
    q, binding = begin(c)
    provider.next_id_token = provider.issue(q["nonce"])
    c.app.state.oidc.clock = lambda: time.time() + oidc.STATE_SECONDS + 5
    refused(c.post("/auth/oidc/callback", json={"code": "c", "state": q["state"],
                                                "binding": binding}))
    assert provider.token_posts == []


def test_a_state_that_is_just_inside_the_window_works(c, provider):
    q, binding = begin(c)
    provider.next_id_token = provider.issue(q["nonce"])
    c.app.state.oidc.clock = lambda: time.time() + oidc.STATE_SECONDS - 30
    assert c.post("/auth/oidc/callback", json={"code": "c", "state": q["state"],
                                               "binding": binding}).status_code == 200


def test_old_pending_states_are_dropped_and_the_table_is_bounded(c, provider, monkeypatch):
    client = c.app.state.oidc
    begin(c)
    client.clock = lambda: time.time() + oidc.STATE_SECONDS + 5
    begin(c)  # prunes the first
    assert len(client._pending) == 1
    monkeypatch.setattr(oidc, "MAX_PENDING", 3)
    client.clock = time.time
    for _ in range(5):  # a flood never locks SSO out: the oldest are dropped instead
        begin(c)
    assert len(client._pending) <= 3


def test_username_already_linked_to_another_subject_is_refused(app, c, provider):
    assert signin(c, provider, sub="sub-1").status_code == 200
    refused(signin(c, provider, sub="sub-2"))
    assert get_user(app, "analyst").oidc_subject == "sub-1"


def test_the_same_subject_is_not_linked_to_two_users(app, c, provider):
    assert signin(c, provider, sub="sub-1").status_code == 200
    refused(signin(c, provider, sub="sub-9", preferred_username="analyst"))
    # an unrelated user claiming the same sub is resolved by sub: it is the analyst, not admin
    r = signin(c, provider, sub="sub-1", preferred_username="admin")
    assert c.get("/auth/me", headers=bearer(r.json()["access_token"])).json()[
        "username"] == "analyst"
    assert get_user(app, "admin").oidc_subject is None


def test_the_subject_is_per_issuer(app, c, provider):
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "analyst"))
        user.oidc_issuer, user.oidc_subject = "https://old.test/realms/x", "sub-1"
        db.commit()
    # same sub but another issuer was linked: the username path finds it linked elsewhere
    refused(signin(c, provider, sub="sub-1"))


# --- email as the username claim ---------------------------------------------------------------

@pytest.fixture
def email_app(soc_settings, provider):
    app = make_app(make_settings(soc_settings, oidc_username_claim="email"))
    with app.state.session_factory() as db:
        auth.create_user(db, "ana@example.com", ANALYST_PW, Role.ANALYST)
    return app


@pytest.mark.parametrize("verified,ok", [(None, False), (False, False), ("true", False),
                                         (1, False), (True, True)])
def test_email_claim_verification(email_app, provider, verified, ok):
    c = TestClient(email_app)
    r = signin(c, provider, email="ana@example.com", email_verified=verified, sub="e-1",
               preferred_username=None)
    if ok:
        assert r.status_code == 200
        assert get_user(email_app, "ana@example.com").oidc_subject == "e-1"
    else:
        refused(r)
        assert get_user(email_app, "ana@example.com").oidc_subject is None


def test_email_claim_is_not_needed_once_linked(email_app, provider):
    c = TestClient(email_app)
    assert signin(c, provider, email="ana@example.com", email_verified=True,
                  sub="e-1").status_code == 200
    assert signin(c, provider, sub="e-1", email=None, preferred_username=None).status_code == 200


# --- key rotation ------------------------------------------------------------------------------

def test_a_new_kid_triggers_exactly_one_jwks_refresh(c, provider):
    assert signin(c, provider).status_code == 200
    assert provider.jwks_fetches == 1
    assert signin(c, provider).status_code == 200  # cached
    assert provider.jwks_fetches == 1
    provider.rotate()
    assert signin(c, provider).status_code == 200
    assert provider.jwks_fetches == 2


def test_unknown_kid_refreshes_once_per_attempt_then_refuses(c, provider):
    refused(signin(c, provider, kid="rotated-away"))
    assert provider.jwks_fetches == 2  # the initial fetch and one refresh
    refused(signin(c, provider, kid="rotated-away"))
    assert provider.jwks_fetches == 3


def test_old_key_is_refused_after_rotation(c, provider):
    assert signin(c, provider).status_code == 200
    old = provider.keys[0]
    provider.rotate()
    # inside the cache window the old key is still trusted; once the cache expires it is gone
    c.app.state.oidc.clock = lambda: time.time() + oidc.DISCOVERY_SECONDS + 5
    refused(signin(c, provider, key=old, kid=provider.kid(0)))


# --- MFA applies on top of SSO -----------------------------------------------------------------

def test_an_admin_via_sso_still_has_to_enrol_and_then_verify(soc_settings, provider, monkeypatch):
    app = make_app(make_settings(soc_settings, mfa_required_for_admins=True))
    c = TestClient(app)
    step = {"n": mfa.current_step()}
    monkeypatch.setattr(mfa, "current_step", lambda now=None: step["n"])
    refused(signin(c, provider, preferred_username="admin", sub="adm-1"))  # no MFA yet: no link
    body = c.post("/auth/login", json={"username": "admin", "password": ADMIN_PW}).json()
    assert body["mfa"] == "enrol"  # the admin sets up MFA with their password first
    secret = c.post("/auth/mfa/enrol/start", json={"mfa_token": body["mfa_token"]}).json()["secret"]
    ok = c.post("/auth/mfa/enrol/confirm", json={"mfa_token": body["mfa_token"],
                                                 "code": mfa.code_at(secret, step["n"])})
    assert ok.status_code == 200
    body = signin(c, provider, preferred_username="admin", sub="adm-1").json()
    assert body["mfa"] == "verify" and body["access_token"] is None
    step["n"] += 2
    r = c.post("/auth/mfa/verify", json={"mfa_token": body["mfa_token"],
                                         "code": mfa.code_at(secret, step["n"])})
    assert r.status_code == 200 and r.json()["access_token"]


def test_an_analyst_with_mfa_must_verify_after_sso(soc_settings, provider):
    app = make_app(make_settings(soc_settings))
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "analyst"))
        user.mfa_enabled = True
        db.commit()
    body = signin(TestClient(app), provider).json()
    assert body["mfa"] == "verify" and body["access_token"] is None


# --- throttling --------------------------------------------------------------------------------

def test_failed_callbacks_are_throttled(c, provider):
    for _ in range(5):
        refused(c.post("/auth/oidc/callback", json={"code": "c", "state": "s", "binding": "b"}))
    r = c.post("/auth/oidc/callback", json={"code": "c", "state": "s", "binding": "b"})
    assert r.status_code == 429


def test_callback_rejects_unknown_fields_and_empty_values(c, provider):
    assert c.post("/auth/oidc/callback", json={"code": "c", "state": "s", "binding": "b",
                                               "extra": 1}).status_code == 422
    assert c.post("/auth/oidc/callback", json={"code": "", "state": "s",
                                               "binding": "b"}).status_code == 422


# --- admin: unlink -----------------------------------------------------------------------------

def test_admin_can_unlink_an_sso_account(app, c, provider):
    token = signin(c, provider).json()["access_token"]
    admin = c.post("/auth/login", json={"username": "admin", "password": ADMIN_PW}).json()
    users = c.get("/admin/users", headers=bearer(admin["access_token"]))
    row = next(u for u in users.json() if u["username"] == "analyst")
    assert row["sso_linked"] is True and "oidc_subject" not in users.text
    assert "sub-1" not in users.text
    r = c.post(f"/admin/users/{row['id']}/sso/unlink", headers=bearer(admin["access_token"]))
    assert r.status_code == 200 and r.json()["sso_linked"] is False
    (entry,) = audits(app, "user_sso_unlink")
    assert entry.actor_name == "admin" and entry.target == "user:analyst"
    user = get_user(app, "analyst")
    assert user.oidc_issuer is None and user.oidc_subject is None
    assert c.get("/auth/me", headers=bearer(token)).status_code == 401  # logged out
    assert c.post(f"/admin/users/{row['id']}/sso/unlink",
                  headers=bearer(admin["access_token"])).status_code == 409
    # the next sign-in links by username again, with a new subject
    assert signin(c, provider, sub="sub-new").status_code == 200
    assert get_user(app, "analyst").oidc_subject == "sub-new"


def test_unlink_is_admin_only_and_404_for_unknown_users(c, provider):
    analyst = c.post("/auth/login", json={"username": "analyst", "password": ANALYST_PW}).json()
    assert c.post("/admin/users/1/sso/unlink",
                  headers=bearer(analyst["access_token"])).status_code == 403
    admin = c.post("/auth/login", json={"username": "admin", "password": ADMIN_PW}).json()
    assert c.post("/admin/users/999/sso/unlink",
                  headers=bearer(admin["access_token"])).status_code == 404


# --- settings validation -----------------------------------------------------------------------

def _settings(**kw):
    base = dict(jwt_secret=TEST_SECRET, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID,
                oidc_client_secret=CLIENT_SECRET, oidc_redirect_uri=REDIRECT)
    return SocSettings(**(base | kw))


def test_valid_settings_normalise_the_issuer():
    s = _settings(oidc_issuer=f"  {ISSUER}/ ")
    assert s.oidc_issuer == ISSUER


def test_http_issuer_is_refused_unless_allowed():
    with pytest.raises(ValidationError):
        _settings(oidc_issuer="http://idp.test/realms/soc")
    assert _settings(oidc_issuer="http://idp.test/realms/soc",
                     oidc_allow_http=True).oidc_issuer == "http://idp.test/realms/soc"


@pytest.mark.parametrize("issuer", ["ftp://idp.test", "idp.test/realms", "https://idp.test/a?x=1",
                                    "https://idp.test/a#frag", "https://idp.test/a b"])
def test_odd_issuers_are_refused(issuer):
    with pytest.raises(ValidationError):
        _settings(oidc_issuer=issuer)


@pytest.mark.parametrize("missing", ["oidc_client_id", "oidc_client_secret", "oidc_redirect_uri"])
def test_missing_client_settings_are_refused(missing):
    with pytest.raises(ValidationError) as exc:
        _settings(**{missing: None})
    assert CLIENT_SECRET not in str(exc.value)


def test_scopes_must_include_openid():
    with pytest.raises(ValidationError):
        _settings(oidc_scopes="profile email")
    assert _settings(oidc_scopes="email openid").oidc_scopes == "email openid"


def test_redirect_uri_must_be_http_s():
    with pytest.raises(ValidationError):
        _settings(oidc_redirect_uri="javascript:alert(1)")


def test_blank_issuer_means_off(monkeypatch):
    monkeypatch.setenv("IDPS_SOC_OIDC_ISSUER", "")
    assert SocSettings(jwt_secret=TEST_SECRET).oidc_issuer is None


def test_no_oidc_without_an_issuer():
    assert SocSettings(jwt_secret=TEST_SECRET).oidc_issuer is None


# --- http_json ---------------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://idp.test/x", "file:///etc/passwd", "ftp://idp.test/x",
                                 "//idp.test/x", "idp.test/x", "HTTPS://idp.test/x"])
def test_http_json_refuses_non_https_without_any_network(url, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not reach the network")

    monkeypatch.setattr(oidc.urllib.request, "build_opener", boom)
    with pytest.raises(oidc.OidcError, match="non-https"):
        oidc.http_json(url)


def test_http_json_allows_http_only_when_asked(monkeypatch):
    reached = []

    def fake_build_opener(*a, **k):
        reached.append(1)
        raise OSError("no network in tests")

    monkeypatch.setattr(oidc.urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(OSError):
        oidc.http_json("http://idp.test/x", allow_http=True)
    assert reached


class _Resp:
    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        return self.raw[:n]


def _opener_returning(raw, monkeypatch):
    class Opener:
        def open(self, req, timeout=None):
            return _Resp(raw)

    monkeypatch.setattr(oidc.urllib.request, "build_opener", lambda *a, **k: Opener())


def test_http_json_parses_an_object_and_refuses_everything_else(monkeypatch):
    _opener_returning(b'{"a": 1}', monkeypatch)
    assert oidc.http_json("https://idp.test/x") == {"a": 1}
    for raw, msg in ((b"[1]", "not a JSON object"), (b"nope", "not JSON"),
                     (b"x" * (oidc.MAX_RESPONSE_BYTES + 1), "too large")):
        _opener_returning(raw, monkeypatch)
        with pytest.raises(oidc.OidcError, match=msg):
            oidc.http_json("https://idp.test/x")


def test_http_json_does_not_follow_redirects():
    assert oidc._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://x/") is None


# --- login history ------------------------------------------------------------------------------

def history_rows(app):
    from soc.api.models import LoginHistory

    with app.state.session_factory() as db:
        return list(db.scalars(select(LoginHistory).order_by(LoginHistory.id)))


@pytest.fixture(autouse=True)
def _forget_history_throttles():
    from soc.api.iam import history

    history._recent_locked.clear()
    history._recent_fails.clear()
    yield
    history._recent_locked.clear()
    history._recent_fails.clear()


def test_a_single_sign_on_is_recorded_in_the_login_history(app, c, provider):
    r = signin(c, provider)
    assert r.status_code == 200
    (row,) = history_rows(app)
    assert (row.username, row.success, row.reason, row.mfa_used) == ("analyst", True, "ok", False)
    assert row.user_id == get_user(app, "analyst").id and row.ip == "testclient"


def test_sso_with_mfa_is_recorded_once_the_code_is_accepted(soc_settings, provider):
    app = make_app(make_settings(soc_settings))
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "analyst"))
        user.mfa_enabled = True
        db.commit()
    body = signin(TestClient(app), provider).json()
    assert body["mfa"] == "verify"
    assert history_rows(app) == []  # a first factor alone is not a sign-in


@pytest.mark.parametrize("claims,reason,username", [
    (dict(nonce="wrong"), "sso_failed", "(single sign-on)"),
    (dict(preferred_username=None), "sso_refused", "(single sign-on)"),
])
def test_sso_failures_are_recorded_with_a_reason(app, c, provider, claims, reason, username):
    refused(signin(c, provider, **claims))
    (row,) = history_rows(app)
    assert (row.success, row.reason, row.username, row.user_id) == (False, reason, username, None)


def test_sso_with_no_such_account_stores_a_label_not_the_name(app, c, provider):
    refused(signin(c, provider, preferred_username="hunter2-pasted-password"))
    (row,) = history_rows(app)
    assert row.reason == "unknown_user" and row.user_id is None
    assert "hunter2" not in row.username and row.username.startswith("?")


def test_sso_for_a_disabled_account_is_recorded_against_it(app, c, provider):
    with app.state.session_factory() as db:
        auth.set_disabled(db, db.scalar(select(User).where(User.username == "analyst")), True)
    refused(signin(c, provider))
    (row,) = history_rows(app)
    assert (row.username, row.reason, row.success) == ("analyst", "disabled", False)
    assert row.user_id == get_user(app, "analyst").id


def test_sso_for_an_unenrolled_admin_is_recorded_as_refused(app, c, provider):
    refused(signin(c, provider, preferred_username="admin", sub="admin-sub"))
    (row,) = history_rows(app)
    assert (row.username, row.reason) == ("admin", "sso_refused")


def test_throttled_sso_callbacks_are_recorded_as_locked_once(app, c, provider):
    for _ in range(5):
        refused(c.post("/auth/oidc/callback", json={"code": "c", "state": "s", "binding": "b"}))
    for _ in range(3):
        assert c.post("/auth/oidc/callback", json={"code": "c", "state": "s",
                                                   "binding": "b"}).status_code == 429
    assert [r.reason for r in history_rows(app)] == ["sso_failed"] * 5 + ["locked"]


def test_a_failing_history_write_never_breaks_sso(app, c, provider, monkeypatch):
    from soc.api.iam import history

    def boom(*a, **k):
        raise RuntimeError("history is broken")

    monkeypatch.setattr(history, "LoginHistory", boom)
    assert signin(c, provider).status_code == 200
    refused(signin(c, provider, nonce="wrong"))
