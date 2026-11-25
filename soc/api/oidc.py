"""Optional single sign-on with OpenID Connect (authorization code flow with PKCE).

Off unless IDPS_SOC_OIDC_ISSUER is set (see settings.py). The flow:

1. POST /auth/oidc/start: the SOC makes a `state`, a `nonce`, a PKCE verifier and a `binding`
   secret, keeps them in memory for 10 minutes, and returns the provider's sign-in address plus
   the binding. The dashboard keeps the binding in sessionStorage.
2. The provider sends the browser back to the dashboard's /auth/callback page with `code` and
   `state`; the page POSTs them with the binding to /auth/oidc/callback. The binding stops a
   login CSRF (someone else's half-finished sign-in completed in your browser): only the browser
   that started a sign-in can finish it. Each state works once.
3. The SOC exchanges the code at the provider's token endpoint (client secret + PKCE verifier,
   https only) and checks the ID token completely: signature against the provider's published
   keys (asymmetric algorithms only), issuer, audience, authorised party, expiry, issued-at and
   the nonce.
4. The account: the user linked to this provider subject; the first time, the existing SOC user
   whose username equals the configured claim (preferred_username by default), which is then
   linked. Nobody gets an account by signing in, and a disabled user stays out. MFA applies on
   top, exactly as after a password.

The in-memory state store means one SOC process (as for the live feed, see main.py).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc.api import auth, security
from soc.api.common import audit
from soc.api.db import get_db
from soc.api.iam.history import record_login
from soc.api.models import Role, User

router = APIRouter(prefix="/auth/oidc", tags=["auth"])

STATE_SECONDS = 600
MAX_PENDING = 1000
MAX_PENDING_PER_CLIENT = 10  # sign-ins in progress from one address
MAX_RESPONSE_BYTES = 512 * 1024
DISCOVERY_SECONDS = 3600
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]
LEEWAY_SECONDS = 60


class OidcError(Exception):
    """Sign-in failed. The message is for the log; the browser gets a generic one.

    `reason` is what the login history records (sso_failed: the provider or token was refused;
    sso_refused: a valid sign-in the SOC will not accept; unknown_user; disabled). `user` is the
    SOC account concerned when there is one; `name` the claimed username when there is none."""

    def __init__(self, message: str, reason: str = "sso_failed", user=None,
                 name: str | None = None) -> None:
        super().__init__(message)
        self.reason, self.user, self.name = reason, user, name


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def http_json(url: str, *, data: dict | None = None, auth_header: str | None = None,
              timeout: float = 5.0, allow_http: bool = False) -> dict:
    """GET (or POST a form to) `url` and return its JSON object. https only unless allow_http;
    responses over MAX_RESPONSE_BYTES are refused. Tests replace this function."""
    if not (url.startswith("https://") or (allow_http and url.startswith("http://"))):
        raise OidcError(f"refusing a non-https provider address: {url[:80]}")
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    req.add_header("Accept", "application/json")
    if body:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if auth_header:
        req.add_header("Authorization", auth_header)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()), _NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise OidcError(f"provider answered {exc.code} for {urllib.parse.urlsplit(url).path}") from None
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as exc:
        raise OidcError(f"provider unreachable: {type(exc).__name__}") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OidcError("provider response too large")
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise OidcError("provider response is not JSON") from None
    if not isinstance(value, dict):
        raise OidcError("provider response is not a JSON object")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow a redirect off the provider
        return None


class OidcClient:
    """Provider metadata and keys (cached), pending sign-ins, and the token checks."""

    def __init__(self, settings, clock=time.time) -> None:
        self.settings = settings
        self.clock = clock
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}
        self._meta: dict | None = None
        self._meta_at = 0.0
        self._keys: jwt.PyJWKSet | None = None
        self._keys_at = 0.0

    # --- provider metadata ----------------------------------------------------------------

    def _get(self, url: str, **kw) -> dict:
        return http_json(url, timeout=self.settings.oidc_timeout_seconds,
                         allow_http=self.settings.oidc_allow_http, **kw)

    def metadata(self) -> dict:
        now = self.clock()
        if self._meta is None or now - self._meta_at > DISCOVERY_SECONDS:
            issuer = self.settings.oidc_issuer
            meta = self._get(f"{issuer}/.well-known/openid-configuration")
            if meta.get("issuer") != issuer:  # OIDC Discovery 4.3: must match exactly
                raise OidcError("discovery document is for a different issuer")
            schemes = ("https://", "http://") if self.settings.oidc_allow_http else ("https://",)
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not isinstance(meta.get(key), str) or not meta[key].startswith(schemes):
                    raise OidcError(f"discovery document has no usable https {key}")
            self._meta, self._meta_at = meta, now
        return self._meta

    def _key_set(self, refresh: bool = False) -> jwt.PyJWKSet:
        now = self.clock()
        if refresh or self._keys is None or now - self._keys_at > DISCOVERY_SECONDS:
            try:
                self._keys = jwt.PyJWKSet.from_dict(self._get(self.metadata()["jwks_uri"]))
            except jwt.PyJWKSetError as exc:
                raise OidcError(f"provider keys unusable: {exc}") from None
            self._keys_at = now
        return self._keys

    def _signing_key(self, kid: str | None, may_refresh: bool) -> jwt.PyJWK:
        keys = self._key_set()
        match = [k for k in keys.keys if kid is None or k.key_id == kid]
        if not match and may_refresh:  # the provider rotated its keys
            keys = self._key_set(refresh=True)
            match = [k for k in keys.keys if kid is None or k.key_id == kid]
        if len(match) != 1:
            raise OidcError("no single provider key matches the ID token")
        return match[0]

    # --- pending sign-ins -----------------------------------------------------------------

    def start(self, client: str = "") -> tuple[str, str]:
        """The provider's sign-in address and the browser binding secret. One address may have
        MAX_PENDING_PER_CLIENT sign-ins in progress (its oldest is dropped beyond that); when
        MAX_PENDING is reached the oldest overall is dropped, so a flood cannot lock SSO out."""
        meta = self.metadata()
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier, binding = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        now = self.clock()
        with self._lock:
            for k in [k for k, v in self._pending.items() if now - v["at"] > STATE_SECONDS]:
                del self._pending[k]
            mine = [k for k, v in self._pending.items() if v["client"] == client]
            for k in mine[:max(0, len(mine) - MAX_PENDING_PER_CLIENT + 1)]:
                del self._pending[k]  # dicts keep insertion order: the oldest first
            while len(self._pending) >= MAX_PENDING:
                del self._pending[next(iter(self._pending))]
            self._pending[state] = {"nonce": nonce, "verifier": verifier, "at": now,
                                    "client": client,
                                    "binding": hashlib.sha256(binding.encode()).hexdigest()}
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": self.settings.oidc_client_id,
            "redirect_uri": self.settings.oidc_redirect_uri, "scope": self.settings.oidc_scopes,
            "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256"})
        endpoint = meta["authorization_endpoint"]
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{query}", binding

    def _take(self, state: str, binding: str) -> dict:
        with self._lock:
            pending = self._pending.pop(state, None)  # one use, right or wrong binding
        if pending is None or self.clock() - pending["at"] > STATE_SECONDS:
            raise OidcError("unknown or expired state")
        if not security.tokens_equal(pending["binding"],
                                     hashlib.sha256(binding.encode()).hexdigest()):
            raise OidcError("sign-in was started in another browser")
        return pending

    # --- finishing ------------------------------------------------------------------------

    def finish(self, code: str, state: str, binding: str) -> dict:
        """Exchange the code and return the checked ID token claims."""
        pending = self._take(state, binding)
        s = self.settings
        basic = base64.b64encode(
            f"{urllib.parse.quote(s.oidc_client_id, safe='')}:"
            f"{urllib.parse.quote(s.oidc_client_secret.get_secret_value(), safe='')}"
            .encode()).decode()
        tokens = self._get(self.metadata()["token_endpoint"], auth_header=f"Basic {basic}", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": s.oidc_redirect_uri,
            "code_verifier": pending["verifier"]})
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise OidcError("token response has no id_token")
        return self.check_id_token(id_token, pending["nonce"])

    def check_id_token(self, id_token: str, nonce: str) -> dict:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError(f"malformed ID token: {exc}") from None
        if header.get("alg") not in ALGORITHMS:  # never "none" or a shared-secret HS*
            raise OidcError(f"ID token algorithm {header.get('alg')!r} not allowed")
        key = self._signing_key(header.get("kid"), may_refresh=True)
        try:
            claims = jwt.decode(
                id_token, key=key, algorithms=[header["alg"]],
                audience=self.settings.oidc_client_id, issuer=self.settings.oidc_issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]})
        except jwt.PyJWTError as exc:
            raise OidcError(f"ID token refused: {exc}") from None
        if not security.tokens_equal(str(claims["nonce"]), nonce):
            raise OidcError("ID token nonce does not match")
        aud = claims["aud"]
        if (isinstance(aud, list) and len(aud) > 1) or "azp" in claims:
            if claims.get("azp") != self.settings.oidc_client_id:  # OIDC Core 3.1.3.7
                raise OidcError("ID token authorised party is not this client")
        if not isinstance(claims["sub"], str) or not claims["sub"] or len(claims["sub"]) > 255:
            raise OidcError("ID token subject is not usable")
        return claims


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def find_user(db: Session, settings, claims: dict) -> User:
    """The SOC user for checked ID token claims (linking it the first time), or OidcError."""
    issuer, subject = settings.oidc_issuer, claims["sub"]
    user = db.scalar(select(User).where(User.oidc_issuer == issuer, User.oidc_subject == subject))
    if user is None:
        name = claims.get(settings.oidc_username_claim)
        if settings.oidc_username_claim == "email" and claims.get("email_verified") is not True:
            raise OidcError("the provider has not verified this email address", "sso_refused")
        if not isinstance(name, str) or not name:
            raise OidcError(f"ID token has no {settings.oidc_username_claim} claim", "sso_refused")
        user = db.scalar(select(User).where(User.username == name))
        if user is None:
            raise OidcError("no linked SOC account", "unknown_user", name=name)
        if user.oidc_subject is not None:  # linked to another provider account already
            raise OidcError(f"SOC account {name[:64]!r} is linked to another sign-in", "sso_refused",
                            user=user)
        if user.disabled:
            raise OidcError(f"SOC account {user.username!r} is disabled", "disabled", user=user)
        if user.role == Role.ADMIN and not user.mfa_enabled:
            # Linking by a name claim trusts the provider's usernames. An admin without MFA would
            # then be one provider account named like them away from enrolling an attacker's
            # authenticator. The admin signs in with their password and sets up MFA first.
            raise OidcError(f"admin {user.username!r} must set up MFA before the first single "
                            "sign-on", "sso_refused", user=user)
        user.oidc_issuer, user.oidc_subject = issuer, subject
        audit(db, user, "sso_link", f"user:{user.username}", {"issuer": issuer[:200]})
        db.commit()
    if user.disabled:
        raise OidcError(f"SOC account {user.username!r} is disabled", "disabled", user=user)
    return user


# --- routes ------------------------------------------------------------------------------------

class OidcConfig(BaseModel):
    enabled: bool
    label: str | None = None


class OidcStart(BaseModel):
    authorization_url: str
    binding: str  # keep in the browser (sessionStorage) and send back with the callback


class OidcCallback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=2048)
    state: str = Field(min_length=1, max_length=256)
    binding: str = Field(min_length=1, max_length=256)


SSO_NAME = "(single sign-on)"  # the login-history name when no account is concerned
_FAILED = "single sign-on failed; try again or ask an admin"


def _client(request: Request) -> OidcClient:
    client = getattr(request.app.state, "oidc", None)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "single sign-on is not configured")
    return client


@router.get("/config", response_model=OidcConfig)
def oidc_config(request: Request):
    settings = request.app.state.settings
    if getattr(request.app.state, "oidc", None) is None:
        return OidcConfig(enabled=False)
    return OidcConfig(enabled=True, label=settings.oidc_button_label)


@router.post("/start", response_model=OidcStart)
def oidc_start(request: Request):
    client = _client(request)
    try:
        url, binding = client.start(auth.client_ip(request))
    except OidcError as exc:
        request.app.state.oidc_log.warning("single sign-on start failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "the sign-in provider is not reachable") from None
    return OidcStart(authorization_url=url, binding=binding)


@router.post("/callback", response_model=auth.TokenResponse)
def oidc_callback(body: OidcCallback, request: Request, db: Annotated[Session, Depends(get_db)]):
    client = _client(request)
    throttle: security.LoginThrottle = request.app.state.login_throttle
    ip = auth.client_ip(request)
    ticket = throttle.begin_attempt("(single sign-on)", ip)
    settings = request.app.state.settings
    agent = request.headers.get("user-agent")
    if ticket is None:
        record_login(db, username=SSO_NAME, user_id=None, success=False, reason="locked", ip=ip,
                     user_agent=agent)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed sign-ins; try again later")
    try:
        claims = client.finish(body.code, body.state, body.binding)
        user = find_user(db, settings, claims)
    except OidcError as exc:
        db.rollback()
        request.app.state.oidc_log.warning("single sign-on refused from %s: %s", ip, exc)
        if exc.user is not None:
            who = {"username": exc.user.username, "user_id": exc.user.id}
        elif exc.name is not None:  # an account name nobody has: stored only as a hash
            who = {"username": exc.name, "user_id": None, "settings": settings, "unknown": True}
        else:
            who = {"username": SSO_NAME, "user_id": None}
        record_login(db, success=False, reason=exc.reason, ip=ip, user_agent=agent, **who)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _FAILED) from None
    throttle.succeeded("(single sign-on)", ip, ticket)
    result = auth.after_first_factor(user, settings)
    if result.access_token:  # no second step: the sign-in is complete (else: at /mfa/verify)
        record_login(db, username=user.username, user_id=user.id, success=True, reason="ok",
                     ip=ip, user_agent=agent)
    return result
