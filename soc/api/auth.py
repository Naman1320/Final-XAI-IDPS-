"""Login, current-user and role dependencies, and sensor authentication."""

import logging
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from soc.api import email_mfa, mfa, security
from soc.api.common import audit
from soc.api.db import get_db
from soc.api.iam import engine as iam_engine
from soc.api.iam.history import record_login
from soc.api.models import Role, SensorToken, User

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)

# One message for every login failure, so responses don't reveal whether a username exists.
_LOGIN_FAILED = "incorrect username or password"
_UNAUTHORIZED = HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated",
                              headers={"WWW-Authenticate": "Bearer"})


class LoginRequest(BaseModel):
    request_email_code: bool = False
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=security.MAX_PASSWORD_LENGTH)


class TokenResponse(BaseModel):
    """A login result: an access token, or (mfa set, access_token null) a challenge to answer at
    /auth/mfa/verify ("verify") or /auth/mfa/enrol/* ("enrol", an admin without MFA yet)."""

    email_status: Literal["sent", "cooldown", "unavailable"] | None = None
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None  # seconds
    mfa: Literal["verify", "enrol"] | None = None
    mfa_token: str | None = None


class UserOut(BaseModel):
    id: int
    username: str
    role: Role
    mfa_enabled: bool = False
    # MFA is required for this user (admins, by default): it cannot be turned off.
    mfa_required: bool = False
    # What the user may do (soc/api/iam): the whole catalog for an admin. Additive.
    permissions: list[str] = []


def client_ip(request: Request) -> str:
    # The direct peer address. If the API is put behind a reverse proxy, configure the
    # proxy-headers support in uvicorn (--proxy-headers / --forwarded-allow-ips) rather
    # than trusting X-Forwarded-For here, which any client could forge.
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Annotated[Session, Depends(get_db)]):
    settings = request.app.state.settings
    throttle: security.LoginThrottle = request.app.state.login_throttle
    ip = client_ip(request)
    agent = request.headers.get("user-agent")
    ticket = throttle.begin_attempt(body.username, ip)  # counted as a failure until proven
    if ticket is None:
        try:
            known = db.scalar(select(User.id).where(User.username == body.username)) is not None
        except SQLAlchemyError:  # best-effort history must not expose the submitted name
            db.rollback()
            known = False
        record_login(db, username=body.username, user_id=None, success=False, reason="locked",
                     ip=ip, user_agent=agent, settings=settings, unknown=not known)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed logins; try again later")
    user = db.scalar(select(User).where(User.username == body.username))
    ok = security.verify_password(body.password, user.password_hash if user else None)
    if not ok or user is None or user.disabled:
        # The response is the same for every cause; the history (admins only) tells them apart.
        reason = ("unknown_user" if user is None else "disabled" if ok else "bad_password")
        record_login(db, username=body.username, user_id=user.id if user else None,
                     success=False, reason=reason, ip=ip, user_agent=agent, settings=settings,
                     unknown=user is None)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _LOGIN_FAILED)
    throttle.succeeded(body.username, ip, ticket)
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
        db.commit()
    result = after_first_factor(user, settings)
    if body.request_email_code and result.mfa == "verify" and user.mfa_email:
        result.email_status = email_mfa.deliver(db, settings, user, result.mfa_token)
    if result.access_token:  # no second step: the sign-in is complete (else: at /mfa/verify)
        record_login(db, username=user.username, user_id=user.id, success=True, reason="ok",
                     ip=ip, user_agent=agent)
    return result


def mfa_required(user: User, settings) -> bool:
    return user.role == Role.ADMIN and settings.mfa_required_for_admins


def access_token(user: User, settings) -> TokenResponse:
    minutes = settings.access_token_minutes
    token = security.create_access_token(
        user_id=user.id, account_created=user.created_at.isoformat(),
        token_version=user.token_version,
        secret=settings.jwt_secret.get_secret_value(), minutes=minutes)
    return TokenResponse(access_token=token, expires_in=minutes * 60)


def after_first_factor(user: User, settings) -> TokenResponse:
    """After a correct password or single sign-on: an access token, or the MFA step."""
    if user.mfa_enabled:
        purpose = "verify"
    elif mfa_required(user, settings):
        purpose = "enrol"
    else:
        return access_token(user, settings)
    minutes = settings.mfa_challenge_minutes
    challenge = security.create_challenge_token(
        user_id=user.id, account_created=user.created_at.isoformat(),
        token_version=user.token_version, purpose=purpose,
        secret=settings.jwt_secret.get_secret_value(), minutes=minutes)
    return TokenResponse(mfa=purpose, mfa_token=challenge, expires_in=minutes * 60)


def user_from_token(token: str, request_or_app, db: Session) -> User | None:
    """The active user a token belongs to, or None. Shared by HTTP and WebSocket auth."""
    app = getattr(request_or_app, "app", request_or_app)
    try:
        claims = security.decode_access_token(
            token, secret=app.state.settings.jwt_secret.get_secret_value())
    except security.TokenError:
        return None
    user = db.get(User, int(claims["sub"]))
    if (user is None or user.disabled or user.token_version != claims["ver"]
            or user.created_at.isoformat() != claims["account_created"]):
        return None
    if mfa_required(user, app.state.settings) and not user.mfa_enabled:
        return None  # e.g. made admin since the token was issued: log in again and enrol
    return user


def current_user(request: Request, db: Annotated[Session, Depends(get_db)],
                 creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _UNAUTHORIZED
    user = user_from_token(creds.credentials, request, db)
    if user is None:
        raise _UNAUTHORIZED
    return user


def require_role(*roles: Role) -> Callable[..., User]:
    """Dependency factory: the current user, who must have one of `roles` (admins always pass)."""
    allowed = set(roles) | {Role.ADMIN}

    def dependency(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not allowed for your role")
        return user

    return dependency


AnyUser = Annotated[User, Depends(require_role(Role.ANALYST))]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]


_sensor_log = logging.getLogger("soc.sensor_auth")


def current_sensor(request: Request, db: Annotated[Session, Depends(get_db)],
                   creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
                   ) -> SensorToken:
    """Authenticate a sensor by its API token (Authorization: Bearer idps_sensor_...) and, on the
    mutual-TLS listener (soc/api/serve.py), its client certificate: the certificate's common name
    must be the sensor's name. With IDPS_SOC_SENSOR_MTLS_REQUIRED, a request without a verified
    certificate (the main listener) is refused."""
    if creds is None or not creds.credentials.startswith(security.SENSOR_TOKEN_PREFIX):
        raise _UNAUTHORIZED
    digest = security.hash_sensor_token(creds.credentials)
    sensor = db.scalar(select(SensorToken).where(SensorToken.token_hash == digest))
    if sensor is None or sensor.revoked or not security.tokens_equal(sensor.token_hash, digest):
        raise _UNAUTHORIZED
    from soc.api.serve import CERT_EXTENSION

    extensions = request.scope.get("extensions") or {}
    cert = extensions.get(CERT_EXTENSION)
    if cert is None:
        if request.app.state.settings.sensor_mtls_required:
            _sensor_log.warning("sensor %r refused: no client certificate (mutual TLS is "
                                "required; use the sensor port)", sensor.name)
            raise _UNAUTHORIZED
    elif cert.get("cn") != sensor.name:
        _sensor_log.warning("sensor %r refused: its client certificate is for %r", sensor.name,
                            str(cert.get("cn"))[:64])
        raise _UNAUTHORIZED
    return sensor


Sensor = Annotated[SensorToken, Depends(current_sensor)]


@router.get("/me", response_model=UserOut)
def me(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    return UserOut(id=user.id, username=user.username, role=user.role,
                   mfa_enabled=user.mfa_enabled,
                   mfa_required=mfa_required(user, request.app.state.settings),
                   permissions=sorted(iam_engine.effective_permissions(db, user)))


# --- MFA -------------------------------------------------------------------------------------

Code = Annotated[str, Field(min_length=6, max_length=16)]  # 6 digits, or a recovery code


class MfaVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mfa_token: str = Field(min_length=1, max_length=2048)
    code: Code


class MfaEnrolStart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mfa_token: str | None = Field(default=None, max_length=2048)  # or a bearer access token
    # Needed with a bearer access token (not with an "enrol" step token, which already followed
    # the password): a stolen session token alone must not be able to put its own authenticator
    # on the account (that would lock the owner out). Checked in the handler, after auth.
    password: str | None = Field(default=None, max_length=security.MAX_PASSWORD_LENGTH)


class MfaEnrolConfirm(MfaEnrolStart):
    # Checked in the handler, after authentication: an unauthenticated request gets 401, not 422.
    code: str = Field(default="", max_length=8)


class MfaEnrolment(BaseModel):
    secret: str  # for typing into the app by hand
    otpauth_uri: str
    qr_svg: str  # the URI as a QR code, drawn by the SOC (never by an outside service)
    issuer: str


class MfaEnabled(TokenResponse):
    recovery_codes: list[str]  # shown once


class MfaDisable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=security.MAX_PASSWORD_LENGTH)
    code: Code


class MfaRecoveryRegenerate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Annotated[str, Field(min_length=6, max_length=8)]  # a current app code


class RecoveryCodes(BaseModel):
    recovery_codes: list[str]


_BAD_CODE = "incorrect code"
# For a signed-in user (a bearer access token), a wrong password or code is 403, not 401: the
# dashboard treats any 401 as "session over" and would log them out over a typo.
_SIGNED_IN_REFUSAL = status.HTTP_403_FORBIDDEN
_BAD_CHALLENGE = HTTPException(status.HTTP_401_UNAUTHORIZED,
                               "the sign-in step has expired; sign in again")


def _keys(request: Request) -> mfa.MfaKeys:
    return mfa.MfaKeys(request.app.state.settings.mfa_master_key)


def _challenge_user(request: Request, db: Session, token: str, purpose: str) -> User:
    settings = request.app.state.settings
    try:
        claims = security.decode_challenge_token(
            token, secret=settings.jwt_secret.get_secret_value(), purpose=purpose)
    except security.TokenError:
        raise _BAD_CHALLENGE from None
    user = db.get(User, int(claims["sub"]))
    if (user is None or user.disabled or user.token_version != claims["ver"]
            or user.created_at.isoformat() != claims["account_created"]):
        raise _BAD_CHALLENGE
    return user


class _CodeAttempt:
    """Wrong codes are counted per user (from any address): mfa_max_failures per lockout."""

    def __init__(self, request: Request, user: User) -> None:
        self.throttle: security.LoginThrottle = request.app.state.mfa_throttle
        self.key = f"user#{user.id}"
        self.ticket = self.throttle.begin_attempt(self.key, self.key)
        if self.ticket is None:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many wrong codes; try again later")

    def succeeded(self) -> None:
        self.throttle.succeeded(self.key, self.key, self.ticket)


def _use_totp(db: Session, keys: mfa.MfaKeys, user: User, code: str) -> bool:
    """Check an app code against the user's secret and mark its step used, atomically: of two
    requests with the same code, only one wins."""
    try:
        secret = keys.decrypt(user.totp_secret or "", user.id)
    except mfa.MfaError:
        return False
    step = mfa.matching_step(secret, code, user.totp_last_step)
    if step is None:
        return False
    done = db.execute(
        update(User).where(User.id == user.id, or_(User.totp_last_step.is_(None),
                                                    User.totp_last_step < step))
        .values(totp_last_step=step).execution_options(synchronize_session=False))
    db.commit()
    db.refresh(user)
    return done.rowcount == 1


def _use_recovery(db: Session, keys: mfa.MfaKeys, user: User, code: str) -> int | None:
    """Spend a recovery code. Returns how many are left, or None if it is not one of them. Using
    one also logs out the user's other sessions (token_version), which makes the update atomic."""
    digest = keys.recovery_hash(code)
    codes = list(user.recovery_codes or [])
    match = next((c for c in codes if security.tokens_equal(c, digest)), None)
    if match is None:
        return None
    codes.remove(match)
    done = db.execute(
        update(User).where(User.id == user.id, User.token_version == user.token_version)
        .values(recovery_codes=codes, token_version=user.token_version + 1)
        .execution_options(synchronize_session=False))
    if done.rowcount != 1:
        db.rollback()
        return None
    audit(db, user, "mfa_recovery_code_used", f"user:{user.username}", {"left": len(codes)})
    db.commit()
    db.refresh(user)
    return len(codes)


def _check_second_factor(db: Session, request: Request, user: User, code: str,
                         attempt: "_CodeAttempt | None" = None,
                         bad_status: int = status.HTTP_401_UNAUTHORIZED) -> None:
    attempt = attempt or _CodeAttempt(request, user)
    keys = _keys(request)
    ok = (_use_recovery(db, keys, user, code) is not None if mfa.looks_like_recovery(code)
          else _use_totp(db, keys, user, code))
    if not ok:
        raise HTTPException(bad_status, _BAD_CODE)
    attempt.succeeded()


@router.post("/mfa/verify", response_model=TokenResponse)
def mfa_verify(body: MfaVerify, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Second step of a login: an app code, or one of the recovery codes."""
    user = _challenge_user(request, db, body.mfa_token, "verify")
    if not user.mfa_enabled:
        raise _BAD_CHALLENGE
    who = {"username": user.username, "user_id": user.id, "ip": client_ip(request),
           "user_agent": request.headers.get("user-agent"), "mfa_used": True}
    try:
        if len(body.code) == 8 and body.code.isascii() and body.code.isdigit():
            attempt = _CodeAttempt(request, user)
            if not email_mfa.consume(db, request.app.state.settings, user, body.mfa_token, body.code):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, _BAD_CODE)
            attempt.succeeded()
        else:
            _check_second_factor(db, request, user, body.code)
    except HTTPException as exc:
        record_login(db, success=False, reason=("locked" if exc.status_code == 429
                                                else "mfa_failed"), **who)
        raise
    record_login(db, success=True, reason="ok", **who)
    return access_token(user, request.app.state.settings)


def _enrolling_user(request: Request, db: Session, mfa_token: str | None,
                    creds: HTTPAuthorizationCredentials | None) -> User:
    """Enrolment is for a signed-in user (bearer access token) or an admin at login who must
    enrol first (the "enrol" challenge)."""
    if mfa_token:
        return _challenge_user(request, db, mfa_token, "enrol")
    if creds is None or creds.scheme.lower() != "bearer":
        raise _UNAUTHORIZED
    user = user_from_token(creds.credentials, request, db)
    if user is None:
        raise _UNAUTHORIZED
    return user


@router.post("/mfa/enrol/start", response_model=MfaEnrolment)
def mfa_enrol_start(body: MfaEnrolStart, request: Request,
                    db: Annotated[Session, Depends(get_db)],
                    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]):
    """A new secret to scan. It only takes effect once a code from it is confirmed."""
    user = _enrolling_user(request, db, body.mfa_token, creds)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already on for this account")
    if not body.mfa_token:  # a signed-in user: prove it is still them
        attempt = _CodeAttempt(request, user)  # a wrong password counts as a wrong code
        if not body.password or not security.verify_password(body.password, user.password_hash):
            raise HTTPException(_SIGNED_IN_REFUSAL, _LOGIN_FAILED)
        attempt.succeeded()
    settings = request.app.state.settings
    secret = mfa.new_secret()
    user.totp_pending = _keys(request).encrypt(secret, user.id)
    db.commit()
    uri = mfa.otpauth_uri(secret, user.username, settings.mfa_issuer)
    return MfaEnrolment(secret=secret, otpauth_uri=uri, qr_svg=mfa.qr_svg(uri),
                        issuer=settings.mfa_issuer)


@router.post("/mfa/enrol/confirm", response_model=MfaEnabled)
def mfa_enrol_confirm(body: MfaEnrolConfirm, request: Request,
                      db: Annotated[Session, Depends(get_db)],
                      creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]):
    """Turn MFA on with a code from the new secret. Logs out every other session and returns a
    fresh access token and the recovery codes (shown once)."""
    user = _enrolling_user(request, db, body.mfa_token, creds)
    if len(body.code.strip()) < 6:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "enter the 6-digit code")
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already on for this account")
    if not user.totp_pending:
        raise HTTPException(status.HTTP_409_CONFLICT, "start the enrolment first")
    attempt = _CodeAttempt(request, user)
    keys = _keys(request)
    try:
        secret = keys.decrypt(user.totp_pending, user.id)
    except mfa.MfaError:
        raise HTTPException(status.HTTP_409_CONFLICT, "start the enrolment again") from None
    step = mfa.matching_step(secret, body.code, None)
    if step is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED if body.mfa_token else _SIGNED_IN_REFUSAL,
                            _BAD_CODE)
    attempt.succeeded()
    codes = mfa.new_recovery_codes()
    # Atomic: of two confirms at once (or a confirm racing a new start), only one wins, so the
    # recovery codes shown are always the ones stored.
    done = db.execute(
        update(User).where(User.id == user.id, User.mfa_enabled.is_(False),
                           User.totp_pending == user.totp_pending,
                           User.token_version == user.token_version)
        .values(totp_secret=user.totp_pending, totp_pending=None, totp_last_step=step,
                recovery_codes=[keys.recovery_hash(c) for c in codes], mfa_enabled=True,
                token_version=user.token_version + 1)
        .execution_options(synchronize_session=False))
    if done.rowcount != 1:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "the enrolment changed; start it again")
    audit(db, user, "mfa_enable", f"user:{user.username}")
    db.commit()
    db.refresh(user)
    token = access_token(user, request.app.state.settings)
    if body.mfa_token:  # an admin's first sign-in: the enrolment completed it
        record_login(db, username=user.username, user_id=user.id, success=True, reason="ok",
                     ip=client_ip(request), user_agent=request.headers.get("user-agent"),
                     mfa_used=True)
    return MfaEnabled(**token.model_dump(), recovery_codes=codes)


@router.post("/mfa/disable", response_model=TokenResponse)
def mfa_disable(body: MfaDisable, user: AnyUser, request: Request,
                db: Annotated[Session, Depends(get_db)]):
    """Turn MFA off (password and a code needed). Not allowed where MFA is required."""
    settings = request.app.state.settings
    if mfa_required(user, settings):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA is required for admins")
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not on for this account")
    attempt = _CodeAttempt(request, user)  # a wrong password counts as a wrong code here
    if not security.verify_password(body.password, user.password_hash):
        raise HTTPException(_SIGNED_IN_REFUSAL, _LOGIN_FAILED)
    _check_second_factor(db, request, user, body.code, attempt, bad_status=_SIGNED_IN_REFUSAL)
    clear_mfa(user)
    audit(db, user, "mfa_disable", f"user:{user.username}")
    db.commit()
    return access_token(user, settings)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodes)
def mfa_new_recovery_codes(body: MfaRecoveryRegenerate, user: AnyUser, request: Request,
                           db: Annotated[Session, Depends(get_db)]):
    """Replace the recovery codes (a current app code needed). The old ones stop working."""
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not on for this account")
    attempt = _CodeAttempt(request, user)
    keys = _keys(request)
    if not _use_totp(db, keys, user, body.code):
        raise HTTPException(_SIGNED_IN_REFUSAL, _BAD_CODE)
    attempt.succeeded()
    codes = mfa.new_recovery_codes()
    user.recovery_codes = [keys.recovery_hash(c) for c in codes]
    audit(db, user, "mfa_recovery_codes_replaced", f"user:{user.username}")
    db.commit()
    return RecoveryCodes(recovery_codes=codes)


# --- helpers used by the CLI and the admin endpoints -------------------------------------

def create_user(db: Session, username: str, password: str, role: Role) -> User:
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise ValueError(f"user {username!r} already exists")
    user = User(username=username, password_hash=security.hash_password(password), role=role)
    db.add(user)
    db.commit()
    return user


def set_password(db: Session, user: User, password: str) -> None:
    user.password_hash = security.hash_password(password)
    user.token_version += 1  # log out every existing session
    db.commit()


def clear_mfa(user: User) -> None:
    """Remove the user's MFA (the caller commits). Logs out every session."""
    user.mfa_enabled = False
    user.totp_secret = user.totp_pending = None
    user.totp_last_step = None
    user.recovery_codes = None
    user.mfa_email = user.email_code_hash = user.email_sent_at = None
    user.token_version += 1


def set_disabled(db: Session, user: User, disabled: bool) -> None:
    user.disabled = disabled
    user.token_version += 1
    db.commit()


def create_sensor_token(db: Session, name: str) -> str:
    """Create a sensor and return its token. The token is shown once and never stored."""
    token = security.generate_sensor_token()
    db.add(SensorToken(name=name, token_hash=security.hash_sensor_token(token)))
    db.commit()
    return token
