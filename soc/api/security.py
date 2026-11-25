"""Password hashing, login tokens, sensor tokens and login throttling."""

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

ALGORITHM = "HS256"
ISSUER = AUDIENCE = "idps-soc"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256  # bounds hashing cost for absurd inputs

_hasher = PasswordHasher()  # argon2id with the library's current recommended parameters
# Verified against when the username doesn't exist, so a login for an unknown user
# takes as long as one for a real user (no username discovery by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


class PasswordPolicyError(ValueError):
    pass


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")


def hash_password(password: str) -> str:
    check_password_policy(password)
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-effort check; pass None for an unknown user."""
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# --- login tokens (JWT) -----------------------------------------------------------------

class TokenError(Exception):
    pass


def create_access_token(*, user_id: int, account_created: str, token_version: int, secret: str,
                        minutes: int) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id), "account_created": account_created,
        "ver": token_version,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=minutes),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, *, secret: str) -> dict:
    """Return the claims, or raise TokenError. Only HS256 is accepted (no 'none', no RS/HS mixups).

    The role is NOT taken from the token: callers load the user and use its current role,
    so a demoted or disabled user loses access immediately.
    """
    try:
        claims = jwt.decode(
            token, secret, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER,
            options={"require": ["sub", "account_created", "ver", "exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if not str(claims["sub"]).isdigit() or not isinstance(claims["ver"], int):
        raise TokenError("malformed claims")
    return claims


# --- MFA challenge tokens ---------------------------------------------------------------
# After a correct password (or a single sign-on), a user who has MFA, or an admin who must enrol,
# gets one of these instead of an access token. A different audience, so it can never be used as
# an access token; it names what it is for ("verify" or "enrol") and the user's token_version.

CHALLENGE_AUDIENCE = "idps-soc-mfa"
CHALLENGE_PURPOSES = ("verify", "enrol")


def create_challenge_token(*, user_id: int, account_created: str, token_version: int, purpose: str,
                           secret: str, minutes: int) -> str:
    if purpose not in CHALLENGE_PURPOSES:
        raise ValueError(f"unknown challenge purpose {purpose!r}")
    now = datetime.now(UTC)
    claims = {"sub": str(user_id), "account_created": account_created, "ver": token_version,
              "purpose": purpose, "iat": now,
              "nbf": now, "exp": now + timedelta(minutes=minutes), "iss": ISSUER,
              "aud": CHALLENGE_AUDIENCE, "jti": uuid.uuid4().hex}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_challenge_token(token: str, *, secret: str, purpose: str) -> dict:
    try:
        claims = jwt.decode(
            token, secret, algorithms=[ALGORITHM], audience=CHALLENGE_AUDIENCE, issuer=ISSUER,
            options={"require": ["sub", "account_created", "ver", "purpose", "exp", "iat", "iss", "aud"]})
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if (not str(claims["sub"]).isdigit() or not isinstance(claims["ver"], int)
            or claims["purpose"] != purpose):
        raise TokenError("malformed or wrong-purpose challenge")
    return claims


# --- sensor API tokens ------------------------------------------------------------------

SENSOR_TOKEN_PREFIX = "idps_sensor_"


def generate_sensor_token() -> str:
    return SENSOR_TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_sensor_token(token: str) -> str:
    # Sensor tokens are long random strings, so a plain SHA-256 is enough (no slow hash needed).
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# --- login throttling -------------------------------------------------------------------

class LoginThrottle:
    """Counts failed logins per (username, client IP) and per client IP, in memory.

    After too many failures in the lockout window, further attempts are refused until the
    window passes, even with the right password. In-memory only: it resets on restart and
    isn't shared between API processes (documented in docs/soc.md).
    """

    def __init__(self, max_failures: int, max_failures_per_ip: int, lockout_seconds: int,
                 clock=time.monotonic, max_keys: int = 100_000):
        self.max_failures = max_failures
        self.max_failures_per_ip = max_failures_per_ip
        self.window = lockout_seconds
        self.clock = clock
        self.max_keys = max_keys
        self._fails: dict[tuple, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: tuple, now: float) -> list[float]:
        times = [t for t in self._fails.get(key, []) if now - t < self.window]
        if times:
            self._fails[key] = times
        else:
            self._fails.pop(key, None)
        return times

    def is_locked(self, username: str, ip: str) -> bool:
        now = self.clock()
        with self._lock:
            return (len(self._recent(("user", username.lower(), ip), now)) >= self.max_failures
                    or len(self._recent(("ip", ip), now)) >= self.max_failures_per_ip)

    def record_failure(self, username: str, ip: str) -> None:
        now = self.clock()
        with self._lock:
            if len(self._fails) >= self.max_keys:  # bound memory under a spray of usernames
                for key in list(self._fails)[: self.max_keys // 10]:
                    del self._fails[key]
            for key in (("user", username.lower(), ip), ("ip", ip)):
                self._fails.setdefault(key, []).append(now)

    def record_success(self, username: str, ip: str) -> None:
        with self._lock:
            self._fails.pop(("user", username.lower(), ip), None)

    def begin_attempt(self, username: str, ip: str) -> float | None:
        """Atomically check the lockout and count this attempt as a failure up front.

        Returns a ticket, or None when locked out. Counting before the (slow) password check
        means many parallel requests can't all slip past the limit. Call `succeeded` with
        the ticket when the password was right, to take the attempt back.
        """
        now = self.clock()
        with self._lock:
            if (len(self._recent(("user", username.lower(), ip), now)) >= self.max_failures
                    or len(self._recent(("ip", ip), now)) >= self.max_failures_per_ip):
                return None
            if len(self._fails) >= self.max_keys:
                for key in list(self._fails)[: self.max_keys // 10]:
                    del self._fails[key]
            for key in (("user", username.lower(), ip), ("ip", ip)):
                self._fails.setdefault(key, []).append(now)
            return now

    def succeeded(self, username: str, ip: str, ticket: float) -> None:
        """Undo a `begin_attempt` whose password was correct, and clear this user's failures."""
        with self._lock:
            self._fails.pop(("user", username.lower(), ip), None)
            times = self._fails.get(("ip", ip))
            if times and ticket in times:
                times.remove(ticket)
