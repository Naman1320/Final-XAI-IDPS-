"""Two-factor login with an authenticator app (TOTP, RFC 6238) and one-time recovery codes.

- Codes: 6 digits, 30-second steps, HMAC-SHA1 (what every authenticator app uses). A code from
  the step before or after is accepted too (clock skew), and never one at or before the last step
  already used, so a code seen over someone's shoulder cannot be replayed.
- The secret is stored encrypted (AES-256-GCM, the user id as associated data, so a ciphertext
  copied onto another user does not decrypt). The key is IDPS_SOC_MFA_KEY, or derived from the
  JWT secret when that is not set (then changing the JWT secret means everyone enrols again).
- Recovery codes: 10 random codes of 10 base32 characters (50 bits), shown once. Only an
  HMAC-SHA256 of each is stored (keyed, so a stolen database alone cannot be brute-forced
  offline); each works once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STEP_SECONDS = 30
DIGITS = 6
SKEW_STEPS = 1  # accept the step before and after
SECRET_BYTES = 20  # 160 bits, as RFC 4226 recommends
RECOVERY_CODES = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I
_CIPHER_PREFIX = "v1:"


class MfaError(ValueError):
    """A stored MFA value cannot be used (wrong key, corrupted)."""


# --- keys ------------------------------------------------------------------------------------

def _derive(master: str, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"idps-soc-mfa",
                info=info).derive(master.encode())


class MfaKeys:
    """The encryption key for secrets and the HMAC key for recovery codes, from one master."""

    def __init__(self, master: str) -> None:
        if len(master) < 32:
            raise ValueError("the MFA key must be at least 32 characters")
        self._aes = AESGCM(_derive(master, b"totp-secret-v1"))
        self._mac = _derive(master, b"recovery-code-v1")

    def encrypt(self, secret: str, user_id: int) -> str:
        nonce = secrets.token_bytes(12)
        ct = self._aes.encrypt(nonce, secret.encode(), _aad(user_id))
        return _CIPHER_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, value: str, user_id: int) -> str:
        if not value.startswith(_CIPHER_PREFIX):
            raise MfaError("unknown secret format")
        try:
            raw = base64.urlsafe_b64decode(value[len(_CIPHER_PREFIX):])
            return self._aes.decrypt(raw[:12], raw[12:], _aad(user_id)).decode()
        except (InvalidTag, ValueError) as exc:
            raise MfaError("the MFA secret cannot be decrypted (wrong IDPS_SOC_MFA_KEY?)") from exc

    def recovery_hash(self, code: str) -> str:
        return hmac.new(self._mac, normalise_recovery(code).encode(), hashlib.sha256).hexdigest()


def _aad(user_id: int) -> bytes:
    return f"idps-user:{user_id}".encode()


# --- TOTP ------------------------------------------------------------------------------------

def new_secret() -> str:
    """A base32 secret (no padding), as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def matching_step(secret: str, code: str, last_step: int | None,
                  now: float | None = None) -> int | None:
    """The step `code` is valid for (within the skew, after `last_step`), or None. Every
    candidate is compared in constant time, and all of them are always computed."""
    code = code.strip().replace(" ", "")
    # isascii too: str.isdigit() is true for other scripts' digits ("١٢٣٤٥٦"), which
    # hmac.compare_digest refuses with a TypeError.
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    step = current_step(now)
    found = None
    for candidate in range(step - SKEW_STEPS, step + SKEW_STEPS + 1):
        ok = hmac.compare_digest(code_at(secret, candidate), code)
        if ok and (last_step is None or candidate > last_step) and found is None:
            found = candidate
    return found


def otpauth_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}", safe="")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                       "digits": DIGITS, "period": STEP_SECONDS}, quote_via=quote)
    return f"otpauth://totp/{label}?{query}"


def qr_svg(uri: str) -> str:
    """The URI as a QR code (SVG text), drawn locally: the secret never goes to a QR service."""
    import segno

    out = io.BytesIO()
    segno.make(uri, error="m").save(out, kind="svg", scale=5, border=2, xmldecl=False,
                                    dark="#000", light="#fff")
    return out.getvalue().decode()


# --- recovery codes --------------------------------------------------------------------------

def normalise_recovery(code: str) -> str:
    return "".join(c for c in code.upper() if c.isalnum())


def looks_like_recovery(code: str) -> bool:
    c = normalise_recovery(code)
    return len(c) == 10 and all(ch in _RECOVERY_ALPHABET for ch in c)


def new_recovery_codes(n: int = RECOVERY_CODES) -> list[str]:
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes
