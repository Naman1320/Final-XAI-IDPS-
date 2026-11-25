"""Signed model bundles (Ed25519), checked by the sensor before it unpickles a model.

The sha256 file next to a bundle (bundle.py) catches accidents and careless tampering, but
whoever can write the bundle can write its sha256 too. A signature closes that gap: the private
key stays with whoever trains and approves models (never on a sensor), and a sensor given the
public key (IDPS_MODEL_PUBLIC_KEY) refuses any bundle without a valid `<bundle>.sig` from it.
Unpickling runs code, so this check happens on the exact bytes that are then loaded.

    python -m idps.detect keygen --out keys/model-signing          (writes .key 0600 and .pub)
    python -m idps.detect sign models/x.joblib --key keys/model-signing.key
    python -m idps.detect verify models/x.joblib --public-key keys/model-signing.pub

`<bundle>.sig` is JSON: what was signed (format, algorithm, key id, the bundle's sha256, when)
and the signature over exactly those fields. The key id is the first 16 hex digits of the
sha256 of the raw public key, so a signature from another key is reported as such.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_FORMAT = 1
ALGORITHM = "ed25519"
_DOMAIN = b"idps-model-signature-v1\n"
MAX_SIG_BYTES = 4096


class SignatureError(ValueError):
    """The bundle's signature is missing, from another key, or does not match."""


def sig_path(bundle_path: str | Path) -> Path:
    return Path(f"{bundle_path}.sig")


# --- keys --------------------------------------------------------------------------------------

def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair(out: str | Path) -> tuple[Path, Path]:
    """Write `<out>.key` (private, PKCS8 PEM, 0600) and `<out>.pub` (public PEM). Refuses to
    replace an existing key."""
    out = Path(out)
    priv_path, pub_path = Path(f"{out}.key"), Path(f"{out}.pub")
    for p in (priv_path, pub_path):
        if p.exists():
            raise FileExistsError(f"{p} exists; refusing to replace a signing key")
    out.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(pub_path, 0o644)
    return priv_path, pub_path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    path = Path(path)
    if path.stat().st_mode & 0o077:
        raise ValueError(f"{path} is readable by others; refusing to use it (chmod 600 {path})")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise SignatureError(f"cannot load the model public key {path}: {exc}") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError(f"{path} is not an Ed25519 public key")
    return key


# --- signing and checking ----------------------------------------------------------------------

def _message(fields: dict) -> bytes:
    return _DOMAIN + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign_bytes(data: bytes, key: Ed25519PrivateKey, now: datetime | None = None) -> dict:
    fields = {"format": SIGNATURE_FORMAT, "algorithm": ALGORITHM,
              "key_id": key_id(key.public_key()), "sha256": hashlib.sha256(data).hexdigest(),
              "signed_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return fields | {"signature": base64.b64encode(key.sign(_message(fields))).decode()}


def sign_bundle(bundle_path: str | Path, key: Ed25519PrivateKey) -> Path:
    """Sign the bundle's current bytes; writes `<bundle>.sig` (not group- or world-writable)."""
    data = Path(bundle_path).read_bytes()
    out = sig_path(bundle_path)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(sign_bytes(data, key), indent=1) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)
    return out


def verify_bytes(data: bytes, signature: dict, public_key: Ed25519PublicKey) -> dict:
    """Check `signature` (the parsed .sig) is a valid signature of `data` by `public_key`.
    Returns the signed fields; raises SignatureError otherwise."""
    if not isinstance(signature, dict):
        raise SignatureError("the signature file is not a JSON object")
    fields = {k: signature.get(k) for k in ("format", "algorithm", "key_id", "sha256",
                                            "signed_at")}
    if fields["format"] != SIGNATURE_FORMAT or fields["algorithm"] != ALGORITHM:
        raise SignatureError("unsupported signature format or algorithm")
    expected_id = key_id(public_key)
    if fields["key_id"] != expected_id:
        raise SignatureError(f"signed with another key ({str(fields['key_id'])[:16]!r}, "
                             f"expected {expected_id})")
    try:
        raw = base64.b64decode(str(signature.get("signature", "")), validate=True)
        public_key.verify(raw, _message(fields))
    except (InvalidSignature, ValueError):
        raise SignatureError("the signature is not valid") from None
    if fields["sha256"] != hashlib.sha256(data).hexdigest():
        raise SignatureError("the model file was changed after it was signed")
    return fields


def read_signature(bundle_path: str | Path) -> dict:
    path = sig_path(bundle_path)
    try:
        if path.stat().st_mode & 0o022:
            raise SignatureError(f"{path} is group- or world-writable; refusing it "
                                 f"(chmod go-w {path})")
        raw = path.read_bytes()
    except FileNotFoundError:
        raise SignatureError(f"{path} is missing: the model is not signed") from None
    if len(raw) > MAX_SIG_BYTES:
        raise SignatureError(f"{path} is too large to be a signature")
    try:
        return json.loads(raw)
    except ValueError:
        raise SignatureError(f"{path} is not valid JSON") from None
