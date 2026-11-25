"""Signed model bundles: keys, signatures, load_bundle(public_key=...), the CLI and the sensor."""

import base64
import hashlib
import json
import os
import shutil
import stat
from datetime import UTC, datetime

import numpy as np
import pandas as pd
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from idps.detect import signing
from idps.detect.__main__ import main
from idps.detect.bundle import Bundle, digest_path, load_bundle, save_bundle
from idps.features import MODEL_FEATURES, extraction_meta

META = extraction_meta("scapy", 60, 120)


def _tiny_bundle() -> Bundle:
    rng = np.random.default_rng(0)
    rows, labels = [], []
    for label, ports in (("BENIGN", (53, 443)), ("DDoS", (80,))):
        for _ in range(40):
            r = dict.fromkeys(MODEL_FEATURES, 0.0)
            r.update(dst_port=float(rng.choice(ports)), protocol=6.0,
                     fwd_packets=float(rng.integers(1, 60)))
            rows.append(r)
            labels.append(label)
    X, enc = pd.DataFrame(rows)[MODEL_FEATURES], LabelEncoder().fit(labels)
    model = XGBClassifier(n_estimators=5, max_depth=2, random_state=0)
    model.fit(X, enc.transform(labels))
    return Bundle("xgboost", model, enc, list(MODEL_FEATURES), META, {"mode": "test"}, {})


@pytest.fixture(scope="module")
def pristine(tmp_path_factory):
    return save_bundle(_tiny_bundle(), tmp_path_factory.mktemp("pristine") / "m.joblib")


@pytest.fixture
def model(pristine, tmp_path):
    """A fresh copy of the bundle (and its sha256 file) to damage."""
    d = tmp_path / "models"
    d.mkdir()
    out = d / "m.joblib"
    shutil.copy2(pristine, out)
    shutil.copy2(digest_path(pristine), digest_path(out))
    return out


@pytest.fixture
def keys(tmp_path):
    priv, pub = signing.generate_keypair(tmp_path / "keys" / "model-signing")
    return priv, pub


@pytest.fixture
def signed(model, keys):
    signing.sign_bundle(model, signing.load_private_key(keys[0]))
    return model


def rewrite_bundle(path, mutate):
    """Change the bundle's bytes and regenerate the .sha256 so it matches (the attacker's move)."""
    data = bytearray(path.read_bytes())
    mutate(data)
    path.write_bytes(bytes(data))
    digest_path(path).write_text(f"{hashlib.sha256(data).hexdigest()}  {path.name}\n")


def edit_sig(path, **changes):
    sig = signing.sig_path(path)
    body = json.loads(sig.read_text())
    body.update(changes)
    sig.write_text(json.dumps(body))
    os.chmod(sig, 0o644)


# --- keys --------------------------------------------------------------------------------------

def test_keygen_writes_a_private_key_0600_and_a_public_key(keys):
    priv, pub = keys
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert not stat.S_IMODE(pub.stat().st_mode) & 0o022
    assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert b"PRIVATE" not in pub.read_bytes()
    assert (signing.key_id(signing.load_public_key(pub))
            == signing.key_id(signing.load_private_key(priv).public_key()))


def test_keygen_refuses_to_overwrite(tmp_path, keys):
    priv, pub = keys
    before = priv.read_bytes()
    with pytest.raises(FileExistsError):
        signing.generate_keypair(tmp_path / "keys" / "model-signing")
    assert priv.read_bytes() == before
    # also when only one of the two exists
    pub.unlink()
    with pytest.raises(FileExistsError):
        signing.generate_keypair(tmp_path / "keys" / "model-signing")
    assert not pub.exists() and priv.read_bytes() == before


def test_keygen_cli_and_overwrite_refusal(tmp_path, capsys):
    out = tmp_path / "k" / "sig"
    assert main(["keygen", "--out", str(out)]) == 0
    err = capsys.readouterr().err
    assert "key id" in err and "BEGIN" not in err
    assert stat.S_IMODE((tmp_path / "k" / "sig.key").stat().st_mode) == 0o600
    before = (tmp_path / "k" / "sig.key").read_bytes()
    assert main(["keygen", "--out", str(out)]) == 2
    assert "refusing" in capsys.readouterr().err
    assert (tmp_path / "k" / "sig.key").read_bytes() == before


def test_key_id_is_16_hex_and_differs_between_keys():
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    assert len(signing.key_id(a.public_key())) == 16
    assert signing.key_id(a.public_key()) != signing.key_id(b.public_key())


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o610])
def test_private_key_readable_by_others_is_refused(keys, mode):
    os.chmod(keys[0], mode)
    with pytest.raises(ValueError, match="readable by others"):
        signing.load_private_key(keys[0])


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_private_key_owner_only_loads(keys, mode):
    os.chmod(keys[0], mode)
    assert isinstance(signing.load_private_key(keys[0]), Ed25519PrivateKey)


def test_private_key_of_the_wrong_type_or_garbage_is_refused(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p = tmp_path / "rsa.key"
    p.write_bytes(rsa_key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    os.chmod(p, 0o600)
    with pytest.raises(ValueError, match="not an Ed25519"):
        signing.load_private_key(p)
    g = tmp_path / "garbage.key"
    g.write_text("not a key")
    os.chmod(g, 0o600)
    with pytest.raises(ValueError):
        signing.load_private_key(g)


def test_public_key_problems_are_signature_errors(tmp_path):
    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    p = tmp_path / "rsa.pub"
    p.write_bytes(rsa_pub.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(signing.SignatureError, match="not an Ed25519"):
        signing.load_public_key(p)
    (tmp_path / "junk.pub").write_text("junk")
    with pytest.raises(signing.SignatureError):
        signing.load_public_key(tmp_path / "junk.pub")
    with pytest.raises(signing.SignatureError):
        signing.load_public_key(tmp_path / "missing.pub")


# --- signing bytes -----------------------------------------------------------------------------

def test_sign_and_verify_bytes():
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 5, 6, 7, 8, 9, 999999, tzinfo=UTC)
    sig = signing.sign_bytes(b"model bytes", key, now)
    assert sig["signed_at"] == "2026-05-06T07:08:09Z"
    assert sig["sha256"] == hashlib.sha256(b"model bytes").hexdigest()
    assert (sig["format"], sig["algorithm"]) == (1, "ed25519")
    fields = signing.verify_bytes(b"model bytes", sig, key.public_key())
    assert fields["key_id"] == signing.key_id(key.public_key())
    with pytest.raises(signing.SignatureError, match="changed after"):
        signing.verify_bytes(b"model byteS", sig, key.public_key())


def test_verify_bytes_refuses_other_keys_and_odd_inputs():
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    sig = signing.sign_bytes(b"x", key)
    with pytest.raises(signing.SignatureError, match="another key"):
        signing.verify_bytes(b"x", sig, other.public_key())
    for bad in ([], "str", None, 5):
        with pytest.raises(signing.SignatureError, match="not a JSON object"):
            signing.verify_bytes(b"x", bad, key.public_key())
    with pytest.raises(signing.SignatureError, match="unsupported"):
        signing.verify_bytes(b"x", sig | {"format": 2}, key.public_key())
    with pytest.raises(signing.SignatureError, match="unsupported"):
        signing.verify_bytes(b"x", sig | {"algorithm": "rsa"}, key.public_key())


def test_a_signature_for_another_purpose_does_not_verify():
    # The domain prefix: a raw Ed25519 signature over the same JSON fields without it is refused.
    key = Ed25519PrivateKey.generate()
    sig = signing.sign_bytes(b"x", key)
    fields = {k: sig[k] for k in ("format", "algorithm", "key_id", "sha256", "signed_at")}
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    forged = sig | {"signature": base64.b64encode(key.sign(raw)).decode()}
    with pytest.raises(signing.SignatureError, match="not valid"):
        signing.verify_bytes(b"x", forged, key.public_key())


# --- load_bundle with a public key -------------------------------------------------------------

def test_sign_then_load_with_a_path_and_with_a_key_object(signed, keys):
    assert isinstance(load_bundle(signed, public_key=keys[1]), Bundle)
    assert isinstance(load_bundle(signed, public_key=str(keys[1])), Bundle)
    assert isinstance(load_bundle(signed, public_key=signing.load_public_key(keys[1])), Bundle)
    sig = signing.sig_path(signed)
    assert not stat.S_IMODE(sig.stat().st_mode) & 0o022
    assert not list(sig.parent.glob("*.tmp"))
    body = json.loads(sig.read_text())
    assert set(body) == {"format", "algorithm", "key_id", "sha256", "signed_at", "signature"}


def test_resigning_replaces_the_signature(signed, keys):
    again = signing.sign_bundle(signed, signing.load_private_key(keys[0]))
    assert again == signing.sig_path(signed)
    load_bundle(signed, public_key=keys[1])


def test_unsigned_bundle_is_refused_when_a_key_is_given(model, keys):
    with pytest.raises(ValueError, match="not signed"):
        load_bundle(model, public_key=keys[1])
    assert isinstance(load_bundle(model), Bundle)  # no key: only the sha256 is checked


def test_signature_by_another_key_is_refused_and_says_so(signed, tmp_path):
    _, other_pub = signing.generate_keypair(tmp_path / "other")
    with pytest.raises(ValueError, match="another key"):
        load_bundle(signed, public_key=other_pub)


def test_one_changed_byte_is_refused_even_with_the_sha256_regenerated(signed, keys):
    def flip(data):
        data[len(data) // 2] ^= 0x01

    rewrite_bundle(signed, flip)
    with pytest.raises(ValueError, match="changed after it was signed"):
        load_bundle(signed, public_key=keys[1])


def test_appended_byte_is_refused(signed, keys):
    rewrite_bundle(signed, lambda d: d.append(0))
    with pytest.raises(ValueError, match="changed after it was signed"):
        load_bundle(signed, public_key=keys[1])


def test_a_stale_sha256_file_is_still_refused_without_a_key(signed):
    signed.write_bytes(signed.read_bytes() + b"x")
    with pytest.raises(ValueError, match="does not match"):
        load_bundle(signed)


@pytest.mark.parametrize("change", [
    {"signed_at": "2030-01-01T00:00:00Z"},
    {"sha256": "0" * 64},
    {"signature": "!!!not base64!!!"},
    {"signature": "QUJD"},  # valid base64, wrong signature
    {"signature": ""},
    {"signature": 123},
    {"signature": None},
    {"format": 2},
    {"algorithm": "rsa"},
])
def test_an_edited_signature_file_is_refused(signed, keys, change):
    edit_sig(signed, **change)
    with pytest.raises(ValueError, match="refusing to load"):
        load_bundle(signed, public_key=keys[1])


def test_edited_sha256_that_matches_a_tampered_bundle_is_still_refused(signed, keys):
    rewrite_bundle(signed, lambda d: d.append(0))
    edit_sig(signed, sha256=hashlib.sha256(signed.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="not valid"):
        load_bundle(signed, public_key=keys[1])


def test_missing_signature_field_is_refused(signed, keys):
    sig = signing.sig_path(signed)
    body = json.loads(sig.read_text())
    del body["signature"]
    sig.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="not valid"):
        load_bundle(signed, public_key=keys[1])


@pytest.mark.parametrize("text,msg", [("not json", "not valid JSON"), ("[]", "not a JSON object"),
                                      ("\"str\"", "not a JSON object"), ("null", "not a JSON object"),
                                      ("", "not valid JSON")])
def test_garbage_signature_files_are_refused(signed, keys, text, msg):
    signing.sig_path(signed).write_text(text)
    with pytest.raises(ValueError, match=msg):
        load_bundle(signed, public_key=keys[1])


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666, 0o620])
def test_group_or_world_writable_signature_is_refused(signed, keys, mode):
    os.chmod(signing.sig_path(signed), mode)
    with pytest.raises(ValueError, match="writable"):
        load_bundle(signed, public_key=keys[1])


def test_oversized_signature_is_refused(signed, keys):
    sig = signing.sig_path(signed)
    sig.write_text(json.dumps({"pad": "x" * signing.MAX_SIG_BYTES}))
    os.chmod(sig, 0o644)
    with pytest.raises(ValueError, match="too large"):
        load_bundle(signed, public_key=keys[1])


def test_a_signature_that_is_a_directory_or_unreadable_is_an_error_not_a_pass(signed, keys):
    sig = signing.sig_path(signed)
    sig.unlink()
    sig.mkdir()
    with pytest.raises(OSError):
        load_bundle(signed, public_key=keys[1])


def test_group_writable_bundle_is_still_refused_with_a_key(signed, keys):
    os.chmod(signed, 0o664)
    with pytest.raises(ValueError, match="writable"):
        load_bundle(signed, public_key=keys[1])


def test_bad_public_key_path_refuses_to_load(signed, tmp_path):
    with pytest.raises(signing.SignatureError):
        load_bundle(signed, public_key=tmp_path / "nope.pub")


def test_trust_unverified_cannot_be_combined_with_a_public_key(signed, keys):
    with pytest.raises(ValueError, match="trust_unverified"):
        load_bundle(signed, trust_unverified=True, public_key=keys[1])
    assert isinstance(load_bundle(signed, trust_unverified=True), Bundle)


def test_nothing_is_unpickled_when_the_signature_is_bad(model, keys, tmp_path, monkeypatch):
    import joblib

    def boom(*a, **k):
        raise AssertionError("joblib.load must not run")

    monkeypatch.setattr(joblib, "load", boom)
    with pytest.raises(ValueError, match="not signed"):
        load_bundle(model, public_key=keys[1])


# --- CLI ---------------------------------------------------------------------------------------

def test_cli_sign_then_verify_exit_codes(model, keys, tmp_path, capsys):
    priv, pub = keys
    assert main(["verify", str(model), "--public-key", str(pub)]) == 1  # unsigned
    assert "not signed" in capsys.readouterr().err
    assert main(["sign", str(model), "--key", str(priv)]) == 0
    capsys.readouterr()
    assert main(["verify", str(model), "--public-key", str(pub)]) == 0
    err = capsys.readouterr().err
    assert err.startswith("OK: signed by key") and signing.key_id(
        signing.load_public_key(pub)) in err
    _, other = signing.generate_keypair(tmp_path / "other")
    assert main(["verify", str(model), "--public-key", str(other)]) == 1
    assert "another key" in capsys.readouterr().err
    rewrite_bundle(model, lambda d: d.append(1))
    assert main(["verify", str(model), "--public-key", str(pub)]) == 1
    assert "changed after" in capsys.readouterr().err


def test_cli_verify_with_bad_inputs(model, keys, tmp_path, capsys):
    assert main(["verify", str(model), "--public-key", str(tmp_path / "none.pub")]) == 1
    capsys.readouterr()
    assert main(["verify", str(tmp_path / "missing.joblib"), "--public-key", str(keys[1])]) == 2


def test_cli_sign_refuses_a_loose_key_and_a_damaged_bundle(model, keys, capsys):
    priv, _ = keys
    os.chmod(priv, 0o644)
    assert main(["sign", str(model), "--key", str(priv)]) == 2
    assert "readable by others" in capsys.readouterr().err
    assert not signing.sig_path(model).exists()
    os.chmod(priv, 0o600)
    model.write_bytes(model.read_bytes() + b"x")  # sha256 no longer matches
    assert main(["sign", str(model), "--key", str(priv)]) == 2
    assert not signing.sig_path(model).exists()


def test_cli_verify_does_not_unpickle(tmp_path, keys, capsys):
    import pickle

    marker = tmp_path / "pwned"

    class Evil:
        def __reduce__(self):
            return (os.mkdir, (str(marker),))

    evil = tmp_path / "evil.joblib"
    evil.write_bytes(pickle.dumps(Evil()))
    signing.sign_bundle(evil, signing.load_private_key(keys[0]))
    assert main(["verify", str(evil), "--public-key", str(keys[1])]) == 0
    assert not marker.exists()
    # and a file that is not a pickle at all verifies too
    junk = tmp_path / "junk.joblib"
    junk.write_bytes(b"\x00not a pickle\xff")
    signing.sign_bundle(junk, signing.load_private_key(keys[0]))
    assert main(["verify", str(junk), "--public-key", str(keys[1])]) == 0
    junk.write_bytes(b"\x00not a pickle\xfe")
    assert main(["verify", str(junk), "--public-key", str(keys[1])]) == 1


# --- the sensor --------------------------------------------------------------------------------

def test_live_settings_read_the_public_key_path(monkeypatch):
    from idps.live.config import LiveSettings

    for name in [n for n in os.environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)
    assert LiveSettings().model_public_key is None
    monkeypatch.setenv("IDPS_MODEL_PUBLIC_KEY", "keys/model-signing.pub")
    assert LiveSettings().model_public_key == "keys/model-signing.pub"
    monkeypatch.setenv("IDPS_MODEL_PUBLIC_KEY", "   ")
    assert LiveSettings().model_public_key is None  # blank means unset


def _status(bundle, **kw):
    from idps.config import Settings
    from idps.live.config import LiveSettings
    from idps.live.metrics import Metrics
    from idps.live.status import build_status
    from idps.respond.engine import ResponseEngine

    class NoBlocker:
        def ensure_ruleset(self):
            pass

        def block(self, *a, **k):
            pass

        def unblock(self, *a, **k):
            pass

    class ListSink:
        def pending(self):
            return 0

    engine = ResponseEngine(Settings(dry_run=True, allowlist=["10.10.1.1"]), blocker=NoBlocker())
    return build_status(engine=engine, bundle=bundle, live_settings=LiveSettings(),
                        metrics=Metrics(), sink=ListSink(), interface="eth1", **kw)


@pytest.fixture(scope="module")
def tiny():
    return _tiny_bundle()


def test_status_has_signed_by_only_when_given(tiny):
    assert "signed_by" not in _status(tiny)["model"]
    assert "signed_by" not in _status(tiny, signed_by=None)["model"]
    assert _status(tiny, signed_by="0123456789abcdef")["model"]["signed_by"] == "0123456789abcdef"
    # an older SOC (extended=False) is not sent anything new
    assert "signed_by" not in _status(tiny, extended=False, signed_by="0123456789abcdef")["model"]


def test_the_socs_status_schema_accepts_signed_by(tiny):
    from soc.api.routes.sensors import StatusReport

    with_key = json.loads(json.dumps(_status(tiny, signed_by="0123456789abcdef")))
    assert StatusReport.model_validate(with_key).model.signed_by == "0123456789abcdef"
    StatusReport.model_validate(json.loads(json.dumps(_status(tiny))))
    for bad in ("short", "0123456789ABCDEF", "x" * 16, "0123456789abcdef0"):
        bad_payload = json.loads(json.dumps(_status(tiny, signed_by=bad)))
        with pytest.raises(Exception):  # noqa: B017  pydantic ValidationError
            StatusReport.model_validate(bad_payload)
