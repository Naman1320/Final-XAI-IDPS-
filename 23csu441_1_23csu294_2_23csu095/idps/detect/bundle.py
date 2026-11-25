"""One-file model bundle (joblib): model + label encoder + exact feature list + the training
data's extraction metadata + split description + metrics + library versions.

SECURITY: joblib files are pickles, and unpickling runs code. save_bundle() therefore also
writes `<bundle>.sha256`, and load_bundle() refuses (before unpickling anything) a bundle whose
digest file is missing or does not match, or that is group- or world-writable. This catches
tampering and accidents, not an attacker who can write both files: only load bundles you
created yourself.
"""

import hashlib
import hmac
import io
import os
import platform
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost
from sklearn.preprocessing import LabelEncoder

from idps.config import Settings
from idps.detect.models import anomaly_flags, anomaly_scores, predict_labels
from idps.features import FEATURE_COLUMNS, check_same_extraction

BUNDLE_FORMAT = 1
DEFAULT_MODEL_PATH = Settings.model_fields["model_path"].default  # "models/model.joblib"


def library_versions() -> dict:
    return {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__, "numpy": np.__version__,
            "pandas": pd.__version__, "joblib": joblib.__version__}


@dataclass
class Bundle:
    model_name: str
    model: object
    label_encoder: LabelEncoder
    features: list[str]
    extraction_meta: dict
    split: dict
    metrics: dict
    anomaly: object | None = None
    versions: dict = field(default_factory=library_versions)
    format: int = BUNDLE_FORMAT
    # `<model>-<UTC yyyymmddHHMM>-<sha8 of the training rows>`; None in bundles saved before
    # versions existed (those report model_version() instead). Old pickles lack the attribute,
    # so reading it falls back to this class default.
    version: str | None = None

    def select(self, df: pd.DataFrame, meta: dict) -> pd.DataFrame:
        """Return df[features] after refusing mismatched extraction metadata or columns."""
        if not meta:
            raise ValueError("feature data has no extraction metadata; refusing to use it")
        check_same_extraction(self.extraction_meta, meta)
        missing = [c for c in self.features if c not in df.columns]
        if missing:
            raise ValueError(f"data is missing model feature column(s): {missing}")
        return df[self.features]

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return predict_labels(self.model, self.label_encoder, X[self.features])

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Columns follow label_encoder.classes_."""
        return self.model.predict_proba(X[self.features])

    def anomaly_scores(self, X: pd.DataFrame) -> np.ndarray:
        if self.anomaly is None:
            raise ValueError("bundle has no anomaly detector")
        return anomaly_scores(self.anomaly, X[self.features])

    def anomaly_flags(self, X: pd.DataFrame) -> np.ndarray:
        if self.anomaly is None:
            raise ValueError("bundle has no anomaly detector")
        return anomaly_flags(self.anomaly, X[self.features])


def make_version(model_name: str, train_rows: pd.DataFrame, features: list[str],
                 now: datetime | None = None) -> str:
    """`<model>-<UTC yyyymmddHHMM>-<first 8 hex of a hash of the training rows>`."""
    cols = [*features, "label"]
    h = hashlib.sha256(pd.util.hash_pandas_object(
        train_rows[cols].reset_index(drop=True), index=False).to_numpy().tobytes()).hexdigest()
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d%H%M")
    return f"{model_name}-{stamp}-{h[:8]}"


def model_version(bundle: Bundle, sha256: str | None = None) -> str:
    """The bundle's version; for a bundle without one, `<model_name>-<sha256[:8]>` (or
    `<model_name>-unversioned` when the digest is not known either)."""
    version = getattr(bundle, "version", None)
    if version:
        return str(version)
    return f"{bundle.model_name}-{sha256[:8] if sha256 else 'unversioned'}"


def digest_path(path: str | Path) -> Path:
    return Path(f"{path}.sha256")


def _not_group_world_writable(path: Path) -> None:
    os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~(stat.S_IWGRP | stat.S_IWOTH))


def save_bundle(bundle: Bundle, path: str | Path = DEFAULT_MODEL_PATH) -> Path:
    """Write the bundle and `<path>.sha256` (sha256sum format); neither is left group- or
    world-writable."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    digest_path(path).write_text(f"{digest}  {path.name}\n")
    _not_group_world_writable(path)
    _not_group_world_writable(digest_path(path))
    return path


def read_digest(path: str | Path) -> str:
    """The sha256 (hex) in `<path>.sha256`. After load_bundle(path) succeeded this IS the digest of
    the loaded bytes, because load_bundle refuses a bundle that does not match it."""
    parts = digest_path(path).read_text().split()
    if not parts:
        raise ValueError(f"{digest_path(path)} is empty")
    return parts[0].lower()


def _read_verified(path: Path, public_key=None) -> bytes:
    """The bundle's bytes, after checking permissions and the sha256 file, and (when
    `public_key` is given: an Ed25519 public key, or a path to one) its `<bundle>.sig`
    signature (idps.detect.signing). The same bytes are unpickled, so the file cannot change
    between the checks and the load."""
    for p in (path, digest_path(path)):
        if p.exists() and p.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"{p} is group- or world-writable; refusing to load it "
                             f"(fix with: chmod go-w {p})")
    sha_file = digest_path(path)
    if not sha_file.exists():
        raise ValueError(f"{sha_file} is missing; refusing to unpickle {path} without a digest "
                         "(models saved by save_bundle() have one)")
    parts = sha_file.read_text().split()
    expected = parts[0].lower() if parts else ""
    data = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
        raise ValueError(f"{path} does not match {sha_file}; the model file was changed or "
                         "corrupted, refusing to load it")
    if public_key is not None:
        from idps.detect import signing

        if not hasattr(public_key, "verify"):
            public_key = signing.load_public_key(public_key)
        try:
            signing.verify_bytes(data, signing.read_signature(path), public_key)
        except signing.SignatureError as exc:
            raise ValueError(f"refusing to load {path}: {exc}") from None
    return data


def load_bundle(path: str | Path = DEFAULT_MODEL_PATH, live_meta: dict | None = None,
                live_columns: list[str] | None = None, *,
                trust_unverified: bool = False, public_key=None) -> Bundle:
    """Load a bundle. Pass `live_meta` (extraction metadata of the data you will feed it) to
    refuse a mismatch immediately; `live_columns` likewise checks the model's features exist.
    Also refuses a bundle whose feature_columns layout differs from this code.

    Before unpickling, the sha256 file and the file permissions are checked (see the module
    docstring), and with `public_key` the bundle's signature too: an unsigned bundle, or one
    signed by another key or changed since, is refused before anything is unpickled.
    `trust_unverified=True` skips all of that; it exists for tests only (and cannot be combined
    with a public key)."""
    path = Path(path)
    if trust_unverified and public_key is not None:
        raise ValueError("trust_unverified cannot be combined with a public key")
    bundle = (joblib.load(path) if trust_unverified
              else joblib.load(io.BytesIO(_read_verified(path, public_key))))
    if not isinstance(bundle, Bundle):
        raise TypeError(f"{path} is not an IDPS model bundle")
    if bundle.format != BUNDLE_FORMAT:
        raise ValueError(f"unsupported bundle format {bundle.format} (expected {BUNDLE_FORMAT})")
    if bundle.extraction_meta.get("feature_columns") != FEATURE_COLUMNS:
        raise ValueError("bundle was trained with a different FEATURE_COLUMNS layout than this "
                         "code; retrain the model")
    if live_meta is not None:
        check_same_extraction(bundle.extraction_meta, live_meta)
    if live_columns is not None:
        missing = [c for c in bundle.features if c not in live_columns]
        if missing:
            raise ValueError(f"live data is missing model feature column(s): {missing}")
    return bundle
