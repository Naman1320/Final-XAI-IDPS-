"""First-start setup of the lab SOC: the admin user, the sensor token and its certificate.

Run by lab/soc/start.sh with the SOC settings in the environment. Idempotent:
- the admin `LAB_SOC_ADMIN_USER` (default "admin") is created once, with LAB_SOC_ADMIN_PASSWORD;
- a sensor token is created when the shared token file is missing, empty, or holds a token this
  database doesn't know (or has revoked), e.g. after the SOC's data volume was recreated. It is
  written there (0600, via a temporary file) for the sensor container, which mounts the same
  volume read-only. The SOC keeps only its hash.
- the sensor's client certificate for mutual TLS (soc/api/serve.py): common name = the sensor's
  name, signed by a sensor CA made for the purpose whose private key is deleted right after
  (a new CA each time). Re-issued when missing, for another sensor name, or within 30 days of
  expiry. sensor-ca.pem stays in the SOC's data volume (the SOC trusts it for client
  certificates); sensor.pem (0644) and sensor.key (0600) go to the shared volume. The SOC
  container makes the sensor's key: acceptable in the lab (it makes the token the same way); in a
  real deployment the sensor makes its key and only a CSR leaves it (docs/soc.md).
"""

from __future__ import annotations

import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from soc.api import auth
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.models import Role, SensorToken, User
from soc.api.security import PasswordPolicyError, hash_sensor_token
from soc.api.settings import get_settings


def _token_is_valid(db, token_file: str) -> bool:
    try:
        with open(token_file) as fh:
            token = fh.read().strip()
    except FileNotFoundError:
        return False
    if not token:
        return False
    row = db.scalar(select(SensorToken).where(SensorToken.token_hash == hash_sensor_token(token)))
    return row is not None and not row.revoked


def _current_sensor_name(db, token_file: str) -> str | None:
    with open(token_file) as fh:
        token = fh.read().strip()
    row = db.scalar(select(SensorToken).where(SensorToken.token_hash == hash_sensor_token(token)))
    return row.name if row is not None else None


def _cert_ok(cert_file: Path, ca_file: Path, name: str) -> bool:
    from cryptography import x509

    from soc.api import pki

    try:
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        ca = x509.load_pem_x509_certificate(ca_file.read_bytes())
    except (OSError, ValueError):
        return False
    return (pki.common_name(cert) == name and cert.issuer == ca.subject
            and cert.not_valid_after_utc - datetime.now(UTC) > timedelta(days=30))


def ensure_sensor_cert(shared: Path, data: Path, name: str) -> bool:
    """Issue the sensor certificate if needed. Returns True when a new one was made."""
    from soc.api import pki

    cert_file, key_file, ca_file = shared / "sensor.pem", shared / "sensor.key", data / "sensor-ca.pem"
    if key_file.exists() and _cert_ok(cert_file, ca_file, name):
        return False
    ca_key, ca = pki.make_ca("IDPS lab sensor CA", days=400)
    key, cert = pki.issue_client_cert(ca_key, ca, name, days=365)
    del ca_key  # never written anywhere: nothing else can be signed with this CA
    pki.write_public(ca_file, pki.cert_pem(ca))
    pki.write_private(key_file, pki.key_pem(key))
    pki.write_public(cert_file, pki.cert_pem(cert))
    return True


def main(token_file: str) -> int:
    user = os.environ.get("LAB_SOC_ADMIN_USER", "admin")
    password = os.environ.get("LAB_SOC_ADMIN_PASSWORD", "")
    engine = make_engine(get_settings().database_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        if db.scalar(select(User).where(User.username == user)) is None:
            try:
                auth.create_user(db, user, password, Role.ADMIN)
            except (ValueError, PasswordPolicyError) as exc:
                print(f"soc: cannot create the admin user: {exc}", file=sys.stderr)
                return 1
            print(f"soc: created admin user {user!r}")
        if not _token_is_valid(db, token_file):
            # A new name each time, so a replaced token never collides with an old sensor.
            name = f"lab-sensor-{int(time.time())}"
            token = auth.create_sensor_token(db, name)
            tmp = f"{token_file}.tmp"
            if os.path.exists(tmp):
                os.unlink(tmp)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(token)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, token_file)
            print(f"soc: created sensor {name!r}; its token is in {token_file}")
        name = _current_sensor_name(db, token_file)
    if name and ensure_sensor_cert(Path(token_file).parent, Path(os.environ.get(
            "IDPS_SOC_DATA", "/var/lib/idps-soc")), name):
        print(f"soc: issued the client certificate for sensor {name!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
