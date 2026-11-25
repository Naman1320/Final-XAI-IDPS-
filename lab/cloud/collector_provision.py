"""Make the cloud collector's credentials at the lab SOC (docs/cloud-plan.md step C4).

Run INSIDE the SOC container by lab/cloud/collector_provision.sh (the script is piped in on
standard input, so the SOC image does not need to be rebuilt):

    docker exec -i idps-soc python - --token-sha256 <hash> --have-key 1 < collector_provision.py | tar x ...

What it does (idempotent):
- a sensor token named NAME ("cloud"): created when the SOC has no usable one, or the token in
  the collector's volume is not the SOC's (hash compared; the old row is revoked and renamed).
  This is the LAST step, after the certificate and the CA file, so a failure leaves the SOC as it was;
- `--check`: a read-only check of the SOC's sensor CA file for start_collector.sh;
- a client certificate for NAME (mutual TLS, common name = the sensor's name) signed by a CA made
  for it ("IDPS lab cloud sensor CA"), whose private key is never written anywhere. The lab's own
  sensor CA key was deleted after it signed the lab sensor's certificate (lab/soc/bootstrap.py),
  so the new CA's certificate is ADDED to the SOC's sensor CA file (a PEM bundle: both CAs are
  trusted for client certificates, nothing else changes). The SOC reads that file when it
  starts, so it has to be restarted once after a new CA was added (stderr says so);
- a tar archive on standard output with what the collector needs: soc-ca.pem (the SOC's server CA,
  public), and, only when newly made, sensor_token, client.pem, client.key. Nothing secret is ever
  printed anywhere else; progress goes to standard error.

Environment: IDPS_SOC_DATABASE_URL and IDPS_SOC_JWT_SECRET are taken from the SOC's own process
(/proc/1/environ) when they are not set. PROVISION_SOC_DATA (default /var/lib/idps-soc) and
PROVISION_SHARED (default /run/idps-soc) exist for the tests.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

CA_COMMON_NAME = "IDPS lab cloud sensor CA"
BEGIN = b"-----BEGIN CERTIFICATE-----"
END = b"-----END CERTIFICATE-----"


def say(message: str) -> None:
    print(f"collector provision: {message}", file=sys.stderr)


def adopt_soc_environment() -> None:
    """Database URL and JWT secret from the SOC's own process, if not already set."""
    wanted = ("IDPS_SOC_DATABASE_URL", "IDPS_SOC_JWT_SECRET")
    if all(os.environ.get(k) for k in wanted):
        return
    try:
        raw = Path("/proc/1/environ").read_bytes()
    except OSError:
        return
    for item in raw.split(b"\0"):
        key, _, value = item.partition(b"=")
        name = key.decode(errors="replace")
        if name in wanted and not os.environ.get(name):
            os.environ[name] = value.decode()


def split_pem_certs(data: bytes) -> list[bytes]:
    certs, rest = [], data
    while BEGIN in rest and END in rest:
        start = rest.index(BEGIN)
        stop = rest.index(END, start) + len(END)
        certs.append(rest[start:stop] + b"\n")
        rest = rest[stop:]
    return certs


def cert_common_name(pem: bytes) -> str | None:
    from cryptography import x509

    from soc.api import pki

    return pki.common_name(x509.load_pem_x509_certificate(pem))


def bundle_with(bundle: bytes, new_ca: bytes) -> bytes:
    """The sensor CA bundle without any earlier cloud CA, plus new_ca."""
    keep = [c for c in split_pem_certs(bundle) if cert_common_name(c) != CA_COMMON_NAME]
    return b"".join(keep) + new_ca


def current_cert_ok(name: str, cloud_dir: Path, bundle: bytes, have_key: bool) -> tuple[bool, bool]:
    """(certificate is usable, its CA is in the SOC's bundle)."""
    from cryptography import x509

    from soc.api import pki

    try:
        cert = x509.load_pem_x509_certificate((cloud_dir / "client.pem").read_bytes())
        ca_pem = (cloud_dir / "ca.pem").read_bytes()
        ca = x509.load_pem_x509_certificate(ca_pem)
    except (OSError, ValueError):
        return False, False
    good = (
        have_key
        and pki.common_name(cert) == name
        and cert.issuer == ca.subject
        and cert.not_valid_after_utc - datetime.now(UTC) > timedelta(days=30)
    )
    in_bundle = any(c.strip() == ca_pem.strip() for c in split_pem_certs(bundle))
    return good, in_bundle


def ensure_token(name: str, volume_token_sha256: str | None, force: bool) -> str | None:
    """A new token (shown once) when one has to be made, else None.

    The SOC keeps only a SHA-256 of a token, so "the volume holds the right token" is checked by
    comparing the hash of the volume's file (sent by the host script, never the token itself) with
    the SOC's row. A missing, revoked or different token is replaced (the old row is revoked and
    renamed). --force-token replaces it anyway."""
    from sqlalchemy import select

    from soc.api import auth
    from soc.api.db import init_db, make_engine, make_session_factory
    from soc.api.models import SensorToken
    from soc.api.settings import get_settings

    engine = make_engine(get_settings().database_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        row = db.scalar(select(SensorToken).where(SensorToken.name == name))
        if (
            row is not None
            and not row.revoked
            and not force
            and volume_token_sha256
            and row.token_hash == volume_token_sha256
        ):
            say(f"the token in the collector's volume is the SOC's token for {name!r}; kept")
            return None
        if row is not None:  # a hash cannot be turned back into a token: retire it, make a new one
            row.revoked = True
            row.name = f"{name}-revoked-{int(time.time())}-{row.id}"[
                :64
            ]  # unique even within a second
            db.commit()
            say(f"revoked the earlier token of {name!r}")
        token = auth.create_sensor_token(db, name)
        say(f"created the sensor token for {name!r}")
        return token


def provision(
    name: str,
    volume_token_sha256: str | None,
    have_key: bool,
    data: Path,
    shared: Path,
    force_token: bool = False,
) -> bytes:
    """Certificate and CA first, the token LAST: if any earlier step fails nothing has been
    created or revoked at the SOC, so a re-run starts from the same place (a token made here but
    lost on the way to the volume is replaced on the next run, because its hash will not match)."""
    from soc.api import pki

    files: dict[str, tuple[bytes, int]] = {}
    cloud_dir = data / "cloud-sensor"
    cloud_dir.mkdir(exist_ok=True)
    bundle_path = data / "sensor-ca.pem"
    bundle = bundle_path.read_bytes()
    good, in_bundle = current_cert_ok(name, cloud_dir, bundle, have_key)
    if good and in_bundle:
        say("the certificate is current and its CA is trusted by the SOC; kept")
    else:
        if good and not in_bundle:  # the lab CA file was rewritten (its certificate was renewed)
            say("the certificate is current but the SOC's CA file lost its CA; adding it back")
            ca_pem = (cloud_dir / "ca.pem").read_bytes()
        else:
            ca_key, ca = pki.make_ca(CA_COMMON_NAME, days=400)
            key, cert = pki.issue_client_cert(ca_key, ca, name, days=365)
            del ca_key  # never written anywhere: nothing else can be signed with this CA
            ca_pem = pki.cert_pem(ca)
            pki.write_public(cloud_dir / "ca.pem", ca_pem)
            pki.write_public(cloud_dir / "client.pem", pki.cert_pem(cert))
            files["client.pem"] = (pki.cert_pem(cert), 0o644)
            files["client.key"] = (pki.key_pem(key), 0o600)
            say(f"issued a client certificate for {name!r} (valid 365 days)")
        pki.write_public(bundle_path, bundle_with(bundle, ca_pem))
        say(
            "the SOC's sensor CA file now trusts the cloud CA: RESTART THE SOC so it reloads it "
            "(docker compose up -d --no-build --force-recreate soc-net soc-db soc, in lab/)"
        )
    files["soc-ca.pem"] = ((shared / "ca.pem").read_bytes(), 0o644)
    token = ensure_token(
        name, volume_token_sha256, force_token
    )  # the last step that changes the SOC
    if token is not None:
        files["sensor_token"] = (token.encode(), 0o600)

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for member, (content, mode) in files.items():
            info = tarfile.TarInfo(member)
            info.size, info.mode, info.mtime = len(content), mode, int(time.time())
            info.uid = info.gid = 65534  # the unprivileged collector owns its credentials
            tar.addfile(info, io.BytesIO(content))
    return out.getvalue()


def fingerprint(pem: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    return x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()).hex()


def process_started_at() -> float | None:
    """When the SOC process (PID 1 of this container) started, as a Unix time; None if unknown."""
    try:
        fields = Path("/proc/1/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[19])  # starttime, in clock ticks since boot
        boot = next(
            int(line.split()[1])
            for line in Path("/proc/stat").read_text().splitlines()
            if line.startswith("btime")
        )
        return boot + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def check(name: str, data: Path) -> int:
    """Read-only check for start_collector.sh. Prints `key=value` lines (public facts only) and
    returns 0 = fine, 3 = the SOC's sensor CA file no longer holds the cloud CA (re-run the
    provisioning), 4 = it holds it but the SOC has not been restarted since (it reads the file
    at start). Fingerprints of public certificates are compared; nothing secret is read."""
    from cryptography import x509

    cloud_dir = data / "cloud-sensor"
    try:
        ca_pem = (cloud_dir / "ca.pem").read_bytes()
        cert = x509.load_pem_x509_certificate((cloud_dir / "client.pem").read_bytes())
        ca_cert = x509.load_pem_x509_certificate(ca_pem)
        bundle_path = data / "sensor-ca.pem"
        bundle = bundle_path.read_bytes()
    except (OSError, ValueError):
        print("cloud_ca=none")
        return 3
    now = datetime.now(UTC)
    print(f"client_cert_days_left={(cert.not_valid_after_utc - now).days}")
    print(f"cloud_ca_days_left={(ca_cert.not_valid_after_utc - now).days}")
    want = fingerprint(ca_pem)
    held = {fingerprint(c) for c in split_pem_certs(bundle)}
    if want not in held:
        print("cloud_ca=missing_from_soc_ca_file")
        return 3
    started = process_started_at()
    if started is not None and bundle_path.stat().st_mtime > started:
        print("cloud_ca=added_after_soc_start")
        return 4
    print("cloud_ca=trusted")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--name", default="cloud")
    parser.add_argument("--check", action="store_true", help="only check the CA file (see check())")
    parser.add_argument(
        "--token-sha256",
        default="",
        help="SHA-256 of the token file in the collector's volume (empty: none)",
    )
    parser.add_argument(
        "--have-key",
        choices=("0", "1"),
        default="0",
        help="the collector's volume already holds the certificate's key",
    )
    parser.add_argument(
        "--force-token", action="store_true", help="replace the token even if it matches"
    )
    args = parser.parse_args(argv)
    data = Path(os.environ.get("PROVISION_SOC_DATA", "/var/lib/idps-soc"))
    shared = Path(os.environ.get("PROVISION_SHARED", "/run/idps-soc"))
    if args.check:
        return check(args.name, data)
    if args.token_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.token_sha256):
        say("error: --token-sha256 must be 64 hex digits")
        return 2
    adopt_soc_environment()
    try:
        blob = provision(
            args.name,
            args.token_sha256 or None,
            args.have_key == "1",
            data,
            shared,
            args.force_token,
        )
    except (OSError, ValueError) as exc:
        say(f"error: {type(exc).__name__}: {exc}")
        return 1
    sys.stdout.buffer.write(blob)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
