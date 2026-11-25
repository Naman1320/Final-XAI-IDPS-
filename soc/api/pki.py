"""A small certificate authority for sensor client certificates (mutual TLS, soc/api/serve.py).

    python -m soc.api sensor-ca  --out-dir DIR            -> DIR/sensor-ca.pem, DIR/sensor-ca.key
    python -m soc.api sensor-cert NAME --ca-dir DIR --out-dir OUT
                                                          -> OUT/NAME.pem, OUT/NAME.key

The common name of a sensor certificate is the sensor's name at the SOC (as made by
`create-sensor`): the SOC refuses a certificate whose name is not the token's sensor. Keys are
ECDSA P-256; private keys are written 0600 and never printed. Keep the CA key offline (or
delete it after issuing, as the lab does: lab/soc/bootstrap.py makes a new CA each time).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn: str = "IDPS sensor CA", days: int = 365):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_client_cert(ca_key, ca_cert: x509.Certificate, cn: str, days: int = 365):
    """A TLS client certificate (clientAuth only) for sensor `cn`, signed by the CA."""
    if not cn or len(cn) > 64:
        raise ValueError("the sensor name must be 1 to 64 characters")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def issue_server_cert(ca_key, ca_cert: x509.Certificate, cn: str, sans: list[str],
                      days: int = 365):
    """A TLS server certificate (serverAuth only) valid for the names/IP addresses in `sans`."""
    import ipaddress

    if not sans:
        raise ValueError("at least one name or address is needed")
    entries: list[x509.GeneralName] = []
    for san in sans:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(san)))
        except ValueError:
            if not san or len(san) > 253 or any(c in san for c in " /@\\"):
                raise ValueError(f"not a host name or address: {san!r}") from None
            entries.append(x509.DNSName(san))
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(entries), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_private(path: Path, data: bytes) -> None:
    """Write a private key 0600 through a temporary file (never readable by others, even briefly)."""
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def write_public(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def load_ca(ca_dir: Path, name: str = "sensor-ca"):
    cert = x509.load_pem_x509_certificate((ca_dir / f"{name}.pem").read_bytes())
    key = serialization.load_pem_private_key((ca_dir / f"{name}.key").read_bytes(), None)
    return key, cert


def cert_sans(cert: x509.Certificate) -> set[str]:
    """The names and addresses of a certificate's subjectAltName, as strings."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    return {str(v) for v in ext.get_values_for_type(x509.DNSName)} | {
        str(v) for v in ext.get_values_for_type(x509.IPAddress)}


def common_name(cert: x509.Certificate) -> str | None:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if len(names) == 1 else None
