"""Mutual TLS between sensors and the SOC (soc/api/serve.py), against a real server on two ports."""

import ssl
import threading
import time
import urllib.error
from pathlib import Path

import pytest
import uvicorn
from conftest import TEST_SECRET
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from idps.soc_client import SocClient, SocError, SocRejectedError
from soc.api import auth, pki
from soc.api.main import create_app
from soc.api.models import Role
from soc.api.serve import SensorOnly, cert_identity, make_servers, sensor_config, serve
from soc.api.settings import SocSettings

ALERT = {"src_ip": "10.10.1.10", "src_port": 4444, "dst_ip": "10.10.2.10", "dst_port": 80,
         "protocol": 6, "start_ms": 1, "end_ms": 2, "predicted_class": "PortScan",
         "confidence": 0.9}


def _server_cert(tmp: Path) -> tuple[Path, Path, Path]:
    """A server CA and a certificate for 127.0.0.1 (the SOC's own TLS certificate)."""
    ca_key, ca = pki.make_ca("test server CA")
    key = ec.generate_private_key(ec.SECP256R1())
    from datetime import UTC, datetime, timedelta
    import ipaddress

    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "soc")]))
            .issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    pki.write_public(tmp / "server-ca.pem", pki.cert_pem(ca))
    pki.write_public(tmp / "server.pem", pki.cert_pem(cert))
    pki.write_private(tmp / "server.key", pki.key_pem(key))
    return tmp / "server-ca.pem", tmp / "server.pem", tmp / "server.key"


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Lab:
    """A SOC with a main listener and a mutual-TLS sensor listener, two sensors and their certs."""

    def __init__(self, tmp: Path, required: bool) -> None:
        self.tmp = tmp
        self.server_ca, cert, key = _server_cert(tmp)
        ca_key, ca = pki.make_ca()
        pki.write_public(tmp / "sensor-ca.pem", pki.cert_pem(ca))
        self.settings = SocSettings(jwt_secret=TEST_SECRET, database_url="sqlite://",
                                    mfa_required_for_admins=False, sensor_mtls_required=required)
        self.app = create_app(self.settings)
        with self.app.state.session_factory() as db:
            self.tokens = {n: auth.create_sensor_token(db, n) for n in ("sensor-a", "sensor-b")}
            auth.create_user(db, "admin", "admin-password-123", Role.ADMIN)
        for name in ("sensor-a", "sensor-b"):
            k, c = pki.issue_client_cert(ca_key, ca, name)
            pki.write_public(tmp / f"{name}.pem", pki.cert_pem(c))
            pki.write_private(tmp / f"{name}.key", pki.key_pem(k))
        other_key, other_ca = pki.make_ca("someone else's CA")  # same name, wrong issuer
        k, c = pki.issue_client_cert(other_key, other_ca, "sensor-a")
        pki.write_public(tmp / "rogue.pem", pki.cert_pem(c))
        pki.write_private(tmp / "rogue.key", pki.key_pem(k))
        self.port, self.sensor_port = _free_port(), _free_port()
        main_cfg = uvicorn.Config(self.app, host="127.0.0.1", port=self.port,
                                  ssl_keyfile=str(key), ssl_certfile=str(cert), log_level="warning")
        sensor_cfg = sensor_config(self.app, "127.0.0.1", self.sensor_port, str(key), str(cert),
                                   str(tmp / "sensor-ca.pem"), log_level="warning")
        import asyncio

        self.servers = make_servers(main_cfg, sensor_cfg)

        def thread():
            asyncio.run(serve(main_cfg, sensor_cfg, self.servers))

        self.thread = threading.Thread(target=thread, daemon=True)
        self.thread.start()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                self.client(self.port, "sensor-a", cert=False).post_status({})
            except Exception as exc:  # noqa: BLE001
                if "refused" not in str(exc).lower() and "unreachable" not in str(exc).lower():
                    break
            time.sleep(0.1)

    def client(self, port: int, token_of: str, cert: str | bool = True) -> SocClient:
        name = token_of if cert is True else cert
        kw = {} if cert is False else {"client_cert": str(self.tmp / f"{name}.pem"),
                                       "client_key": str(self.tmp / f"{name}.key")}
        return SocClient(f"https://127.0.0.1:{port}", self.tokens[token_of], timeout=5,
                         ca_file=str(self.server_ca), **kw)

    def stop(self) -> None:
        for server in self.servers:
            server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def lab_required(tmp_path):
    lab = Lab(tmp_path, required=True)
    yield lab
    lab.stop()


@pytest.fixture
def lab_optional(tmp_path):
    lab = Lab(tmp_path, required=False)
    yield lab
    lab.stop()


def _ingest(client: SocClient) -> dict:
    return client.post_alerts([ALERT])


def test_sensor_with_its_certificate_is_accepted(lab_required):
    assert _ingest(lab_required.client(lab_required.sensor_port, "sensor-a"))["accepted"] == 1


def test_sensor_without_a_certificate_is_refused_in_the_handshake(lab_required):
    ctx = ssl.create_default_context(cafile=str(lab_required.server_ca))
    import socket

    with socket.create_connection(("127.0.0.1", lab_required.sensor_port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            # TLS 1.3: the server's refusal of the missing certificate arrives on first read.
            with pytest.raises((ssl.SSLError, ConnectionResetError, OSError)):
                tls.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                if not tls.recv(1024):
                    raise ConnectionResetError("closed")
    with pytest.raises(SocError) as info:
        _ingest(lab_required.client(lab_required.sensor_port, "sensor-a", cert=False))
    assert not isinstance(info.value, SocRejectedError)  # refused before any HTTP answer


def test_certificate_from_another_ca_is_refused(lab_required):
    with pytest.raises(SocError) as info:
        _ingest(lab_required.client(lab_required.sensor_port, "sensor-a", cert="rogue"))
    assert not isinstance(info.value, SocRejectedError)  # the handshake failed


def test_another_sensors_certificate_is_refused(lab_required):
    """sensor-a's token with sensor-b's (valid) certificate: the names differ."""
    with pytest.raises(SocRejectedError) as info:
        _ingest(lab_required.client(lab_required.sensor_port, "sensor-a", cert="sensor-b"))
    assert info.value.status == 401


def test_main_port_refuses_sensors_when_mtls_is_required(lab_required):
    with pytest.raises(SocRejectedError) as info:
        _ingest(lab_required.client(lab_required.port, "sensor-a", cert=False))
    assert info.value.status == 401


def test_main_port_still_serves_the_dashboard(lab_required):
    import json
    import urllib.request

    ctx = ssl.create_default_context(cafile=str(lab_required.server_ca))
    req = urllib.request.Request(
        f"https://127.0.0.1:{lab_required.port}/auth/login", method="POST",
        data=json.dumps({"username": "admin", "password": "admin-password-123"}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        assert json.loads(resp.read())["access_token"]


def test_sensor_port_serves_only_sensor_endpoints(lab_required):
    import urllib.request

    ctx = ssl.create_default_context(cafile=str(lab_required.server_ca))
    ctx.load_cert_chain(str(lab_required.tmp / "sensor-a.pem"),
                        str(lab_required.tmp / "sensor-a.key"))
    with pytest.raises(urllib.error.HTTPError) as info:
        urllib.request.urlopen(f"https://127.0.0.1:{lab_required.sensor_port}/alerts",
                               context=ctx, timeout=5)
    assert info.value.code == 404
    with urllib.request.urlopen(f"https://127.0.0.1:{lab_required.sensor_port}/health",
                                context=ctx, timeout=5) as resp:
        assert resp.status == 200


def test_optional_mode_accepts_both_but_still_checks_names(lab_optional):
    assert _ingest(lab_optional.client(lab_optional.port, "sensor-a", cert=False))["accepted"] == 1
    assert _ingest(lab_optional.client(lab_optional.sensor_port, "sensor-b"))["accepted"] == 1
    with pytest.raises(SocRejectedError) as info:
        _ingest(lab_optional.client(lab_optional.sensor_port, "sensor-b", cert="sensor-a"))
    assert info.value.status == 401


def test_cert_identity_reads_the_common_name(tmp_path):
    key, ca = pki.make_ca()
    _, cert = pki.issue_client_cert(key, ca, "lab-sensor-1")
    from cryptography.hazmat.primitives import serialization

    ident = cert_identity(cert.public_bytes(serialization.Encoding.DER))
    assert ident["cn"] == "lab-sensor-1" and len(ident["sha256"]) == 64
    assert cert_identity(None) is None


def test_scope_extension_cannot_be_set_by_a_client_header(tmp_path):
    """On the main listener there is no certificate extension, whatever the request says."""
    from fastapi.testclient import TestClient

    settings = SocSettings(jwt_secret=TEST_SECRET, database_url="sqlite://",
                           mfa_required_for_admins=False, sensor_mtls_required=True)
    app = create_app(settings)
    with app.state.session_factory() as db:
        token = auth.create_sensor_token(db, "sensor-a")
    c = TestClient(app)
    r = c.post("/ingest/alerts", json={"alerts": [ALERT]},
               headers={"Authorization": f"Bearer {token}", "idps.client_cert": "sensor-a",
                        "X-Client-Cert": "sensor-a"})
    assert r.status_code == 401


def test_sensor_only_wrapper_refuses_websockets():
    import asyncio

    sent = []

    async def app(scope, receive, send):  # pragma: no cover - must not be reached
        raise AssertionError("reached the app")

    async def send(msg):
        sent.append(msg)

    asyncio.run(SensorOnly(app)({"type": "websocket", "path": "/ws/alerts"}, None, send))
    assert sent == [{"type": "websocket.close", "code": 1008}]
