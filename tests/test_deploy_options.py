"""Step 12: serve.py without TLS behind a proxy, separate sensor certificate, create-user
--password-file, and the server-cert command the installer uses."""

import asyncio
import ssl
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import uvicorn
from conftest import TEST_SECRET
from cryptography import x509
from sqlalchemy import select

from soc.api import __main__ as cli
from soc.api import pki, serve
from soc.api.main import create_app
from soc.api.models import Role, User
from soc.api.settings import SocSettings

# --- serve.py options ---------------------------------------------------------------------------


def test_main_listener_without_tls_and_proxy_options():
    args = serve.parse_args(["--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"])
    cfg, sensor = serve.build_configs(args, object())
    assert sensor is None
    assert cfg.ssl_keyfile is None and cfg.ssl_certfile is None
    assert cfg.proxy_headers is True
    assert cfg.forwarded_allow_ips == "*"


def test_forwarded_allow_ips_default_is_uvicorns():
    args = serve.parse_args(["--proxy-headers"])
    cfg, _ = serve.build_configs(args, object())
    assert cfg.forwarded_allow_ips == uvicorn.Config(object()).forwarded_allow_ips


def test_main_tls_still_works_and_is_the_sensor_default():
    args = serve.parse_args(["--ssl-keyfile", "k", "--ssl-certfile", "c",
                             "--sensor-port", "8444", "--sensor-ca", "ca"])
    cfg, sensor = serve.build_configs(args, object())
    assert cfg.ssl_keyfile == "k" and cfg.ssl_certfile == "c"
    assert (sensor.ssl_keyfile, sensor.ssl_certfile) == ("k", "c")
    assert sensor.ssl_cert_reqs == ssl.CERT_REQUIRED


def test_sensor_listener_has_its_own_certificate_and_stays_mutual_tls():
    args = serve.parse_args(["--sensor-port", "8444", "--sensor-ca", "ca",
                             "--sensor-ssl-keyfile", "sk", "--sensor-ssl-certfile", "sc"])
    cfg, sensor = serve.build_configs(args, object())
    assert cfg.ssl_keyfile is None  # main listener plain
    assert (sensor.ssl_keyfile, sensor.ssl_certfile) == ("sk", "sc")
    assert sensor.ssl_ca_certs == "ca" and sensor.ssl_cert_reqs == ssl.CERT_REQUIRED


def test_sensor_listener_does_not_trust_forwarded_headers():
    args = serve.parse_args(["--proxy-headers", "--forwarded-allow-ips", "*",
                             "--sensor-port", "8444", "--sensor-ca", "ca",
                             "--sensor-ssl-keyfile", "sk", "--sensor-ssl-certfile", "sc"])
    _, sensor = serve.build_configs(args, object())
    assert sensor.proxy_headers is False  # sensors connect directly: forwarded headers ignored
    assert cfg_proxy_on(args).proxy_headers is True  # ...while the main listener keeps them


def cfg_proxy_on(args):
    return serve.build_configs(args, object())[0]


@pytest.mark.parametrize("argv", [
    ["--sensor-port", "8444", "--sensor-ca", "ca"],  # no certificate anywhere
    ["--ssl-keyfile", "k"],  # half a pair
    ["--ssl-certfile", "c"],
    ["--sensor-port", "8444", "--sensor-ca", "ca", "--sensor-ssl-keyfile", "k"],
    ["--sensor-port", "8444"],  # no CA
    ["--sensor-ca", "ca"],  # no port
    ["--sensor-ssl-keyfile", "k", "--sensor-ssl-certfile", "c"],  # without a sensor port
])
def test_bad_combinations_are_refused(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        serve.parse_args(argv)
    assert exc.value.code == 2
    assert "error" in capsys.readouterr().err


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_plain_http_main_listener_serves_the_app_and_trusts_forwarded_for():
    settings = SocSettings(jwt_secret=TEST_SECRET, database_url="sqlite://")
    app = create_app(settings)
    port = _free_port()
    args = serve.parse_args(["--host", "127.0.0.1", "--port", str(port), "--proxy-headers",
                             "--forwarded-allow-ips", "127.0.0.1"])
    cfg, _ = serve.build_configs(args, app)
    cfg.log_level = "warning"
    servers = serve.make_servers(cfg, None)
    t = threading.Thread(target=lambda: asyncio.run(serve.serve(cfg, None, servers)), daemon=True)
    t.start()
    try:
        deadline = time.time() + 15
        body = None
        while time.time() < deadline and body is None:
            try:
                body = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2).read()
            except OSError:
                time.sleep(0.1)
        assert body and b"ok" in body
    finally:
        for s in servers:
            s.should_exit = True
        t.join(timeout=10)


# --- create-user --password-file ----------------------------------------------------------------


@pytest.fixture
def cli_db(tmp_path, monkeypatch):
    monkeypatch.setenv("IDPS_SOC_DATABASE_URL", f"sqlite:///{tmp_path / 'u.db'}")
    monkeypatch.setenv("IDPS_SOC_JWT_SECRET", TEST_SECRET)
    from soc.api.settings import get_settings

    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _users(tmp_path):
    from soc.api.db import make_engine, make_session_factory

    with make_session_factory(make_engine(f"sqlite:///{tmp_path / 'u.db'}"))() as db:
        return {u.username: u for u in db.scalars(select(User))}


def test_create_user_password_file(cli_db, capsys):
    pw = cli_db / "pw"
    pw.write_text("a-long-generated-password-1\n")
    assert cli.main(["create-user", "boss", "--role", "admin", "--password-file", str(pw)]) == 0
    out = capsys.readouterr()
    assert "a-long-generated-password-1" not in out.out + out.err
    from soc.api import security

    user = _users(cli_db)["boss"]
    assert user.role == Role.ADMIN
    assert security.verify_password("a-long-generated-password-1", user.password_hash)


def test_create_user_password_file_enforces_the_policy(cli_db, capsys):
    pw = cli_db / "pw"
    pw.write_text("short\n")
    assert cli.main(["create-user", "boss", "--role", "admin", "--password-file", str(pw)]) == 1
    out = capsys.readouterr()
    assert "short" not in out.out.replace("error", "")  # never echoed
    assert "boss" not in _users(cli_db)


def test_create_user_password_file_missing_and_duplicate(cli_db, capsys):
    assert cli.main(["create-user", "x", "--role", "admin",
                     "--password-file", str(cli_db / "nope")]) == 1
    assert "cannot read" in capsys.readouterr().err
    pw = cli_db / "pw"
    pw.write_text("a-long-generated-password-1")
    assert cli.main(["create-user", "dup", "--role", "analyst", "--password-file", str(pw)]) == 0
    assert cli.main(["create-user", "dup", "--role", "analyst", "--password-file", str(pw)]) == 1


# --- server-cert --------------------------------------------------------------------------------


def test_server_cert_is_issued_once_and_reissued_when_names_change(tmp_path, capsys):
    d = str(tmp_path / "pki")
    assert cli.main(["server-cert", "--dir", d, "--san", "soc.example", "--san", "10.0.0.5"]) == 0
    ca_pem = (Path(d) / "server-ca.pem").read_bytes()
    first = (Path(d) / "server.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(first)
    assert pki.cert_sans(cert) == {"soc.example", "10.0.0.5"}
    assert oct((Path(d) / "server.key").stat().st_mode & 0o777) == "0o600"
    assert oct((Path(d) / "server-ca.key").stat().st_mode & 0o777) == "0o600"
    # same names (any order): unchanged
    assert cli.main(["server-cert", "--dir", d, "--san", "10.0.0.5", "--san", "soc.example"]) == 0
    assert (Path(d) / "server.pem").read_bytes() == first
    # new name: new certificate, same CA (bundles stay valid)
    assert cli.main(["server-cert", "--dir", d, "--san", "other.example"]) == 0
    assert (Path(d) / "server.pem").read_bytes() != first
    assert (Path(d) / "server-ca.pem").read_bytes() == ca_pem
    ca = x509.load_pem_x509_certificate(ca_pem)
    new = x509.load_pem_x509_certificate((Path(d) / "server.pem").read_bytes())
    assert new.issuer == ca.subject


def test_server_cert_rejects_a_bad_name(tmp_path):
    assert cli.main(["server-cert", "--dir", str(tmp_path / "p"), "--san", "a b"]) == 1


def test_server_cert_with_the_ca_key_in_another_directory(tmp_path):
    pki_dir, ca_dir = tmp_path / "pki", tmp_path / "cakeys"
    assert cli.main(["server-cert", "--dir", str(pki_dir), "--ca-dir", str(ca_dir),
                     "--san", "soc.example"]) == 0
    assert (ca_dir / "server-ca.key").exists() and not (pki_dir / "server-ca.key").exists()
    assert (pki_dir / "server-ca.pem").read_bytes() == (ca_dir / "server-ca.pem").read_bytes()
    assert (pki_dir / "server.key").exists()
    # second call: current, nothing rewritten
    first = (pki_dir / "server.pem").read_bytes()
    assert cli.main(["server-cert", "--dir", str(pki_dir), "--ca-dir", str(ca_dir),
                     "--san", "soc.example"]) == 0
    assert (pki_dir / "server.pem").read_bytes() == first
