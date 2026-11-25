"""Step C1 of docs/cloud-plan.md: the billing guard, the emulator-only proxy, env.sh and tf.sh."""

import http.client
import importlib.util
import os
import socket
import subprocess
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLOUD = ROOT / "lab" / "cloud"
ENV_SH = CLOUD / "env.sh"
TF_SH = CLOUD / "tf.sh"

# The sensor image doesn't contain lab/, so these tests only run from a repo checkout.
pytestmark = pytest.mark.skipif(not CLOUD.exists(), reason="lab/cloud not present")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"cloud_{name}", CLOUD / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if CLOUD.exists():
    guard = _load("guard")
    proxy = _load("egress_proxy")

SAFE_ENV = {
    "AWS_ACCESS_KEY_ID": "test",
    "AWS_SECRET_ACCESS_KEY": "test",
    "AWS_ENDPOINT_URL": "http://127.0.0.1:4566",
    "AWS_CONFIG_FILE": "/dev/null",
    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    "IDPS_EMULATOR_ACCOUNT": "000000000000",
}


def moto_up() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:4566/moto-api/", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


class Spy:
    """A probe / account_of stand-in that records whether it was called."""

    def __init__(self, result=True, raises=None):
        self.result, self.raises, self.calls = result, raises, 0

    def __call__(self, *_args):
        self.calls += 1
        if self.raises:
            raise self.raises
        return self.result


def safe_problems(env, **kw):
    return guard.problems(env, probe=Spy(True), account_of=Spy("000000000000"), **kw)


# ---------------------------------------------------------------- guard.problems


def test_safe_env_passes():
    assert safe_problems(SAFE_ENV) == []


@pytest.mark.parametrize("key", ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"])
def test_real_looking_key_refused(key):
    found = safe_problems(SAFE_ENV | {"AWS_ACCESS_KEY_ID": key})
    assert any("real AWS key" in f for f in found)


def test_non_test_secret_refused():
    found = safe_problems(SAFE_ENV | {"AWS_SECRET_ACCESS_KEY": "hunter2"})
    assert any("fake test/test" in f for f in found)


@pytest.mark.parametrize("name", guard.BLOCKED_VARS if CLOUD.exists() else [])
def test_each_blocked_var_refused(name):
    found = safe_problems(SAFE_ENV | {name: "x"})
    assert any(name in f for f in found)


@pytest.mark.parametrize("name", ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"])
@pytest.mark.parametrize("value", ["/home/me/.aws/config", ""])
def test_config_files_must_be_dev_null(name, value):
    assert any(name in f for f in safe_problems(SAFE_ENV | {name: value}))


def test_config_files_missing_refused():
    env = {k: v for k, v in SAFE_ENV.items() if k != "AWS_CONFIG_FILE"}
    assert any("AWS_CONFIG_FILE" in f for f in safe_problems(env))


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.amazonaws.com",
        "http://127.0.0.1.evil.com:4566",
        "http://localhost.attacker.net",
        "http://evil.com/127.0.0.1",
        "http://127.0.0.1@evil.com:4566",
        "",
        "ftp://127.0.0.1:4566",
        "127.0.0.1:4566",
        "http://moto:5000",
        "http://moto:4566",
        "http://localhost:5000",
        "http://127.0.0.1:4567",
        "http://localhost",
        "http://127.0.0.1",
        "http://user:pw@127.0.0.1:4566",
        "http://user@localhost:4566",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:notaport",
        "http://idps-cloud-moto:4566",
    ],
)
def test_non_local_endpoint_refused(endpoint):
    found = safe_problems(SAFE_ENV | {"AWS_ENDPOINT_URL": endpoint})
    assert any("local emulator" in f for f in found)


def test_endpoint_unset_refused():
    env = {k: v for k, v in SAFE_ENV.items() if k != "AWS_ENDPOINT_URL"}
    assert any("local emulator" in f for f in safe_problems(env))


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:4566",
        "http://127.0.0.1:4566",
        "http://[::1]:4566",
        "http://10.10.4.10:4566",
        "http://127.0.0.1:4566/",
    ],
)
def test_local_endpoints_accepted(endpoint):
    assert safe_problems(SAFE_ENV | {"AWS_ENDPOINT_URL": endpoint}) == []


@pytest.mark.parametrize(
    "name", ["AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_EC2"]
)
def test_per_service_endpoint_refused(name):
    probe, account = Spy(True), Spy("000000000000")
    found = guard.problems(
        SAFE_ENV | {name: "http://127.0.0.1:4566"}, probe=probe, account_of=account
    )
    assert any(name in f for f in found)
    assert probe.calls == 0 and account.calls == 0


def test_empty_per_service_endpoint_is_ignored():
    assert safe_problems(SAFE_ENV | {"AWS_ENDPOINT_URL_S3": ""}) == []


def test_probe_false_refused():
    account = Spy("000000000000")
    found = guard.problems(SAFE_ENV, probe=Spy(False), account_of=account)
    assert len(found) == 1 and "not answering as Moto" in found[0]
    assert account.calls == 0


def test_account_of_raising_refused():
    found = guard.problems(SAFE_ENV, probe=Spy(True), account_of=Spy(raises=RuntimeError("boom")))
    assert len(found) == 1 and "STS get-caller-identity failed" in found[0] and "boom" in found[0]


def test_wrong_account_refused():
    found = guard.problems(SAFE_ENV, probe=Spy(True), account_of=Spy("123456789012"))
    assert len(found) == 1 and "123456789012" in found[0]


def test_custom_emulator_account_is_honoured():
    env = SAFE_ENV | {"IDPS_EMULATOR_ACCOUNT": "111111111111"}
    assert guard.problems(env, probe=Spy(True), account_of=Spy("111111111111")) == []


@pytest.mark.parametrize(
    "bad",
    [
        {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
        {"AWS_SECRET_ACCESS_KEY": "nope"},
        {"AWS_SESSION_TOKEN": "tok"},
        {"AWS_PROFILE": "prod"},
        {"AWS_CONFIG_FILE": "/home/me/.aws/config"},
        {"AWS_ENDPOINT_URL": "https://sts.amazonaws.com"},
        {"AWS_ENDPOINT_URL": ""},
        {"AWS_ENDPOINT_URL": "http://localhost:5000"},
        {"AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4566"},
        {"AWS_CA_BUNDLE": "/tmp/ca.pem"},
        {"HTTPS_PROXY": "http://proxy:3128"},
        {"http_proxy": "http://proxy:3128"},
        {"ALL_PROXY": "socks5://proxy:1080"},
    ],
)
def test_unsafe_env_makes_no_network_contact(bad):
    probe, account = Spy(True), Spy("000000000000")
    found = guard.problems(SAFE_ENV | bad, probe=probe, account_of=account)
    assert found
    assert probe.calls == 0 and account.calls == 0


def test_all_problems_are_reported_together():
    env = SAFE_ENV | {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_PROFILE": "prod"}
    assert len(safe_problems(env)) >= 3


# ---------------------------------------------------------------- guard.main


def test_main_exit_1_on_unsafe_env(monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", dict(SAFE_ENV, AWS_SESSION_TOKEN="tok"))
    monkeypatch.setattr(guard, "_probe_moto", Spy(True))
    assert guard.main() == 1
    err = capsys.readouterr().err
    assert "REFUSED" in err and "AWS_SESSION_TOKEN" in err


def test_main_exit_0_on_safe_env(monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", dict(SAFE_ENV))
    monkeypatch.setattr(guard, "_probe_moto", Spy(True))
    monkeypatch.setattr(guard, "_account", Spy("000000000000"))
    assert guard.main() == 0
    assert "billing guard: ok" in capsys.readouterr().out


def test_main_exit_1_when_emulator_down(monkeypatch):
    monkeypatch.setattr(os, "environ", dict(SAFE_ENV))
    monkeypatch.setattr(guard, "_probe_moto", Spy(False))
    assert guard.main() == 1


# ---------------------------------------------------------------- egress_proxy.allowed


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "localhost",
        "000000000000.localhost",
        "localhost.",
        "LOCALHOST",
        "000000000000.LocalHost.",
        "127.0.0.1.",
    ],
)
def test_allowed_emulator_hosts(host):
    assert proxy.allowed(host, 4566, 4566)


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("evil.com", 4566),
        ("localhost.evil.com", 4566),
        ("127.0.0.1.nip.io", 4566),
        ("s3.amazonaws.com", 4566),
        ("127.0.0.1", 80),
        ("localhost", 4567),
        ("127.0.0.1", None),
        (None, 4566),
        ("", 4566),
        ("10.0.0.1", 4566),
    ],
)
def test_allowed_refuses_everything_else(host, port):
    assert not proxy.allowed(host, port, 4566)


# ---------------------------------------------------------------- egress_proxy server


class _Stub(BaseHTTPRequestHandler):
    seen: ClassVar[list] = []
    raw_headers: ClassVar[list] = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        type(self).raw_headers.append(list(self.headers.items()))
        if self.path.startswith("/nocontent"):
            self.send_response(204)
            self.end_headers()
            return
        if self.path.startswith("/trunc"):
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
            self.wfile.flush()
            self.close_connection = True
            return
        out = b"stub-says-hi"
        self.send_response(201, "Made")
        self.send_header("X-Stub", "yes")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _handle


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_STUBS: list = []  # stub handler classes, newest last (for the raw header lists)


@pytest.fixture
def stub():
    stub_cls = type("Stub", (_Stub,), {"seen": [], "raw_headers": []})
    server = _serve(stub_cls)
    _STUBS.append(stub_cls)
    yield server, stub_cls.seen
    server.shutdown()
    server.server_close()


@pytest.fixture
def proxied(stub):
    """(proxy_port, stub_port, stub_requests): the proxy's upstream is the stub."""
    server, seen = stub
    saved = proxy.Handler.upstream_host, proxy.Handler.upstream_port
    proxy.Handler.upstream_host, proxy.Handler.upstream_port = "127.0.0.1", server.server_address[1]
    psrv = _serve(proxy.Handler)
    yield psrv.server_address[1], server.server_address[1], seen
    psrv.shutdown()
    psrv.server_close()
    proxy.Handler.upstream_host, proxy.Handler.upstream_port = saved


def via_proxy(port, method, url, body=None, headers=None, chunked=False):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, url, body=body, headers=headers or {}, encode_chunked=chunked)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def test_forwarded_get(proxied):
    pport, sport, seen = proxied
    host = f"000000000000.localhost:{sport}"
    status, headers, body = via_proxy(
        pport, "GET", f"http://{host}/bucket/key?tagging&x=1%202", headers={"Host": host}
    )
    assert (status, body) == (201, b"stub-says-hi")
    assert headers["X-Stub"] == "yes" and headers["Content-Type"] == "text/plain"
    assert int(headers["Content-Length"]) == len(body)
    [(method, path, req_headers, req_body)] = seen
    assert (method, path, req_body) == ("GET", "/bucket/key?tagging&x=1%202", b"")
    assert req_headers["Host"] == host


def test_forwarded_get_without_path_becomes_slash(proxied):
    pport, sport, seen = proxied
    via_proxy(pport, "GET", f"http://localhost:{sport}")
    assert seen[0][1] == "/"


def test_forwarded_post_content_length(proxied):
    pport, sport, seen = proxied
    host = f"localhost:{sport}"
    payload = b"Action=GetCallerIdentity&Version=2011-06-15"
    status, _, _ = via_proxy(
        pport,
        "POST",
        f"http://{host}/?a=b",
        body=payload,
        headers={"Host": host, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert status == 201
    [(method, path, req_headers, req_body)] = seen
    assert (method, path, req_body) == ("POST", "/?a=b", payload)
    assert req_headers["Host"] == host
    assert req_headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_forwarded_post_chunked(proxied):
    pport, sport, seen = proxied
    host = f"127.0.0.1:{sport}"
    chunks = [b"hello ", b"chunked ", b"world" * 100]
    status, _, body = via_proxy(
        pport,
        "POST",
        f"http://{host}/up",
        body=iter(chunks),
        headers={"Host": host, "Transfer-Encoding": "chunked"},
        chunked=True,
    )
    assert (status, body) == (201, b"stub-says-hi")
    [(_, path, req_headers, req_body)] = seen
    assert path == "/up" and req_body == b"".join(chunks)
    assert req_headers["Content-Length"] == str(len(req_body))
    assert "chunked" not in req_headers.get("Transfer-Encoding", "")
    assert req_headers["Host"] == host


def test_head_has_no_body_but_keeps_upstream_length(proxied):
    pport, sport, seen = proxied
    status, headers, body = via_proxy(pport, "HEAD", f"http://localhost:{sport}/x")
    assert status == 201 and body == b"" and seen[0][0] == "HEAD"
    assert headers["Content-Length"] == str(len(b"stub-says-hi"))  # the stub's length for HEAD


def raw_exchange(port, data, timeout=5, half_close=False):
    """Send raw bytes to the proxy; return (status, header list, body). Never hangs past timeout."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(data)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                more = sock.recv(4096)
                if not more:
                    break
                buf += more
        except TimeoutError:
            pytest.fail("proxy hung instead of answering")
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = [tuple(line.split(":", 1)) for line in lines[1:]]
    return status, [(k.strip().lower(), v.strip()) for k, v in headers], rest


def raw_post(sport, headers, body=b""):
    request = f"POST http://localhost:{sport}/x HTTP/1.1\r\nHost: localhost:{sport}\r\n"
    request += "".join(f"{h}\r\n" for h in headers) + "\r\n"
    return request.encode() + body


def test_handler_has_a_read_timeout():
    assert proxy.Handler.timeout == 30


def test_conflicting_content_length_is_400(proxied):
    pport, sport, seen = proxied
    data = raw_post(sport, ["Content-Length: 3", "Content-Length: 5"], b"abc")
    status, _, _ = raw_exchange(pport, data)
    assert status == 400 and seen == []


def test_identical_duplicate_content_length_is_forwarded_once(proxied):
    pport, sport, seen = proxied
    data = raw_post(sport, ["Content-Length: 3", "Content-Length: 3"], b"abc")
    status, _, _ = raw_exchange(pport, data)
    assert status == 201 and seen[0][3] == b"abc"


@pytest.mark.parametrize("length", ["-1", "abc", "1e3", "99999999999"])
def test_bad_content_length_is_400(proxied, length):
    pport, sport, seen = proxied
    status, _, _ = raw_exchange(pport, raw_post(sport, [f"Content-Length: {length}"], b"abc"))
    assert status == 400 and seen == []


def test_body_shorter_than_content_length_is_400(proxied):
    pport, sport, seen = proxied
    data = raw_post(sport, ["Content-Length: 10"], b"abc")
    status, _, _ = raw_exchange(pport, data, half_close=True)
    assert status == 400 and seen == []


@pytest.mark.parametrize(
    "chunks", [b"-5\r\nhello\r\n0\r\n\r\n", b"zz\r\nhello\r\n0\r\n\r\n", b"", b"a\r\nabc"]
)
def test_bad_chunked_body_is_400(proxied, chunks):
    pport, sport, seen = proxied
    data = raw_post(sport, ["Transfer-Encoding: chunked"], chunks)
    status, _, _ = raw_exchange(pport, data, half_close=True)
    assert status == 400 and seen == []


def test_lowercase_content_length_not_duplicated(proxied):
    pport, sport, seen = proxied
    status, _, _ = raw_exchange(pport, raw_post(sport, ["content-length: 3"], b"abc"))
    assert status == 201
    names = [k.lower() for k, _ in _STUBS[-1].raw_headers[0]]
    assert names.count("content-length") == 1
    assert seen[0][3] == b"abc"


def test_repeated_request_headers_preserved(proxied):
    pport, sport, _seen = proxied
    request = (
        f"GET http://localhost:{sport}/x HTTP/1.1\r\nHost: localhost:{sport}\r\n"
        "X-Rep: one\r\nX-Other: mid\r\nX-Rep: two\r\n\r\n"
    ).encode()
    status, _, _ = raw_exchange(pport, request)
    assert status == 201
    sent = _STUBS[-1].raw_headers[0]
    assert [v for k, v in sent if k.lower() == "x-rep"] == ["one", "two"]
    assert [k for k, _ in sent if k.lower().startswith("x-")] == ["X-Rep", "X-Other", "X-Rep"]


def test_204_has_no_length_and_no_body(proxied):
    pport, sport, _seen = proxied
    status, headers, rest = raw_exchange(
        pport,
        f"GET http://localhost:{sport}/nocontent HTTP/1.1\r\nHost: localhost:{sport}\r\n\r\n".encode(),
    )
    assert status == 204
    assert "content-length" not in [k for k, _ in headers]
    assert rest == b""


def test_single_date_and_server_header(proxied):
    pport, sport, _seen = proxied
    _, headers, _ = raw_exchange(
        pport,
        f"GET http://localhost:{sport}/x HTTP/1.1\r\nHost: localhost:{sport}\r\n\r\n".encode(),
    )
    names = [k for k, _ in headers]
    assert names.count("date") == 1 and names.count("server") == 1
    assert names.count("content-length") == 1


def test_truncated_upstream_response_gives_502(proxied):
    pport, sport, _seen = proxied
    status, _, _ = raw_exchange(
        pport,
        f"GET http://localhost:{sport}/trunc HTTP/1.1\r\nHost: localhost:{sport}\r\n\r\n".encode(),
    )
    assert status == 502


@pytest.mark.parametrize(
    "host", ["evil.com", "localhost.evil.com", "127.0.0.1.nip.io", "169.254.169.254"]
)
def test_other_host_refused_and_stub_untouched(proxied, host):
    pport, sport, seen = proxied
    status, _, body = via_proxy(pport, "GET", f"http://{host}:{sport}/secret")
    assert status == 403 and b"refused" in body
    assert seen == []


def test_wrong_port_refused(proxied):
    pport, sport, seen = proxied
    status, _, _ = via_proxy(pport, "GET", f"http://localhost:{sport + 1}/")
    assert status == 403 and seen == []


def test_default_port_refused(proxied):
    pport, _, seen = proxied
    status, _, _ = via_proxy(pport, "GET", "http://localhost/")
    assert status == 403 and seen == []


def test_connect_refused(proxied):
    pport, sport, seen = proxied
    status, _, body = via_proxy(pport, "CONNECT", f"localhost:{sport}")
    assert status == 403 and b"tunnels" in body
    assert seen == []


def test_https_url_refused(proxied):
    pport, sport, seen = proxied
    status, _, _ = via_proxy(pport, "GET", f"https://localhost:{sport}/")
    assert status == 403 and seen == []


def test_relative_url_refused(proxied):
    pport, sport, seen = proxied
    status, _, _ = via_proxy(pport, "GET", "/bucket/key", headers={"Host": f"localhost:{sport}"})
    assert status == 403 and seen == []


def test_upstream_down_gives_502():
    dead = _free_port()
    saved = proxy.Handler.upstream_host, proxy.Handler.upstream_port
    proxy.Handler.upstream_host, proxy.Handler.upstream_port = "127.0.0.1", dead
    psrv = _serve(proxy.Handler)
    try:
        status, _, _ = via_proxy(psrv.server_address[1], "GET", f"http://localhost:{dead}/")
        assert status == 502
    finally:
        psrv.shutdown()
        psrv.server_close()
        proxy.Handler.upstream_host, proxy.Handler.upstream_port = saved


# ---------------------------------------------------------------- env.sh


def source_env(extra=None, tail="env -0"):
    base = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/nonexistent"}
    result = subprocess.run(
        ["bash", "-c", f'source "{ENV_SH}" && {tail}'],
        env=base | (extra or {}),
        capture_output=True,
        check=True,
    )
    pairs = (item.split("=", 1) for item in result.stdout.decode().split("\0") if "=" in item)
    return dict(pairs)


def test_env_sh_exports_fake_values():
    env = source_env()
    assert env["AWS_ACCESS_KEY_ID"] == "test"
    assert env["AWS_SECRET_ACCESS_KEY"] == "test"
    assert env["AWS_REGION"] == "eu-west-1" and env["AWS_DEFAULT_REGION"] == "eu-west-1"
    assert env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:4566"
    assert env["AWS_CONFIG_FILE"] == "/dev/null"
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["IDPS_EMULATOR_ACCOUNT"] == "000000000000"
    assert env["CHECKPOINT_DISABLE"] == "1"


def test_env_sh_unsets_dangerous_vars():
    dirty = {name: "x" for name in guard.BLOCKED_VARS} | {
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": "x",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "realsecret",
        "AWS_ENDPOINT_URL": "https://sts.amazonaws.com",
        "AWS_CONFIG_FILE": "/home/me/.aws/config",
        "AWS_ENDPOINT_URL_S3": "https://s3.amazonaws.com",
        "AWS_ENDPOINT_URL_STS": "https://sts.amazonaws.com",
        "AWS_ENDPOINT_URL_IAM_IDENTITY_CENTER": "https://x",
        "NO_PROXY": "everything.example",
        "no_proxy": "everything.example",
    }
    env = source_env(dirty)
    for name in list(guard.BLOCKED_VARS) + ["AWS_CONTAINER_AUTHORIZATION_TOKEN"]:
        assert name not in env
    assert not [n for n in env if n.startswith("AWS_ENDPOINT_URL_")]
    assert env["NO_PROXY"] == "127.0.0.1,localhost"
    assert env["no_proxy"] == "127.0.0.1,localhost"
    assert env["AWS_ACCESS_KEY_ID"] == "test"
    assert env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:4566"
    assert safe_problems(env) == []


def test_env_sh_result_passes_guard():
    assert safe_problems(source_env()) == []


def test_env_sh_syntax():
    subprocess.run(["bash", "-n", str(ENV_SH)], check=True)


# ---------------------------------------------------------------- tf.sh


def test_tf_sh_syntax():
    subprocess.run(["bash", "-n", str(TF_SH)], check=True)


@pytest.mark.skipif(moto_up(), reason="emulator is running, so the guard would pass")
@pytest.mark.skipif(not (ROOT / ".venv" / "bin" / "python").exists(), reason="no repo venv")
@pytest.mark.parametrize("cmd", ["plan", "apply", "destroy", "init"])
def test_tf_sh_refuses_without_emulator_and_never_starts_terraform(tmp_path, cmd):
    marker = tmp_path / "terraform-started"
    fake_tf = tmp_path / "terraform"
    fake_tf.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    fake_tf.chmod(0o755)
    work = tmp_path / "work"
    result = subprocess.run(
        ["bash", str(TF_SH), cmd],
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(tmp_path),
            "TERRAFORM": str(fake_tf),
            "IDPS_CLOUD_TF_DIR": str(work),
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_PROFILE": "prod",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode != 0
    assert "REFUSED" in result.stderr
    assert not marker.exists()
    assert not work.exists()  # refused before anything was copied


# ---------------------------------------------------------------- live emulator


@pytest.mark.skipif(not moto_up(), reason="Moto is not running on 127.0.0.1:4566")
def test_live_emulator_passes_guard_and_is_account_zero():
    env = source_env()
    assert guard.problems(env) == []
    assert guard._account(env) == "000000000000"


# ---------------------------------------------------------------- tf.sh argument checks
# These run before the guard, so they are the same whether or not Moto is up.

VENV_PY = ROOT / ".venv" / "bin" / "python"
BASE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def make_stub_tf(tmp_path):
    """A stand-in for terraform that records how it was called."""
    out = tmp_path / "out"
    out.mkdir()
    stub_tf = tmp_path / "terraform"
    stub_tf.write_text(
        "#!/bin/sh\n"
        f'touch "{out}/started"\n'
        f'printf "%s\\n" "$@" > "{out}/args"\n'
        f'env > "{out}/env"\n'
        f'ls -A > "{out}/ls"\n'
        'exit "${STUB_EXIT:-0}"\n'
    )
    stub_tf.chmod(0o755)
    return stub_tf, out


def run_tf(tmp_path, args, work=None, extra_env=None):
    stub_tf, out = make_stub_tf(tmp_path)
    env = {
        "PATH": BASE_PATH,
        "HOME": str(tmp_path),
        "TERRAFORM": str(stub_tf),
        "IDPS_CLOUD_TF_DIR": str(work or tmp_path / "work"),
    } | (extra_env or {})
    result = subprocess.run(
        ["bash", str(TF_SH), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return result, out


@pytest.mark.parametrize(
    "cmd", ["console", "-chdir=../infra", "import", "force-unlock", "workspace"]
)
def test_tf_sh_unknown_subcommand_refused(tmp_path, cmd):
    result, out = run_tf(tmp_path, [cmd])
    assert result.returncode == 2
    assert "not allowed" in result.stderr
    assert not (out / "started").exists()
    assert not (tmp_path / "work").exists()


@pytest.mark.parametrize(
    "option",
    [
        "-chdir=../infra",
        "-state=/tmp/real.tfstate",
        "-var-file=prod.tfvars",
        "-backend-config=bucket=real",
        "-backup=x",
        "-plugin-dir=/x",
    ],
)
@pytest.mark.parametrize("cmd", ["plan", "apply", "init"])
def test_tf_sh_forbidden_option_refused(tmp_path, cmd, option):
    result, out = run_tf(tmp_path, [cmd, "-input=false", option])
    assert result.returncode == 2
    assert "not allowed" in result.stderr
    assert not (out / "started").exists()


# ---------------------------------------------------------------- tf.sh with the emulator up

needs_moto = pytest.mark.skipif(not moto_up(), reason="Moto is not running on 127.0.0.1:4566")
needs_venv = pytest.mark.skipif(not VENV_PY.exists(), reason="no repo venv")


@needs_moto
@needs_venv
def test_tf_sh_refuses_non_empty_unmarked_work_dir(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "precious.txt").write_text("keep me")
    (work / "sub").mkdir()
    (work / "sub" / "x.tf").write_text("x")
    result, out = run_tf(tmp_path, ["validate"], work=work)
    assert result.returncode == 1
    assert "refusing to sync" in result.stderr
    assert not (out / "started").exists()
    assert sorted(p.name for p in work.iterdir()) == ["precious.txt", "sub"]
    assert (work / "precious.txt").read_text() == "keep me"


def _port_closed(port, wait=5.0):
    import time

    end = time.time() + wait
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return True
        time.sleep(0.1)
    return False


def _parse_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


@needs_moto
@needs_venv
def test_tf_sh_validate_runs_behind_proxy_and_propagates_exit(tmp_path):
    work = tmp_path / "work"
    result, out = run_tf(tmp_path, ["validate"], work=work, extra_env={"STUB_EXIT": "3"})
    assert result.returncode == 3, result.stderr
    assert (out / "args").read_text().splitlines() == ["validate"]
    assert (work / ".idps-cloud-tf").exists()
    assert (work / "emulator_override.tf").exists()
    # the TLS-only Deny workaround is copied into the work copy of the bucket module only
    copied = work / "modules" / "secure_bucket" / "secure_bucket_override.tf"
    assert copied.read_text() == (CLOUD / "terraform" / "secure_bucket_override.tf").read_text()
    assert not list(work.rglob("*.tfvars")) and not list(work.rglob("*.tfvars.json"))
    env = _parse_env(out / "env")
    assert env["TF_VAR_admin_cidrs"] == '["203.0.113.25/32"]'
    import re

    m = re.fullmatch(r"http://127\.0\.0\.1:(\d+)", env["HTTP_PROXY"])
    assert m and env["HTTPS_PROXY"] == env["HTTP_PROXY"]
    assert "NO_PROXY" not in env and "no_proxy" not in env
    assert env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:4566"
    assert _port_closed(int(m.group(1))), "egress proxy was left running"


@needs_moto
@needs_venv
def test_tf_sh_init_has_no_proxy_and_passes_args_exactly(tmp_path):
    work = tmp_path / "work"
    result, out = run_tf(tmp_path, ["init", "-input=false", "-upgrade"], work=work)
    assert result.returncode == 0, result.stderr
    assert (out / "args").read_text().splitlines() == ["init", "-input=false", "-upgrade"]
    env = _parse_env(out / "env")
    assert "HTTP_PROXY" not in env and "HTTPS_PROXY" not in env
    assert "http_proxy" not in env and "https_proxy" not in env


@needs_moto
@needs_venv
def test_tf_sh_reuses_its_own_work_dir(tmp_path):
    work = tmp_path / "work"
    first = tmp_path / "one"
    first.mkdir()
    assert run_tf(first, ["validate"], work=work)[0].returncode == 0
    second = tmp_path / "two"
    second.mkdir()
    result, out = run_tf(second, ["validate"], work=work)
    assert result.returncode == 0, result.stderr
    assert (out / "started").exists()


# ---------------------------------------------------------------- bucket policy override (C3)


def test_secure_bucket_override_never_touches_infra_and_the_real_tls_deny_is_intact():
    module = ROOT / "infra" / "modules" / "secure_bucket" / "main.tf"
    text = module.read_text()
    # the real design: Deny s3:* for everyone when aws:SecureTransport is false
    assert 'sid     = "DenyInsecureTransport"' in text and 'effect  = "Deny"' in text
    assert 'actions = ["s3:*"]' in text
    assert 'variable = "aws:SecureTransport"' in text and 'values   = ["false"]' in text
    assert "BypassGovernanceRetention" not in text
    # the emulator-only workaround lives under lab/cloud and nowhere in infra/
    assert not list((ROOT / "infra").rglob("*override*.tf"))
    assert not list((ROOT / "infra").rglob("secure_bucket_override*"))
    override = (CLOUD / "terraform" / "secure_bucket_override.tf").read_text()
    assert '"DenyInsecureTransport"' in override and "BypassGovernanceRetention" in override
    assert 's3:*"' not in override
    script = (CLOUD / "tf.sh").read_text()
    assert 'cp "$repo/lab/cloud/terraform/secure_bucket_override.tf" "$work/modules/secure_bucket/"' in script
    assert "$repo/infra" not in script.split("secure_bucket_override.tf", 1)[1].splitlines()[0]


# ---------------------------------------------------------------- static checks

SERVICE_BY_PREFIX = [
    ("s3_bucket", ["s3", "s3control"]),
    ("iam_", ["iam"]),
    ("kms_", ["kms"]),
    ("ssm_", ["ssm"]),
    ("budgets_", ["budgets"]),
    ("caller_identity", ["sts"]),
    ("partition", []),
    ("availability_zones", ["ec2"]),
    ("default_security_group", ["ec2"]),
    ("vpc", ["ec2"]),
    ("subnet", ["ec2"]),
    ("route", ["ec2"]),
    ("internet_gateway", ["ec2"]),
    ("security_group", ["ec2"]),
    ("network_acl", ["ec2"]),
    ("instance", ["ec2"]),
    ("eip", ["ec2"]),
    ("flow_log", ["ec2"]),
]


def test_every_aws_service_in_infra_has_an_emulator_endpoint():
    import re

    files = list((ROOT / "infra").glob("*.tf")) + list((ROOT / "infra" / "modules").rglob("*.tf"))
    assert files
    used = set()
    unmapped = set()
    for f in files:
        for m in re.finditer(
            r'^(?:resource|data)\s+"aws_([a-z0-9_]+)"', f.read_text(), re.MULTILINE
        ):
            name = m.group(1)
            for prefix, services in SERVICE_BY_PREFIX:
                if name.startswith(prefix):
                    used.update(services)
                    break
            else:
                unmapped.add(name)
    assert not unmapped, f"add these to SERVICE_BY_PREFIX: {sorted(unmapped)}"
    override = (CLOUD / "terraform" / "emulator_override.tf").read_text()
    endpoints = set(
        re.findall(
            r'^\s*([a-z0-9_]+)\s*=\s*"http://(?:127\.0\.0\.1|localhost):4566"',
            override,
            re.MULTILINE,
        )
    )
    assert used <= endpoints, f"no emulator endpoint for {sorted(used - endpoints)}"


# ---------------------------------------------------------------- git


def test_no_lab_cloud_file_is_git_ignored():
    if subprocess.run(["git", "rev-parse"], cwd=ROOT, capture_output=True, check=False).returncode:
        pytest.skip("not a git checkout")
    files = [p for p in CLOUD.rglob("*") if p.is_file()]
    assert files
    for path in files:
        rel = path.relative_to(ROOT)
        r = subprocess.run(["git", "check-ignore", "-q", str(rel)], cwd=ROOT, check=False)
        assert r.returncode == 1, f"{rel} is git-ignored (or git failed: {r.returncode})"


# ---------------------------------------------------------------- live: emulator network isolation


def _running(name):
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


needs_containers = pytest.mark.skipif(
    not (moto_up() and _running("idps-cloud-moto") and _running("idps-cloud-moto-net")),
    reason="docker or the idps-cloud containers are not available",
)


@needs_containers
def test_emulator_container_cannot_reach_the_internet():
    code = "import socket;s=socket.socket();s.settimeout(5);s.connect(('1.1.1.1',443))"
    r = subprocess.run(
        ["docker", "exec", "idps-cloud-moto", "python", "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert r.returncode != 0, "the emulator container reached 1.1.1.1:443"


@needs_containers
def test_emulator_netns_has_no_default_route():
    r = subprocess.run(
        ["docker", "exec", "idps-cloud-moto-net", "ip", "route"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip()
    assert not any(line.startswith("default") for line in r.stdout.splitlines())
