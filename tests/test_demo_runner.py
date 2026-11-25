"""scripts/demo_runner.py against a fake local HTTP SOC and a fake command executor."""

import importlib.util
import io
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location("demo_runner", _SCRIPTS / "demo_runner.py")
dr = importlib.util.module_from_spec(_spec)
sys.modules["demo_runner"] = dr
_spec.loader.exec_module(dr)

TOKEN = "tok-SECRET-123"
PASSWORD = "p@ss(w)ord$HOME;'x'&|<>"


class FakeSoc:
    def __init__(self, steps, cancel_on_report=None):
        self.run = {"id": "r1", "status": "running", "steps": [{"key": k} for k in steps]}
        self.reports = []
        self.tokens = []
        self.cancel_on_report = cancel_on_report  # cancel from the Nth report on (1-based)
        soc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                body = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                soc.tokens.append(self.headers.get("X-Demo-Token"))
                self._send({"run": soc.run})

            def do_POST(self):
                soc.tokens.append(self.headers.get("X-Demo-Token"))
                n = int(self.headers["Content-Length"])
                soc.reports.append(json.loads(self.rfile.read(n)))
                c = soc.cancel_on_report is not None and len(soc.reports) >= soc.cancel_on_report
                self._send({"cancelled": c})

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def statuses(self):
        return [(r["step_key"], r["status"]) for r in self.reports]


@pytest.fixture
def make(tmp_path):
    servers = []
    (tmp_path / ".env").write_text(f"OTHER=1\nLAB_VICTIM_PASSWORD='{PASSWORD}'\n")

    def _make(steps, cancel_on_report=None, results=None, lab_up=True):
        soc = FakeSoc(steps, cancel_on_report)
        servers.append(soc)
        calls = []
        envs = []
        results = results or {}

        def executor(argv, timeout, should_abort, env=None):
            calls.append(argv)
            envs.append(env)
            assert isinstance(argv, list)
            if "ps" in argv:
                return 0, ("attacker\nvictim\n" if lab_up else "victim\n"), False
            script = next(a for a in argv if a.startswith("/attacks/"))
            code, output = results.get(script, (0, "ok"))
            return code, output, False

        out = io.StringIO()
        sleeps = []
        r = dr.Runner(
            soc.url, TOKEN, urllib.request.build_opener(), executor, tmp_path,
            poll_seconds=0, settle_seconds=30, sleep=sleeps.append, out=out,
        )
        r.envs = envs
        return soc, r, calls, out, sleeps

    yield _make
    for s in servers:
        s.httpd.shutdown()


def scripts_run(calls):
    return [a for c in calls if "pkill" not in c for a in c if a.startswith("/attacks/")]


def test_full_run_and_fixed_argv(make):
    soc, r, calls, out, sleeps = make(["portscan", "ssh_bruteforce", "syn_flood", "settle"])
    r.serve(once=True)
    assert scripts_run(calls) == [
        "/attacks/portscan.sh", "/attacks/ssh_bruteforce.sh", "/attacks/dos.sh"
    ]
    dos = calls[-1]
    assert dos[-3:] == ["/attacks/dos.sh", "syn", "u500"]
    assert dos[dos.index("attacker"):dos.index("/attacks/dos.sh")] == [
        "attacker", "timeout", "-k", "5", "40"]  # ends in the container even if our client dies
    assert dos[:3] == ["docker", "compose", "-f"]
    assert ("settle", "done") in soc.statuses()
    assert sum(sleeps) == pytest.approx(30)


def test_unknown_step_never_executed(make):
    soc, r, calls, out, _ = make(["rm_rf", "portscan"])
    r.serve(once=True)
    assert scripts_run(calls) == ["/attacks/portscan.sh"]
    assert not any("rm_rf" in a for c in calls for a in c)
    assert ("rm_rf", "skipped") in soc.statuses()


def test_argv_has_no_shell(make):
    soc, r, calls, out, _ = make(["portscan", "ssh_bruteforce", "syn_flood"])
    r.serve(once=True)
    for argv in calls:
        assert all(isinstance(a, str) for a in argv)
        assert argv[0] == "docker"
        assert not any(a in ("sh", "bash", "-c") for a in argv)
    import inspect
    assert "shell=True" not in inspect.getsource(dr).replace('"shell=True" not in', "")


def test_password_from_env_with_special_chars_not_printed(make):
    soc, r, calls, out, _ = make(["ssh_bruteforce"])
    r.serve(once=True)
    argv = next(c for c in calls if "/attacks/ssh_bruteforce.sh" in c)
    assert "-e" in argv and argv[argv.index("-e") + 1] == "LAB_VICTIM_PASSWORD"  # name only
    assert argv.index("-e") < argv.index("attacker")
    assert not any(PASSWORD in a for c in calls for a in c)  # never in the docker argv
    assert r.envs == [None, {"LAB_VICTIM_PASSWORD": PASSWORD}]  # only the ssh step gets it
    assert PASSWORD not in out.getvalue()
    assert all(PASSWORD not in json.dumps(rep) for rep in soc.reports)


def test_password_missing_fails_step(make, tmp_path):
    (tmp_path / ".env").write_text("OTHER=1\n")
    soc, r, calls, out, _ = make(["ssh_bruteforce", "syn_flood"])
    r.serve(once=True)
    assert scripts_run(calls) == []
    assert ("ssh_bruteforce", "failed") in soc.statuses()
    assert "syn_flood" not in [k for k, _ in soc.statuses()]


def test_read_env_value_variants(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\nexport K="a b(c)"\nJ=plain\nQ=\'x\'\n')
    assert dr.read_env_value(f, "K") == "a b(c)"
    assert dr.read_env_value(f, "J") == "plain"
    assert dr.read_env_value(f, "Q") == "x"
    assert dr.read_env_value(f, "NOPE") is None
    assert dr.read_env_value(tmp_path / "missing", "K") is None


def test_cancel_mid_run_stops(make):
    # reports: 1 portscan running, 2 portscan done, 3 ssh running -> cancelled
    soc, r, calls, out, _ = make(["portscan", "ssh_bruteforce", "syn_flood"], cancel_on_report=3)
    r.serve(once=True)
    assert scripts_run(calls) == ["/attacks/portscan.sh"]
    assert "cancelled" in out.getvalue()


def test_cancel_during_settle(make):
    soc, r, calls, out, sleeps = make(["settle"], cancel_on_report=2)
    r.serve(once=True)
    assert ("settle", "done") not in soc.statuses()
    assert sum(sleeps) < 30


def test_executor_abort_flag_is_a_cancel_check(make):
    soc, r, calls, out, _ = make(["portscan", "syn_flood"])
    r.executor = lambda argv, t, abort, env=None: (0, "", False) if "ps" in argv else (-1, "", True)
    r.serve(once=True)
    assert ("portscan", "done") not in soc.statuses()
    assert "syn_flood" not in [k for k, _ in soc.statuses()]


def test_first_failure_stops_run(make):
    soc, r, calls, out, _ = make(
        ["portscan", "ssh_bruteforce", "syn_flood"],
        results={"/attacks/ssh_bruteforce.sh": (1, "x\nAuth failed\x1b[31m\n")},
    )
    r.serve(once=True)
    assert scripts_run(calls) == ["/attacks/portscan.sh", "/attacks/ssh_bruteforce.sh"]
    fail = [x for x in soc.reports if x["status"] == "failed"]
    assert len(fail) == 1 and fail[0]["step_key"] == "ssh_bruteforce"
    assert fail[0]["note"] == "Auth failed[31m"  # control chars stripped
    assert len(fail[0]["note"]) <= 200


def test_syn_flood_exit_124_is_success_but_other_codes_fail(make):
    # dos.sh wraps hping3 in `timeout 20`, whose normal end is 124
    soc, r, *_ = make(["syn_flood"], results={"/attacks/dos.sh": (124, "")})
    r.serve(once=True)
    assert soc.statuses() == [("syn_flood", "running"), ("syn_flood", "done")]
    soc, r, *_ = make(["syn_flood"], results={"/attacks/dos.sh": (1, "usage: dos.sh")})
    r.serve(once=True)
    assert soc.statuses()[-1] == ("syn_flood", "failed")
    assert soc.reports[-1]["note"] == "usage: dos.sh"


@pytest.mark.parametrize("key", ["portscan", "ssh_bruteforce"])
def test_124_fails_the_other_steps(make, key):
    script = dr.STEPS[key].script
    soc, r, *_ = make([key], results={script: (124, "")})
    r.serve(once=True)
    assert soc.statuses()[-1] == (key, "failed")


def test_note_truncated():
    assert len(dr.clean_note("a" * 500)) == 200


def test_lab_not_running(make):
    soc, r, calls, out, _ = make(["portscan", "syn_flood"], lab_up=False)
    r.serve(once=True)
    assert scripts_run(calls) == []
    assert soc.reports == [
        {"run_id": "r1", "step_key": "portscan", "status": "failed", "note": "lab is not running"}
    ]


def test_token_sent_but_never_printed(make):
    soc, r, calls, out, _ = make(["portscan", "settle"])
    r.serve(once=True)
    assert soc.tokens and set(soc.tokens) == {TOKEN}
    assert TOKEN not in out.getvalue()
    assert all(TOKEN not in a for c in calls for a in c)
    r.log(f"oops {TOKEN}")
    assert TOKEN not in out.getvalue()


def test_poll_errors_printed_once_with_backoff(tmp_path):
    out = io.StringIO()
    sleeps = []
    r = dr.Runner("http://127.0.0.1:1", TOKEN, urllib.request.build_opener(),
                  lab_dir=tmp_path, poll_seconds=3, sleep=sleeps.append, out=out)
    r.serve(max_polls=5)
    assert out.getvalue().count("cannot reach SOC") == 1
    assert sleeps == [6, 12, 15, 15, 15]  # never near the SOC's 30 s offline limit


def test_main_requires_env_token_and_https(monkeypatch, capsys):
    monkeypatch.delenv(dr.TOKEN_ENV, raising=False)
    assert dr.main([]) == 2
    monkeypatch.setenv(dr.TOKEN_ENV, TOKEN)
    assert dr.main(["--url", "http://x"]) == 2


def test_no_token_cli_option():
    with pytest.raises(SystemExit):
        dr.main(["--token", "x"])


def test_production_opener_verifies_tls():
    op = dr.build_opener(None)
    h = next(h for h in op.handlers if h.__class__.__name__ == "HTTPSHandler")
    import ssl
    ctx = h._context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


# --- abort and timeout stop the command inside the container -------------------------------

def pkills(calls):
    return [c for c in calls if "pkill" in c]


def test_abort_kills_the_script_in_the_container_before_the_next_poll(make):
    soc, r, calls, *_ = make(["ssh_bruteforce", "syn_flood"])
    base = r.executor

    def executor(argv, timeout, abort, env=None):
        if "ssh_bruteforce.sh" in " ".join(argv) and "pkill" not in argv:
            calls.append(argv)
            return -1, "", True
        return base(argv, timeout, abort, env)

    r.executor = executor
    r.serve(once=True)
    (kill,) = pkills(calls)
    assert kill[-4:] == ["attacker", "pkill", "-f", "/attacks/ssh_bruteforce.sh"]
    assert calls.index(kill) == len(calls) - 1  # nothing ran after it
    assert "syn_flood" not in [k for k, _ in soc.statuses()]


def test_host_timeout_also_kills_in_the_container_and_fails_the_step(make):
    soc, r, calls, *_ = make(["portscan"])
    base = r.executor
    r.executor = lambda argv, t, a, env=None: (
        (-1, "partial\ntimed out after 120s", False) if "/attacks/portscan.sh" in argv and "pkill" not in argv
        else base(argv, t, a, env))
    r.serve(once=True)
    assert len(pkills(calls)) == 1 and pkills(calls)[0][-1] == "/attacks/portscan.sh"
    assert soc.statuses()[-1] == ("portscan", "failed")
    assert soc.reports[-1]["note"] == "timed out after 120s"


def test_ctrl_c_kills_in_the_container_and_propagates(make):
    _, r, calls, *_ = make(["portscan"])
    base = r.executor

    def executor(argv, t, a, env=None):
        if "/attacks/portscan.sh" in argv and "pkill" not in argv:
            raise KeyboardInterrupt
        return base(argv, t, a, env)

    r.executor = executor
    with pytest.raises(KeyboardInterrupt):
        r.serve(once=True)
    assert len(pkills(calls)) == 1 and pkills(calls)[0][-1] == "/attacks/portscan.sh"


def test_failing_cleanup_does_not_mask_the_outcome(make):
    _, r, _, out, _ = make(["portscan"])

    def executor(argv, t, a, env=None):
        if "pkill" in argv:
            raise OSError("docker gone")
        if "ps" in argv:
            return 0, "attacker\n", False
        return -1, "", True

    r.executor = executor
    r.serve(once=True)  # no exception
    assert "could not stop" in out.getvalue()


# --- subprocess_executor, with harmless real commands ---------------------------------------

def test_executor_runs_and_returns_output():
    code, output, aborted = dr.subprocess_executor(["echo", "hello"], 10, lambda: False)
    assert (code, output.strip(), aborted) == (0, "hello", False)
    code, output, aborted = dr.subprocess_executor(["sh", "-c", "echo oops >&2; exit 3"], 10,
                                                   lambda: False)
    assert code == 3 and "oops" in output and not aborted


def test_executor_timeout_kills():
    start = time.monotonic()
    code, output, aborted = dr.subprocess_executor(["sleep", "30"], 1, lambda: False)
    assert code == dr.TIMED_OUT and not aborted and "timed out after 1s" in output
    assert time.monotonic() - start < 10


def test_executor_abort_kills(monkeypatch):
    monkeypatch.setattr(dr, "CANCEL_CHECK_SECONDS", 0)
    asked = []
    start = time.monotonic()
    code, _, aborted = dr.subprocess_executor(
        ["sleep", "30"], 60, lambda: asked.append(1) or True)
    assert code == dr.TIMED_OUT and aborted and asked
    assert time.monotonic() - start < 10


def test_executor_keeps_only_the_tail_of_huge_output():
    script = ("i=0; while [ $i -lt 2000 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; "
              "i=$((i+1)); done; echo THE-END")
    code, output, _ = dr.subprocess_executor(["sh", "-c", script], 30, lambda: False)
    assert code == 0 and len(output) <= dr.OUTPUT_CAP
    assert output.rstrip().endswith("THE-END") and "line-0-" not in output  # the tail, not the head


def test_executor_environment_is_minimal(monkeypatch):
    monkeypatch.setenv(dr.TOKEN_ENV, TOKEN)
    monkeypatch.setenv("DOCKER_HOST", "unix:///x.sock")
    monkeypatch.setenv("SECRET_OTHER", "nope")
    _, output, _ = dr.subprocess_executor(["env"], 10, lambda: False,
                                          env={"LAB_VICTIM_PASSWORD": "pw1"})
    names = {ln.split("=", 1)[0] for ln in output.splitlines() if "=" in ln}
    assert "PATH" in names and "DOCKER_HOST" in names and "LAB_VICTIM_PASSWORD" in names
    assert dr.TOKEN_ENV not in names and "SECRET_OTHER" not in names
    assert TOKEN not in output
    _, output, _ = dr.subprocess_executor(["env"], 10, lambda: False)
    assert "LAB_VICTIM_PASSWORD" not in output


# --- report(): retries, abandonment and the SOC saying no ------------------------------------

class ScriptedOpener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return _Resp(o)


class _Resp:
    def __init__(self, obj):
        self.body = json.dumps(obj).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body


def http_error(code):
    return urllib.error.HTTPError("https://soc/x", code, "msg", {}, io.BytesIO(b"{}"))


def scripted_runner(outcomes, tmp_path):
    sleeps = []
    op = ScriptedOpener(outcomes)
    r = dr.Runner("https://soc", TOKEN, op, lab_dir=tmp_path, sleep=sleeps.append, out=io.StringIO())
    return r, op, sleeps


def test_report_retries_then_succeeds(tmp_path):
    r, op, sleeps = scripted_runner([urllib.error.URLError("down"), {"cancelled": False}], tmp_path)
    assert r.report("r1", "portscan", "running") is False
    assert op.calls == 2 and sleeps == [1]


def test_report_abandons_after_three_failures(tmp_path):
    r, op, sleeps = scripted_runner([urllib.error.URLError("down")] * 3, tmp_path)
    assert r.report("r1", "portscan", "running") is True  # treated as cancelled
    assert op.calls == 3 and sleeps == [1, 2, 3]
    assert "abandoning" in r.out.getvalue()


def test_report_retries_server_errors(tmp_path):
    r, op, _ = scripted_runner([http_error(503), {"cancelled": True}], tmp_path)
    assert r.report("r1", "portscan", "running") is True and op.calls == 2


@pytest.mark.parametrize("code", [401, 404, 409, 429])
def test_report_stops_at_once_when_the_soc_refuses(tmp_path, code):
    r, op, sleeps = scripted_runner([http_error(code)], tmp_path)
    assert r.report("r1", "portscan", "running") is True
    assert op.calls == 1 and sleeps == []
    assert f"HTTP {code}" in r.out.getvalue()


# --- token, redirects, proxies, poll interval -----------------------------------------------

def test_token_whitespace_is_stripped_and_still_matches(make, monkeypatch):
    monkeypatch.setenv(dr.TOKEN_ENV, "  " + TOKEN + "\n")
    token = dr.read_token()
    assert token == TOKEN
    soc, r, *_ = make(["portscan"])
    r.token = token
    r.serve(once=True)
    assert set(soc.tokens) == {TOKEN}  # no stray whitespace on the wire
    assert dr.read_token({}) == ""
    assert dr.read_token({dr.TOKEN_ENV: " \n"}) == ""


class Redirecting:
    def __init__(self):
        self.hits = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.hits.append((self.path, self.headers.get("X-Demo-Token")))
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{outer.httpd.server_port}/elsewhere")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


def test_redirects_are_refused():
    srv = Redirecting()
    try:
        req = urllib.request.Request(srv.url + "/start", headers={"X-Demo-Token": TOKEN})
        with pytest.raises(urllib.error.HTTPError) as exc:
            dr.build_opener(None).open(req, timeout=5)
        assert exc.value.code == 302
        assert [p for p, _ in srv.hits] == ["/start"]  # the redirect target was never requested
    finally:
        srv.httpd.shutdown()


def test_production_opener_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    op = dr.build_opener(None)
    # an empty ProxyHandler replaces the default one (it has no handlers, so the opener keeps none)
    assert not [h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)]
    srv = FakeSoc([])
    try:
        req = urllib.request.Request(srv.url + "/demo/runner/next")
        with op.open(req, timeout=5) as resp:  # a proxy on port 9 would have failed this
            assert resp.status == 200
    finally:
        srv.httpd.shutdown()


@pytest.mark.parametrize("value", ["0", "0.5", "11", "-1", "nan", "inf"])
def test_poll_seconds_is_validated(monkeypatch, value, capsys):
    monkeypatch.setenv(dr.TOKEN_ENV, TOKEN)
    assert dr.main(["--poll-seconds", value]) == 2
    assert "--poll-seconds" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["1", "3", "10"])
def test_poll_seconds_in_range_is_accepted(monkeypatch, value):
    monkeypatch.setenv(dr.TOKEN_ENV, TOKEN)
    seen = {}

    class Fake:
        def __init__(self, *a, poll_seconds, **kw):
            seen["poll"] = poll_seconds

        def log(self, m):
            pass

        def serve(self, once=False):
            pass

    monkeypatch.setattr(dr, "Runner", Fake)
    monkeypatch.setattr(dr, "build_opener", lambda ca: None)
    assert dr.main(["--poll-seconds", value]) == 0 and seen["poll"] == float(value)


def test_log_strips_control_characters_from_network_values(make):
    soc, r, _, out, _ = make(["portscan"])
    soc.run["id"] = "r1\x1b[2J\nFAKE"
    soc.run["steps"] = [{"key": "weird\rkey"}]
    r.serve(once=True)
    text = out.getvalue()
    assert "\x1b" not in text and "\r" not in text
    assert "FAKE" in text.replace("\n", "") and text.count("\nFAKE") == 0
