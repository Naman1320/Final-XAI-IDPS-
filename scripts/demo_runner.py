#!/usr/bin/env python3
"""Host-side demo runner for the SOC dashboard's "Run demo" button.

The SOC is isolated from the lab attacker, so this runs on the student's machine: it polls the
SOC for a demo run and executes FIXED lab attack commands (the STEPS table below is the only thing
it will ever run; unknown step keys are reported "skipped"). Python stdlib only.

    export IDPS_SOC_DEMO_TOKEN=...      # never passed on the command line, never printed
    python scripts/demo_runner.py --ca-file path/to/ca.pem

Seams for tests: `opener` (anything with .open(req, timeout=)) and `executor`
(callable(argv, timeout, should_abort, env=None) -> (returncode, output, aborted); `env` is
only passed for the step that needs the lab password, as extra variables for that one subprocess).
A returncode of TIMED_OUT (-1) with aborted False means the host-side timeout killed the command.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

TOKEN_ENV = "IDPS_SOC_DEMO_TOKEN"
PASSWORD_KEY = "LAB_VICTIM_PASSWORD"
HOST_GRACE = 20  # the host-side timeout is the step's in-container limit plus this
CANCEL_CHECK_SECONDS = 15  # also how often the SOC hears from us while a step runs (heartbeat)
NOTE_MAX = 200
OUTPUT_CAP = 16_384  # bytes of command output kept (the tail); the rest is read and dropped
TIMED_OUT = -1
MIN_POLL, MAX_POLL = 1.0, 10.0  # --poll-seconds; the SOC calls a runner offline after 30 s
MAX_BACKOFF = 15.0
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class Step(NamedTuple):
    script: str  # path inside the attacker container
    args: tuple[str, ...]
    needs_password: bool
    limit: int  # seconds, enforced in the container by `timeout` and on the host with HOST_GRACE
    ok_codes: tuple[int, ...] = (0,)  # exit codes that count as success


# key -> Step. dos.sh wraps hping3 in `timeout 20`, whose normal end is exit code 124.
STEPS: dict[str, Step] = {
    "portscan": Step("/attacks/portscan.sh", (), False, 100),
    "ssh_bruteforce": Step("/attacks/ssh_bruteforce.sh", (), True, 100),
    "syn_flood": Step("/attacks/dos.sh", ("syn", "u500"), False, 40, ok_codes=(0, 124)),
}
SETTLE = "settle"
SAFE_ENV_PREFIXES = ("DOCKER_",)  # DOCKER_HOST, DOCKER_CONFIG, DOCKER_CONTEXT ...


def minimal_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment for a subprocess: PATH, HOME, DOCKER_* and `extra`. Never the SOC token."""
    env = {k: v for k, v in os.environ.items()
           if (k in ("PATH", "HOME") or k.startswith(SAFE_ENV_PREFIXES)) and k != TOKEN_ENV}
    env.update(extra or {})
    return env


class StepFailed(Exception):
    pass


def clean_note(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Plain text, no control characters, secrets masked, at most NOTE_MAX chars."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return _CONTROL.sub("", text).strip()[:NOTE_MAX]


def last_line(output: str) -> str:
    lines = [ln for ln in output.splitlines() if _CONTROL.sub("", ln).strip()]
    return lines[-1] if lines else ""


def read_env_value(env_file: Path, key: str) -> str | None:
    """Read KEY=VALUE as plain text (never sourced/evaluated). Strips one pair of matching quotes.

    Limitation: this is not docker compose's parser. Inline comments (`KEY=v # note`) and `$VAR`
    interpolation are NOT interpreted, so such a value is read literally. Keep the password line
    simple, as lab/.env.example does."""
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError:
        return None
    value = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() != key:
            continue
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        value = v  # last assignment wins, like a real env file
    return value or None


def subprocess_executor(argv: list[str], timeout: float, should_abort: Callable[[], bool],
                        env: dict[str, str] | None = None):
    """Run argv (no shell) with a minimal environment (minimal_env). Polls should_abort every
    CANCEL_CHECK_SECONDS; kills the command on abort or timeout (TIMED_OUT). `env` adds variables
    to this subprocess's environment only (never to argv). Only the last OUTPUT_CAP bytes of
    output are kept, so a chatty tool cannot fill memory.

    Killing here stops only the local client (for example `docker compose exec`); the caller
    cleans up inside the container (Runner._stop_in_container)."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=minimal_env(env))
    tail = bytearray()

    def drain() -> None:
        while chunk := proc.stdout.read(4096):
            tail.extend(chunk)
            if len(tail) > OUTPUT_CAP:
                del tail[:len(tail) - OUTPUT_CAP]

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()

    def text() -> str:
        reader.join(5)  # a grandchild holding the pipe open must not hang us
        return bytes(tail).decode("utf-8", errors="replace")

    deadline = time.monotonic() + timeout
    next_check = time.monotonic() + CANCEL_CHECK_SECONDS
    try:
        while True:
            try:
                proc.wait(timeout=1)
                return proc.returncode, text(), False
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            if now >= deadline:
                proc.kill()
                proc.wait()
                return TIMED_OUT, text() + f"\ntimed out after {timeout:g}s", False
            if now >= next_check:
                next_check = now + CANCEL_CHECK_SECONDS
                if should_abort():
                    proc.kill()
                    proc.wait()
                    return TIMED_OUT, text(), True
    except BaseException:
        proc.kill()
        proc.wait()
        raise


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the token would go to wherever the SOC (or whoever answers) says."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def build_opener(ca_file: str | None) -> urllib.request.OpenerDirector:
    """Production opener: TLS verification is always on (system CAs, plus ca_file if given), no
    redirects, and no proxies (an empty ProxyHandler replaces the one that reads HTTPS_PROXY)."""
    ctx = ssl.create_default_context(cafile=ca_file)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))


def read_token(environ=os.environ) -> str:
    return environ.get(TOKEN_ENV, "").strip()  # a pasted trailing newline must not break the match


class Runner:
    def __init__(
        self,
        url: str,
        token: str,
        opener,
        executor=subprocess_executor,
        lab_dir: str | Path = "./lab",
        poll_seconds: float = 3,
        settle_seconds: float = 150,
        sleep: Callable[[float], None] = time.sleep,
        out=None,
    ):
        self.url = url.rstrip("/")
        self.token = token
        self.opener = opener
        self.executor = executor
        self.lab_dir = Path(lab_dir)
        self.poll_seconds = poll_seconds
        self.settle_seconds = settle_seconds
        self.sleep = sleep
        self.out = out if out is not None else sys.stdout
        self._last_error: str | None = None
        self._password: str | None = None

    # ---- output -------------------------------------------------------------------------
    def log(self, msg: str) -> None:
        msg = _CONTROL.sub("", self._mask(msg))
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=self.out, flush=True)

    def _mask(self, text: str) -> str:
        for s in (self.token, self._password):
            if s:
                text = text.replace(s, "***")
        return text

    # ---- HTTP ---------------------------------------------------------------------------
    def _request(self, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.url + path,
            data=data,
            method="POST" if payload is not None else "GET",
            headers={"X-Demo-Token": self.token, "Content-Type": "application/json"},
        )
        with self.opener.open(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def poll(self) -> dict | None:
        return self._request("/demo/runner/next").get("run")

    def report(self, run_id: str, step_key: str, status: str, note: str = "") -> bool:
        """Returns True if the run was cancelled. Retries briefly; if the SOC stays unreachable
        the run is abandoned (treated as cancelled) rather than attacking unsupervised."""
        payload = {
            "run_id": run_id,
            "step_key": step_key,
            "status": status,
            "note": clean_note(note, (self.token, self._password or "")),
        }
        for attempt in range(3):
            try:
                return bool(self._request("/demo/runner/report", payload).get("cancelled"))
            except urllib.error.HTTPError as e:
                if e.code in (401, 403, 404, 409, 429):  # the SOC said no: retrying cannot help
                    self.log(f"SOC refused the report (HTTP {e.code}); stopping this run")
                    return True
                self.log(f"report failed (HTTP {e.code}), retrying")
                self.sleep(1 + attempt)
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.log(f"report failed ({type(e).__name__}), retrying")
                self.sleep(1 + attempt)
        self.log("SOC unreachable while reporting; abandoning this run")
        return True

    # ---- run handling -------------------------------------------------------------------
    def lab_is_up(self) -> bool:
        argv = self._compose("ps", "--status", "running", "--services")
        try:
            code, output, _ = self.executor(argv, 30, lambda: False)
        except OSError:
            return False
        return code == 0 and "attacker" in output.split()

    def _compose(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.lab_dir / "docker-compose.yml"), *args]

    def handle_run(self, run: dict) -> None:
        run_id = clean_note(str(run["id"]))  # from the network: no control characters in logs
        steps = [clean_note(str(s.get("key"))) for s in run.get("steps", [])]
        self.log(f"run {run_id}: {', '.join(steps)}")
        first_real = next((k for k in steps if k in STEPS), None)
        if first_real and not self.lab_is_up():
            self.log("lab is not running (start it with docker compose up -d)")
            self.report(run_id, first_real, "failed", "lab is not running")
            return
        for key in steps:
            try:
                if key == SETTLE:
                    cancelled = self._settle(run_id)
                elif key in STEPS:
                    cancelled = self._run_step(run_id, key)
                else:
                    self.log(f"step {key}: not in the fixed table, skipped")
                    cancelled = self.report(run_id, key, "skipped", "unknown step, not executed")
            except StepFailed as e:
                self.log(f"step {key}: FAILED - {e}")
                self.report(run_id, key, "failed", str(e))
                return
            if cancelled:
                self.log("run cancelled, stopping")
                return
        self.log(f"run {run_id}: finished")

    def _stop_in_container(self, script: str) -> None:
        """Best effort: killing the host `docker compose exec` client leaves the command running
        inside the container, so kill it there too. Fixed script names only, never SOC input."""
        try:
            self.executor(self._compose("exec", "-T", "attacker", "pkill", "-f", script),
                          15, lambda: False)
        except Exception as e:  # noqa: BLE001 - cleanup must never mask the real outcome
            self.log(f"could not stop {script} in the container ({type(e).__name__})")

    def _run_step(self, run_id: str, key: str) -> bool:
        step = STEPS[key]
        self.log(f"step {key}: starting")
        if self.report(run_id, key, "running", "started"):
            return True
        argv = self._compose("exec", "-T")
        env = None
        if step.needs_password:
            pw = read_env_value(self.lab_dir / ".env", PASSWORD_KEY)
            if not pw:
                raise StepFailed(f"{PASSWORD_KEY} not found in {self.lab_dir / '.env'}")
            self._password = pw
            # `-e NAME` without a value makes compose copy it from our own environment, so the
            # password never appears in the docker command line (visible in `ps`).
            argv += ["-e", PASSWORD_KEY]
            env = {PASSWORD_KEY: pw}
        # `timeout` inside the container ends the command (and its group) even if our docker client
        # is killed; fixed argv, no shell.
        argv += ["attacker", "timeout", "-k", "5", str(step.limit), step.script, *step.args]
        abort = lambda: self.report(run_id, key, "running", "still running")
        host_timeout = step.limit + HOST_GRACE
        try:
            if env:
                code, output, aborted = self.executor(argv, host_timeout, abort, env=env)
            else:
                code, output, aborted = self.executor(argv, host_timeout, abort)
        except OSError as e:
            raise StepFailed(f"could not start command: {type(e).__name__}") from None
        except BaseException:  # Ctrl-C and the like: the command must not outlive us
            self._stop_in_container(step.script)
            raise
        if aborted or code == TIMED_OUT:
            self._stop_in_container(step.script)  # before the next poll, so nothing overlaps
        if aborted:
            return True
        if code not in step.ok_codes:
            raise StepFailed(clean_note(last_line(output) or f"exit code {code}", (self._password or "",)))
        self.log(f"step {key}: done")
        return self.report(run_id, key, "done", "completed")

    def _settle(self, run_id: str) -> bool:
        self.log(f"step settle: waiting {self.settle_seconds:g}s for the detector to catch up")
        remaining = float(self.settle_seconds)
        while True:
            note = f"settling, {remaining:.0f}s left"
            if self.report(run_id, SETTLE, "running", note):
                return True
            if remaining <= 0:
                break
            chunk = min(CANCEL_CHECK_SECONDS, remaining)
            self.sleep(chunk)
            remaining -= chunk
        self.log("step settle: done")
        return self.report(run_id, SETTLE, "done", "settled")

    # ---- main loop ----------------------------------------------------------------------
    def serve(self, once: bool = False, max_polls: int | None = None) -> None:
        backoff = self.poll_seconds
        handled: set[str] = set()
        polls = 0
        while max_polls is None or polls < max_polls:
            polls += 1
            try:
                run = self.poll()
                if self._last_error is not None:
                    self.log("SOC reachable again")
                    self._last_error = None
                backoff = self.poll_seconds
            except urllib.error.HTTPError as e:
                self._poll_error(f"SOC answered HTTP {e.code}")
                backoff = min(backoff * 2, MAX_BACKOFF)
                run = None
            except (urllib.error.URLError, OSError, ValueError) as e:
                self._poll_error(f"cannot reach SOC ({type(e).__name__})")
                backoff = min(backoff * 2, MAX_BACKOFF)
                run = None
            else:
                if run and str(run.get("id")) not in handled:
                    handled.add(str(run["id"]))
                    self.handle_run(run)
                    if once:
                        return
            self.sleep(backoff)

    def _poll_error(self, msg: str) -> None:
        if msg != self._last_error:
            self._last_error = msg
            self.log(msg + "; retrying with backoff")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="https://127.0.0.1:8443")
    ap.add_argument("--ca-file", help="CA pem used to verify the SOC certificate")
    ap.add_argument("--lab-dir", default="./lab")
    ap.add_argument("--poll-seconds", type=float, default=3,
                    help=f"{MIN_POLL:g} to {MAX_POLL:g}")
    ap.add_argument("--settle-seconds", type=float, default=150)
    ap.add_argument("--once", action="store_true", help="handle at most one run, then exit")
    args = ap.parse_args(argv)

    if not MIN_POLL <= args.poll_seconds <= MAX_POLL:  # also rejects nan
        print(f"--poll-seconds must be {MIN_POLL:g} to {MAX_POLL:g}", file=sys.stderr)
        return 2
    token = read_token()
    if not token:
        print(f"set {TOKEN_ENV} in the environment first", file=sys.stderr)
        return 2
    if not args.url.lower().startswith("https://"):
        print("--url must be https://", file=sys.stderr)
        return 2
    if args.ca_file and not Path(args.ca_file).is_file():
        print(f"CA file not found: {args.ca_file}", file=sys.stderr)
        return 2

    runner = Runner(
        args.url,
        token,
        build_opener(args.ca_file),
        lab_dir=args.lab_dir,
        poll_seconds=args.poll_seconds,
        settle_seconds=args.settle_seconds,
    )
    runner.log(f"demo runner polling {args.url} every {args.poll_seconds:g}s (Ctrl-C to stop)")
    try:
        runner.serve(once=args.once)
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
