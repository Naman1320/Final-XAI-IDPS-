"""Host-side checks for deploy/tests/*.sh (standard library only). Run with `python3 -I`.

    api_check.py health         --base URL --cafile CA
    api_check.py login-state    --base URL --cafile CA --password-file F        -> mfa value
    api_check.py sensor-nocert  --sensor-url URL --cafile CA                    -> exit 0 if refused
    api_check.py sensor-post    --sensor-url URL --cafile CA --bundle DIR --count N   -> accepted
    api_check.py sensor-on-main --base URL --cafile CA --bundle DIR             -> HTTP status
    api_check.py snapshot       --base URL --cafile CA --password-file F --totp-file F
                                [--create-case TITLE]                          -> alerts=N cases=M

Passwords, tokens and TOTP secrets are read from files and never printed.
"""

import argparse
import base64
import hashlib
import hmac
import json
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def ctx(cafile, cert=None, key=None):
    c = ssl.create_default_context(cafile=cafile) if cafile else ssl._create_unverified_context()
    if cert:
        c.load_cert_chain(cert, key)
    return c


def call(url, cafile, method="GET", body=None, headers=None, cert=None, key=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, context=ctx(cafile, cert, key), timeout=15) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, None


def totp(secret: str, now=None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    step = int((time.time() if now is None else now) // 30)
    d = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 15
    return str((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


def read(path) -> str:
    return Path(path).read_text().strip()


def login(a):
    status, body = call(a.base + "/api/auth/login", a.cafile, "POST",
                        {"username": a.user, "password": read(a.password_file)})
    if not a.totp_file:  # an account without MFA (not an admin): the token comes at once
        assert status == 200 and body.get("access_token"), (status, body and body.get("mfa"))
        return {"Authorization": "Bearer " + body["access_token"]}
    assert status == 200 and body["mfa"] == "verify", (status, body and body.get("mfa"))
    for attempt in range(2):  # a code is valid once: after a recent login, wait for the next step
        status, tok = call(a.base + "/api/auth/mfa/verify", a.cafile, "POST",
                           {"mfa_token": body["mfa_token"], "code": totp(read(a.totp_file))})
        if status == 200:
            return {"Authorization": "Bearer " + tok["access_token"]}
        time.sleep(31)
    raise SystemExit(f"mfa verify failed: {status}")


def count(a, headers, path):
    n, cursor = 0, None
    while True:
        url = f"{a.base}/api{path}?limit=100" + (f"&cursor={cursor}" if cursor else "")
        status, page = call(url, a.cafile, headers=headers)
        assert status == 200, (path, status)
        n += len(page["items"])
        cursor = page.get("next_cursor")
        if not cursor:
            return n


def main():
    p = argparse.ArgumentParser()
    p.add_argument("cmd")
    for opt in ("base", "cafile", "password-file", "totp-file", "sensor-url", "bundle", "create-case"):
        p.add_argument("--" + opt)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--user", default="admin")
    a = p.parse_args()
    if a.cmd == "health":
        status, body = call(a.base + "/api/health", a.cafile)
        print(json.dumps(body))
        return 0 if status == 200 and body == {"status": "ok"} else 1
    if a.cmd == "login-state":
        status, body = call(a.base + "/api/auth/login", a.cafile, "POST",
                            {"username": a.user, "password": read(a.password_file)})
        print(f"status={status} mfa={body and body.get('mfa')} access_token={'set' if body and body.get('access_token') else 'none'}")
        return 0 if status == 200 and body.get("mfa") == "enrol" and not body.get("access_token") else 1
    if a.cmd == "sensor-nocert":
        try:
            status, _ = call(a.sensor_url + "/health", a.cafile)
        except (ssl.SSLError, OSError, urllib.error.URLError) as exc:
            print(f"refused: {type(exc).__name__}")
            return 0
        print(f"NOT refused: HTTP {status}")
        return 1
    if a.cmd in ("sensor-post", "sensor-on-main"):
        b = Path(a.bundle)
        auth = {"Authorization": "Bearer " + read(b / "token")}
        alerts = [{"src_ip": "10.10.1.10", "src_port": 40000 + a.offset + i, "dst_ip": "10.10.2.10",
                   "dst_port": 80, "protocol": 6, "start_ms": 1000 + a.offset + i, "end_ms": 2000 + a.offset + i,
                   "predicted_class": "PortScan", "confidence": 0.9} for i in range(a.count)]
        if a.cmd == "sensor-on-main":  # the token alone, on the dashboard port: must be refused
            status, _ = call(a.base + "/api/ingest/alerts", a.cafile, "POST", {"alerts": alerts[:1]}, auth)
            print(status)
            return 0 if status in (401, 403) else 1
        status, body = call(a.sensor_url + "/ingest/alerts", str(b / "ca.pem"), "POST",
                            {"alerts": alerts}, auth, str(b / "client.pem"), str(b / "client.key"))
        print(f"status={status} accepted={body and body.get('accepted')}")
        return 0 if status in (200, 201) and body.get("accepted") == a.count else 1
    if a.cmd == "snapshot":
        h = login(a)
        if a.create_case:
            status, _ = call(a.base + "/api/cases", a.cafile, "POST", {"title": a.create_case}, h)
            assert status == 201, status
        print(f"alerts={count(a, h, '/alerts')} cases={count(a, h, '/cases')}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
