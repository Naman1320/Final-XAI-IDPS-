"""Billing guard for the emulated cloud (docs/cloud-plan.md, "no billing, ever").

Exits non-zero, and so stops any wrapper script, unless every one of these holds:
- the credentials are the fake ones (test/test), with no session token, profile or role;
- the endpoint is the local emulator on port 4566 (127.0.0.1, localhost, ::1, or its fixed
  cloud_net address 10.10.4.10; no DNS names, which a search domain could send elsewhere);
- no per-service endpoint (AWS_ENDPOINT_URL_<SERVICE>), CA bundle or proxy is set;
- the endpoint really is Moto (its /moto-api/ page answers);
- STS there reports the emulator account (IDPS_EMULATOR_ACCOUNT, default 000000000000).

    source lab/cloud/env.sh && .venv/bin/python lab/cloud/guard.py
"""

from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

FAKE_KEY = "test"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "10.10.4.10"}
EMULATOR_PORT = 4566
# Real AWS access key ids: AKIA (long-term), ASIA (temporary) and friends.
REAL_KEY = re.compile(r"^(AKIA|ASIA|AIDA|AROA|ABIA|ACCA)[A-Z0-9]{12,}$")
BLOCKED_VARS = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def problems(env: dict[str, str], probe=None, account_of=None) -> list[str]:
    """Return every reason to refuse; empty means safe. probe/account_of are injectable for tests."""
    found: list[str] = []
    key = env.get("AWS_ACCESS_KEY_ID", "")
    secret = env.get("AWS_SECRET_ACCESS_KEY", "")
    if REAL_KEY.match(key):
        found.append("AWS_ACCESS_KEY_ID looks like a real AWS key")
    if key != FAKE_KEY or secret != FAKE_KEY:
        found.append("credentials must be the fake test/test pair (source lab/cloud/env.sh)")
    for name in BLOCKED_VARS:
        if env.get(name):
            found.append(f"{name} is set")
    for name in sorted(env):
        if name.startswith("AWS_ENDPOINT_URL_") and env[name]:
            found.append(f"{name} is set (per-service endpoints are not allowed)")
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        if env.get(name) != "/dev/null":
            found.append(f"{name} must be /dev/null so real profiles can't be read")

    endpoint = env.get("AWS_ENDPOINT_URL", "")
    parsed = urlparse(endpoint)
    try:
        port = parsed.port
    except ValueError:
        port = None
    if (
        parsed.scheme not in ("http", "https")
        or parsed.hostname not in LOCAL_HOSTS
        or port != EMULATOR_PORT
        or parsed.username
        or parsed.password
    ):
        found.append(
            f"AWS_ENDPOINT_URL must point at the local emulator on port {EMULATOR_PORT}, "
            f"got {endpoint!r}"
        )
    if found:
        return found  # don't contact anything with an unsafe setup

    probe = probe or _probe_moto
    if not probe(endpoint):
        return [f"{endpoint} is not answering as Moto (is the emulator up?)"]

    want = env.get("IDPS_EMULATOR_ACCOUNT", "000000000000")
    account_of = account_of or _account
    try:
        got = account_of(env)
    except Exception as exc:  # noqa: BLE001 - any failure here means "not safe"
        return [f"STS get-caller-identity failed: {exc}"]
    if got != want:
        found.append(f"account is {got}, expected the emulator account {want}")
    return found


def _probe_moto(endpoint: str) -> bool:
    try:
        with urllib.request.urlopen(endpoint.rstrip("/") + "/moto-api/", timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _account(env: dict[str, str]) -> str:
    import boto3

    sts = boto3.client(
        "sts",
        endpoint_url=env["AWS_ENDPOINT_URL"],
        region_name=env.get("AWS_REGION", "eu-west-1"),
        aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
    )
    return sts.get_caller_identity()["Account"]


def main() -> int:
    found = problems(dict(os.environ))
    if found:
        print("billing guard: REFUSED", file=sys.stderr)
        for item in found:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print(
        f"billing guard: ok (emulator at {os.environ['AWS_ENDPOINT_URL']}, account "
        f"{os.environ.get('IDPS_EMULATOR_ACCOUNT', '000000000000')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
