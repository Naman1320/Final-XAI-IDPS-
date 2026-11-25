"""Every SOC route except /health and /auth/login must require authentication."""

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

PUBLIC = {("GET", "/health"), ("POST", "/auth/login"),
          # Single sign-on: whether it is on (and its button text), and its start; the callback
          # is checked by the state + binding, not a token (tests/test_soc_oidc.py).
          ("GET", "/auth/oidc/config"), ("POST", "/auth/oidc/start"), ("POST", "/auth/oidc/callback"),
          # The MFA sign-in step: authenticated by its challenge token in the body
          # (tests/test_soc_mfa.py); the other MFA routes need a bearer token as usual.
          ("POST", "/auth/mfa/verify"),
          # The privacy notice is for data principals (the people whose traffic is monitored), who
          # have no SOC account. It holds no secrets: only what the operator set for the notice,
          # the retention periods in force and channel names, never their targets
          # (tests/test_soc_privacy.py).
          ("GET", "/privacy/notice")}
# The live demo runner's routes take X-Demo-Token, not a bearer token. With IDPS_SOC_DEMO_TOKEN
# unset (the default, as here) they don't exist (404); with it set they answer 401 without the
# right token (tests/test_soc_demo.py).
DEMO_RUNNER = {("GET", "/demo/runner/next"), ("POST", "/demo/runner/report"),
               ("POST", "/c6/worker/claim"), ("POST", "/c6/worker/report")}


def flat_routes(routes, prefix=""):
    """app.routes with included routers expanded (newer FastAPI nests them)."""
    for route in routes:
        if hasattr(route, "original_router"):
            yield from flat_routes(route.original_router.routes,
                                   prefix + route.include_context.prefix)
        else:
            yield prefix, route


def http_endpoints(app):
    for prefix, route in flat_routes(app.routes):
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                yield method, (prefix + route.path)


def test_every_non_public_route_requires_a_token(soc_app):
    client = TestClient(soc_app)
    endpoints = sorted(http_endpoints(soc_app))
    assert len(endpoints) > 30  # the walk really found the routers
    checked = 0
    for method, path in endpoints:
        if (method, path) in PUBLIC:
            continue
        if (method, path) in DEMO_RUNNER:
            for headers in ({}, {"Authorization": "Bearer junk"}):
                r = client.request(method, path, json={}, headers=headers)
                assert r.status_code == 404, f"{method} {path} is open while demo mode is off"
            checked += 1
            continue
        url = path.replace("{alert_id}", "1").replace("{case_id}", "1") \
            .replace("{action_id}", "1").replace("{user_id}", "1").replace("{sensor_id}", "1") \
            .replace("{conversation_id}", "1").replace("{group_id}", "1") \
            .replace("{role_id}", "1").replace("{policy_id}", "1") \
            .replace("{instance_id}", "i-00000001").replace("{volume_id}", "vol-00000001") \
            .replace("{name}", "some-bucket").replace("{sg_id}", "sg-00000001") \
            .replace("{rule_id}", "1") \
            .replace("{channel}", "webhook")
        assert "{" not in url, f"unhandled path parameter in {path}"
        r = client.request(method, url, json={})
        assert r.status_code == 401, f"{method} {path} returned {r.status_code} without a token"
        r = client.request(method, url, json={}, headers={"Authorization": "Bearer junk"})
        assert r.status_code == 401, f"{method} {path} accepted a junk token"
        checked += 1
    assert checked == len(endpoints) - len(PUBLIC)


def test_public_routes_are_only_health_and_login(soc_app):
    client = TestClient(soc_app)
    assert client.get("/health").status_code == 200
    # docs are off by default, so they are not an unauthenticated side door
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


@pytest.mark.parametrize("method,path", [
    ("GET", "/admin/users"), ("POST", "/admin/users"), ("GET", "/admin/sensors"),
    ("POST", "/admin/sensors"), ("GET", "/admin/audit"), ("PATCH", "/admin/users/1/role"),
    ("POST", "/admin/users/1/disable"), ("POST", "/admin/users/1/enable"),
    ("POST", "/admin/users/1/reset-password"), ("POST", "/admin/sensors/1/revoke"),
    ("GET", "/admin/integrations"), ("POST", "/admin/integrations/webhook/test"),
    ("POST", "/admin/privacy/erase/preview"), ("POST", "/admin/privacy/erase"),
    ("GET", "/admin/privacy/erasures"), ("GET", "/admin/privacy/access-log"),
    ("POST", "/admin/reports/weekly/email"),
    ("POST", "/admin/demo/run"), ("POST", "/admin/demo/cancel"),
])
def test_analysts_cannot_use_admin_routes(client, analyst_headers, method, path):
    assert client.request(method, path, json={}, headers=analyst_headers).status_code == 403


@pytest.mark.parametrize("method,path", [
    ("POST", "/ingest/alerts"), ("POST", "/ingest/blocks"), ("GET", "/sensor/actions"),
    ("POST", "/sensor/actions/1/result"),
])
def test_sensor_routes_reject_user_tokens(client, analyst_headers, admin_headers, method, path):
    for headers in (analyst_headers, admin_headers):
        assert client.request(method, path, json={}, headers=headers).status_code == 401


def test_sensor_token_is_not_a_user_token(client, sensor_headers):
    for path in ("/alerts", "/blocks", "/actions", "/cases", "/metrics/summary", "/topology",
                 "/admin/users", "/auth/me"):
        assert client.get(path, headers=sensor_headers).status_code == 401, path
