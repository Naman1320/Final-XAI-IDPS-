"""SOC API: the live demo (soc/api/routes/demo.py): admin run/cancel, the runner protocol,
step transitions, expiry and demo mode being off by default."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from soc.api.routes import demo
from soc.api.settings import SocSettings

TOKEN = "demo-token-" + "y" * 40
RUNNER = {"X-Demo-Token": TOKEN}
KEYS = ["portscan", "ssh_bruteforce", "syn_flood", "settle"]


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def soc_settings(soc_settings):
    return soc_settings.model_copy(update={"demo_token": SecretStr(TOKEN)})


@pytest.fixture
def clock(soc_app):
    c = Clock()
    soc_app.state.demo.clock = c
    return c


def demo_off(app) -> None:
    app.state.settings = app.state.settings.model_copy(update={"demo_token": None})


def poll(client, headers=RUNNER):
    return client.get("/demo/runner/next", headers=headers)


def report(client, run_id, step_key, status, note="", headers=RUNNER):
    return client.post("/demo/runner/report", headers=headers, json={
        "run_id": run_id, "step_key": step_key, "status": status, "note": note})


def start(client, admin_headers, clock):
    assert poll(client).json() == {"run": None}  # the runner is online
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 202, r.text
    return r.json()


def picked_up(client, admin_headers, clock):
    run = start(client, admin_headers, clock)
    got = poll(client).json()["run"]
    assert got["id"] == run["id"] and got["status"] == "running"
    return run["id"]


def state(client, headers):
    r = client.get("/demo", headers=headers)
    assert r.status_code == 200
    return r.json()


def audit_actions(client, admin_headers):
    return [(e["action"], e["actor_name"], e["target"]) for e in
            client.get("/admin/audit", headers=admin_headers).json()["items"]
            if e["action"].startswith("demo_")]


# --- off by default ---------------------------------------------------------------------

def test_demo_token_is_unset_by_default(monkeypatch):
    monkeypatch.delenv("IDPS_SOC_DEMO_TOKEN", raising=False)
    assert SocSettings(jwt_secret="s" * 40).demo_token is None
    monkeypatch.setenv("IDPS_SOC_DEMO_TOKEN", "  ")  # docker compose's "" for an unset variable
    assert SocSettings(jwt_secret="s" * 40).demo_token is None


@pytest.mark.parametrize("value", ["short", "x" * 257, "é" * 40, "a" * 31 + "\n"])
def test_demo_token_must_be_long_printable_ascii(monkeypatch, value):
    monkeypatch.setenv("IDPS_SOC_DEMO_TOKEN", value)
    with pytest.raises(ValidationError) as exc:
        SocSettings(jwt_secret="s" * 40)
    assert value not in str(exc.value)  # never echoed


def test_off_disables_runner_and_run_endpoints(client, soc_app, admin_headers, analyst_headers):
    demo_off(soc_app)
    for headers in ({}, RUNNER):
        r = poll(client, headers)
        assert r.status_code == 404 and "demo mode is off" in r.json()["detail"]
        r = report(client, "00000000-0000-4000-8000-000000000000", "portscan", "running",
                   headers=headers)
        assert r.status_code == 404
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 503 and "demo mode is off" in r.json()["detail"]
    assert state(client, analyst_headers) == {"enabled": False, "runner_online": False, "run": None}
    assert audit_actions(client, admin_headers) == []


# --- authentication ---------------------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"X-Demo-Token": ""}, {"X-Demo-Token": TOKEN + "x"},
                                     {"X-Demo-Token": TOKEN[:-1]}, {"X-Demo-Token": "x" * 5000},
                                     {"Authorization": f"Bearer {TOKEN}"}])
def test_runner_needs_the_right_token(client, admin_headers, headers):
    assert poll(client, headers).status_code == 401
    assert report(client, "00000000-0000-4000-8000-000000000000", "portscan", "running",
                  headers=headers).status_code == 401
    # a rejected poll is no heartbeat
    assert state(client, admin_headers)["runner_online"] is False


def test_user_tokens_are_not_runner_tokens(client, admin_headers):
    assert poll(client, admin_headers).status_code == 401


def test_wrong_tokens_are_throttled(client):
    for _ in range(demo.BAD_TOKEN_LIMIT):
        assert poll(client, {"X-Demo-Token": "wrong"}).status_code == 401
    assert poll(client, {"X-Demo-Token": "wrong"}).status_code == 429
    assert report(client, "00000000-0000-4000-8000-000000000000", "portscan", "running",
                  headers={"X-Demo-Token": "wrong"}).status_code == 429


def test_correct_token_is_accepted_during_lockout(client, admin_headers, clock):
    """Everything on the host shares one address; ten bad tokens must not cut off the runner."""
    run_id = picked_up(client, admin_headers, clock)
    for _ in range(demo.BAD_TOKEN_LIMIT + 3):
        poll(client, {"X-Demo-Token": "wrong"})
    assert poll(client, {"X-Demo-Token": "wrong"}).status_code == 429
    assert poll(client).status_code == 200
    assert report(client, run_id, "portscan", "running").status_code == 200
    assert poll(client, {"X-Demo-Token": "wrong"}).status_code == 429  # wrong ones stay refused
    assert poll(client, {}).status_code == 429


def test_token_throttle_exists_from_start(soc_app):
    assert soc_app.state.demo_token_throttle is not None


def test_good_tokens_are_not_counted(client):
    for _ in range(demo.BAD_TOKEN_LIMIT + 5):
        assert poll(client).status_code == 200


def test_analyst_cannot_run_or_cancel(client, analyst_headers, admin_headers, clock):
    poll(client)
    assert client.post("/admin/demo/run", headers=analyst_headers).status_code == 403
    assert client.post("/admin/demo/cancel", headers=analyst_headers).status_code == 403
    assert state(client, analyst_headers)["run"] is None
    assert audit_actions(client, admin_headers) == []


def test_status_needs_sign_in(client):
    assert client.get("/demo").status_code == 401
    assert client.get("/demo", headers=RUNNER).status_code == 401


def test_run_takes_no_body(client, admin_headers, clock):
    poll(client)
    r = client.post("/admin/demo/run",
                    headers={**admin_headers, "Content-Type": "application/json"},
                    content=b"{" + b" " * 2048 + b"}")
    assert r.status_code == 413
    r = client.post("/demo/runner/report", headers={**RUNNER, "Content-Type": "application/json"},
                    content=b"{" + b" " * 4096 + b"}")
    assert r.status_code == 413


# --- 409s -------------------------------------------------------------------------------

def test_run_refused_without_runner(client, admin_headers, clock):
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 409 and "demo runner is not running" in r.json()["detail"]
    poll(client)
    clock.advance(seconds=31)
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 409 and "demo runner is not running" in r.json()["detail"]
    assert audit_actions(client, admin_headers) == []


def test_runner_online_window(client, analyst_headers, clock):
    assert state(client, analyst_headers)["runner_online"] is False
    poll(client)
    clock.advance(seconds=30)
    assert state(client, analyst_headers)["runner_online"] is True
    clock.advance(seconds=1)
    assert state(client, analyst_headers)["runner_online"] is False


def test_second_run_refused_while_queued_or_running(client, admin_headers, clock):
    start(client, admin_headers, clock)
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 409 and "already queued" in r.json()["detail"]
    poll(client)
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 409 and "already running" in r.json()["detail"]
    assert [a for a, _, _ in audit_actions(client, admin_headers)] == ["demo_run"]


# --- happy path -------------------------------------------------------------------------

def test_full_run(client, admin_headers, analyst_headers, clock):
    run = start(client, admin_headers, clock)
    assert run["status"] == "queued" and run["requested_by"] == "admin"
    assert run["finished_at"] is None
    assert [(s["key"], s["label"], s["status"]) for s in run["steps"]] == [
        (s["key"], s["label"], "pending") for s in demo.STEPS]
    assert all(s["started_at"] is None and s["ended_at"] is None and s["note"] == ""
               for s in run["steps"])
    seen = state(client, analyst_headers)  # everyone signed in sees it
    assert seen["enabled"] and seen["runner_online"] and seen["run"]["id"] == run["id"]

    got = poll(client).json()["run"]
    assert got["id"] == run["id"] and got["status"] == "running"
    assert poll(client).json() == {"run": None}  # handed out once only

    for key in KEYS:
        clock.advance(seconds=10)
        assert report(client, run["id"], key, "running").json() == {"cancelled": False}
        clock.advance(seconds=20)
        assert report(client, run["id"], key, "done", f"{key} ok").json() == {"cancelled": False}
    final = state(client, analyst_headers)["run"]
    assert final["status"] == "done" and final["finished_at"] is not None
    for step in final["steps"]:
        assert step["status"] == "done" and step["note"] == f"{step['key']} ok"
        start_at = datetime.fromisoformat(step["started_at"])
        end_at = datetime.fromisoformat(step["ended_at"])
        assert end_at - start_at == timedelta(seconds=20)
    assert audit_actions(client, admin_headers) == [("demo_run", "admin", f"demo:{run['id']}")]

    # a finished run stays visible and doesn't block the next one
    r = client.post("/admin/demo/run", headers=admin_headers)
    assert r.status_code == 202 and r.json()["id"] != run["id"]


def test_runner_skipped_step_still_finishes_done(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    for key in KEYS:
        status = "skipped" if key == "ssh_bruteforce" else "done"
        assert report(client, run_id, key, status).status_code == 200
    run = state(client, admin_headers)["run"]
    assert run["status"] == "done"
    assert run["steps"][1]["status"] == "skipped" and run["steps"][1]["started_at"] is None


def test_retried_report_is_harmless(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    assert report(client, run_id, "portscan", "running").status_code == 200
    first = state(client, admin_headers)["run"]["steps"][0]["started_at"]
    clock.advance(seconds=5)
    assert report(client, run_id, "portscan", "running").json() == {"cancelled": False}
    assert state(client, admin_headers)["run"]["steps"][0]["started_at"] == first


def test_repeated_running_report_updates_only_the_note(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    for key in ("portscan", "ssh_bruteforce", "syn_flood"):
        report(client, run_id, key, "running")
        report(client, run_id, key, "done")
    report(client, run_id, "settle", "running", "settling, 150s left")
    before = state(client, admin_headers)["run"]["steps"][3]
    clock.advance(seconds=15)
    assert report(client, run_id, "settle", "running", "settling, 135s left").json() == {
        "cancelled": False}
    after = state(client, admin_headers)["run"]["steps"][3]
    assert after["note"] == "settling, 135s left"
    assert after["status"] == "running" and after["started_at"] == before["started_at"]
    # an empty note changes nothing, and a repeated "done" never rewrites its note
    report(client, run_id, "settle", "running", "")
    assert state(client, admin_headers)["run"]["steps"][3]["note"] == "settling, 135s left"
    report(client, run_id, "settle", "done", "settled")
    report(client, run_id, "settle", "done", "other")
    assert state(client, admin_headers)["run"]["steps"][3]["note"] == "settled"


def test_running_note_is_not_applied_to_a_cancelled_run(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    report(client, run_id, "portscan", "running", "started")
    client.post("/admin/demo/cancel", headers=admin_headers)
    assert report(client, run_id, "portscan", "running", "late").json() == {"cancelled": True}
    assert state(client, admin_headers)["run"]["steps"][0]["note"] == "started"


# --- failure, cancel, expiry ------------------------------------------------------------

def test_failed_step_skips_the_rest(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    report(client, run_id, "portscan", "running")
    report(client, run_id, "portscan", "done")
    report(client, run_id, "ssh_bruteforce", "running")
    r = report(client, run_id, "ssh_bruteforce", "failed", "hydra exited 255")
    assert r.json() == {"cancelled": False}
    run = state(client, admin_headers)["run"]
    assert run["status"] == "failed" and run["finished_at"] is not None
    assert [s["status"] for s in run["steps"]] == ["done", "failed", "skipped", "skipped"]
    assert run["steps"][1]["note"] == "hydra exited 255"
    assert "failed" in run["steps"][2]["note"]
    # nothing moves after the run is over
    assert report(client, run_id, "syn_flood", "running").status_code == 409
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 404


def test_cancel(client, admin_headers, analyst_headers, clock):
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 404
    run_id = picked_up(client, admin_headers, clock)
    report(client, run_id, "portscan", "running")
    r = client.post("/admin/demo/cancel", headers=admin_headers)
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    run = state(client, analyst_headers)["run"]
    assert run["status"] == "cancelled" and run["finished_at"] is not None
    assert [s["status"] for s in run["steps"]] == ["skipped"] * 4
    assert run["steps"][0]["ended_at"] is not None  # it had started
    # the runner learns to stop from its next report, and the report changes nothing
    assert report(client, run_id, "portscan", "done").json() == {"cancelled": True}
    assert state(client, analyst_headers)["run"]["steps"][0]["status"] == "skipped"
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 404
    assert [a for a, _, _ in audit_actions(client, admin_headers)] == ["demo_cancel", "demo_run"]
    assert audit_actions(client, admin_headers)[0][2] == f"demo:{run_id}"


def test_cancel_a_queued_run_is_never_handed_out(client, admin_headers, clock):
    start(client, admin_headers, clock)
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 200
    assert poll(client).json() == {"run": None}


def test_runs_expire_after_15_minutes(client, admin_headers, analyst_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    report(client, run_id, "portscan", "running")
    for _ in range(14):  # the runner keeps reporting, so only the 15-minute limit applies
        clock.advance(minutes=1)
        report(client, run_id, "portscan", "running", "still going")
    clock.advance(seconds=59)
    report(client, run_id, "portscan", "running", "still going")
    assert state(client, analyst_headers)["run"]["status"] == "running"
    clock.advance(seconds=1)
    poll(client)  # keep the runner online
    run = state(client, analyst_headers)["run"]
    assert run["status"] == "expired" and run["finished_at"] is not None
    assert all(s["status"] == "skipped" for s in run["steps"])
    assert report(client, run_id, "portscan", "done").json() == {"cancelled": True}
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 404
    assert client.post("/admin/demo/run", headers=admin_headers).status_code == 202


def test_run_fails_early_when_the_runner_goes_silent(client, admin_headers, analyst_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    report(client, run_id, "portscan", "running", "started")
    clock.advance(seconds=demo.RUNNER_GONE_SECONDS)  # exactly the limit: still fine
    assert state(client, analyst_headers)["run"]["status"] == "running"
    clock.advance(seconds=1)
    run = state(client, analyst_headers)["run"]
    assert run["status"] == "failed" and run["finished_at"] is not None
    assert [s["status"] for s in run["steps"]] == ["skipped"] * 4
    assert run["steps"][0]["note"] == "runner went away"  # replaces the stale "started"
    assert all(s["note"] == "runner went away" for s in run["steps"][1:])
    # the slot is free again, and a runner that comes back is told to stop (409: the run is over)
    assert report(client, run_id, "portscan", "done").status_code == 409
    poll(client)
    assert client.post("/admin/demo/run", headers=admin_headers).status_code == 202


def test_a_heartbeat_keeps_a_run_alive(client, admin_headers, analyst_headers, clock):
    picked_up(client, admin_headers, clock)
    for _ in range(10):
        clock.advance(seconds=demo.RUNNER_GONE_SECONDS)
        poll(client)
    assert state(client, analyst_headers)["run"]["status"] == "running"


def test_queued_run_expires_too(client, admin_headers, clock):
    start(client, admin_headers, clock)
    clock.advance(minutes=15)
    assert poll(client).json() == {"run": None}
    assert state(client, admin_headers)["run"]["status"] == "expired"


# --- validation and transitions ---------------------------------------------------------

def test_unknown_run_is_404(client, admin_headers, clock):
    picked_up(client, admin_headers, clock)
    r = report(client, "00000000-0000-4000-8000-000000000000", "portscan", "running")
    assert r.status_code == 404


@pytest.mark.parametrize("body", [
    {"step_key": "rm -rf /"}, {"step_key": "PortScan"}, {"step_key": ""},
    {"status": "pending"}, {"status": "cancelled"}, {"status": "DONE"},
    {"note": "n" * 201}, {"note": "bad\x1b[31m"}, {"note": "rtl\u202eoverride"},
    {"run_id": "not-a-uuid"}, {"extra": 1}, {"note": 5},
])
def test_report_validation(client, admin_headers, clock, body):
    run_id = picked_up(client, admin_headers, clock)
    payload = {"run_id": run_id, "step_key": "portscan", "status": "running", "note": "", **body}
    r = client.post("/demo/runner/report", headers=RUNNER, json=payload)
    assert r.status_code == 422
    assert state(client, admin_headers)["run"]["steps"][0]["status"] == "pending"


def test_note_of_200_characters_is_accepted(client, admin_headers, clock):
    run_id = picked_up(client, admin_headers, clock)
    assert report(client, run_id, "portscan", "running", "n" * 200).status_code == 200


@pytest.mark.parametrize("steps,bad,detail", [
    # a later step before an earlier one has finished
    ([], ("ssh_bruteforce", "running"), "portscan has not finished"),
    ([("portscan", "running")], ("syn_flood", "running"), "portscan has not finished"),
    # backwards
    ([("portscan", "running"), ("portscan", "done")], ("portscan", "running"), "already done"),
    ([("portscan", "running"), ("portscan", "done")], ("portscan", "failed"), "already done"),
    ([("portscan", "skipped")], ("portscan", "done"), "already skipped"),
])
def test_invalid_transitions(client, admin_headers, clock, steps, bad, detail):
    run_id = picked_up(client, admin_headers, clock)
    for key, status in steps:
        assert report(client, run_id, key, status).status_code == 200
    before = state(client, admin_headers)["run"]
    r = report(client, run_id, *bad)
    assert r.status_code == 409 and detail in r.json()["detail"]
    assert state(client, admin_headers)["run"] == before


def test_report_before_pickup_is_refused(client, admin_headers, clock):
    run = start(client, admin_headers, clock)
    r = report(client, run["id"], "portscan", "running")
    assert r.status_code == 409 and "queued" in r.json()["detail"]


def test_state_is_shared_safely_between_threads(soc_app, admin_headers, clock):
    """Many runners polling at once still hand the queued run out exactly once."""
    from concurrent.futures import ThreadPoolExecutor

    client = TestClient(soc_app)
    start(client, admin_headers, clock)
    with ThreadPoolExecutor(8) as pool:
        runs = list(pool.map(lambda _: poll(client).json()["run"], range(32)))
    assert sum(r is not None for r in runs) == 1


# --- the audit row and the run slot change together ---------------------------------------

def test_failed_audit_rolls_the_run_back(soc_app, admin_headers, clock, monkeypatch):
    client = TestClient(soc_app, raise_server_exceptions=False)
    assert poll(client).status_code == 200

    def boom(*a, **kw):
        raise RuntimeError("audit down")

    with monkeypatch.context() as m:
        m.setattr(demo, "audit", boom)
        assert client.post("/admin/demo/run", headers=admin_headers).status_code == 500
    assert state(client, admin_headers)["run"] is None  # no audit row, so no run

    run = start(client, admin_headers, clock)
    with monkeypatch.context() as m:
        m.setattr(demo, "audit", boom)
        assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 500
    assert state(client, admin_headers)["run"]["status"] == "queued"  # still cancellable
    assert client.post("/admin/demo/cancel", headers=admin_headers).status_code == 200
    assert [a for a, _, _ in audit_actions(client, admin_headers)] == ["demo_cancel", "demo_run"]
    assert run["id"] == audit_actions(client, admin_headers)[0][2].removeprefix("demo:")
