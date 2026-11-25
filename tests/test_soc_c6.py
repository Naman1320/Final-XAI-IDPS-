"""C6 state, evidence provenance, access boundaries and ACL read-back."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import alert_payload, ingest
from pydantic import SecretStr, ValidationError

from scripts.c6_worker import EvidenceError, cli_readback, deny_entries
from soc.api import auth
from soc.api.routes import c6

TOKEN = "c6-unit-" + "x" * 40
WORKER = {"X-C6-Token": TOKEN}


@pytest.fixture
def soc_settings(soc_settings):
    return soc_settings.model_copy(update={"c6_token": SecretStr(TOKEN)})


def start(client, admin, mode="replay"):
    assert client.post("/c6/worker/claim", headers=WORKER).json() is None
    result = client.post("/admin/c6/run", headers=admin, json={"mode": mode})
    assert result.status_code == 202
    run = client.post("/c6/worker/claim", headers=WORKER).json()
    assert run["id"] == result.json()["id"]
    return run["id"]


def report(client, rid, stage, detail="observed evidence"):
    return client.post("/c6/worker/report", headers=WORKER, json={
        "run_id": rid, "stage": stage, "evidence": detail})


def test_c6_permission_boundaries(client, analyst_headers, admin_headers):
    assert client.get("/c6", headers=analyst_headers).status_code == 403
    assert client.post("/admin/c6/run", headers=analyst_headers, json={"mode": "replay"}).status_code == 403
    assert client.post("/admin/c6/run", headers=admin_headers, json={"mode": "replay"}).status_code == 503
    for headers in [admin_headers, {"X-Demo-Token": TOKEN}]:
        assert client.post("/c6/worker/claim", headers=headers).status_code == 401
    assert client.get("/demo/runner/next", headers=WORKER).status_code == 404


def test_rejects_a_shared_live_demo_and_evidence_credential(soc_settings):
    from soc.api.settings import SocSettings

    with pytest.raises(ValidationError, match="separate credentials"):
        SocSettings(jwt_secret=soc_settings.jwt_secret, demo_token=TOKEN, c6_token=TOKEN)


def test_atomic_claim_and_evidence_completion(client, admin_headers):
    rid = start(client, admin_headers)
    assert client.post("/c6/worker/claim", headers=WORKER).json() is None
    assert client.post("/admin/c6/run", headers=admin_headers, json={"mode": "replay"}).status_code == 409
    assert report(client, str(uuid4()), "acl").status_code == 409
    for stage in sorted(c6.REQUIRED - {"acl"}):
        assert report(client, rid, stage).json()["status"] == "running"
    assert report(client, rid, "baseline").status_code == 200
    assert report(client, rid, "baseline", "different").status_code == 409
    assert report(client, rid, "acl").json()["status"] == "verified"
    assert report(client, rid, "acl").status_code == 200
    assert report(client, rid, "error").status_code == 409
    run = client.get("/c6", headers=admin_headers).json()["run"]
    assert len(run["events"]) == 7 and run["ended_at"] >= run["started_at"]


def test_error_and_expiration_preserve_partial_evidence(client, soc_app, admin_headers):
    rid = start(client, admin_headers)
    assert report(client, rid, "error", "worker offline").json()["status"] == "failed"
    rid = start(client, admin_headers)
    assert report(client, rid, "baseline").status_code == 200
    soc_app.state.c6.run.started_at -= timedelta(minutes=7)
    run = client.get("/c6", headers=admin_headers).json()["run"]
    assert run["status"] == "incomplete" and len(run["events"]) == 1
    assert report(client, rid, "acl").status_code == 409


def test_live_only_accepts_soc_sensor_evidence(client, soc_app, admin_headers):
    rid = start(client, admin_headers, "observe")
    assert report(client, rid, "baseline").status_code == 200
    for stage in ("lab_block", "cloud_alert", "capture"):
        assert report(client, rid, stage).status_code == 422
    demo = soc_app.state.demo
    demo.next_for_runner()
    current = demo.start("admin")
    demo.next_for_runner()
    demo.report(current["id"], "portscan", "running", "")
    with soc_app.state.session_factory() as db:
        cloud = {"Authorization": "Bearer " + auth.create_sensor_token(db, "cloud")}
        lab = {"Authorization": "Bearer " + auth.create_sensor_token(db, "lab-sensor-123")}
    # Old captures delivered in the current window are excluded.
    flow = alert_payload(src_ip=c6.SOURCE, dst_ip="10.10.2.10")
    ingest(client, cloud, flow)
    assert [e["stage"] for e in client.get("/c6", headers=admin_headers).json()["run"]["events"]] == ["baseline", "capture"]
    now = int(datetime.now(UTC).timestamp()*1000)
    flow.update(start_ms=now, end_ms=now)
    ingest(client, cloud, flow)
    ingest(client, lab, flow)
    for stage in ("baseline", "response", "acl"):
        assert report(client, rid, stage).json()["status"] == "running"
    events = client.get("/c6", headers=admin_headers).json()["run"]["events"]
    assert {"cloud_alert", "lab_alert"} <= {e["stage"] for e in events}
    r = client.post("/ingest/blocks", headers=lab, json={"events": [
        {"ip": c6.SOURCE, "event": "blocked", "source": "auto", "reason": "sensor test", "ttl_seconds": 90}]})
    assert r.status_code in (200, 201), r.text
    assert client.get("/c6", headers=admin_headers).json()["run"]["status"] == "verified"


def test_live_requires_a_baseline_before_the_runner_step(client, soc_app, admin_headers):
    rid = start(client, admin_headers, "observe")
    demo = soc_app.state.demo
    demo.next_for_runner()
    session = demo.start("admin")
    demo.next_for_runner()
    demo.report(session["id"], "portscan", "running", "")
    assert report(client, rid, "baseline").json()["status"] == "failed"
    assert report(client, rid, "acl").status_code == 409


def test_verification_requires_correct_account_acl_and_both_directions(monkeypatch):
    import json
    from types import SimpleNamespace
    acl = "acl-12345678"
    row = {"CidrBlock": c6.SOURCE + "/32", "Egress": False, "Protocol": "-1",
           "RuleAction": "deny", "RuleNumber": 1}
    doc = {"NetworkAcls": [{"OwnerId": "000000000000", "NetworkAclId": acl, "Entries": [row]}]}
    assert deny_entries(doc, acl) == [("ingress", 1)]
    monkeypatch.setattr("scripts.c6_worker.subprocess.run",
                        lambda *a, **kw: SimpleNamespace(stdout=json.dumps(doc)))
    with pytest.raises(EvidenceError):
        cli_readback(acl, [("ingress", 1)])
    doc["NetworkAcls"][0]["OwnerId"] = "111111111111"
    with pytest.raises(EvidenceError):
        deny_entries(doc, acl)
