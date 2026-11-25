"""SOC API: cases, notes and attached alerts."""

import pytest
from conftest import alert_payload, ingest


def make_case(client, headers, **kw):
    r = client.post("/cases", headers=headers, json={"title": "SSH brute force"} | kw)
    assert r.status_code == 201, r.text
    return r.json()


def test_case_crud(client, analyst_headers, sensor_headers):
    a1, a2 = ingest(client, sensor_headers, alert_payload(), alert_payload())
    case = make_case(client, analyst_headers, alert_ids=[a1])
    assert case["status"] == "open" and case["alert_count"] == 1
    assert [a["id"] for a in case["alerts"]] == [a1]
    cid = case["id"]

    r = client.post(f"/cases/{cid}/alerts", json={"alert_ids": [a1, a2]}, headers=analyst_headers)
    assert r.status_code == 200 and r.json()["alert_count"] == 2
    assert client.get(f"/alerts/{a2}", headers=analyst_headers).json()["case_id"] == cid

    r = client.patch(f"/cases/{cid}", json={"status": "investigating", "title": "  Renamed "},
                     headers=analyst_headers)
    assert r.json()["status"] == "investigating" and r.json()["title"] == "Renamed"

    note = client.post(f"/cases/{cid}/notes", json={"text": "Looks like hydra."},
                       headers=analyst_headers)
    assert note.status_code == 201 and note.json()["author"] == "analyst"
    detail = client.get(f"/cases/{cid}", headers=analyst_headers).json()
    assert [n["text"] for n in detail["notes"]] == ["Looks like hydra."]
    assert detail["notes"][0]["author"] == "analyst"

    assert client.delete(f"/cases/{cid}/alerts/{a2}", headers=analyst_headers).status_code == 204
    assert client.delete(f"/cases/{cid}/alerts/{a2}", headers=analyst_headers).status_code == 404
    listing = client.get("/cases?status=investigating", headers=analyst_headers).json()
    assert [c["id"] for c in listing["items"]] == [cid] and listing["items"][0]["alert_count"] == 1
    assert client.get("/cases?status=closed", headers=analyst_headers).json()["items"] == []

    assert client.delete(f"/cases/{cid}", headers=analyst_headers).status_code == 204
    assert client.get(f"/cases/{cid}", headers=analyst_headers).status_code == 404
    assert client.get(f"/alerts/{a1}", headers=analyst_headers).json()["case_id"] is None


def test_alert_cannot_be_in_two_cases(client, analyst_headers, sensor_headers):
    (a,) = ingest(client, sensor_headers, alert_payload())
    make_case(client, analyst_headers, alert_ids=[a])
    other = make_case(client, analyst_headers, title="Other")
    r = client.post(f"/cases/{other['id']}/alerts", json={"alert_ids": [a]},
                    headers=analyst_headers)
    assert r.status_code == 409


def test_unknown_alert_ids(client, analyst_headers):
    assert client.post("/cases", json={"title": "t", "alert_ids": [999]},
                       headers=analyst_headers).status_code == 422
    # the failed create left nothing behind
    assert client.get("/cases", headers=analyst_headers).json()["items"] == []


@pytest.mark.parametrize("body", [
    {"title": ""}, {"title": "   "}, {"title": "x" * 201}, {}, {"title": "t", "extra": 1},
    {"title": "t", "alert_ids": list(range(1, 102))}, {"title": "t", "status": "closed"},
])
def test_case_validation(client, analyst_headers, body):
    assert client.post("/cases", json=body, headers=analyst_headers).status_code == 422


def test_note_limits(client, analyst_headers):
    cid = make_case(client, analyst_headers)["id"]
    url = f"/cases/{cid}/notes"
    assert client.post(url, json={"text": "x" * 10_000}, headers=analyst_headers).status_code == 201
    for bad in ("x" * 10_001, "", "   "):
        assert client.post(url, json={"text": bad}, headers=analyst_headers).status_code == 422
    assert client.post("/cases/999/notes", json={"text": "hi"},
                       headers=analyst_headers).status_code == 404


def test_patch_needs_a_change_and_valid_status(client, analyst_headers):
    cid = make_case(client, analyst_headers)["id"]
    assert client.patch(f"/cases/{cid}", json={}, headers=analyst_headers).status_code == 422
    assert client.patch(f"/cases/{cid}", json={"status": "weird"},
                        headers=analyst_headers).status_code == 422
    assert client.patch("/cases/999", json={"status": "closed"},
                        headers=analyst_headers).status_code == 404


def test_case_pagination(client, analyst_headers):
    ids = [make_case(client, analyst_headers, title=f"c{i}")["id"] for i in range(5)]
    first = client.get("/cases?limit=2", headers=analyst_headers).json()
    second = client.get(f"/cases?limit=2&cursor={first['next_cursor']}",
                        headers=analyst_headers).json()
    assert [c["id"] for c in first["items"] + second["items"]] == sorted(ids, reverse=True)[:4]


def test_admin_can_use_cases_too(client, admin_headers):
    make_case(client, admin_headers)
