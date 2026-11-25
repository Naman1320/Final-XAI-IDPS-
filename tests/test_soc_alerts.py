"""SOC API: alert ingest, listing, detail and triage."""

import json

import pytest
from conftest import alert_payload, ingest


def test_ingest_stores_and_derives_severity(client, sensor_headers, analyst_headers):
    r = client.post("/ingest/alerts", headers=sensor_headers, json={"alerts": [
        alert_payload(predicted_class="DDoS", confidence=0.99),
        alert_payload(predicted_class="DDoS", confidence=0.3),  # unsure: one level lower
        alert_payload(predicted_class="Unheard-Of", confidence=0.9),  # default severity
        alert_payload(predicted_class="BENIGN", confidence=0.9),  # never stored
    ]})
    assert r.status_code == 201
    assert r.json()["accepted"] == 3 and r.json()["skipped_benign"] == 1
    items = client.get("/alerts", headers=analyst_headers).json()["items"]
    assert sorted(a["severity"] for a in items) == ["critical", "high", "medium"]
    assert "explanation" not in items[0]


def test_alert_detail_has_explanation_and_normalised_ips(client, sensor_headers, analyst_headers):
    (alert_id,) = ingest(client, sensor_headers, alert_payload(src_ip="::ffff:203.0.113.9",
                                                               dst_ip="2001:DB8::1"))
    a = client.get(f"/alerts/{alert_id}", headers=analyst_headers).json()
    assert a["src_ip"] == "203.0.113.9" and a["dst_ip"] == "2001:db8::1"
    assert a["explanation"]["method"] == "shap"
    assert a["status"] == "new" and a["case_id"] is None
    assert a["received_at"].endswith("Z") or "+00:00" in a["received_at"]
    assert client.get("/alerts/99999", headers=analyst_headers).status_code == 404


@pytest.mark.parametrize("override", [
    {"src_ip": "999.1.1.1"}, {"dst_ip": "not-an-ip"}, {"src_port": 65536}, {"dst_port": -1},
    {"protocol": 256}, {"confidence": 1.01}, {"confidence": -0.1},
    {"start_ms": 10, "end_ms": 5}, {"predicted_class": ""}, {"predicted_class": "x" * 65},
    {"src_port": "80"}, {"src_port": 80.5}, {"explanation": "text"}, {"unexpected": 1},
    {"explanation": {"pad": "x" * 17_000}},
])
def test_ingest_rejects_bad_alerts(client, sensor_headers, override):
    r = client.post("/ingest/alerts", headers=sensor_headers,
                    json={"alerts": [alert_payload(**override)]})
    assert r.status_code == 422


def test_ingest_rejects_nan(client, sensor_headers):
    body = json.dumps({"alerts": [alert_payload(confidence="CONF")]}).replace('"CONF"', "NaN")
    r = client.post("/ingest/alerts", headers=sensor_headers | {"Content-Type": "application/json"},
                    content=body)
    assert r.status_code == 422


def test_explanation_at_the_limit_is_accepted(client, sensor_headers):
    size = len('{"pad":""}')
    ingest(client, sensor_headers, alert_payload(explanation={"pad": "x" * (16 * 1024 - size)}))


def test_ingest_batch_limits(client, sensor_headers):
    assert client.post("/ingest/alerts", headers=sensor_headers,
                       json={"alerts": []}).status_code == 422
    batch = [alert_payload() for _ in range(501)]
    assert client.post("/ingest/alerts", headers=sensor_headers,
                       json={"alerts": batch}).status_code == 422
    assert len(ingest(client, sensor_headers, *batch[:500])) == 500


def test_ingest_is_sensor_only(client, analyst_headers, admin_headers):
    body = {"alerts": [alert_payload()]}
    for headers in (analyst_headers, admin_headers, {}):
        assert client.post("/ingest/alerts", json=body, headers=headers).status_code == 401


def test_revoked_sensor_is_refused(client, sensor_headers, admin_headers):
    sensor_id = client.get("/admin/sensors", headers=admin_headers).json()[0]["id"]
    client.post(f"/admin/sensors/{sensor_id}/revoke", headers=admin_headers)
    r = client.post("/ingest/alerts", json={"alerts": [alert_payload()]}, headers=sensor_headers)
    assert r.status_code == 401


def test_sensor_token_cannot_read_alerts(client, sensor_headers):
    assert client.get("/alerts", headers=sensor_headers).status_code == 401


def test_filters(client, sensor_headers, analyst_headers):
    ingest(client, sensor_headers,
           alert_payload(predicted_class="DDoS", src_ip="198.51.100.1", dst_ip="10.0.0.1"),
           alert_payload(predicted_class="PortScan", src_ip="198.51.100.2", dst_ip="198.51.100.1"),
           alert_payload(predicted_class="Bot", src_ip="198.51.100.3", dst_ip="10.0.0.9"))

    def get(**params):
        r = client.get("/alerts", params=params, headers=analyst_headers)
        assert r.status_code == 200, r.text
        return r.json()["items"]

    assert {a["predicted_class"] for a in get(severity="critical")} == {"DDoS"}
    assert len(get(severity=["low", "high"])) == 2
    assert {a["predicted_class"] for a in get(predicted_class="Bot")} == {"Bot"}
    assert len(get(ip="198.51.100.1")) == 2  # matches source or destination
    assert get(ip="198.51.100.99") == []
    assert get(status="resolved") == []
    assert len(get(since="2000-01-01T00:00:00Z", until="2999-01-01T00:00:00Z")) == 3
    assert get(since="2999-01-01T00:00:00Z") == []
    assert get(until="2000-01-01T00:00:00Z") == []
    for bad in ({"severity": "urgent"}, {"ip": "nope"}, {"limit": 0}, {"limit": 501},
                {"since": "2020-01-01T00:00:00"}, {"status": "weird"}, {"cursor": 0}):
        assert client.get("/alerts", params=bad, headers=analyst_headers).status_code == 422


def test_keyset_pagination(client, sensor_headers, analyst_headers):
    ids = ingest(client, sensor_headers, *[alert_payload() for _ in range(7)])
    seen, cursor = [], None
    while True:
        params = {"limit": 3} | ({"cursor": cursor} if cursor else {})
        page = client.get("/alerts", params=params, headers=analyst_headers).json()
        seen += [a["id"] for a in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert len(page["items"]) == 3
    assert seen == sorted(ids, reverse=True)


def test_patch_status(client, sensor_headers, analyst_headers):
    (alert_id,) = ingest(client, sensor_headers, alert_payload())
    r = client.patch(f"/alerts/{alert_id}", json={"status": "false_positive"},
                     headers=analyst_headers)
    assert r.status_code == 200 and r.json()["status"] == "false_positive"
    assert client.patch(f"/alerts/{alert_id}", json={"status": "bogus"},
                        headers=analyst_headers).status_code == 422
    assert client.patch(f"/alerts/{alert_id}", json={"status": "new", "x": 1},
                        headers=analyst_headers).status_code == 422
    assert client.patch("/alerts/12345", json={"status": "new"},
                        headers=analyst_headers).status_code == 404


def test_severity_mapping_is_configurable(soc_settings, sensor_headers):
    from soc.api.common import derive_severity
    settings = soc_settings.model_copy(update={"severity_by_class": {"bot": "low"},
                                               "default_severity": "high"})
    assert derive_severity(settings, "Bot", 0.9).value == "low"
    assert derive_severity(settings, "Other", 0.9).value == "high"
    assert derive_severity(settings, "Other", 0.1).value == "medium"
    assert derive_severity(settings, "Bot", 0.1).value == "low"  # never below low
