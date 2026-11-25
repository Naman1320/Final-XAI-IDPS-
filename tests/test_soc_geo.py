"""Attack world map data (/geo/attacks) and the geolocator."""

from types import SimpleNamespace

from conftest import alert_payload, ingest

from soc.api.geo import GeoLocator, Location


def test_without_database_or_demo_private_sources_are_unlocated(client, sensor_headers,
                                                                analyst_headers):
    ingest(client, sensor_headers, alert_payload(src_ip="10.10.1.10"))
    r = client.get("/geo/attacks", headers=analyst_headers).json()
    assert r["points"] == [] and r["unlocated_sources"] == 1
    assert "IDPS_SOC_GEOIP_DB" in r["geoip_status"] and r["demo"] is False and r["home"] is None


def test_demo_mode_places_lab_addresses_and_labels_them(client, soc_app, sensor_headers,
                                                       analyst_headers):
    soc_app.state.geo = GeoLocator(None, demo=True)
    soc_app.state.settings = soc_app.state.settings.model_copy(
        update={"home_lat": 28.6, "home_lon": 77.2, "home_label": "Lab"})
    ingest(client, sensor_headers, alert_payload(src_ip="10.10.1.10"),
           alert_payload(src_ip="10.10.1.10", predicted_class="DDoS"),
           alert_payload(src_ip="10.10.1.23"))
    r = client.get("/geo/attacks", headers=analyst_headers).json()
    assert r["home"] == {"lat": 28.6, "lon": 77.2, "label": "Lab"}
    pts = {p["ip"]: p for p in r["points"]}
    assert pts["10.10.1.10"]["count"] == 2 and pts["10.10.1.10"]["max_severity"] == "critical"
    assert all(p["source"] == "demo" and p["city"].startswith("Demo:") for p in pts.values())
    # stable across requests
    again = client.get("/geo/attacks", headers=analyst_headers).json()["points"]
    assert {p["ip"]: (p["lat"], p["lon"]) for p in again} == \
        {ip: (p["lat"], p["lon"]) for ip, p in pts.items()}


def test_public_addresses_use_the_geoip_reader():
    loc = GeoLocator("/nonexistent.mmdb", demo=False)
    assert loc.locate("203.0.113.9") is None  # documentation range: not global, no demo
    fake = SimpleNamespace(
        city=lambda ip: SimpleNamespace(location=SimpleNamespace(latitude=48.86, longitude=2.35),
                                        country=SimpleNamespace(iso_code="FR"),
                                        city=SimpleNamespace(name="Paris")))
    loc._reader = fake
    assert loc.locate("8.8.4.4") == Location(48.86, 2.35, "FR", "Paris", "geoip")
    assert loc.status == "ok"


def test_unreadable_database_is_reported_not_raised():
    loc = GeoLocator("/nonexistent/GeoLite2-City.mmdb", demo=False)
    assert loc.locate("8.8.8.8") is None
    assert "could not be opened" in loc.status
