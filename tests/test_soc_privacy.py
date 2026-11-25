"""Privacy controls (roadmap step 13): erasing an IP address everywhere, the matcher's token
boundaries, the privacy notice."""

import ipaddress
import json
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from conftest import alert_payload, ingest
from sqlalchemy import select

from soc.api import access_log, privacy
from soc.api.db import Base
from soc.api.models import (
    AccessLog,
    Action,
    ActionKind,
    ActionStatus,
    Alert,
    AssistantConversation,
    AuditEntry,
    Block,
    BlockSource,
    Case,
    CaseNote,
    ErasureRecord,
    ModelVersion,
    SensorStatus,
    SensorToken,
    Severity,
    WouldBlock,
)
from soc.api.privacy import IpMatcher

V4 = "198.51.100.23"
V6 = "2001:db8::17"


# --- the matcher ------------------------------------------------------------------------------

@pytest.mark.parametrize("ip,text,hits", [
    # IPv4: token boundaries
    ("10.0.0.1", "from 10.0.0.1", 1),
    ("10.0.0.1", "from 10.0.0.10", 0),               # a longer address
    ("10.0.0.1", "from 10.0.0.100 and 110.0.0.1", 0),
    ("10.0.0.1", "10.0.0.1.5.6 is not an address", 0),
    ("10.0.0.1", "10.0.0.1.443 > 10.0.0.9.51514: Flags [S]", 1),   # tcpdump: address.port
    ("10.0.0.1", "10.0.0.1.443: and 10.0.0.1.80.", 2),
    ("10.0.0.1", "10.0.0.1.123456 and 10.0.0.10.443", 0),
    ("2001:db8::1", "2001:db8::1.443 > 2001:db8::9.51514", 1),
    ("2001:db8::1", "2001:db8::1.123456", 0),
    ("2001:db8::1", "2001:db8::1.2.3.4", 0),
    ("10.0.0.1", "version 3.10.0.0.1", 0),           # part of a longer dotted number
    ("10.0.0.1", "10.0.0.1:443, 10.0.0.1/32 and (10.0.0.1).", 3),
    ("10.0.0.1", "ip:10.0.0.1 ip=10.0.0.1 ip_10.0.0.1", 3),
    ("10.0.0.1", "10.0.0.1. Next sentence", 1),      # a full stop is not part of the address
    ("10.0.0.10", "10.0.0.1 and 10.0.0.10", 1),
    # IPv4-mapped IPv6 spellings of an IPv4 address
    ("1.2.3.4", "::ffff:1.2.3.4", 1),
    ("1.2.3.4", "::FFFF:1.2.3.4", 1),
    ("1.2.3.4", "::ffff:102:304", 1),
    ("1.2.3.4", "0:0:0:0:0:ffff:0102:0304", 1),
    ("1.2.3.4", "::ffff:102:3040", 0),
    # IPv6: any spelling of the same address, never a different one
    ("2001:db8::1", "2001:db8::1", 1),
    ("2001:db8::1", "2001:DB8::1", 1),
    ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", 1),
    ("2001:db8::1", "2001:db8:0:0:0:0:0:1", 1),
    ("2001:db8::1", "2001:db8::10", 0),
    ("2001:db8::1", "2001:db8::1:80", 1),    # "[2001:db8::1]:80" without brackets: over-redacts, safely
    ("2001:db8::1", "[2001:db8::1]:80 2001:db8::10:80", 1),
    ("2001:db8::1", "2001:db8::10.0.0.1", 0), ("2001:db8::a00:1", "2001:db8::10.0.0.1", 1),
    ("2001:db8::a00:1", "2001:db8::a00:10", 0),
    ("2001:db8::1", "12001:db8::1", 0),
    ("2001:db8::1", "[2001:db8::1]:443 and 2001:db8::1.", 2),
    ("2001:db8::1", "src:2001:db8::1 id:2001:db8::1", 2),
    ("::1", "2001:db8::1", 0),                       # a suffix of another address
    ("::1", "listening on ::1", 1),
])
def test_matcher_boundaries(ip, text, hits):
    new, n = IpMatcher(ip).redact_text(text)
    assert n == hits, (text, new)
    if hits:
        assert privacy.ERASED in new


def test_matcher_replaces_exactly_the_address():
    m = IpMatcher("10.0.0.1")
    assert m.redact_text("a 10.0.0.1 b 10.0.0.10 c") == ("a [erased] b 10.0.0.10 c", 1)


def test_ipv4_mapped_is_the_ipv4_address():
    assert IpMatcher("::ffff:1.2.3.4").ip == "1.2.3.4"


def test_matcher_json_keys_values_and_thinking_blocks():
    m = IpMatcher("10.0.0.1")
    value = {"10.0.0.1": 1, "list": ["x 10.0.0.1", {"deep": "10.0.0.10"}], "n": 5, "none": None,
             "content": [{"type": "thinking", "thinking": "scan from 10.0.0.1", "signature": "s"},
                         {"type": "text", "text": "ok 10.0.0.1"}]}
    new, n = m.redact_json(value)
    assert n == 4
    assert new["[erased]"] == 1 and new["list"] == ["x [erased]", {"deep": "10.0.0.10"}]
    assert new["n"] == 5 and new["none"] is None
    # the signed thinking block cannot be edited: it is dropped, the rest is rewritten
    assert new["content"] == [{"type": "text", "text": "ok [erased]"}]
    assert "10.0.0.1\"" not in json.dumps(new)


def test_matcher_survives_deep_nesting():
    deep: object = "10.0.0.1"
    for _ in range(300):
        deep = [deep]
    new, n = IpMatcher("10.0.0.1").redact_json(deep)
    assert n >= 1 and "10.0.0.1" not in json.dumps(new)


def test_sensor_status_allowlist_entry_is_removed_not_rewritten():
    m = IpMatcher("10.0.0.1")
    new, n = m.redact_status({"allowlist": ["10.0.0.1/32", "10.0.0.0/8", "10.0.0.10/32"],
                              "interface": "eth0 10.0.0.1"})
    assert new["allowlist"] == ["10.0.0.0/8", "10.0.0.10/32"]
    assert new["interface"] == "eth0 [erased]" and n == 2
    assert IpMatcher("2001:db8::1").redact_status({"allowlist": ["2001:db8::1/128"]})[0] \
        == {"allowlist": []}


# --- seeding every table ----------------------------------------------------------------------

def spellings_text(ip: str) -> str:
    """The address in many spellings that occur in free text: mixed zero compression, leading
    zeros, upper case, IPv4-mapped in dotted and hex form, tcpdump's address.port."""
    a = ipaddress.ip_address(ip)
    if a.version == 6:
        g = [int(x, 16) for x in a.exploded.split(":")]  # 2001:db8::17 -> 2001:db8:0:0:0:0:0:17
        low = f"{g[7]:x}"
        return " / ".join([ip, f"2001:db8:0:0::{low}", f"2001:0db8::{low}",
                           f"2001:DB8:0:0:0:0:0:{low.upper()}", a.exploded, f"{ip}.443"])
    hi, lo = divmod(int(a), 1 << 16)
    return " / ".join([ip, f"::ffff:{ip}", f"::FFFF:{hi:x}:{lo:x}", f"::ffff:{hi:04x}:{lo:04x}",
                       f"0:0:0:0:0:ffff:{hi:x}:{lo:x}", f"{ip}.443"])


def all_spellings(ip: str) -> set[str]:
    """Every spelling of the address, generated here and not by privacy.py: all the ways to
    compress a run of zero groups (or none), with and without leading zeros, both cases; for IPv4
    the dotted form and every IPv4-mapped form."""
    a = ipaddress.ip_address(ip)
    out = {ip}
    if a.version == 4:
        hi, lo = divmod(int(a), 1 << 16)
        out |= {f"::ffff:{ip}", f"0:0:0:0:0:ffff:{ip}"}
        for h, low in ((f"{hi:x}", f"{lo:x}"), (f"{hi:04x}", f"{lo:04x}")):
            out |= {f"::ffff:{h}:{low}", f"0:0:0:0:0:ffff:{h}:{low}"}
        out.add(f"0000:0000:0000:0000:0000:ffff:{hi:04x}:{lo:04x}")
    else:
        g = [int(x, 16) for x in a.exploded.split(":")]
        for pad in (False, True):
            parts = [f"{x:04x}" if pad else f"{x:x}" for x in g]
            out.add(":".join(parts))
            for i in range(8):
                for j in range(i, 8):
                    if all(g[k] == 0 for k in range(i, j + 1)):
                        out.add(":".join(parts[:i]) + "::" + ":".join(parts[j + 1:]))
            # the last 32 bits as a dotted IPv4 tail, the first six groups spelled either way
            dotted = str(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
            head = parts[:6]
            out.add(":".join(head) + ":" + dotted)
            for i in range(6):
                for j in range(i, 6):
                    if all(g[k] == 0 for k in range(i, j + 1)):
                        right = ":".join(head[j + 1:])
                        out.add(":".join(head[:i]) + "::" + (right + ":" if right else "") + dotted)
    return out | {x.upper() for x in out} | {x.lower() for x in out}


def seed(app, ip: str) -> dict:
    """The address in every table and field privacy.REDACTION_TARGETS / ADDRESS_COLUMNS name,
    next to rows that must survive (a longer address, an unrelated one)."""
    full, short = spellings_text(ip), f"x {ip}"
    longer = longer_neighbour(ip)
    now = datetime.now(UTC)
    with app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))

        def alert(src, dst, **kw):
            fields = dict(sensor_id=sensor.id, received_at=now, src_ip=src, src_port=1, dst_ip=dst,
                          dst_port=2, protocol=6, start_ms=1, end_ms=2, predicted_class="DoS",
                          confidence=0.9, severity=Severity.HIGH, explanation={}) | kw
            a = Alert(**fields)
            db.add(a)
            db.flush()
            return a

        case = Case(title=short)
        db.add(case)
        db.flush()
        own1 = alert(ip, "10.10.1.5", case_id=case.id, explanation={"method": full})
        own2 = alert("10.10.1.9", ip)
        alert("203.0.113.1", "10.10.1.5", predicted_class=short, model_version=short,
                      explanation={"method": full, "top_features": [{"feature": full}]},
                      rule={"sid": 1, "signature": full, "severity": 1})
        keep = alert(longer, "10.10.1.5", explanation={"method": longer})
        db.add_all([
            CaseNote(case_id=case.id, text=f"seen {full}; also {longer}"),
            Block(sensor_id=sensor.id, ip=ip, reason="own", source=BlockSource.AUTO,
                  blocked_at=now, unblocked_at=now),  # lifted: an active one needs force
            Block(sensor_id=sensor.id, ip="203.0.113.9", reason=full, source=BlockSource.AUTO,
                  alert_id=own1.id, blocked_at=now),
            Block(sensor_id=sensor.id, ip=longer, reason="longer", source=BlockSource.AUTO,
                  blocked_at=now),
            WouldBlock(sensor_id=sensor.id, ip=ip, reason="own", source=BlockSource.AUTO, at=now),
            WouldBlock(sensor_id=sensor.id, ip="203.0.113.9", reason=full,
                       source=BlockSource.AUTO, alert_id=own2.id, at=now),
            Action(kind=ActionKind.BLOCK_IP, params={"ip": ip}, reason=full, proposed_by="user",
                   sensor_id=sensor.id, status=ActionStatus.PENDING),
            Action(kind=ActionKind.BLOCK_IP, params={"ip": ip}, reason="r", proposed_by="user",
                   sensor_id=sensor.id, status=ActionStatus.CONFIRMED),
            Action(kind=ActionKind.BLOCK_IP, params={"ip": "203.0.113.9"}, reason="r",
                   proposed_by="user", sensor_id=sensor.id, status=ActionStatus.EXECUTED,
                   result={"note": full, "ok": True}),
            AssistantConversation(user_id=1, title=short, messages=[
                {"role": "user", "content": full},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": full, "signature": "sig"},
                    {"type": "tool_use", "id": "t1", "name": "x", "input": {"ip": ip}}]}]),
            AuditEntry(actor_type="user", actor_name="admin", action="reputation_lookup",
                       target=f"ip:{ip}", details={"ip": ip, "free": full}),
            ModelVersion(sensor_id=sensor.id, name=short, sha256="a" * 64, version=short),
            SensorStatus(sensor_id=sensor.id, payload={
                "allowlist": [f"{ip}/{128 if ':' in ip else 32}", "10.0.0.0/8"],
                "interface": short, "model": {"name": "m"}}),
            ErasureRecord(requested_by="admin", reason=f"earlier request about {full}",
                          subject_fp="f" * 64, counts={}),
        ])
        db.commit()
        keep_id = keep.id
    state = app.state
    state.reputation._cache[ip] = (0.0, {"ip": ip})
    state.geo._cache[ip] = None
    state.notifier.runners["email"]._dedupe[("ml", "DoS", ip)] = (0.0, 0)
    return {"keep_alert": keep_id, "longer": longer}


def string_columns():
    """(table, column) for every String/Text/JSON column of every table (Enum is a String)."""
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            if isinstance(col.type, sa.String | sa.Text | sa.JSON):
                yield table, col


def longer_neighbour(ip: str) -> str:
    return ip + "0"  # 198.51.100.230, 2001:db8::170: contains the text of `ip`, is another address


def scan_for(app, ip: str) -> set[tuple[str, str]]:
    """Every (table, column) whose stored value mentions the address in ANY spelling. Independent
    of privacy.py's matcher: plain substring tests on the lower-cased text of every value, after
    removing the longer neighbour address that is meant to survive."""
    needles = {x.lower() for x in all_spellings(ip)}
    neighbour = longer_neighbour(ip).lower()
    found = set()
    with app.state.engine.connect() as conn:
        for table, col in string_columns():
            for (value,) in conn.execute(sa.select(col)):
                if value is None:
                    continue
                text = (json.dumps(value) if not isinstance(value, str) else value).lower()
                text = text.replace(neighbour, "")
                if any(n in text for n in needles):
                    found.add((table.name, col.name))
                    break
    return found


# --- the acceptance test ----------------------------------------------------------------------

def test_every_text_column_has_a_decision():
    """A table or column added without deciding what erasure does with it fails here."""
    undecided = []
    for table, col in string_columns():
        name = table.name
        decided = (name in privacy.EXEMPT_TABLES
                   or col.name in privacy.REDACTION_TARGETS.get(name, {})
                   or col.name in privacy.ADDRESS_COLUMNS.get(name, ())
                   or (name, col.name) in privacy.EXEMPT_COLUMNS)
        if not decided:
            undecided.append(f"{name}.{col.name}")
    assert not undecided, f"decide how erasure treats: {undecided}"
    # and the registry names nothing that does not exist
    tables = Base.metadata.tables
    for name, cols in privacy.REDACTION_TARGETS.items():
        assert set(cols) <= set(tables[name].columns.keys()), name
    for name, cols in privacy.ADDRESS_COLUMNS.items():
        assert set(cols) <= set(tables[name].columns.keys()), name
    assert set(privacy.EXEMPT_TABLES) <= set(tables)
    assert {t for t, _ in privacy.EXEMPT_COLUMNS} <= set(tables)


@pytest.mark.parametrize("ip", [V4, V6])
def test_erasing_an_address_removes_it_everywhere(client, soc_app, admin_headers, sensor_token, ip):
    info = seed(soc_app, ip)
    expected = {(t, c) for t, cols in privacy.REDACTION_TARGETS.items() for c in cols}
    expected |= {(t, c) for t, cols in privacy.ADDRESS_COLUMNS.items() for c in cols}
    # the seed really put the address in every field the registry names (and nowhere else)
    assert scan_for(soc_app, ip) == expected

    preview = client.post("/admin/privacy/erase/preview", json={"ip": ip}, headers=admin_headers)
    assert preview.status_code == 200, preview.text
    pv = preview.json()
    assert set(pv["counts"]) == set(privacy.COUNT_KEYS)
    assert pv["counts"]["alerts"] == 2 and pv["counts"]["blocks"] == 1
    assert pv["counts"]["would_blocks"] == 1
    assert pv["counts"]["actions.cancelled"] == 2  # the pending and the confirmed block action
    for table, cols in privacy.REDACTION_TARGETS.items():
        for col in cols:
            assert pv["counts"][f"{table}.{col}"] >= 1, f"{table}.{col} was not found"
    for key in ("memory.reputation_cache", "memory.geo_cache", "memory.notification_dedupe"):
        assert pv["counts"][key] == 1, key
    assert pv["total"] == sum(v for k, v in pv["counts"].items() if k != "actions.cancelled")
    assert scan_for(soc_app, ip) == expected  # a preview changes nothing

    r = client.post("/admin/privacy/erase", json={"ip": ip, "reason": "data principal request"},
                    headers=admin_headers)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["counts"] == pv["counts"] and result["total"] == pv["total"]  # preview == erase
    assert result["subject_fp"] == pv["subject_fp"] and result["record_id"] >= 1

    assert scan_for(soc_app, ip) == set()  # nothing in any table or column
    again = client.post("/admin/privacy/erase/preview", json={"ip": ip}, headers=admin_headers)
    assert again.json()["total"] == 0 and not any(again.json()["counts"].values())
    assert soc_app.state.reputation._cache == {} and soc_app.state.geo._cache == {}
    assert soc_app.state.notifier.runners["email"]._dedupe == {}

    with soc_app.state.session_factory() as db:
        # what is not the address stays: the longer address's alert, block and note text
        assert db.get(Alert, info["keep_alert"]).src_ip == info["longer"]
        assert db.scalar(select(Block).where(Block.ip == info["longer"])) is not None
        assert info["longer"] in db.scalar(select(CaseNote.text))
        assert db.scalar(select(sa.func.count()).select_from(Case)) == 1  # the case stays
        # the case lost its alert but not its notes; the other block lost only its link
        other_block = db.scalar(select(Block).where(Block.ip == "203.0.113.9"))
        assert other_block.alert_id is None and "[erased]" in other_block.reason
        # open actions that named the address were cancelled, not left for a sensor to pick up
        statuses = sorted(a.status.value for a in db.scalars(select(Action)))
        assert statuses == ["executed", "failed", "rejected"]
        status = db.scalar(select(SensorStatus)).payload
        assert status["allowlist"] == ["10.0.0.0/8"]
        convo = db.scalar(select(AssistantConversation)).messages
        assert [b["type"] for b in convo[1]["content"]] == ["tool_use"]  # thinking block dropped
        # the record and the audit entry hold a fingerprint and counts, never the address
        record = db.scalars(select(ErasureRecord).order_by(ErasureRecord.id.desc())).first()
        assert record.subject_fp == result["subject_fp"] and record.requested_by == "admin"
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "privacy_erase"))
        assert audit.details["subject_fp"] == result["subject_fp"]
        assert audit.details["counts"]["alerts"] == 2
        assert ip not in json.dumps(audit.details) and ip not in audit.target


def test_second_erase_finds_nothing(client, soc_app, admin_headers, sensor_token):
    seed(soc_app, V4)
    first = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"},
                        headers=admin_headers).json()
    assert first["total"] > 0
    second = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "again"},
                         headers=admin_headers)
    assert second.status_code == 200
    assert second.json()["total"] == 0 and not any(second.json()["counts"].values())
    listing = client.get("/admin/privacy/erasures", headers=admin_headers).json()
    assert [i["reason"] for i in listing["items"]][:2] == ["again", "r"]


def test_a_boundary_neighbour_is_untouched(client, soc_app, admin_headers, sensor_token):
    ids = ingest(client, {"Authorization": f"Bearer {sensor_token}"},
                 alert_payload(src_ip="10.0.0.1"), alert_payload(src_ip="10.0.0.10"),
                 alert_payload(src_ip="110.0.0.1"))
    with soc_app.state.session_factory() as db:
        case = Case(title="t 10.0.0.1 and 10.0.0.10")
        db.add(case)
        db.flush()
        db.add(CaseNote(case_id=case.id, text="10.0.0.1 10.0.0.10"))
        db.commit()
    r = client.post("/admin/privacy/erase", json={"ip": "10.0.0.1", "reason": "r"},
                    headers=admin_headers)
    assert r.json()["counts"]["alerts"] == 1
    with soc_app.state.session_factory() as db:
        assert sorted(a.src_ip for a in db.scalars(select(Alert))) == ["10.0.0.10", "110.0.0.1"]
        assert ids[0] not in list(db.scalars(select(Alert.id)))
        assert db.scalar(select(CaseNote.text)) == "[erased] 10.0.0.10"
        assert db.scalar(select(Case.title)) == "t [erased] and 10.0.0.10"


@pytest.mark.parametrize("spelling", ["::ffff:198.51.100.23", " 198.51.100.23 "])
def test_an_ipv4_mapped_request_is_the_ipv4_address(client, soc_app, admin_headers, sensor_token,
                                                    spelling):
    seed(soc_app, V4)
    r = client.post("/admin/privacy/erase", json={"ip": spelling, "reason": "r"},
                    headers=admin_headers)
    assert r.status_code == 200 and r.json()["ip"] == V4
    assert scan_for(soc_app, V4) == set()


def test_an_ipv6_address_in_another_spelling_is_erased(client, soc_app, admin_headers, sensor_token):
    seed(soc_app, V6)
    r = client.post("/admin/privacy/erase",
                    json={"ip": "2001:0DB8:0:0:0:0:0:17", "reason": "r"}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["ip"] == V6
    assert scan_for(soc_app, V6) == set()


# --- the endpoint -----------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", [
    ("POST", "/admin/privacy/erase/preview", {"ip": V4}),
    ("POST", "/admin/privacy/erase", {"ip": V4, "reason": "r"}),
    ("GET", "/admin/privacy/erasures", None),
    ("GET", "/admin/privacy/access-log", None),
])
def test_privacy_admin_routes_are_admin_only(client, analyst_headers, method, path, body):
    assert client.request(method, path, json=body, headers=analyst_headers).status_code == 403
    assert client.request(method, path, json=body).status_code == 401


@pytest.mark.parametrize("ip", ["not-an-ip", "", "999.1.1.1", "1.2.3", "10.0.0.1%eth0"])
def test_an_invalid_address_is_refused(client, admin_headers, ip):
    for path, body in (("/admin/privacy/erase/preview", {"ip": ip}),
                       ("/admin/privacy/erase", {"ip": ip, "reason": "r"})):
        r = client.post(path, json=body, headers=admin_headers)
        assert r.status_code == 422, (path, ip)
        assert ip not in r.text or not ip  # the input is not echoed back


@pytest.mark.parametrize("cidr", ["10.0.0.0/24", "10.0.0.1/32", "2001:db8::/32"])
def test_a_network_is_refused_with_an_explanation(client, admin_headers, cidr):
    r = client.post("/admin/privacy/erase", json={"ip": cidr, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 422
    assert "CIDR" in r.text and "not supported" in r.text


@pytest.mark.parametrize("body", [
    {"ip": V4}, {"ip": V4, "reason": ""}, {"ip": V4, "reason": "x" * 501},
    {"ip": V4, "reason": "   "}, {"ip": V4, "reason": "r", "extra": 1},
])
def test_a_reason_is_required(client, admin_headers, body):
    assert client.post("/admin/privacy/erase", json=body, headers=admin_headers).status_code == 422


def test_the_reason_may_not_contain_the_address(client, admin_headers):
    for reason in (f"request from {V4}", "::ffff:198.51.100.23 asked", "198.51.100.23."):
        r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": reason},
                        headers=admin_headers)
        assert r.status_code == 422 and "reason" in r.text
    ok = client.post("/admin/privacy/erase", json={"ip": V4, "reason": f"neighbour {V4}0"},
                     headers=admin_headers)
    assert ok.status_code == 200  # a different (longer) address is fine


def test_the_erase_body_is_size_limited(client, admin_headers):
    r = client.post("/admin/privacy/erase", content=b"{" + b" " * 5000 + b"}",
                    headers=admin_headers | {"Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.parametrize("ip", [V4, V6, "10.0.0.1", "::1", "fe80::a:b", "2001:db8:0:0:1::7",
                                "::a00:1", "2001:db8::a00:1", "64:ff9b::1"])
def test_every_spelling_passes_the_sql_prefilter_and_is_redacted(ip):
    m = IpMatcher(ip)
    for sp in all_spellings(ip):
        low = sp.lower()
        assert any(all(n in low for n in group) for group in m.prefilter), (ip, sp)
        new, n = m.redact_text(f"seen {sp} here")
        assert n == 1 and new == "seen [erased] here", (ip, sp, new)
        _, n = m.redact_text(f"seen {sp}.443 here")
        assert n == 1, (ip, sp)


def test_the_address_never_reaches_the_audit_or_access_log(client, soc_app, admin_headers,
                                                          sensor_token):
    seed(soc_app, V4)
    client.post("/admin/privacy/erase/preview", json={"ip": V4}, headers=admin_headers)
    client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    client.get("/admin/privacy/erasures", headers=admin_headers)
    with soc_app.state.session_factory() as db:
        for model in (ErasureRecord, AccessLog):
            for row in db.scalars(select(model)):
                blob = json.dumps({c.name: str(getattr(row, c.name))
                                   for c in model.__table__.columns})
                assert V4 not in blob
        actions = [r.action for r in db.scalars(select(AccessLog))]
        assert "privacy_erase_preview" in actions
        fp = access_log.fingerprint(soc_app.state.settings, V4)
        assert db.scalar(select(AccessLog.subject_fp).where(
            AccessLog.action == "privacy_erase_preview")) == fp


def test_erasure_listing_has_no_addresses_and_paginates(client, soc_app, admin_headers):
    for i in range(3):
        r = client.post("/admin/privacy/erase", json={"ip": f"192.0.2.{i + 1}", "reason": f"r{i}"},
                        headers=admin_headers)
        assert r.status_code == 200
    page = client.get("/admin/privacy/erasures?limit=2", headers=admin_headers).json()
    assert [i["reason"] for i in page["items"]] == ["r2", "r1"] and page["next_cursor"]
    rest = client.get(f"/admin/privacy/erasures?limit=2&cursor={page['next_cursor']}",
                      headers=admin_headers).json()
    assert [i["reason"] for i in rest["items"]] == ["r0"] and rest["next_cursor"] is None
    assert "192.0.2." not in json.dumps(page) + json.dumps(rest)
    assert set(page["items"][0]) == {"id", "at", "requested_by", "reason", "subject_fp", "counts"}


def test_account_and_sensor_names_that_are_addresses_are_reported_not_rewritten(
        client, soc_app, admin_headers):
    from soc.api import auth
    from soc.api.models import Role

    with soc_app.state.session_factory() as db:
        auth.create_user(db, "10.0.0.7", "a-long-password-123", Role.ANALYST)
        auth.create_sensor_token(db, "10.0.0.7")
    r = client.post("/admin/privacy/erase/preview", json={"ip": "10.0.0.7"},
                    headers=admin_headers).json()
    assert r["manual_review"] == {"users.username": 1, "sensor_tokens.name": 1}
    assert any("rename" in w for w in r["warnings"]) and r["total"] == 0
    longer = client.post("/admin/privacy/erase/preview", json={"ip": "10.0.0.70"},
                         headers=admin_headers).json()
    assert longer["manual_review"] == {}


def test_an_active_block_needs_force(client, soc_app, admin_headers, sensor_token):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(Block(sensor_id=sensor.id, ip=V4, reason="x", source=BlockSource.AUTO,
                     blocked_at=now, expires_at=now + timedelta(hours=1)))
        db.commit()
    pv = client.post("/admin/privacy/erase/preview", json={"ip": V4}, headers=admin_headers).json()
    assert any("active block" in w and "force" in w for w in pv["warnings"])
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 409 and "active block" in r.text
    with soc_app.state.session_factory() as db:  # nothing happened
        assert db.scalar(select(sa.func.count()).select_from(Block)) == 1
        assert db.scalar(select(sa.func.count()).select_from(ErasureRecord)) == 0
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r", "force": True},
                    headers=admin_headers)
    assert r.status_code == 200 and r.json()["counts"]["blocks"] == 1
    with soc_app.state.session_factory() as db:
        audit = db.scalar(select(AuditEntry).where(AuditEntry.action == "privacy_erase"))
        assert audit.details["forced"] is True


def test_a_block_that_has_expired_or_been_lifted_needs_no_force(client, soc_app, admin_headers,
                                                                sensor_token):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        db.add(Block(sensor_id=sensor.id, ip=V4, reason="x", source=BlockSource.AUTO,
                     blocked_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1)))
        db.commit()
    assert client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"},
                       headers=admin_headers).status_code == 200


def test_a_sensor_polling_after_the_erasure_gets_no_broken_action(client, soc_app, admin_headers,
                                                                 sensor_token):
    seed(soc_app, V4)
    client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    r = client.get("/sensor/actions", headers={"Authorization": f"Bearer {sensor_token}"})
    assert r.status_code == 200 and r.json() == []


def test_erase_is_atomic(client, soc_app, admin_headers, sensor_token, monkeypatch):
    """A failure half way leaves everything as it was."""
    seed(soc_app, V4)
    before = scan_for(soc_app, V4)

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(privacy, "_delete_blocks", boom)
    from fastapi.testclient import TestClient

    r = TestClient(soc_app, raise_server_exceptions=False).post(
        "/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 500
    assert scan_for(soc_app, V4) == before  # alerts, actions and all redactions rolled back
    with soc_app.state.session_factory() as db:
        assert db.scalar(select(sa.func.count()).select_from(ErasureRecord)) == 1  # the seeded one
    assert soc_app.state.reputation._cache  # and the caches were not touched


# --- the privacy notice -----------------------------------------------------------------------

def test_the_notice_is_public_and_states_the_actual_retention(soc_settings, soc_app):
    from fastapi.testclient import TestClient

    r = TestClient(soc_app).get("/privacy/notice")  # no token
    assert r.status_code == 200
    n = r.json()
    s = soc_app.state.settings
    assert n["retention"]["alerts_days"] == s.alert_retention_days == 180
    assert n["retention"]["access_log_days"] == 365
    assert n["retention"]["audit_log_days"] == s.audit_retention_days
    assert n["retention"]["assistant_conversations_days"] == 90
    assert n["retention"]["would_block_records_days"] == 7
    assert n["retention"]["alerts_kept_if_judged_for_training"] is True
    assert {c["category"] for c in n["data_categories"]} >= {
        "Network flow identifiers", "Flow statistics", "Analyst accounts",
        "Audit and access logs", "Assistant conversations"}
    assert any("security monitoring" in p for p in n["purposes"])
    assert any("incident response" in p.lower() for p in n["purposes"])
    assert {x["right"] for x in n["rights"]} >= {"access", "correction", "erasure", "grievance"}
    assert n["controller"] == {"name": None, "contact_email": None, "grievance_officer": None}
    assert "legal advice" in n["note"]


def test_the_notice_follows_the_settings(soc_settings):
    from fastapi.testclient import TestClient

    from soc.api.main import create_app

    settings = soc_settings.model_copy(update={
        "alert_retention_days": 30, "audit_retention_days": 0, "access_log_retention_days": 400,
        "privacy_controller_name": "Example Ltd", "privacy_contact_email": "dpo@example.org",
        "privacy_grievance_officer": "A. Officer"})
    n = TestClient(create_app(settings)).get("/privacy/notice").json()
    assert n["retention"]["alerts_days"] == 30 and n["retention"]["audit_log_days"] == 0
    assert n["retention"]["access_log_days"] == 400
    assert n["controller"] == {"name": "Example Ltd", "contact_email": "dpo@example.org",
                               "grievance_officer": "A. Officer"}
    assert "dpo@example.org" in n["how_to_exercise"]


def test_the_notice_names_channels_but_never_their_targets_or_secrets(soc_settings):
    from fastapi.testclient import TestClient

    from soc.api.main import create_app

    settings = soc_settings.model_copy(update={
        "webhook_url": "https://hooks.example.com/SECRETPATH",
        "webhook_secret": "WEBHOOKSECRET" + "x" * 30,
        "slack_webhook_url": "https://hooks.slack.com/services/T000/B000/SLACKTOKEN",
        "smtp_host": "smtp.internal.example", "smtp_from": "idps@example.org",
        "smtp_to": ["soc-lead@example.org"], "smtp_password": "SMTPPASSWORD" + "y" * 30,
        "syslog_host": "siem.internal.example", "abuseipdb_key": "ABUSEKEY" + "z" * 30,
        "report_email_enabled": True})
    r = TestClient(create_app(settings)).get("/privacy/notice")
    names = {x["name"] for x in r.json()["recipients"]}
    assert names == {"webhook", "slack", "email", "syslog", "AbuseIPDB"}
    for secret in ("SECRETPATH", "hooks.example.com", "SLACKTOKEN", "slack.com", "WEBHOOKSECRET",
                   "smtp.internal", "soc-lead", "SMTPPASSWORD", "siem.internal", "ABUSEKEY",
                   "idps@example.org", "jwt", "test-secret"):
        assert secret not in r.text, secret
    email = next(x for x in r.json()["recipients"] if x["name"] == "email")
    assert "weekly report" in email["description"]


def test_the_notice_without_integrations_lists_no_recipients(soc_app):
    from fastapi.testclient import TestClient

    assert TestClient(soc_app).get("/privacy/notice").json()["recipients"] == []


# --- settings ---------------------------------------------------------------------------------

def test_privacy_settings_are_optional_and_blank_means_unset(monkeypatch):
    from conftest import TEST_SECRET

    from soc.api.settings import SocSettings

    monkeypatch.setenv("IDPS_SOC_PRIVACY_CONTROLLER_NAME", "")
    monkeypatch.setenv("IDPS_SOC_PRIVACY_CONTACT_EMAIL", " ")
    monkeypatch.setenv("IDPS_SOC_PRIVACY_GRIEVANCE_OFFICER", "")
    monkeypatch.setenv("IDPS_SOC_REPORT_EMAIL_ENABLED", "")
    monkeypatch.setenv("IDPS_SOC_REPORT_EMAIL_TO", "")
    monkeypatch.setenv("IDPS_SOC_ACCESS_LOG_RETENTION_DAYS", "")
    s = SocSettings(jwt_secret=TEST_SECRET)
    assert (s.privacy_controller_name, s.privacy_contact_email, s.privacy_grievance_officer) \
        == (None, None, None)
    assert s.report_email_enabled is False and s.access_log_retention_days == 365
    assert s.report_email_weekday == 0 and s.report_email_hour_utc == 6
    assert s.report_mask_ips is False and s.report_recipients == []


def test_privacy_settings_are_validated():
    from conftest import TEST_SECRET
    from pydantic import ValidationError

    from soc.api.settings import SocSettings

    for bad in ({"privacy_contact_email": "not an address"}, {"report_email_weekday": 7},
                {"report_email_hour_utc": 24}, {"report_email_to": "nope"},
                {"privacy_controller_name": "a\nb"}):
        with pytest.raises(ValidationError):
            SocSettings(jwt_secret=TEST_SECRET, **bad)
    s = SocSettings(jwt_secret=TEST_SECRET, smtp_to="a@example.org",
                    report_email_to="b@example.org, c@example.org")
    assert s.report_recipients == ["b@example.org", "c@example.org"]
    assert SocSettings(jwt_secret=TEST_SECRET, smtp_to="a@example.org").report_recipients \
        == ["a@example.org"]


# --- assistant replies in progress ------------------------------------------------------------

def _conversation(app, ip, busy_since):
    with app.state.session_factory() as db:
        c = AssistantConversation(user_id=1, title="t", busy_since=busy_since, messages=[
            {"role": "user", "content": f"what is {ip}?"}])
        db.add(c)
        db.commit()
        return c.id


def test_erasure_is_refused_while_a_matching_reply_is_running(client, soc_app, admin_headers):
    cid = _conversation(soc_app, V4, datetime.now(UTC) - timedelta(seconds=20))
    pv = client.post("/admin/privacy/erase/preview", json={"ip": V4}, headers=admin_headers).json()
    assert any("reply in progress" in w for w in pv["warnings"])
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 409
    assert r.json()["detail"] == "an assistant reply is in progress; try again in a minute"
    with soc_app.state.session_factory() as db:  # nothing was erased
        assert V4 in json.dumps(db.get(AssistantConversation, cid).messages)
    with soc_app.state.session_factory() as db:  # the reply finishes
        db.get(AssistantConversation, cid).busy_since = None
        db.commit()
    assert client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"},
                       headers=admin_headers).status_code == 200


def test_any_running_reply_blocks_erasure_but_a_dead_one_does_not(client, soc_app, admin_headers):
    """A reply in progress writes its copy of the history back (and its new message may quote the
    address): so ANY fresh busy_since refuses, not only conversations that mention the address."""
    _conversation(soc_app, V4, datetime.now(UTC) - timedelta(minutes=30))   # assumed dead
    live = _conversation(soc_app, "10.9.9.9", datetime.now(UTC))             # another topic
    pv = client.post("/admin/privacy/erase/preview", json={"ip": V4}, headers=admin_headers).json()
    assert any("reply in progress" in w for w in pv["warnings"])
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 409 and "reply is in progress" in r.text
    with soc_app.state.session_factory() as db:
        db.get(AssistantConversation, live).busy_since = None
        db.commit()
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["counts"]["assistant_conversations.messages"] == 1


def test_a_conversation_idle_at_the_scan_but_busy_at_the_write_is_refused(soc_app):
    from soc.api.privacy import apply_plan, scan_plan

    cid = _conversation(soc_app, V4, None)
    with soc_app.state.session_factory() as db:
        scanned = scan_plan(db, IpMatcher(V4))
        assert scanned.busy_conversations == 0
        db.get(AssistantConversation, cid).busy_since = datetime.now(UTC)  # a reply starts now
        db.flush()
        with pytest.raises(privacy.HTTPException) as exc:
            apply_plan(db, IpMatcher(V4), scanned, force=False)
        assert exc.value.status_code == 409
        db.rollback()


def test_a_reply_that_finishes_after_an_erasure_does_not_restore_the_address(soc_app):
    from soc.api.routes.assistant import save_reply

    cid = _conversation(soc_app, V4, datetime.now(UTC))
    with soc_app.state.session_factory() as db:
        history = [*db.get(AssistantConversation, cid).messages,       # the copy the reply started with
                   {"role": "user", "content": "and next?"}]
    with soc_app.state.session_factory() as db:  # an erasure rewrote the stored messages meanwhile
        db.get(AssistantConversation, cid).messages = [
            {"role": "user", "content": "what is [erased]?"}]
        db.commit()
    save_reply(soc_app.state.session_factory, cid, history[-1],
               [{"role": "assistant", "content": "an answer"}])
    with soc_app.state.session_factory() as db:
        c = db.get(AssistantConversation, cid)
        assert V4 not in json.dumps(c.messages)
        assert [m["content"] for m in c.messages] == ["what is [erased]?", "and next?", "an answer"]
        assert c.busy_since is None and c.user_turns == 1


# --- the rest of the erasure's behaviour ------------------------------------------------------

def test_an_alert_committed_during_the_erasure_is_deleted_too(client, soc_app, admin_headers,
                                                              sensor_token, monkeypatch):
    """The by-address deletes run again as the last step, so a row that appeared after the first
    sweep (a sensor ingesting at the same moment) does not survive."""
    real = privacy._delete_blocks
    calls = []

    def sweep_then_ingest(db, matcher, plan):
        real(db, matcher, plan)
        calls.append(1)
        if len(calls) == 1:
            sensor = db.scalar(select(SensorToken))
            db.add(Alert(sensor_id=sensor.id, received_at=datetime.now(UTC), src_ip=V4,
                         src_port=1, dst_ip="10.10.1.5", dst_port=2, protocol=6, start_ms=1,
                         end_ms=2, predicted_class="DoS", confidence=0.9, severity=Severity.HIGH,
                         explanation={}))
            db.add(WouldBlock(sensor_id=sensor.id, ip=V4, reason="late", source=BlockSource.AUTO,
                              at=datetime.now(UTC)))
            db.flush()

    monkeypatch.setattr(privacy, "_delete_blocks", sweep_then_ingest)
    r = client.post("/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 200 and len(calls) == 2
    assert r.json()["counts"]["alerts"] == 1 and r.json()["counts"]["would_blocks"] == 1
    assert scan_for(soc_app, V4) == set()


def test_a_database_error_is_a_500_that_says_so_not_a_silent_busy(client, soc_app, admin_headers,
                                                                 monkeypatch, caplog):
    from fastapi.testclient import TestClient
    from sqlalchemy.exc import IntegrityError

    def broken(*a, **k):
        raise IntegrityError("INSERT secret statement", {"p": "secret-value"},
                             Exception("constraint failed"))

    monkeypatch.setattr(privacy, "_delete_alerts", broken)
    r = TestClient(soc_app, raise_server_exceptions=False).post(
        "/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 500 and "nothing was changed" in r.text
    assert "secret" not in r.text and "secret" not in caplog.text
    assert "Exception" in caplog.text  # the driver error type is logged


def test_a_lock_conflict_twice_is_a_503(client, soc_app, admin_headers, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy.exc import OperationalError

    def locked(*a, **k):
        raise OperationalError("stmt", {}, Exception("database is locked"))

    monkeypatch.setattr(privacy, "_delete_alerts", locked)
    monkeypatch.setattr(privacy.time, "sleep", lambda s: None)
    r = TestClient(soc_app, raise_server_exceptions=False).post(
        "/admin/privacy/erase", json={"ip": V4, "reason": "r"}, headers=admin_headers)
    assert r.status_code == 503


def test_erasures_can_be_looked_up_by_address(client, soc_app, admin_headers):
    client.post("/admin/privacy/erase", json={"ip": "192.0.2.1", "reason": "one"},
                headers=admin_headers)
    client.post("/admin/privacy/erase", json={"ip": "192.0.2.2", "reason": "two"},
                headers=admin_headers)
    hit = client.get("/admin/privacy/erasures?ip=::ffff:192.0.2.2", headers=admin_headers).json()
    assert [i["reason"] for i in hit["items"]] == ["two"]
    assert client.get("/admin/privacy/erasures?ip=192.0.2.9", headers=admin_headers
                      ).json()["items"] == []
    assert client.get("/admin/privacy/erasures?ip=nope", headers=admin_headers).status_code == 422


# --- rows written between the scan and the writes ---------------------------------------------

def test_an_action_audit_entry_and_note_written_after_the_scan_are_caught(soc_app, sensor_token):
    """The write phase scans the small tables again under the lock, and alerts above the newest id
    the first scan saw."""
    from soc.api.privacy import apply_plan, scan_plan

    m = IpMatcher(V4)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        case = Case(title="c")
        db.add(case)
        db.commit()
        scanned = scan_plan(db, m)
        assert scanned.total == 0
        # ... and now, after the scan: a pending block (an analyst or the assistant), an audit
        # entry, a note, a status report and a new alert that mentions it in its rule text
        db.add_all([
            Action(kind=ActionKind.BLOCK_IP, params={"ip": V4}, reason="late", proposed_by="user",
                   sensor_id=sensor.id, status=ActionStatus.PENDING),
            AuditEntry(actor_type="user", actor_name="a", action="x", target=f"ip:{V4}",
                       details={}),
            CaseNote(case_id=case.id, text=f"late note {V4}"),
            SensorStatus(sensor_id=sensor.id, payload={"interface": f"eth0 {V4}"}),
            Alert(sensor_id=sensor.id, received_at=datetime.now(UTC), src_ip="9.9.9.9", src_port=1,
                  dst_ip="10.10.1.5", dst_port=2, protocol=6, start_ms=1, end_ms=2,
                  predicted_class="DoS", confidence=0.9, severity=Severity.HIGH, explanation={},
                  rule={"signature": f"scan from {V4}"})])
        db.commit()
        plan = apply_plan(db, m, scanned, force=False)
        db.commit()
    assert plan.counts["actions.cancelled"] == 1 and plan.counts["actions.params"] == 1
    assert plan.counts["audit_log.target"] == 1 and plan.counts["case_notes.text"] == 1
    assert plan.counts["sensor_status.payload"] == 1 and plan.counts["alerts.rule"] == 1
    assert scan_for(soc_app, V4) == set()
    with soc_app.state.session_factory() as db:
        assert db.scalar(select(Action.status)) == ActionStatus.REJECTED  # not left to be fetched


def test_a_candidate_changed_between_scan_and_write_is_rewritten_from_its_current_text(soc_app):
    from soc.api.privacy import apply_plan, scan_plan

    m = IpMatcher(V4)
    with soc_app.state.session_factory() as db:
        case = Case(title="c")
        db.add(case)
        db.flush()
        note = CaseNote(case_id=case.id, text=f"old {V4}")
        gone = CaseNote(case_id=case.id, text=f"old {V4}")
        db.add_all([note, gone])
        db.commit()
        scanned = scan_plan(db, m)
        assert scanned.counts["case_notes.text"] == 2
        note.text = f"edited KEEPME {V4} and {V4}"   # changed since the scan
        gone.text = "edited, no address now"          # no longer a candidate
        db.commit()
        plan = apply_plan(db, m, scanned, force=False)
        db.commit()
        texts = sorted(db.scalars(select(CaseNote.text)))
    assert texts == ["edited KEEPME [erased] and [erased]", "edited, no address now"]
    assert plan.counts["case_notes.text"] == 1


def test_preview_lists_the_number_of_active_blocks(client, soc_app, admin_headers, sensor_token):
    now = datetime.now(UTC)
    with soc_app.state.session_factory() as db:
        sensor = db.scalar(select(SensorToken))
        for _ in range(2):
            db.add(Block(sensor_id=sensor.id, ip=V4, reason="x", source=BlockSource.AUTO,
                         blocked_at=now))
        db.add(Block(sensor_id=sensor.id, ip=V4, reason="x", source=BlockSource.AUTO,
                     blocked_at=now, unblocked_at=now))
        db.commit()
    pv = client.post("/admin/privacy/erase/preview", json={"ip": V4}, headers=admin_headers).json()
    assert pv["active_blocks"] == 2 and pv["counts"]["blocks"] == 3 and pv["warnings"]
    assert client.post("/admin/privacy/erase/preview", json={"ip": "192.0.2.5"},
                       headers=admin_headers).json()["active_blocks"] == 0
