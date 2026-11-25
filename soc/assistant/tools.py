"""The assistant's tools. Each one is a fixed, parameterised query or action: the model picks a
tool and fills in validated arguments, it never writes SQL or reaches anything else.

Read-only tools return SOC data. The only tool that changes anything, propose_block, creates a
PENDING action that does nothing until an analyst confirms it in the action queue on the
Response page.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

import idps
from soc.api import access_log
from soc.api.common import IPAddress, audit, clean_reason
from soc.api.models import (
    Action,
    ActionKind,
    Alert,
    AlertStatus,
    Block,
    Case,
    CaseNote,
    SensorToken,
    Severity,
    User,
)
from soc.api.settings import SocSettings

PLAYBOOK_DIR = Path(idps.__file__).resolve().parents[1] / "docs" / "playbooks"
MAX_RESULT_CHARS = 20_000

# Each playbook covers one attack family; the model asks by the predicted class name.
PLAYBOOKS = {
    "portscan": "portscan.md", "port scan": "portscan.md",
    "ddos": "dos.md", "dos": "dos.md", "dos hulk": "dos.md", "dos goldeneye": "dos.md",
    "dos slowloris": "dos.md", "dos slowhttptest": "dos.md",
    "ftp-patator": "brute-force.md", "ssh-patator": "brute-force.md", "brute force": "brute-force.md",
    "web attack": "web-attack.md", "web attacks": "web-attack.md", "web attack - brute force": "web-attack.md",
    "web attack - xss": "web-attack.md", "web attack - sql injection": "web-attack.md",
    "bot": "bot.md", "infiltration": "infiltration.md", "heartbleed": "heartbleed.md",
    # Families of rule (Suricata) alerts, idps/rules/eve.py rule_family
    "scan": "portscan.md", "malware": "bot.md",
}
# Rule families with no playbook of their own: answered with a note, not an error.
NO_PLAYBOOK_FAMILIES = frozenset({"exploit", "policy", "rule match"})


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchAlertsArgs(_Args):
    severity: Severity | None = None
    predicted_class: str | None = Field(default=None, max_length=64)
    ip: IPAddress | None = None
    status: AlertStatus | None = None
    hours: int = Field(default=24, ge=1, le=24 * 30)
    limit: int = Field(default=20, ge=1, le=50)


class GetAlertArgs(_Args):
    alert_id: int = Field(ge=1)


class TopAttackersArgs(_Args):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    limit: int = Field(default=10, ge=1, le=25)


class ListBlocksArgs(_Args):
    active_only: bool = True
    limit: int = Field(default=25, ge=1, le=100)


class GetCaseArgs(_Args):
    case_id: int = Field(ge=1)


class MetricsArgs(_Args):
    hours: int = Field(default=24, ge=1, le=24 * 30)


class PlaybookArgs(_Args):
    attack_class: str = Field(min_length=1, max_length=64)


class ProposeBlockArgs(_Args):
    ip: IPAddress
    reason: str = Field(min_length=1, max_length=400)
    alert_id: int | None = Field(default=None, ge=1)
    sensor_id: int | None = Field(default=None, ge=1)

    @field_validator("reason")
    @classmethod
    def _plain_reason(cls, value: str) -> str:
        return clean_reason(value)  # model-written text: no control/bidi characters, no NUL


def _schema(model: type[BaseModel]) -> dict:
    """The model's JSON Schema with $refs inlined and titles dropped (plain, self-contained)."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def inline(node):
        if isinstance(node, dict):
            if "$ref" in node:
                return inline(dict(defs[node["$ref"].split("/")[-1]]))
            return {k: inline(v) for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [inline(v) for v in node]
        return node

    return inline(schema)


TOOL_SPECS: list[tuple[str, str, type[_Args]]] = [
    ("search_alerts", ("Find recent alerts. All filters are optional. `ip` matches the source or "
     "destination address. Returns the newest first, without explanations."), SearchAlertsArgs),
    ("get_alert", ("Get one alert with its full flow details and the model's explanation (the top "
     "features and their SHAP or LIME contributions toward the predicted class)."), GetAlertArgs),
    ("top_attackers", ("The source IPs with the most alerts in the last `hours`, with their "
     "alert counts and attack classes."), TopAttackersArgs),
    ("list_blocks", "IP blocks reported by the sensors (active ones by default).", ListBlocksArgs),
    ("get_case", "An incident case with its status, notes and attached alerts.", GetCaseArgs),
    ("metrics_summary", ("SOC metrics for the last `hours`: alert counts by class and severity, "
     "false-positive rate, detection latency, active blocks."), MetricsArgs),
    ("get_playbook", ("The response playbook for an attack class (e.g. 'PortScan', 'DDoS', "
     "'SSH-Patator', 'Web Attack - XSS'): what it is, MITRE ATT&CK mapping, how to confirm it, "
     "containment and remediation steps. Use it when recommending fixes."), PlaybookArgs),
    ("propose_block", ("Propose blocking an IP address. This only creates a PENDING request; "
     "nothing is blocked until an analyst confirms it in the action queue on the Response page. "
     "Give the alert_id it came from when there is one (the sensor is taken from it), "
     "and a short reason."),
     ProposeBlockArgs),
]

TOOLS: list[dict] = [{"name": name, "description": desc, "input_schema": _schema(model)}
                     for name, desc, model in TOOL_SPECS]
_ARGS = {name: model for name, _, model in TOOL_SPECS}


class ToolError(Exception):
    """A problem to report back to the model as an error result (not a crash)."""


def _since(hours: int) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def hostport(ip: str, port: int) -> str:
    """host:port, with an IPv6 address in brackets ("[2001:db8::1]:443"): bare, "2001:db8::1:443"
    reads as one more address."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _alert_brief(a: Alert) -> dict:
    return {"id": a.id, "received_at": a.received_at.isoformat(), "severity": a.severity.value,
            "predicted_class": a.predicted_class, "confidence": round(a.confidence, 3),
            "src": hostport(a.src_ip, a.src_port), "dst": hostport(a.dst_ip, a.dst_port),
            "protocol": a.protocol, "status": a.status.value, "case_id": a.case_id,
            "sensor_id": a.sensor_id, "source": a.source or "ml", **_rule_fields(a)}


def _rule_fields(a: Alert) -> dict:
    """The Suricata rule behind a rule alert (sid, rev, signature, category, severity, count). The
    signature text comes from the ruleset, but it is still data: the caller wraps every result in
    <soc_data>, with < and > escaped."""
    if (a.source or "ml") != "rule" or not isinstance(a.rule, dict):
        return {}
    keys = ("sid", "rev", "signature", "category", "severity", "count")
    return {"rule": {k: a.rule.get(k) for k in keys}}


def _search_alerts(db: Session, a: SearchAlertsArgs, **_) -> dict:
    q = select(Alert).where(Alert.received_at >= _since(a.hours))
    if a.severity:
        q = q.where(Alert.severity == a.severity)
    if a.predicted_class:
        q = q.where(func.lower(Alert.predicted_class) == a.predicted_class.strip().lower())
    if a.ip:
        q = q.where(or_(Alert.src_ip == a.ip, Alert.dst_ip == a.ip))
    if a.status:
        q = q.where(Alert.status == a.status)
    rows = db.scalars(q.order_by(Alert.id.desc()).limit(a.limit)).all()
    return {"count": len(rows), "alerts": [_alert_brief(r) for r in rows]}


def _get_alert(db: Session, a: GetAlertArgs, **_) -> dict:
    alert = db.get(Alert, a.alert_id)
    if alert is None:
        raise ToolError(f"no alert with id {a.alert_id}")
    return {**_alert_brief(alert), "flow_start_ms": alert.start_ms, "flow_end_ms": alert.end_ms,
            "anomaly_score": alert.anomaly_score, "explanation": alert.explanation}


def _top_attackers(db: Session, a: TopAttackersArgs, **_) -> dict:
    since = _since(a.hours)
    rows = db.execute(select(Alert.src_ip, func.count().label("n")).where(Alert.received_at >= since)
                      .group_by(Alert.src_ip).order_by(func.count().desc(), Alert.src_ip)
                      .limit(a.limit)).all()
    out = []
    for ip, n in rows:
        classes = db.execute(select(Alert.predicted_class, func.count())
                             .where(Alert.received_at >= since, Alert.src_ip == ip)
                             .group_by(Alert.predicted_class)).all()
        out.append({"ip": ip, "alerts": n, "classes": {c: k for c, k in classes}})
    return {"hours": a.hours, "top_sources": out}


def _list_blocks(db: Session, a: ListBlocksArgs, **_) -> dict:
    from soc.api.routes.blocks import active_clause

    q = select(Block).order_by(Block.id.desc()).limit(a.limit)
    if a.active_only:
        q = q.where(active_clause(datetime.now(UTC)))
    rows = db.scalars(q).all()
    return {"blocks": [{"ip": b.ip, "sensor_id": b.sensor_id, "reason": b.reason,
                        "source": b.source.value, "blocked_at": b.blocked_at.isoformat(),
                        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                        "alert_id": b.alert_id} for b in rows]}


def _get_case(db: Session, a: GetCaseArgs, **_) -> dict:
    case = db.get(Case, a.case_id)
    if case is None:
        raise ToolError(f"no case with id {a.case_id}")
    notes = db.scalars(select(CaseNote).where(CaseNote.case_id == case.id)
                       .order_by(CaseNote.id).limit(50)).all()
    alerts = db.scalars(select(Alert).where(Alert.case_id == case.id)
                        .order_by(Alert.id.desc()).limit(50)).all()
    return {"id": case.id, "title": case.title, "status": case.status.value,
            "created_at": case.created_at.isoformat(),
            "notes": [{"at": n.created_at.isoformat(), "text": n.text[:2000]} for n in notes],
            "alerts": [_alert_brief(x) for x in alerts]}


def _metrics(db: Session, a: MetricsArgs, user: User, **_) -> dict:
    from soc.api.routes.metrics import metrics_summary

    m = metrics_summary(user=user, db=db, hours=a.hours).model_dump(mode="json")
    m.pop("alerts_per_bucket", None)  # the time series isn't useful in a chat answer
    return m


def _playbook(db: Session, a: PlaybookArgs, **_) -> dict:
    key = a.attack_class.strip().casefold()
    name = PLAYBOOKS.get(key)
    if name is None and key in NO_PLAYBOOK_FAMILIES:
        return {"attack_class": a.attack_class, "playbook": None,
                "note": "no playbook for this rule family; triage from the rule's signature and "
                        "category, the traffic involved and the alert's severity"}
    if name is None:
        raise ToolError(f"no playbook for {a.attack_class!r}; known: {sorted(set(PLAYBOOKS))}")
    return {"attack_class": a.attack_class, "playbook": (PLAYBOOK_DIR / name).read_text()}


def _propose_block(db: Session, a: ProposeBlockArgs, user: User, settings: SocSettings,
                   **_) -> dict:
    from soc.api.routes.actions import create_action

    sensor_id = a.sensor_id
    if a.alert_id is not None:
        alert = db.get(Alert, a.alert_id)
        if alert is None:
            raise ToolError(f"no alert with id {a.alert_id}")
        if a.ip not in (alert.src_ip, alert.dst_ip):
            raise ToolError(f"{a.ip} is not an address in alert #{a.alert_id}")
        sensor_id = alert.sensor_id
    if sensor_id is None:
        sensors = db.scalars(select(SensorToken.id).where(SensorToken.revoked.is_(False))).all()
        if len(sensors) != 1:
            raise ToolError("say which alert this is about (alert_id), so the sensor is known")
        sensor_id = sensors[0]
    from soc.api.models import ActionStatus
    from soc.api.routes.blocks import active_clause

    duplicate = db.scalar(select(Action.id).where(
        Action.kind == ActionKind.BLOCK_IP, Action.sensor_id == sensor_id,
        Action.status.in_([ActionStatus.PENDING, ActionStatus.CONFIRMED]),
        Action.params["ip"].as_string() == a.ip).limit(1))
    if duplicate is not None:
        raise ToolError(f"a block of {a.ip} is already waiting (action #{duplicate})")
    if db.scalar(select(Block.id).where(Block.ip == a.ip, Block.sensor_id == sensor_id,
                                        active_clause(datetime.now(UTC))).limit(1)):
        raise ToolError(f"{a.ip} is already blocked")
    try:
        # Recorded as proposed by the assistant in this analyst's chat; it stays PENDING
        # (an assistant proposal is never confirmed by creation).
        action: Action = create_action(
            db, settings, kind=ActionKind.BLOCK_IP, params={"ip": a.ip},
            reason=f"[assistant, model-written] {a.reason}", sensor_id=sensor_id,
            proposed_by="assistant", user=user)
    except HTTPException as exc:
        raise ToolError(f"the SOC refused this block: {exc.detail}") from exc
    db.flush()
    audit(db, user, "assistant_propose_block", f"action:{action.id}",
          {"ip": a.ip, "alert_id": a.alert_id, "sensor_id": sensor_id})
    db.commit()
    return {"action_id": action.id, "status": "pending", "ip": a.ip, "sensor_id": sensor_id,
            "note": "Created as PENDING. Nothing is blocked until an analyst confirms it in the "
                    "action queue on the Response page."}


_HANDLERS = {
    "search_alerts": _search_alerts, "get_alert": _get_alert, "top_attackers": _top_attackers,
    "list_blocks": _list_blocks, "get_case": _get_case, "metrics_summary": _metrics,
    "get_playbook": _playbook, "propose_block": _propose_block,
}


def _host(endpoint: object) -> str | None:
    """The address of an "ip:port" string as _alert_brief writes it (IPv6 included)."""
    if not isinstance(endpoint, str):
        return None
    if endpoint.startswith("["):  # [addr]:port
        return endpoint[1:].partition("]")[0] or None
    host, sep, port = endpoint.rpartition(":")
    return host if sep and port.isdigit() and ":" not in host else endpoint


def returned_addresses(name: str, data: dict) -> list[str]:
    """The addresses a read-only tool's result exposes, for the access log (the log caps them)."""
    found: list[str] = []

    def alert(a: dict) -> None:
        found.extend(x for x in (_host(a.get("src")), _host(a.get("dst"))) if x)

    if name in ("search_alerts", "get_case"):
        for a in data.get("alerts", []):
            alert(a)
    elif name == "get_alert":
        alert(data)
    elif name == "top_attackers":
        found.extend(r["ip"] for r in data.get("top_sources", []))
    elif name == "list_blocks":
        found.extend(b["ip"] for b in data.get("blocks", []))
    return found


def run_tool(name: str, raw_input: Any, *, db: Session, user: User,
             settings: SocSettings) -> tuple[str, bool, dict]:
    """Run one tool call. Returns (result text for the model, is_error, result data).

    Data that came from sensors or network traffic is attacker-influenced, so results are
    labelled as data. Results are capped in size.
    """
    model = _ARGS.get(name)
    if model is None:
        return f"unknown tool {name!r}", True, {}
    try:
        args = model.model_validate(raw_input)
    except ValidationError as exc:
        msgs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        return f"invalid arguments: {msgs}", True, {}
    try:
        data = _HANDLERS[name](db, args, user=user, settings=settings)
    except ToolError as exc:
        db.rollback()
        return str(exc), True, {}
    # Reading addresses through the assistant is an access like any other (soc/api/access_log.py):
    # logged before the result goes to the model, and if that fails nothing is returned.
    ips = returned_addresses(name, data)
    if name == "search_alerts" and args.ip:
        ips.append(args.ip)  # the address searched for, even when nothing came back
    if ips:
        try:
            access_log.log_access(db, settings, user, f"assistant_{name}",
                                  target_type="assistant", ips=ips)
        except HTTPException:
            return "the access log could not be written; the result is withheld", True, {}
    # Escape < and > so data can't close the <soc_data> wrapper early (an attacker controls
    # some of these strings).
    text = json.dumps(data, default=str, ensure_ascii=False).replace("<", "\\u003c") \
        .replace(">", "\\u003e")
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + ' ... [truncated: narrow the query]'
    return ("<soc_data>\n" + text + "\n</soc_data>"), False, data
