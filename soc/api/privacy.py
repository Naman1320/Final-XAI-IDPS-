"""Privacy controls (docs/privacy.md): erasing an IP address on request, the access-log endpoint
and the public privacy notice.

Erasure ("everywhere"): a read-only scan, then the writes in ONE transaction:
- alerts whose source or destination is the address are deleted (blocks and would-blocks of other
  addresses that pointed at them lose the link; a case left without alerts stays);
- blocks and would-blocks of the address are deleted;
- the address is replaced by "[erased]" wherever it appears as text in what remains: see
  REDACTION_TARGETS (free text and JSON of alerts, blocks, actions, cases, notes, assistant
  conversations, audit entries, sensor status, model versions, earlier erasure reasons);
- the in-memory reputation, location and notification de-duplication caches forget it.
Open actions (pending or confirmed) that name the address are cancelled first: a sensor must not
be handed an action whose address has been erased.

Matching is by token, not by substring: "10.0.0.1" does not match inside "10.0.0.10", "110.0.0.1"
or "10.0.0.1.5.6". A trailing ".443" is read as a port (tcpdump's address.port), so "10.0.0.1.443"
and "2001:db8::1:443" are the address. IPv6 is compared as an address (any spelling: compressed,
expanded, upper case, IPv4-mapped, dotted tail), not as a string.

The erasure leaves a record (who, when, why, a fingerprint of the address and the counts; never the
address) and an audit entry. COVERAGE below classifies every text/JSON column of every table; a test
fails when a column is added without deciding what erasure does with it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, field_validator
from sqlalchemy import Text, and_, cast, delete, func, or_, select, text, update
from sqlalchemy import bindparam as sa_bindparam
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from soc.api import access_log
from soc.api.auth import AdminUser
from soc.api.common import (
    Cursor,
    Limit,
    Page,
    audit,
    canonical_ip,
    clean_reason,
    paginate,
)
from soc.api.db import get_db
from soc.api.models import (
    AccessLog,
    Action,
    ActionStatus,
    Alert,
    AssistantConversation,
    AuditEntry,
    Block,
    Case,
    CaseNote,
    ErasureRecord,
    ModelVersion,
    SensorStatus,
    SensorToken,
    User,
    WouldBlock,
)
from soc.api.retention import _retryable
from soc.api.routes.assistant import BUSY_TIMEOUT
from soc.api.routes.blocks import active_clause

log = logging.getLogger("soc.privacy")
router = APIRouter(tags=["privacy"])

ERASED = "[erased]"
BATCH = 500
MAX_DEPTH = 100


# --- what erasure does with every column ------------------------------------------------------

# Free text and JSON that can mention an address: redacted in place. {table: {column: kind}}.
REDACTION_TARGETS: dict[str, dict[str, str]] = {
    "alerts": {"explanation": "json", "rule": "json", "predicted_class": "text",
               "model_version": "text"},  # of the alerts that remain (the address's own go)
    "blocks": {"reason": "text"},
    "would_blocks": {"reason": "text"},
    "actions": {"params": "json", "result": "json", "reason": "text"},
    "cases": {"title": "text"},
    "case_notes": {"text": "text"},
    "assistant_conversations": {"messages": "json", "title": "text"},
    "audit_log": {"target": "text", "details": "json"},
    "model_versions": {"name": "text", "version": "text"},
    "sensor_status": {"payload": "json"},
    "erasure_records": {"reason": "text"},
}
# Columns holding an address as a value: the rows are deleted.
ADDRESS_COLUMNS: dict[str, tuple[str, ...]] = {
    "alerts": ("src_ip", "dst_ip"), "blocks": ("ip",), "would_blocks": ("ip",)}
# Text/JSON columns that are deliberately left alone, with the reason. Everything else of type
# String/Text/JSON must be in one of the two maps above (tests/test_soc_privacy.py checks it).
EXEMPT_TABLES: dict[str, str] = {
    "users": "analyst accounts: login names and credentials, not network data",
    "sensor_tokens": "sensor names and token hashes, chosen by an admin",
    "access_log": "holds fingerprints and system-written labels only, never an address",
    "report_runs": "the week label and a fixed-vocabulary error",
    # IAM (soc/api/iam). Names and globs are chosen by admins, like sensor names; none is network
    # data. login_history.ip is the signing-in operator's own client address (and user_agent
    # their browser), not the monitored network's addresses this erasure is about: those rows
    # are the sign-in record of SOC accounts and stay for LOGIN_HISTORY_RETENTION_DAYS (365 by
    # default). A username that matched no account is stored only as a keyed hash. Decided as
    # exempt.
    "iam_roles": "admin-chosen role names and descriptions",
    "iam_role_permissions": "catalog permission names",
    "iam_groups": "admin-chosen group names and descriptions",
    "iam_group_members": "ids only",
    "iam_group_roles": "ids only",
    "iam_user_roles": "ids only",
    "iam_policies": "admin-chosen policy names, permission patterns and resource globs",
    "iam_policy_attachments": "ids and a subject type",
    "login_history": "sign-in attempts of SOC accounts: an operator's client address, not network "
                     "data of the monitored hosts",
    # Cloud management (soc/api/cloud, MOCK inventory). Every row is invented demo data or a
    # change an operator made to it: the addresses are private or RFC 5737 documentation
    # addresses of fictional instances, never an address seen on the monitored network, so
    # an erasure request about a monitored host has nothing to find here. Decided as exempt.
    "cloud_vpcs": "mock inventory: fictional network names and private ranges",
    "cloud_subnets": "mock inventory: fictional subnets",
    "cloud_security_groups": "mock inventory: operator-chosen names and descriptions",
    "cloud_sg_rules": "mock inventory: firewall rules over fictional networks",
    "cloud_instances": "mock inventory: fictional instances with private and documentation-range "
                       "addresses",
    "cloud_instance_sgs": "ids only",
    "cloud_volumes": "mock inventory: names and sizes",
    "cloud_buckets": "mock inventory: operator-chosen bucket names",
    "cloud_alerts": "alerts on the mock inventory: fixed rule names and generated text",
    "cloud_activity": "timeline of changes to the mock inventory: account names, resource ids "
                      "and the values changed; no network data of monitored hosts",
    "cloud_cost_daily": "mock cost figures",
}
EXEMPT_COLUMNS: dict[tuple[str, str], str] = {
    ("alerts", "severity"): "enumeration", ("alerts", "status"): "enumeration",
    ("alerts", "source"): "enumeration (ml/rule)", ("alerts", "true_class"): "known class names",
    ("alerts", "model_sha256"): "hex digest", ("alerts", "features"): "fixed model feature names",
    ("blocks", "source"): "enumeration", ("would_blocks", "source"): "enumeration",
    ("actions", "kind"): "enumeration", ("actions", "status"): "enumeration",
    ("actions", "proposed_by"): "user or assistant",
    ("cases", "status"): "enumeration",
    ("audit_log", "actor_type"): "user, sensor or system",
    ("audit_log", "actor_name"): "an account or sensor name",
    ("audit_log", "action"): "action names written by the SOC",
    ("model_versions", "sha256"): "hex digest",
    ("erasure_records", "requested_by"): "an account name",
    ("erasure_records", "subject_fp"): "a fingerprint, not an address",
    ("erasure_records", "counts"): "numbers only",
}

# Accounts and sensors are named by admins; a name that happens to be an address is reported for
# the admin to rename, not rewritten (names are unique keys).
MANUAL_REVIEW = {"users.username": (User, "username"), "sensor_tokens.name": (SensorToken, "name")}

COUNT_KEYS = (
    ["alerts", "blocks", "would_blocks", "actions.cancelled"]
    + [f"{t}.{c}" for t, cols in REDACTION_TARGETS.items() for c in cols]
    + ["memory.reputation_cache", "memory.geo_cache", "memory.notification_dedupe"])


# --- matching an address in text --------------------------------------------------------------

_RUN = re.compile(r"[0-9A-Fa-f:.]+")


def _norm(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


_WORD_TAIL = re.compile(r"[A-Fa-f]{1,4}:(?!:)")


_PORT_TAIL = re.compile(r"\.[0-9]{1,5}$")
_COLON_PORT_TAIL = re.compile(r":[0-9]{1,5}$")


def _parse_run(run: str) -> list[tuple]:
    """The addresses a run of [0-9a-f:.] characters (at least two colons) can be read as, each as
    (address, start, end), most literal reading first. More than one because words and
    punctuation stick to an address: "2001:db8::1." (a full stop), ":2001:db8::1",
    "2001:db8::1.443" (tcpdump's address.port), and "src:2001:db8::1", where the "c" of "src" is
    also a valid first group; the reading without such a lead (letters a-f only) is offered as
    well, so an address is never missed because of the word before it."""
    ends = [len(run)]
    extra = [run.rstrip("."), run.rstrip(".:")]
    port = _PORT_TAIL.search(run)
    if port:
        extra.append(run[:port.start()])  # address.port
    cport = _COLON_PORT_TAIL.search(run)
    if cport:
        # "2001:db8::1:443" is also "[2001:db8::1]:443" written without brackets. Reading it as
        # address + port can over-redact a longer address; that is the safe direction.
        extra.append(run[:cport.start()])
    for trimmed in extra:
        if trimmed and len(trimmed) not in ends:
            ends.append(len(trimmed))
    starts = [0]
    if run[0] == ":" and not run.startswith("::"):
        starts.append(1)
    lead = _WORD_TAIL.match(run)
    if lead:
        starts.append(lead.end())
    found = []
    for s in starts:
        for e in ends:
            if e - s < 2:
                continue
            try:
                found.append((_norm(ipaddress.ip_address(run[s:e])), s, e))
            except ValueError:
                continue
    return found


class IpMatcher:
    """Finds one address in text, JSON and (via `prefilter` and `spellings`) in SQL."""

    def __init__(self, ip: str) -> None:
        self.addr = _norm(ipaddress.ip_address(ip))
        self.ip = str(self.addr)
        forms: set[str] = {self.ip}
        if isinstance(self.addr, ipaddress.IPv4Address):
            hi, lo = divmod(int(self.addr), 1 << 16)
            for pair in (f"{hi:x}:{lo:x}", f"{hi:04x}:{lo:04x}"):
                forms |= {f"::ffff:{pair}", f"0:0:0:0:0:ffff:{pair}",
                          f"0000:0000:0000:0000:0000:ffff:{pair}"}
            forms |= {f"::ffff:{self.ip}", f"0:0:0:0:0:ffff:{self.ip}",
                      f"0000:0000:0000:0000:0000:ffff:{self.ip}"}
            # address.port as tcpdump writes it (10.0.0.1.443): a trailing .1-5 digits is a port
            self._dotted = re.compile(r"(?<![0-9])(?<![0-9]\.)" + re.escape(self.ip)
                                      + r"(?:\.[0-9]{1,5}(?![0-9]))?(?![0-9])(?!\.[0-9])")
            # The dotted text is in every dotted spelling (plain and ::ffff:a.b.c.d); the hex
            # mapped spellings (::ffff:a00:1) all contain "ffff:". Python decides the rest.
            self.prefilter = [[self.ip], ["ffff:"]]
        else:
            groups = self.addr.exploded.split(":")
            forms |= {self.addr.exploded, ":".join(f"{int(g, 16):x}" for g in groups)}
            self._dotted = None
            # Every spelling (any zero compression, leading zeros, case) contains each non-zero
            # group written without leading zeros, EXCEPT that the last 32 bits may be written as
            # a dotted IPv4 tail (2001:db8::10.0.0.1). So the needles come from the first six
            # groups: the two longest (and a colon when they are short), case-insensitively. An
            # address whose first six groups are zero (::1) has no such needle: it is
            # "the hex tail groups" OR "the dotted tail". Python decides the rest.
            def plain(gs):
                p = sorted({f"{int(g, 16):x}" for g in gs if int(g, 16)},
                           key=lambda g: (-len(g), g))[:2]
                return p + [":"] if not p or max(map(len, p)) < 3 else p

            if any(int(g, 16) for g in groups[:6]):
                self.prefilter = [plain(groups[:6])]
            else:
                self.prefilter = [plain(groups[6:]),
                                  [str(ipaddress.IPv4Address(int(self.addr) & 0xFFFFFFFF))]]
        # exact column values: every spelling in both cases
        self.spellings = sorted(forms | {f.upper() for f in forms})

    # text ------------------------------------------------------------------------------------
    def redact_text(self, text: str) -> tuple[str, int]:
        n = 0

        def fix(m: re.Match) -> str:
            nonlocal n
            run = m.group(0)
            if run.count(":") >= 2:
                found = _parse_run(run)
                for addr, s, e in found:
                    if addr == self.addr:
                        n += 1
                        return run[:s] + ERASED + run[e:]
                if found:  # a different IPv6 address is left alone, dotted tail too
                    return run
            if self._dotted is not None:
                run, k = self._dotted.subn(ERASED, run)
                n += k
            return run

        return _RUN.sub(fix, text), n

    def contains(self, text: str) -> bool:
        return self.redact_text(text)[1] > 0

    # JSON ------------------------------------------------------------------------------------
    def redact_json(self, value: Any, depth: int = 0) -> tuple[Any, int]:
        """(new value, replacements). An assistant "thinking" block that mentions the address is
        dropped whole: its text is signed by the model API and cannot be edited."""
        if isinstance(value, str):
            return self.redact_text(value)
        if depth > MAX_DEPTH:
            new, n = self.redact_text(json.dumps(value, default=str))
            return (ERASED, n) if n else (value, 0)
        if isinstance(value, list):
            out, total = [], 0
            for item in value:
                if (isinstance(item, dict) and item.get("type") == "thinking"
                        and isinstance(item.get("thinking"), str)
                        and self.contains(item["thinking"])):
                    total += 1
                    continue
                new, n = self.redact_json(item, depth + 1)
                out.append(new)
                total += n
            return out, total
        if isinstance(value, dict):
            out, total = {}, 0
            for k, v in value.items():
                nk, nk_count = self.redact_text(k) if isinstance(k, str) else (k, 0)
                nv, nv_count = self.redact_json(v, depth + 1)
                out.setdefault(nk, nv)
                total += nk_count + nv_count
            return out, total
        return value, 0

    def is_host_network(self, entry: object) -> bool:
        """An allowlist entry that is exactly this address ("10.0.0.1/32")."""
        if not isinstance(entry, str):
            return False
        try:
            net = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            return False
        return net.prefixlen == net.max_prefixlen and _norm(net.network_address) == self.addr

    def redact_status(self, payload: Any) -> tuple[Any, int]:
        """A sensor status: allowlist entries naming exactly this host are removed (rewriting one
        to "[erased]/32" would make the stored status invalid), everything else as text."""
        removed = 0
        if isinstance(payload, dict) and isinstance(payload.get("allowlist"), list):
            keep = [e for e in payload["allowlist"] if not self.is_host_network(e)]
            removed = len(payload["allowlist"]) - len(keep)
            payload = {**payload, "allowlist": keep}
        new, n = self.redact_json(payload)
        return new, n + removed

    # SQL -------------------------------------------------------------------------------------
    def like_any(self, haystack):
        """A pre-filter over a lower-cased text expression: a superset of the rows that mention
        the address (the exact decision is redact_text)."""
        return or_(*[and_(*[haystack.like(f"%{n}%") for n in group]) for group in self.prefilter])


# --- the erasure plan -------------------------------------------------------------------------

@dataclass
class Plan:
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(COUNT_KEYS, 0))
    manual_review: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    candidates: dict[str, list] = field(default_factory=dict)  # table -> primary keys to rewrite
    active_blocks: int = 0
    busy_conversations: int = 0  # conversations with a fresh busy_since (any, not only matching)
    alerts_max_id: int = 0  # the newest alert id when the scan began

    @property
    def total(self) -> int:
        return sum(n for k, n in self.counts.items() if k != "actions.cancelled")


def _haystack(model, columns: dict[str, str]):
    """lower() of all the table's candidate columns joined."""
    parts = []
    for name, kind in columns.items():
        col = getattr(model, name)
        parts.append(func.coalesce(cast(col, Text) if kind == "json" else col, ""))
    expr = parts[0]
    for p in parts[1:]:
        expr = expr + " " + p
    return func.lower(expr)


_MODELS = {"alerts": Alert, "blocks": Block, "would_blocks": WouldBlock, "actions": Action,
           "cases": Case, "case_notes": CaseNote, "assistant_conversations": AssistantConversation,
           "audit_log": AuditEntry, "model_versions": ModelVersion, "sensor_status": SensorStatus,
           "erasure_records": ErasureRecord}
assert set(_MODELS) == set(REDACTION_TARGETS)


def _address_match(model, table: str, matcher: IpMatcher):
    return or_(*[getattr(model, c).in_(matcher.spellings) for c in ADDRESS_COLUMNS[table]])


def _pk(table: str):
    model = _MODELS[table]
    return model.sensor_id if table == "sensor_status" else model.id


def _count_active_blocks(db: Session, matcher: IpMatcher) -> int:
    return db.scalar(select(func.count()).select_from(Block).where(
        _address_match(Block, "blocks", matcher), active_clause(datetime.now(UTC)))) or 0


def _delete_alerts(db: Session, matcher: IpMatcher, plan: Plan) -> None:
    pg = db.get_bind().dialect.name == "postgresql"
    match = _address_match(Alert, "alerts", matcher)
    last = 0
    while True:
        ids = list(db.scalars(select(Alert.id).where(Alert.id > last, match)
                              .order_by(Alert.id).limit(BATCH)))
        if not ids:
            return
        if pg:
            # Lock order cases -> alerts, as in retention.py and when an analyst attaches an
            # alert: the cases this batch belongs to (in id order), then the alerts (in id order).
            refs = select(Alert.case_id).where(Alert.id.in_(ids), Alert.case_id.is_not(None))
            db.execute(select(Case.id).where(Case.id.in_(refs)).order_by(Case.id)
                       .with_for_update(read=True)).all()
            db.execute(select(Alert.id).where(Alert.id.in_(ids)).order_by(Alert.id)
                       .with_for_update()).all()
        for model in (Block, WouldBlock):  # other addresses' blocks that came from these alerts
            db.execute(update(model).where(model.alert_id.in_(ids)).values(alert_id=None))
        plan.counts["alerts"] += db.execute(delete(Alert).where(Alert.id.in_(ids))).rowcount
        last = ids[-1]


def _delete_blocks(db: Session, matcher: IpMatcher, plan: Plan) -> None:
    for model, table in ((Block, "blocks"), (WouldBlock, "would_blocks")):
        plan.counts[table] += db.execute(delete(model).where(
            _address_match(model, table, matcher))).rowcount


def _row_updates(table: str, matcher: IpMatcher, values: tuple, status, busy_since):
    """(changes to write, fields changed, cancelled?) for one row's candidate columns."""
    columns = REDACTION_TARGETS[table]
    updates: dict[str, Any] = {}
    for (name, kind), value in zip(columns.items(), values, strict=True):
        if value is None:
            continue
        if table == "sensor_status":
            new, n = matcher.redact_status(value)
        elif kind == "json":
            new, n = matcher.redact_json(value)
        else:
            new, n = matcher.redact_text(value)
        if n:
            updates[name] = new
    fields = list(updates)
    cancelled = False
    if table == "actions" and updates and status in (ActionStatus.PENDING, ActionStatus.CONFIRMED):
        cancelled = True
        updates["status"] = (ActionStatus.REJECTED if status == ActionStatus.PENDING
                             else ActionStatus.FAILED)
        if status == ActionStatus.CONFIRMED:
            updates["completed_at"] = datetime.now(UTC)
            updates.setdefault("result", {"error": "cancelled: the address was erased"})
    return updates, fields, cancelled


def _busy_conversations(db: Session) -> int:
    """Conversations with an assistant reply running (a busy_since newer than the stale limit)."""
    return db.scalar(select(func.count()).select_from(AssistantConversation).where(
        AssistantConversation.busy_since > datetime.now(UTC) - BUSY_TIMEOUT)) or 0


def _extra_columns(table: str) -> list:
    return [Action.status] if table == "actions" else []


def _split_row(table: str, row, n: int):
    """(candidate values, status, busy_since) from a row selected as pk, columns, extras."""
    values = tuple(row[1:1 + n])
    status = row[1 + n] if table == "actions" else None
    return values, status, None


def _scan_table(db: Session, table: str, matcher: IpMatcher, plan: Plan, after: int = 0) -> None:
    """Read-only: the rows of `table` that mention the address, counted into `plan` and their
    keys remembered in plan.candidates for the write phase. The text of the row is computed once
    per row (a subquery that SQLite and PostgreSQL do not flatten) and the pre-filter reads it."""
    model, columns = _MODELS[table], REDACTION_TARGETS[table]
    pk = _pk(table)
    cols = [getattr(model, c) for c in columns]
    extras = _extra_columns(table)
    where = [~_address_match(Alert, "alerts", matcher)] if table == "alerts" else []
    inner = (select(pk.label("pk"), *[c.label(f"c{i}") for i, c in enumerate(cols)],
                    *[e.label(f"e{i}") for i, e in enumerate(extras)],
                    _haystack(model, columns).label("hay"))
             .where(pk > sa_bindparam("last"), *where).order_by(pk).limit(2**62).subquery())
    cond = matcher.like_any(inner.c.hay)
    outer = (select(*[c for c in inner.c if c.name != "hay"]).where(cond)
             .order_by(inner.c.pk).limit(BATCH))
    found: list = plan.candidates.setdefault(table, [])
    last = after
    while True:
        rows = db.execute(outer, {"last": last}).all()
        for row in rows:
            values, status, busy = _split_row(table, row, len(columns))
            updates, fields, cancelled = _row_updates(table, matcher, values, status, busy)
            if not updates:
                continue
            found.append(row[0])
            for name in fields:
                plan.counts[f"{table}.{name}"] += 1
            plan.counts["actions.cancelled"] += cancelled
        if len(rows) < BATCH:
            return
        last = rows[-1][0]


def _apply_table(db: Session, table: str, matcher: IpMatcher, plan: Plan) -> None:
    """The write phase for one table: each candidate row is read again (it may have changed
    since the scan) and rewritten from its current content."""
    model, columns = _MODELS[table], REDACTION_TARGETS[table]
    pk = _pk(table)
    cols = [getattr(model, c) for c in columns]
    keys = plan.candidates.get(table, [])
    pg = db.get_bind().dialect.name == "postgresql"
    for i in range(0, len(keys), BATCH):
        chunk = keys[i:i + BATCH]
        query = (select(pk, *cols, *_extra_columns(table)).where(pk.in_(chunk))
                 .order_by(pk))
        if pg:  # lock the rows we rewrite (in key order): no lost update, and a reply's claim of
            query = query.with_for_update()  # a conversation waits, then reads the rewritten text
        rows = db.execute(query).all()
        for row in rows:
            values, status, busy = _split_row(table, row, len(columns))
            updates, fields, cancelled = _row_updates(table, matcher, values, status, busy)
            if not updates:
                continue
            db.execute(update(model).where(pk == row[0]).values(**updates))
            for name in fields:
                plan.counts[f"{table}.{name}"] += 1
            plan.counts["actions.cancelled"] += cancelled


def _manual_review(db: Session, matcher: IpMatcher, plan: Plan) -> None:
    for key, (model, column) in MANUAL_REVIEW.items():
        col = getattr(model, column)
        names = db.scalars(select(col).where(matcher.like_any(func.lower(col))))
        n = sum(1 for name in names if matcher.contains(name))
        if n:
            plan.manual_review[key] = n
            plan.warnings.append(f"{n} {key} value(s) contain this address; rename them by hand "
                                 "(account and sensor names are not rewritten)")


def _memory(request: Request, matcher: IpMatcher, plan: Plan, *, dry_run: bool) -> None:
    ips = {matcher.ip}
    state = request.app.state
    plan.counts["memory.reputation_cache"] = state.reputation.forget(ips, dry_run=dry_run)
    plan.counts["memory.geo_cache"] = state.geo.forget(ips, dry_run=dry_run)
    plan.counts["memory.notification_dedupe"] = state.notifier.forget_ips(ips, dry_run=dry_run)


BUSY_MESSAGE = "an assistant reply is in progress; try again in a minute"


def scan_plan(db: Session, matcher: IpMatcher) -> Plan:
    """Phase 1, read only (no write lock is held, however long the scan takes): what mentions the
    address, per table and field. This is the preview."""
    plan = Plan()
    plan.alerts_max_id = db.scalar(select(func.coalesce(func.max(Alert.id), 0))) or 0
    for table in REDACTION_TARGETS:
        _scan_table(db, table, matcher, plan)
    plan.counts["alerts"] = db.scalar(select(func.count()).select_from(Alert).where(
        _address_match(Alert, "alerts", matcher))) or 0
    for model, table in ((Block, "blocks"), (WouldBlock, "would_blocks")):
        plan.counts[table] = db.scalar(select(func.count()).select_from(model).where(
            _address_match(model, table, matcher))) or 0
    plan.active_blocks = _count_active_blocks(db, matcher)
    if plan.active_blocks:
        plan.warnings.append(
            f"{plan.active_blocks} active block(s) of this address: erasing removes them from the "
            "SOC's records but the sensor's firewall rule stays and the SOC could no longer lift "
            "it. Unblock first, or erase with force: true")
    plan.busy_conversations = _busy_conversations(db)
    if plan.busy_conversations:
        plan.warnings.append(
            f"{plan.busy_conversations} assistant conversation(s) have a reply in progress; "
            "erasing is refused until they finish (a minute or two)")
    _manual_review(db, matcher, plan)
    return plan


def apply_plan(db: Session, matcher: IpMatcher, scanned: Plan, *, force: bool) -> Plan:
    """Phase 2: the writes, in the caller's transaction. On SQLite the write lock is taken here,
    not before the scan. Under it, everything written since the scan is picked up: every table
    except alerts is scanned again (they are small next to alerts), alerts only above the newest id
    the first scan saw (an alert that already existed was found by it); each candidate row is then
    read again (locked, on PostgreSQL) and rewritten from its current content, and the deletes of
    alerts and blocks by address run again last. Refuses (409) while ANY assistant reply is running
    (its conversation is written back when it finishes), and while the address has an active
    block unless `force`."""
    if db.get_bind().dialect.name == "sqlite":
        try:  # take the write lock now: everything below is quick
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        except DBAPIError as exc:
            if "within a transaction" not in str(exc.orig):
                raise
    else:
        # PostgreSQL: no assistant reply may claim a conversation between the busy check below and
        # the commit (it would read the unredacted history and write it back when it finishes).
        # SHARE ROW EXCLUSIVE blocks the claim's UPDATE until this transaction ends, lets this
        # transaction write the table itself, and makes two erasures take turns.
        db.execute(text("LOCK TABLE assistant_conversations IN SHARE ROW EXCLUSIVE MODE"))
    if scanned.busy_conversations or _busy_conversations(db):
        raise HTTPException(409, BUSY_MESSAGE)
    if not force and _count_active_blocks(db, matcher):
        raise HTTPException(409, "the address has an active block; unblock it first or send "
                                 "force: true (the sensor's firewall rule would stay)")
    fresh = Plan()
    for table in REDACTION_TARGETS:
        _scan_table(db, table, matcher, fresh,
                    after=scanned.alerts_max_id if table == "alerts" else 0)
    plan = Plan(manual_review=scanned.manual_review, warnings=scanned.warnings,
                active_blocks=scanned.active_blocks,
                candidates={t: sorted(set(scanned.candidates.get(t, []))
                                      | set(fresh.candidates.get(t, [])))
                            for t in REDACTION_TARGETS})
    _apply_table(db, "actions", matcher, plan)  # first: cancels open actions
    # Cases before alerts (locked FOR UPDATE on PostgreSQL by the re-read), the lock order of
    # retention.py and of attaching an alert to a case; _delete_alerts then only re-takes them.
    _apply_table(db, "cases", matcher, plan)
    _delete_alerts(db, matcher, plan)
    _delete_blocks(db, matcher, plan)
    for table in REDACTION_TARGETS:
        if table not in ("actions", "cases"):
            _apply_table(db, table, matcher, plan)
    _delete_alerts(db, matcher, plan)  # again: rows committed since the scan
    _delete_blocks(db, matcher, plan)
    return plan


# --- requests and answers ---------------------------------------------------------------------

def _no_cidr(value: object) -> object:
    if isinstance(value, str) and "/" in value:
        raise ValueError("CIDR ranges are not supported: give one IP address, not a network")
    return value


SubjectIP = Annotated[str, Field(max_length=64), BeforeValidator(_no_cidr),
                      AfterValidator(canonical_ip)]


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: SubjectIP


class EraseIn(PreviewIn):
    reason: str = Field(min_length=1, max_length=500)
    # erase although the address has an active block (the sensor's firewall rule would stay)
    force: bool = False

    @field_validator("reason")
    @classmethod
    def _plain(cls, value: str) -> str:
        return clean_reason(value)


class ErasePreview(BaseModel):
    ip: str
    subject_fp: str
    counts: dict[str, int]  # every key always present (COUNT_KEYS)
    total: int  # rows and entries affected (not counting `actions.cancelled`)
    active_blocks: int  # active blocks of this address (erasing needs force: true when > 0)
    manual_review: dict[str, int]  # found but not rewritten: account and sensor names
    warnings: list[str]


class EraseResult(ErasePreview):
    record_id: int
    erased_at: datetime


class ErasureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    requested_by: str
    reason: str
    subject_fp: str
    counts: dict[str, Any]


def _preview(plan: Plan, matcher: IpMatcher, fp: str) -> dict:
    return {"ip": matcher.ip, "subject_fp": fp, "counts": plan.counts, "total": plan.total,
            "active_blocks": plan.active_blocks, "manual_review": plan.manual_review, "warnings": plan.warnings}


@router.post("/admin/privacy/erase/preview", response_model=ErasePreview)
def erase_preview(body: PreviewIn, admin: AdminUser, request: Request,
                  db: Annotated[Session, Depends(get_db)]):
    """What an erasure of this address would remove or rewrite, per table and field. Changes
    nothing. Reading it is a look at personal data, so it is access-logged."""
    settings = request.app.state.settings
    matcher = IpMatcher(body.ip)
    plan = scan_plan(db, matcher)
    _memory(request, matcher, plan, dry_run=True)
    db.rollback()
    access_log.log_access(db, settings, admin, "privacy_erase_preview",
                          target_type="privacy", ips=[matcher.ip])
    return ErasePreview(**_preview(plan, matcher, access_log.fingerprint(settings, matcher.ip)))


@router.post("/admin/privacy/erase", response_model=EraseResult)
def erase(body: EraseIn, admin: AdminUser, request: Request,
          db: Annotated[Session, Depends(get_db)]):
    """Erase an IP address everywhere (see the module docstring), in one transaction. Admin only.
    Leaves an erasure record and an audit entry holding a fingerprint of the address, never the
    address. Repeating it is harmless (it finds nothing)."""
    settings = request.app.state.settings
    matcher = IpMatcher(body.ip)
    if matcher.contains(body.reason):
        raise HTTPException(422, "the reason must not contain the address being erased")
    fp = access_log.fingerprint(settings, matcher.ip)
    plan = record = None
    for attempt in (1, 2):
        try:
            scanned = scan_plan(db, matcher)  # reads only: no write lock yet
            plan = apply_plan(db, matcher, scanned, force=body.force)
            _memory(request, matcher, plan, dry_run=True)  # counted now, forgotten after commit
            record = ErasureRecord(requested_by=admin.username, reason=body.reason, subject_fp=fp,
                                   counts=dict(plan.counts))
            db.add(record)
            db.flush()
            audit(db, admin, "privacy_erase", f"subject:{fp[:16]}",
                  {"subject_fp": fp, "record_id": record.id, "forced": body.force,
                   "counts": {k: v for k, v in plan.counts.items() if v}})
            db.commit()
            break
        except DBAPIError as exc:
            db.rollback()
            if _retryable(exc):  # a deadlock, serialisation failure or busy database
                if attempt == 1:
                    time.sleep(0.2)
                    continue
                log.warning("erasure gave up after a lock conflict (%s); nothing was changed",
                            getattr(exc.orig, "sqlstate", None) or type(exc.orig).__name__)
                raise HTTPException(
                    503, "the database is busy; nothing was erased, try again") from None
            # not a lock problem: say so (the code, never the statement or its values)
            log.error("erasure failed, nothing was changed: %s, SQLSTATE %s",
                      type(exc.orig).__name__, getattr(exc.orig, "sqlstate", None))
            raise HTTPException(500, "the erasure failed and nothing was changed; see the SOC "
                                     "log") from None
        except Exception:
            db.rollback()
            raise
    _memory(request, matcher, Plan(), dry_run=False)  # only after the commit
    return EraseResult(**_preview(plan, matcher, fp), record_id=record.id,
                       erased_at=record.at)


@router.get("/admin/privacy/erasures", response_model=Page[ErasureOut])
def list_erasures(admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)],
                  ip: Annotated[str | None, Query(max_length=64, description="was this address "
                                                  "erased?")] = None,
                  limit: Limit = 50, cursor: Cursor = None):
    """Erasures done so far, newest first. No addresses: only fingerprints and counts. `ip`
    (fingerprinted here) answers "was this address erased, when and by whom"."""
    query = select(ErasureRecord).order_by(ErasureRecord.id.desc()).limit(limit + 1)
    if ip:
        try:
            query = query.where(ErasureRecord.subject_fp == access_log.fingerprint(
                request.app.state.settings, canonical_ip(_no_cidr(ip))))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
    if cursor:
        query = query.where(ErasureRecord.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[ErasureOut](items=[ErasureOut.model_validate(r) for r in rows],
                            next_cursor=next_cursor)


# --- access log -------------------------------------------------------------------------------

class AccessLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    user_id: int | None
    username: str
    action: str
    target_type: str
    target: str
    subject_fp: str | None  # fingerprint of the address looked at; null when none


@router.get("/admin/privacy/access-log", response_model=Page[AccessLogOut])
def list_access_log(
    admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)],
    ip: Annotated[str | None, Query(max_length=64, description="who looked at this address")] = None,
    username: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None, until: datetime | None = None,
    limit: Limit = 100, cursor: Cursor = None,
):
    """The access log, newest first. `ip` is fingerprinted here: the log holds no addresses."""
    for moment in (since, until):
        if moment is not None and moment.tzinfo is None:
            raise HTTPException(422, "since/until must include a timezone, e.g. 2026-01-01T00:00:00Z")
    query = select(AccessLog).order_by(AccessLog.id.desc()).limit(limit + 1)
    if ip:
        try:
            query = query.where(AccessLog.subject_fp == access_log.fingerprint(
                request.app.state.settings, canonical_ip(_no_cidr(ip))))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
    if username:
        query = query.where(AccessLog.username == username)
    if action:
        query = query.where(AccessLog.action == action)
    if since:
        query = query.where(AccessLog.at >= since)
    if until:
        query = query.where(AccessLog.at <= until)
    if cursor:
        query = query.where(AccessLog.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[AccessLogOut](items=[AccessLogOut.model_validate(r) for r in rows],
                              next_cursor=next_cursor)


# --- privacy notice (public) ------------------------------------------------------------------

DATA_CATEGORIES = [
    {"category": "Network flow identifiers",
     "description": "Source and destination IP addresses and ports, protocol and timing of the "
                    "network flows that raised an alert, and the sensor that saw them."},
    {"category": "Flow statistics",
     "description": "Numeric statistics of those flows (sizes, durations, packet counts) and the "
                    "model's explanation of why they were flagged."},
    {"category": "Analyst accounts",
     "description": "Login names, password hashes, sign-in method and security settings of the "
                    "people who operate the SOC."},
    {"category": "Audit and access logs",
     "description": "Who did what in the SOC, and who looked at which IP address (the access log "
                    "keeps a one-way fingerprint of the address, not the address)."},
    {"category": "Assistant conversations",
     "description": "Messages exchanged between an analyst and the SOC assistant, which can "
                    "quote addresses from alerts."},
]
PURPOSES = ["Network security monitoring (detecting and blocking attacks on the protected network)",
            "Incident response (investigating, documenting and closing security incidents)"]
RIGHTS = [
    {"right": "access", "description": "Ask what personal data about you the SOC holds and how "
                                       "it is used."},
    {"right": "correction", "description": "Ask for inaccurate or incomplete data to be corrected."},
    {"right": "erasure", "description": "Ask for your data (for example an IP address) to be "
                                         "erased. It can be declined where the law or an "
                                         "ongoing security investigation requires keeping it."},
    {"right": "grievance", "description": "Complain to the grievance officer if you think your "
                                           "data is mishandled."},
    {"right": "nomination", "description": "Nominate someone to exercise these rights for you "
                                             "if you die or cannot."},
]


@router.get("/privacy/notice")
def privacy_notice(request: Request) -> dict:
    """The privacy notice, for the people whose traffic is monitored. PUBLIC (no sign-in): it
    holds no secrets, only what is set for the notice and the retention periods in force. Channels
    are named, never their addresses."""
    s = request.app.state.settings
    state = request.app.state
    recipients = []
    if s.notify_enabled:
        if s.webhook_url is not None:
            recipients.append({"name": "webhook", "description": "alert notifications"})
        if s.slack_webhook_url is not None:
            recipients.append({"name": "slack", "description": "alert notifications"})
        if s.smtp_host and s.smtp_from and s.smtp_to:
            recipients.append({"name": "email", "description": "alert notifications"})
    if s.syslog_host:
        recipients.append({"name": "syslog", "description": "alert and block export to a SIEM"})
    if s.report_email_enabled and s.smtp_host and s.smtp_from and s.report_recipients:
        if not any(r["name"] == "email" for r in recipients):
            recipients.append({"name": "email", "description": "weekly report"})
        else:
            next(r for r in recipients if r["name"] == "email")["description"] += \
                " and the weekly report"
    if state.reputation.configured:
        recipients.append({"name": "AbuseIPDB",
                           "description": "source IP addresses looked up when an analyst asks "
                                          "for an address's reputation"})
    if getattr(state, "assistant_llm", None) is not None:
        recipients.append({"name": "assistant",
                           "description": "the language-model service behind the SOC assistant "
                                          "receives the conversation, which can include addresses"})
    contact = s.privacy_contact_email
    return {
        "controller": {"name": s.privacy_controller_name, "contact_email": contact,
                       "grievance_officer": s.privacy_grievance_officer},
        "data_categories": DATA_CATEGORIES,
        "purposes": PURPOSES,
        "retention": {
            "alerts_days": s.alert_retention_days,
            "alerts_kept_if_judged_for_training": s.alert_retention_keep_labelled,
            "audit_log_days": s.audit_retention_days,
            "access_log_days": s.access_log_retention_days,
            "login_history_days": s.login_history_retention_days,
            "assistant_conversations_days": s.assistant_retention_days,
            "closed_cases_days": s.closed_case_retention_days,
            "would_block_records_days": s.would_block_retention_days,
            "blocks_and_actions": "kept until erased on request",
            "note": "0 days means the data is not deleted automatically. Everything can be "
                    "erased on request.",
        },
        "recipients": recipients,
        "rights": RIGHTS,
        "how_to_exercise": (
            "Write to " + (contact if contact else "the organisation that runs this network")
            + (f"; grievances go to {s.privacy_grievance_officer}"
               if s.privacy_grievance_officer else "")
            + ". Say which IP address or account the request is about. An administrator checks "
              "the request and, where it is granted, erases the data in the SOC."),
        "note": "This notice summarises how the SOC handles personal data; it is not legal advice.",
    }
