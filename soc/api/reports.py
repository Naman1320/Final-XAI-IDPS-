"""Weekly PDF report (docs/soc.md "Reports"): alerts, top sources, blocks, triage and model health
for one ISO week (Monday 00:00 to the next Monday 00:00, UTC), downloadable by any signed-in user
and optionally emailed once a week.

Speed: everything is aggregated in SQL over the week's window of alerts (the received_at index);
no alert is ever loaded into memory. It is two passes over the week's rows (one grouped by
severity/source/status/class, one by source address), seven index-only counts for the per-day
chart, and a bounded sample of the newest alerts for the latency percentiles.

Emailing: ReportRunner (a daemon thread, like retention) sends the last complete week once the
configured weekday and hour (UTC) have passed. The week is claimed first by inserting into
report_runs, whose `week` is unique, so a restart or a second process never sends it twice.

Text from sensors (class names, rule signatures, block reasons) is escaped before it goes into a
Paragraph: reportlab reads markup there.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from email.message import EmailMessage
from importlib import metadata
from io import BytesIO
from typing import Annotated
from xml.sax.saxutils import escape

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import and_, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from soc.api import access_log
from soc.api.auth import AdminUser, AnyUser
from soc.api.common import audit
from soc.api.db import get_db
from soc.api.integrations import channels
from soc.api.integrations.netguard import DeliveryError
from soc.api.models import (
    Alert,
    AlertStatus,
    Block,
    Case,
    CaseStatus,
    ModelVersion,
    ReportRun,
    SensorStatus,
    SensorToken,
    Severity,
    WouldBlock,
)
from soc.api.routes.blocks import active_clause
from soc.api.routes.sensors import ONLINE_SECONDS
from soc.api.settings import SocSettings

log = logging.getLogger("soc.reports")
router = APIRouter(tags=["reports"])

LATENCY_SAMPLE = 20_000  # latency percentiles use the week's newest alerts only
MAX_CLASSES = 25
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
EMAIL_TIMEOUT_SECONDS = 60.0
RETRY_AFTER = timedelta(hours=1)  # a claimed week that was not sent is tried again after this
RETRY_WINDOW = timedelta(hours=24)  # ... but only this long after the scheduled time
INTERVAL_SECONDS = 300.0
FIRST_RUN_DELAY_SECONDS = 60.0
WEEKS_LISTED = 12
FOOTER = "Contains personal data (IP addresses): handle under the SOC privacy notice"
_WEEK = re.compile(r"(\d{4})-W(\d{2})")
_slots = threading.BoundedSemaphore(2)  # reports being built at once (each reads a week of alerts)


# --- weeks ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Week:
    label: str  # "2026-W45"
    start: datetime  # Monday 00:00 UTC
    end: datetime  # the next Monday 00:00 UTC

    @property
    def days(self) -> list[datetime]:
        return [self.start + timedelta(days=n) for n in range(7)]


def week_of(day: date) -> Week:
    monday = day - timedelta(days=day.weekday())
    iso = monday.isocalendar()
    start = datetime(monday.year, monday.month, monday.day, tzinfo=UTC)
    return Week(f"{iso.year}-W{iso.week:02d}", start, start + timedelta(days=7))


def parse_week(value: str) -> Week:
    """"2026-W45" -> the week; ValueError for anything else (including a week that does not
    exist, like 2025-W53)."""
    m = _WEEK.fullmatch(value or "")  # not .match + $: "$" also accepts a trailing newline
    if not m or not 2000 <= int(m.group(1)) <= 2100:
        raise ValueError("week must look like 2026-W45")
    try:
        monday = date.fromisocalendar(int(m.group(1)), int(m.group(2)), 1)
    except ValueError:
        raise ValueError("that ISO week does not exist") from None
    return week_of(monday)


def last_complete_week(now: datetime) -> Week:
    return week_of(now.astimezone(UTC).date() - timedelta(days=7))


def _resolve_week(value: str | None, now: datetime) -> Week:
    if value is None:
        return last_complete_week(now)
    try:
        week = parse_week(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if week.start > now:
        raise HTTPException(422, "that week has not started yet")
    return week


def soc_version() -> str:
    version = os.environ.get("IDPS_VERSION")
    if not version:
        try:
            version = metadata.version("idps")
        except metadata.PackageNotFoundError:
            version = "unknown"
    return version


# --- the numbers ------------------------------------------------------------------------------

@dataclass
class ReportData:
    week: Week
    generated_at: datetime
    version: str
    mask_ips: bool
    complete: bool = True
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_class: list[tuple[str, int]] = field(default_factory=list)
    per_day: list[int] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    triaged: int = 0
    false_positives: int = 0
    latency_ms: tuple[float | None, float | None, int] = (None, None, 0)
    blocks: dict = field(default_factory=dict)
    would_blocks: dict = field(default_factory=dict)
    cases: dict = field(default_factory=dict)
    sensors: list[dict] = field(default_factory=list)
    models: list[dict] = field(default_factory=list)
    would_block_retention_days: int = 7

    @property
    def fp_rate(self) -> float | None:
        return self.false_positives / self.triaged if self.triaged else None


def week_filter(week: Week):
    return and_(Alert.received_at >= week.start, Alert.received_at < week.end)


def count_alerts(db: Session, week: Week) -> int:
    return db.scalar(select(func.count()).select_from(Alert).where(week_filter(week))) or 0


def _val(x) -> str:
    return str(getattr(x, "value", x))


def collect(db: Session, settings: SocSettings, week: Week, now: datetime | None = None) -> ReportData:
    now = now or datetime.now(UTC)
    data = ReportData(week=week, generated_at=now, version=soc_version(),
                      mask_ips=settings.report_mask_ips, complete=week.end <= now,
                      would_block_retention_days=settings.would_block_retention_days)
    in_week = week_filter(week)

    # pass 1: severity x source x status x class, grouped in SQL
    source = func.coalesce(Alert.source, "ml")
    by_class: dict[str, int] = {}
    data.by_severity = {s.value: 0 for s in Severity}
    data.by_source = {"ml": 0, "rule": 0}
    data.by_status = {s.value: 0 for s in AlertStatus}
    for sev, src, status, cls, n in db.execute(
            select(Alert.severity, source, Alert.status, Alert.predicted_class, func.count())
            .where(in_week).group_by(Alert.severity, source, Alert.status, Alert.predicted_class)):
        data.total += n
        data.by_severity[_val(sev)] = data.by_severity.get(_val(sev), 0) + n
        data.by_source[str(src)] = data.by_source.get(str(src), 0) + n
        data.by_status[_val(status)] = data.by_status.get(_val(status), 0) + n
        by_class[str(cls)] = by_class.get(str(cls), 0) + n
    ranked = sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0]))
    data.by_class = ranked[:MAX_CLASSES]
    if len(ranked) > MAX_CLASSES:
        data.by_class.append(("(other)", sum(n for _, n in ranked[MAX_CLASSES:])))
    data.triaged = sum(n for s, n in data.by_status.items() if s != AlertStatus.NEW.value)
    data.false_positives = data.by_status.get(AlertStatus.FALSE_POSITIVE.value, 0)

    # pass 2: the busiest source addresses
    data.top_sources = [(ip, n) for ip, n in db.execute(
        select(Alert.src_ip, func.count().label("n")).where(in_week).group_by(Alert.src_ip)
        .order_by(func.count().desc(), Alert.src_ip).limit(10))]

    # per day: one index-only count each (the same trick as metrics.py)
    data.per_day = [db.scalar(select(func.count()).select_from(Alert).where(
        Alert.received_at >= lo, Alert.received_at < lo + timedelta(days=1), in_week)) or 0
        for lo in week.days]

    # detection latency from the newest alerts of the week (bounded)
    latencies = [max(received.timestamp() * 1000 - end_ms, 0.0)
                 for received, end_ms in db.execute(
                     select(Alert.received_at, Alert.end_ms).where(in_week)
                     .order_by(Alert.received_at.desc()).limit(LATENCY_SAMPLE))]
    if latencies:
        data.latency_ms = (float(np.percentile(latencies, 50)), float(np.percentile(latencies, 95)),
                           len(latencies))

    # blocks (a small table, never pruned) and dry-run would-blocks (kept would_block_retention_days)
    block_week = and_(Block.blocked_at >= week.start, Block.blocked_at < week.end)
    by_block_source = {_val(s): n for s, n in db.execute(
        select(Block.source, func.count()).where(block_week).group_by(Block.source))}
    data.blocks = {
        "created": sum(by_block_source.values()), "by_source": by_block_source,
        "unblocked": db.scalar(select(func.count()).select_from(Block).where(
            Block.unblocked_at >= week.start, Block.unblocked_at < week.end)) or 0,
        "distinct_ips": db.scalar(select(func.count(func.distinct(Block.ip))).where(block_week)) or 0,
        "active_now": db.scalar(select(func.count()).select_from(Block)
                                .where(active_clause(now))) or 0,
        "top": [(ip, n) for ip, n in db.execute(
            select(Block.ip, func.count().label("n")).where(block_week).group_by(Block.ip)
            .order_by(func.count().desc(), Block.ip).limit(10))]}
    would_week = and_(WouldBlock.at >= week.start, WouldBlock.at < week.end)
    by_would_source = {_val(s): n for s, n in db.execute(
        select(WouldBlock.source, func.count()).where(would_week).group_by(WouldBlock.source))}
    data.would_blocks = {
        "total": sum(by_would_source.values()), "by_source": by_would_source,
        "distinct_ips": db.scalar(select(func.count(func.distinct(WouldBlock.ip)))
                                  .where(would_week)) or 0}

    # analyst triage: alert statuses (above) and the week's cases
    data.cases = {
        "opened": db.scalar(select(func.count()).select_from(Case).where(
            Case.created_at >= week.start, Case.created_at < week.end)) or 0,
        "closed": db.scalar(select(func.count()).select_from(Case).where(
            Case.status == CaseStatus.CLOSED, Case.updated_at >= week.start,
            Case.updated_at < week.end)) or 0}

    # model health: what each sensor reported last (as of now) and the models seen in the week
    for token, status in db.execute(
            select(SensorToken, SensorStatus)
            .outerjoin(SensorStatus, SensorStatus.sensor_id == SensorToken.id)
            .where(SensorToken.revoked.is_(False)).order_by(SensorToken.id).limit(200)):
        payload = (status.payload if status else None) or {}
        model, drift = payload.get("model") or {}, payload.get("drift") or {}
        faith = payload.get("faithfulness") or {}
        seen = status.last_seen_at if status else None
        data.sensors.append({
            "name": token.name,
            "online": bool(seen and now - seen <= timedelta(seconds=ONLINE_SECONDS)),
            "model": model.get("name"), "version": model.get("version"),
            "drift": drift.get("level"), "psi_max": drift.get("psi_max"),
            "faithfulness": _faithfulness_text(faith),
            "outbox": payload.get("outbox_pending")})
    models: dict[str, dict] = {}
    for mv in db.scalars(select(ModelVersion).where(
            ModelVersion.last_seen >= week.start, ModelVersion.first_seen < week.end)
            .order_by(ModelVersion.last_seen.desc()).limit(200)):
        m = models.setdefault(mv.sha256, {"name": mv.name, "version": mv.version,
                                          "sha256": mv.sha256, "sensors": 0})
        m["sensors"] += 1
    data.models = list(models.values())
    return data


def _faithfulness_text(faith: dict) -> str:
    if not faith:
        return "not reported"
    parts = []
    for name, m in (faith.get("methods") or {}).items():
        try:
            parts.append(f"{name} mean drop {float(m['mean_drop']):.2f}, "
                         f"label flips {float(m['label_flip_rate']):.0%}")
        except (KeyError, TypeError, ValueError):
            continue
    match = faith.get("model_matches")
    text = "; ".join(parts) or "no methods"
    return text + ("" if match is None else ("" if match else " (report is for another model)"))


# --- rendering --------------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def clean(value: object, limit: int = 200) -> str:
    """Plain text for the PDF: no control or direction characters, only what the built-in
    Helvetica can draw (others become '?'), cut to `limit`."""
    text = _CONTROL.sub("", str(value))
    text = text.encode("cp1252", "replace").decode("cp1252")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def esc(value: object, limit: int = 200) -> str:
    """`clean` and escaped for a Paragraph (reportlab parses < > & as markup there)."""
    return escape(clean(value, limit))


def mask_ip(ip: str) -> str:
    """The address with its last octet hidden: 203.0.113.x; IPv6 keeps its first 48 bits."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv6Address):  # the exploded form, so "::1" and "2001::1" work
        return ":".join(f"{int(g, 16):x}" for g in addr.exploded.split(":")[:3]) + ":x"
    return ".".join(str(addr).split(".")[:3] + ["x"])


def _fmt_ms(ms: float | None) -> str:
    if ms is None:
        return "n/a"
    return f"{ms / 1000:.1f} s" if ms >= 1000 else f"{ms:.0f} ms"


class _NumberedCanvas(canvas.Canvas):
    """Page footer with "Page i of n" and the personal-data notice on every page."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._saved: list[dict] = []

    def showPage(self) -> None:  # reportlab's name
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#555555"))
            self.drawString(18 * mm, 10 * mm, FOOTER)
            self.drawRightString(A4[0] - 18 * mm, 10 * mm,
                                 f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=2,
                                alignment=0),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=10.5,
                              textColor=colors.HexColor("#444444"), spaceAfter=6),
        "h": ParagraphStyle("h", parent=base["Heading2"], fontSize=13, spaceBefore=12,
                            spaceAfter=4),
        "p": ParagraphStyle("p", parent=base["Normal"], fontSize=9, leading=12),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=7.5, leading=9.5,
                                textColor=colors.HexColor("#555555")),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8, leading=10),
    }


_GRID = TableStyle([
    ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("LEADING", (0, 0), (-1, -1), 11),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#c8ced6")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)])


def _table(rows: list[list], widths: list[float], numeric_from: int = 1) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(_GRID)
    t.setStyle(TableStyle([("ALIGN", (numeric_from, 0), (-1, -1), "RIGHT")]))
    return t


def _chart(week: Week, per_day: list[int]) -> Drawing:
    width, height = 174 * mm, 56 * mm
    d = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 34, 22, width - 50, height - 34
    bc.data = [per_day]
    top = max(per_day) if any(per_day) else 1
    bc.valueAxis.valueMin, bc.valueAxis.valueMax = 0, top * 1.1 if top > 1 else 1
    bc.valueAxis.valueStep = max(1, round(top / 4)) if top > 4 else None
    bc.valueAxis.labels.fontSize = 7
    bc.categoryAxis.categoryNames = [lo.strftime("%a %d") for lo in week.days]
    bc.categoryAxis.labels.fontSize = 7
    bc.bars[0].fillColor = colors.HexColor("#3b6ea8")
    bc.barLabelFormat = "%d"
    bc.barLabels.fontSize = 7
    bc.barLabels.nudge = 6
    d.add(bc)
    return d


def render_pdf(data: ReportData) -> bytes:
    """The report as PDF bytes. Every string that came from a sensor or an analyst goes through
    esc() (Paragraph markup) or clean() (table cells)."""
    st = _styles()
    ip = (lambda a: mask_ip(a)) if data.mask_ips else (lambda a: a)
    story: list = []
    w = data.week

    def P(text: str, style: str = "p") -> Paragraph:
        return Paragraph(esc(text, 600), st[style])

    story += [P("IDPS weekly security report", "title"),
              P(f"Week {w.label}: Monday {w.start:%Y-%m-%d} to Sunday "
                f"{(w.end - timedelta(days=1)):%Y-%m-%d} (UTC)"
                + ("" if data.complete else ", partial: the week is not over"), "sub")]
    story.append(_table([
        ["Generated at", f"{data.generated_at:%Y-%m-%d %H:%M} UTC"],
        ["SOC version", clean(data.version, 60)],
        ["Source addresses", "last octet masked" if data.mask_ips else "shown in full"]],
        [40 * mm, 134 * mm], numeric_from=9))

    sev = data.by_severity
    story += [P("Headline numbers", "h"), _table([
        ["Measure", "Value"],
        ["Alerts", f"{data.total:,}"],
        ["By severity (critical / high / medium / low)",
         " / ".join(f"{sev.get(s, 0):,}" for s in ("critical", "high", "medium", "low"))],
        ["Model (ML) / rule (Suricata) alerts",
         f"{data.by_source.get('ml', 0):,} / {data.by_source.get('rule', 0):,}"],
        ["Blocks applied", f"{data.blocks['created']:,}"],
        ["Dry-run would-blocks", f"{data.would_blocks['total']:,}"],
        ["False-positive rate (of triaged alerts)",
         "n/a" if data.fp_rate is None else f"{data.fp_rate:.1%} ({data.false_positives:,} of "
                                            f"{data.triaged:,})"],
        ["Detection latency p50 / p95",
         f"{_fmt_ms(data.latency_ms[0])} / {_fmt_ms(data.latency_ms[1])}"]],
        [100 * mm, 74 * mm])]
    story.append(P(f"Latency is measured on the newest {data.latency_ms[2]:,} alerts of the week "
                   "(time from the end of the flow to the alert being stored).", "small"))

    story += [P("Alerts per day", "h"), _chart(w, data.per_day)]

    story.append(P("Alerts by class", "h"))
    if data.by_class:
        rows = [["Class", "Alerts", "Share"]] + [
            [Paragraph(esc(name, 80), st["cell"]), f"{n:,}", f"{n / data.total:.1%}"]
            for name, n in data.by_class]
        story.append(_table(rows, [100 * mm, 37 * mm, 37 * mm]))
    else:
        story.append(P("No alerts this week."))

    story.append(P("Top 10 source addresses", "h"))
    if data.top_sources:
        story.append(_table([["#", "Source address", "Alerts"]] + [
            [str(i), clean(ip(a), 60), f"{n:,}"]
            for i, (a, n) in enumerate(data.top_sources, 1)], [14 * mm, 120 * mm, 40 * mm],
            numeric_from=2))
    else:
        story.append(P("No alerts this week."))

    story.append(P("Blocks and would-blocks", "h"))
    b, wb = data.blocks, data.would_blocks
    story.append(_table([
        ["", "Count"],
        ["Blocks applied this week", f"{b['created']:,} ({b['distinct_ips']:,} distinct addresses)"],
        ["  by source (auto / analyst)",
         f"{b['by_source'].get('auto', 0):,} / {b['by_source'].get('analyst', 0):,}"],
        ["Blocks lifted this week", f"{b['unblocked']:,}"],
        ["Blocks active now", f"{b['active_now']:,}"],
        ["Would-blocks (dry-run sensors)",
         f"{wb['total']:,} ({wb['distinct_ips']:,} distinct addresses)"]],
        [100 * mm, 74 * mm]))
    story.append(P(f"Would-block records are kept {data.would_block_retention_days} days, so an "
                   "older week may show fewer than were made.", "small"))
    if b["top"]:
        story += [Spacer(1, 4), _table([["Most blocked addresses", "Blocks"]] + [
            [clean(ip(a), 60), f"{n:,}"] for a, n in b["top"]], [134 * mm, 40 * mm])]

    story.append(P("Analyst triage", "h"))
    rows = [["Alert status", "Alerts"]] + [[s.replace("_", " "), f"{n:,}"]
                                          for s, n in data.by_status.items()]
    rows += [["Cases opened this week", f"{data.cases['opened']:,}"],
             ["Cases closed this week", f"{data.cases['closed']:,}"]]
    story.append(_table(rows, [134 * mm, 40 * mm]))

    story.append(P("Model health", "h"))
    online = sum(1 for s in data.sensors if s["online"])
    story.append(P(f"Sensors online now: {online} of {len(data.sensors)} (as of the time this "
                   "report was generated)."))
    if data.sensors:
        story.append(Spacer(1, 3))
        story.append(_table([["Sensor", "State", "Model", "Drift", "Outbox"]] + [
            [Paragraph(esc(s["name"], 40), st["cell"]), "online" if s["online"] else "offline",
             Paragraph(esc(f"{s['model'] or 'unknown'} {s['version'] or ''}", 80), st["cell"]),
             clean(s["drift"] or "n/a", 12)
             + ("" if s["psi_max"] is None else f" ({float(s['psi_max']):.2f})"),
             "n/a" if s["outbox"] is None else f"{int(s['outbox']):,}"] for s in data.sensors],
            [38 * mm, 20 * mm, 66 * mm, 28 * mm, 22 * mm], numeric_from=4))
        story.append(Spacer(1, 3))
        story.append(_table([["Sensor", "Explanation faithfulness"]] + [
            [Paragraph(esc(s["name"], 40), st["cell"]),
             Paragraph(esc(s["faithfulness"], 200), st["cell"])] for s in data.sensors],
            [38 * mm, 136 * mm], numeric_from=9))
    if data.models:
        story.append(Spacer(1, 3))
        story.append(_table([["Model seen this week", "Version", "Digest", "Sensors"]] + [
            [Paragraph(esc(m["name"], 40), st["cell"]), Paragraph(esc(m["version"], 40), st["cell"]),
             clean(m["sha256"][:12], 12), str(m["sensors"])] for m in data.models],
            [50 * mm, 52 * mm, 44 * mm, 28 * mm], numeric_from=3))
    story += [Spacer(1, 10), P(FOOTER + ". The report is generated from the SOC's own records; "
                               "see docs/privacy.md.", "small")]

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
        bottomMargin=18 * mm, title=clean(f"IDPS weekly report {w.label}", 80),
        author="IDPS SOC", subject="Weekly security report")
    doc.build(story, canvasmaker=_NumberedCanvas)
    return buf.getvalue()


class Busy(Exception):
    """Two reports are already being built."""


def build_report(db: Session, settings: SocSettings, week: Week, now: datetime | None = None, *,
                 wait: bool = True) -> tuple[bytes, ReportData]:
    """Collect and render, at most two at once in this process (`wait` False: raise Busy
    instead of queueing). Returns the PDF and the numbers it was made from."""
    if not _slots.acquire(blocking=wait):
        raise Busy
    try:
        data = collect(db, settings, week, now)
        return render_pdf(data), data
    finally:
        _slots.release()


def build_pdf(db: Session, settings: SocSettings, week: Week, now: datetime | None = None, *,
              wait: bool = True) -> bytes:
    return build_report(db, settings, week, now, wait=wait)[0]


def addresses_shown(data: ReportData) -> list[str]:
    """The addresses the PDF prints in full (none when masking is on): for the access log."""
    if data.mask_ips:
        return []
    return [ip for ip, _ in data.top_sources] + [ip for ip, _ in data.blocks.get("top", [])]


def explain(db: Session, week: Week) -> str:
    """The query plan of the report's main pass (tests check it uses the received_at index)."""
    sqlite = db.get_bind().dialect.name == "sqlite"
    lo, hi = ((w.isoformat(" ") for w in (week.start, week.end)) if sqlite
              else (week.start, week.end))
    sql = ("SELECT severity, coalesce(source, 'ml'), status, predicted_class, count(*) FROM alerts "
           "WHERE received_at >= :lo AND received_at < :hi "
           "GROUP BY severity, coalesce(source, 'ml'), status, predicted_class")
    prefix = "EXPLAIN QUERY PLAN " if sqlite else "EXPLAIN "
    return "\n".join(" ".join(str(c) for c in row)
                     for row in db.execute(text(prefix + sql), {"lo": lo, "hi": hi}))


# --- emailing ---------------------------------------------------------------------------------

def email_ready(settings: SocSettings) -> bool:
    return bool(settings.smtp_host and settings.smtp_from and settings.report_recipients)


class ReportTooLarge(Exception):
    pass


def send_report(settings: SocSettings, week: Week, pdf: bytes) -> int:
    """Email the PDF (one attachment) to the report recipients; returns how many. DeliveryError
    (safe text) when sending fails, ReportTooLarge over MAX_ATTACHMENT_BYTES."""
    if len(pdf) > MAX_ATTACHMENT_BYTES:
        raise ReportTooLarge
    recipients = settings.report_recipients
    msg = EmailMessage()
    msg["Subject"] = f"IDPS weekly report {week.label}"
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)
    msg.set_content(
        f"The IDPS weekly security report for {week.label} is attached.\n\n"
        f"{FOOTER}.\n")
    channels.send_email(settings, msg, recipients, timeout=max(settings.notify_timeout_seconds,
                                                              EMAIL_TIMEOUT_SECONDS),
                        attachment=(f"idps-weekly-{week.label}.pdf", "application/pdf", pdf))
    return len(recipients)


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, DeliveryError):
        return str(exc)[:300]
    if isinstance(exc, ReportTooLarge):
        return "the report is over the 10 MB attachment limit"
    return f"unexpected error ({type(exc).__name__})"


def due_week(settings: SocSettings, now: datetime) -> tuple[Week, datetime] | None:
    """The week to email now and when it was due, or None: the last complete week, once the
    configured weekday and hour (UTC) after it ended have passed."""
    week = last_complete_week(now)
    due = week.end + timedelta(days=settings.report_email_weekday,
                               hours=settings.report_email_hour_utc)
    return (week, due) if now >= due else None


def claim_week(db: Session, label: str, now: datetime, due: datetime) -> bool:
    """Take the right to email `label`: True for exactly one caller. A week already sent is never
    claimed again; one claimed but not sent (the process died, or sending failed) is claimed again
    after RETRY_AFTER, until RETRY_WINDOW after it was due."""
    row = db.scalar(select(ReportRun).where(ReportRun.week == label))
    if row is None:
        db.add(ReportRun(week=label, generated_at=now, recipients_count=0))
        try:
            db.commit()
        except IntegrityError:  # another process claimed it between our read and insert
            db.rollback()
            return False
        return True
    if (row.emailed_at is not None or now - row.generated_at < RETRY_AFTER
            or now - due > RETRY_WINDOW):
        return False
    won = db.execute(update(ReportRun).where(
        ReportRun.week == label, ReportRun.emailed_at.is_(None),
        ReportRun.generated_at == row.generated_at).values(generated_at=now, error=None)).rowcount
    db.commit()
    return won == 1


def _finish(db: Session, label: str, *, sent_at: datetime | None, recipients: int,
            error: str | None) -> None:
    run = db.scalar(select(ReportRun).where(ReportRun.week == label))
    if run is None:
        run = ReportRun(week=label, generated_at=datetime.now(UTC))
        db.add(run)
    run.emailed_at, run.recipients_count, run.error = sent_at, recipients, error
    db.commit()


@dataclass
class RunState:
    at: datetime | None = None
    week: str | None = None
    sent: bool = False
    error: str | None = None


def run_once(session_factory: sessionmaker[Session], settings: SocSettings, state: RunState,
             now: datetime | None = None) -> None:
    """One check: email the due week if it has not been sent. Never raises; the result is in
    `state` and in report_runs."""
    now = now or datetime.now(UTC)
    state.at = now
    try:
        if not settings.report_email_enabled or not email_ready(settings):
            return
        due = due_week(settings, now)
        if due is None:
            return
        week, due_at = due
        with session_factory() as db:
            if not claim_week(db, week.label, now, due_at):
                return
            state.week, state.sent, state.error = week.label, False, None
            try:
                pdf = build_pdf(db, settings, week, now)
                db.rollback()  # no transaction held open while the mail server is slow
                n = send_report(settings, week, pdf)
            except Exception as exc:  # recorded, retried later, never raised
                log.debug("report email failed", exc_info=True)
                state.error = _safe_error(exc)
                log.warning("weekly report %s was not emailed: %s", week.label, state.error)
                db.rollback()
                _finish(db, week.label, sent_at=None, recipients=0, error=state.error)
                return
            _finish(db, week.label, sent_at=datetime.now(UTC), recipients=n, error=None)
            state.sent = True
            log.info("weekly report %s emailed to %d recipient(s)", week.label, n)
    except Exception:  # a broken database must not kill the thread
        log.exception("weekly report run failed")
        state.error = "run failed (see the SOC log)"


class ReportRunner:
    """A daemon thread that checks every INTERVAL_SECONDS whether the weekly report is due."""

    def __init__(self, session_factory, settings: SocSettings, *,
                 first_delay: float = FIRST_RUN_DELAY_SECONDS,
                 interval: float = INTERVAL_SECONDS) -> None:
        self.session_factory, self.settings = session_factory, settings
        self.first_delay, self.interval = first_delay, interval
        self.state = RunState()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="soc-reports", daemon=True)

    def start(self) -> None:
        if self.settings.report_email_enabled:  # nothing to wait for when it is off
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        wait = self.first_delay
        if not email_ready(self.settings):
            log.warning("IDPS_SOC_REPORT_EMAIL_ENABLED is on but SMTP host, sender or recipients "
                        "are missing: weekly reports will not be emailed")
        while not self._stop.wait(wait):
            run_once(self.session_factory, self.settings, self.state)
            wait = self.interval


# --- routes -----------------------------------------------------------------------------------

class WeekRow(BaseModel):
    week: str
    start: datetime
    end: datetime
    alerts: int
    run: bool  # a report_runs row exists (an email was attempted)
    emailed: bool
    emailed_at: datetime | None
    recipients_count: int
    error: str | None


class WeeksOut(BaseModel):
    default_week: str
    email_enabled: bool  # scheduled emailing is on
    email_configured: bool  # SMTP host, sender and recipients are set (so "send now" works)
    weeks: list[WeekRow]


class EmailResult(BaseModel):
    week: str
    recipients: int
    emailed_at: datetime
    size_bytes: int


@router.get("/reports/weeks", response_model=WeeksOut)
def list_weeks(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    """The last 12 complete ISO weeks, newest first, with their alert counts and email state."""
    settings = request.app.state.settings
    now = datetime.now(UTC)
    newest = last_complete_week(now)
    weeks = [week_of(newest.start.date() - timedelta(days=7 * i)) for i in range(WEEKS_LISTED)]
    runs = {r.week: r for r in db.scalars(select(ReportRun).where(
        ReportRun.week.in_([w.label for w in weeks])))}
    rows = []
    for w in weeks:
        run = runs.get(w.label)
        rows.append(WeekRow(
            week=w.label, start=w.start, end=w.end, alerts=count_alerts(db, w),
            run=run is not None, emailed=bool(run and run.emailed_at),
            emailed_at=run.emailed_at if run else None,
            recipients_count=run.recipients_count if run else 0, error=run.error if run else None))
    return WeeksOut(default_week=newest.label, email_enabled=settings.report_email_enabled,
                    email_configured=email_ready(settings), weeks=rows)


def _build_or_429(db: Session, settings: SocSettings, week: Week,
                  now: datetime) -> tuple[bytes, ReportData]:
    try:
        return build_report(db, settings, week, now, wait=False)
    except Busy:
        raise HTTPException(429, "two reports are already being built; try again in a moment",
                            headers={"Retry-After": "10"}) from None


@router.get("/reports/weekly")
def weekly_report(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)],
                  week: Annotated[str | None, Query(max_length=12,
                                                    description="ISO week, e.g. 2026-W45")] = None):
    """The weekly report as a PDF attachment (default: the last complete ISO week, UTC). The
    download is access-logged; it contains source addresses."""
    settings = request.app.state.settings
    now = datetime.now(UTC)
    wk = _resolve_week(week, now)
    pdf, data = _build_or_429(db, settings, wk, now)
    # the download contains the addresses it prints (none when they are masked)
    access_log.log_access(db, settings, user, "report_download", target_type="report",
                          target=wk.label, ips=addresses_shown(data), without_subject=True)
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="idps-weekly-{wk.label}.pdf"',
        "Cache-Control": "no-store"})


@router.post("/admin/reports/weekly/email", response_model=EmailResult)
def email_weekly(admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)],
                 week: Annotated[str | None, Query(max_length=12)] = None):
    """Email a week's report now to the configured recipients (SMTP settings; the recipients are
    never shown or accepted here). Audited (`report_email`, with the week and a recipient count).
    Works whether or not scheduled emailing is on, and does not touch the schedule's record
    (`report_runs`)."""
    settings = request.app.state.settings
    now = datetime.now(UTC)
    wk = _resolve_week(week, now)
    if not email_ready(settings):
        raise HTTPException(409, "email is not configured (IDPS_SOC_SMTP_HOST, SMTP_FROM and "
                                 "recipients in IDPS_SOC_REPORT_EMAIL_TO or IDPS_SOC_SMTP_TO)")
    pdf, _ = _build_or_429(db, settings, wk, now)
    db.rollback()  # end the read transaction before talking to the mail server
    try:
        n = send_report(settings, wk, pdf)
    except (DeliveryError, ReportTooLarge) as exc:
        error = _safe_error(exc)
        audit(db, admin, "report_email", f"report:{wk.label}", {"ok": False, "error": error})
        db.commit()
        raise HTTPException(413 if isinstance(exc, ReportTooLarge) else 502,
                            f"the report was not sent: {error}") from None
    sent = datetime.now(UTC)
    # Audit only: report_runs belongs to the schedule. A manual send of an unfinished week must not
    # stop the scheduled full-week email, and a failed re-send must not undo a sent one.
    audit(db, admin, "report_email", f"report:{wk.label}",
          {"ok": True, "recipients": n, "bytes": len(pdf)})
    db.commit()
    return EmailResult(week=wk.label, recipients=n, emailed_at=sent, size_bytes=len(pdf))

