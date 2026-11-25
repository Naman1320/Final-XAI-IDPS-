"""Alert ingest (sensors) and alert triage (analysts)."""

import json
import logging
import math
import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictInt,
    field_validator,
    model_validator,
)
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from idps.features import MODEL_FEATURES
from idps.features.labels import CIC_CLASSES
from soc.api import access_log
from soc.api.auth import AnyUser, Sensor
from soc.api.common import (
    Cursor,
    IPAddress,
    Limit,
    Page,
    audit,
    derive_severity,
    get_or_404,
    no_nul,
    paginate,
    plain_text,
)
from soc.api.db import get_db
from soc.api.geo import geo_out
from soc.api.models import SOURCE_ML, SOURCE_RULE, Alert, AlertStatus, Severity, ml_alerts_clause

log = logging.getLogger("soc.api")
router = APIRouter(tags=["alerts"])

MAX_BATCH = 500
MAX_EXPLANATION_BYTES = 16 * 1024
MAX_FEATURES_BYTES = 4 * 1024  # 42 model features are about 1.5 KiB
KNOWN_CLASSES = frozenset(CIC_CLASSES)  # CIC-IDS2017 labels (the trainer's) incl. BENIGN
MAX_MS = 4_102_444_800_000  # year 2100; catches seconds/microseconds mix-ups


class FeatureContribution(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feature: str = Field(min_length=1, max_length=64)
    value: float | None = Field(default=None, allow_inf_nan=False)
    contribution: float | None = Field(default=None, allow_inf_nan=False)


class ExplanationIn(BaseModel):
    """The idps.explain record format. Typed here so the dashboard can trust its shape;
    unknown keys are dropped."""

    model_config = ConfigDict(extra="ignore")

    method: str | None = Field(default=None, max_length=16)
    predicted_class: str | None = Field(default=None, max_length=64)
    confidence: float | None = Field(default=None, allow_inf_nan=False)
    base_value: float | None = Field(default=None, allow_inf_nan=False)
    output_space: str | None = Field(default=None, max_length=32)
    top_features: list[FeatureContribution] = Field(default_factory=list, max_length=50)


def clean_features(value: object) -> dict[str, float]:
    """The feature vector as {name: float}, or ValueError. Must hold every MODEL_FEATURES name,
    exactly, as finite numbers (a partial vector cannot be a training row), within the size cap."""
    if not isinstance(value, dict) or set(value) != set(MODEL_FEATURES):
        raise ValueError("features must be an object with exactly the model feature names")
    out = {}
    for k, v in value.items():
        if isinstance(v, bool) or not isinstance(v, int | float):
            raise ValueError(f"feature {k} must be a number")  # noqa: TRY004
        try:
            f = float(v)  # OverflowError for an int beyond float range
        except OverflowError as exc:
            raise ValueError(f"feature {k} is out of range") from exc
        if not math.isfinite(f):
            raise ValueError(f"feature {k} must be finite")
        out[k] = f
    if len(json.dumps(out, separators=(",", ":")).encode()) > MAX_FEATURES_BYTES:
        raise ValueError(f"features are over {MAX_FEATURES_BYTES} bytes")
    return out


Source = Literal["ml", "rule"]


class RuleInfo(BaseModel):
    """The rule behind a rule alert (Suricata). `severity` is Suricata's, 1 (most severe) to 4;
    `count` is how many events of the same rule, source, destination and port the alert stands for
    (1 for the first event; a follow-up alert carries the total of its window)."""

    model_config = ConfigDict(extra="forbid")

    sid: StrictInt = Field(ge=0, le=2**32)
    rev: StrictInt | None = Field(default=None, ge=0, le=2**31)
    signature: str = Field(min_length=1, max_length=300)
    category: str | None = Field(default=None, max_length=100)
    severity: StrictInt = Field(ge=1, le=4)
    count: StrictInt = Field(default=1, ge=1, le=2**31)

    @field_validator("signature", "category")
    @classmethod
    def _plain(cls, value: str | None) -> str | None:
        return None if value is None else plain_text(value.strip())


class AlertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src_ip: IPAddress
    src_port: StrictInt = Field(ge=0, le=65535)
    dst_ip: IPAddress
    dst_port: StrictInt = Field(ge=0, le=65535)
    protocol: StrictInt = Field(ge=0, le=255)
    start_ms: StrictInt = Field(ge=0, le=MAX_MS)
    end_ms: StrictInt = Field(ge=0, le=MAX_MS)
    predicted_class: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    anomaly_score: float | None = Field(default=None, allow_inf_nan=False)
    explanation: ExplanationIn = Field(default_factory=ExplanationIn)
    # Retraining inputs, sent by sensors that know how (all optional). Typed Any on purpose: a
    # bad value must not fail the whole batch (version skew between sensor and SOC), so the
    # after-validator below drops it from this alert and counts it (IngestResult).
    features: Any = None
    model_sha256: Any = None
    model_version: Any = None
    # "ml" (the default: sensors that predate rules send neither field) or "rule". A rule alert
    # carries `rule`, names a short family in predicted_class (idps/rules/eve.py rule_family) and
    # derives `confidence` from Suricata's severity; it has no features and no model identity.
    source: Source = SOURCE_ML
    rule: RuleInfo | None = None
    _features_dropped: bool = PrivateAttr(default=False)
    _model_info_dropped: bool = PrivateAttr(default=False)

    @model_validator(mode="after")
    def _source_and_rule(self) -> Self:
        if self.source == SOURCE_RULE:
            if self.rule is None:
                raise ValueError("a rule alert needs a `rule` object")
            # Nothing of the model applies: dropped without counting (nobody sent it by mistake).
            self.features = self.model_sha256 = self.model_version = self.anomaly_score = None
        elif self.rule is not None:
            raise ValueError("`rule` is only for alerts with source \"rule\"")
        return self

    @model_validator(mode="after")
    def _sanitise_optional(self) -> Self:
        if self.features is not None:
            try:
                self.features = clean_features(self.features)
            except ValueError:
                self.features, self._features_dropped = None, True
        if self.model_sha256 is not None:
            sha = self.model_sha256
            if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha):
                self.model_sha256 = sha.lower()
            else:
                self.model_sha256, self._model_info_dropped = None, True
        if self.model_version is not None:
            v = self.model_version
            try:
                if not isinstance(v, str):
                    raise ValueError  # noqa: TRY004
                v = plain_text(v.strip())
                if not 1 <= len(v) <= 80:
                    raise ValueError
                self.model_version = v
            except ValueError:
                self.model_version, self._model_info_dropped = None, True
        return self

    @field_validator("predicted_class")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = plain_text(value.strip())
        if not value:
            raise ValueError("predicted_class must not be blank")
        if value.startswith("("):  # "(other)" is the dashboard's fold bucket: no real class collides
            raise ValueError("predicted_class must not start with '('")
        return value

    @field_validator("explanation", mode="before")
    @classmethod
    def _explanation_size(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("explanation must be a JSON object")  # noqa: TRY004  pydantic needs ValueError
        try:
            size = len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode())
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("explanation must be plain JSON") from exc
        if size > MAX_EXPLANATION_BYTES:
            raise ValueError(f"explanation is {size} bytes; the limit is {MAX_EXPLANATION_BYTES}")
        return no_nul(value)

    @model_validator(mode="after")
    def _start_before_end(self) -> Self:
        if self.start_ms > self.end_ms:
            raise ValueError("start_ms must not be after end_ms")
        return self


class AlertBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts: list[AlertIn] = Field(min_length=1, max_length=MAX_BATCH)


class IngestResult(BaseModel):
    accepted: int
    skipped_benign: int
    ids: list[int]
    # Alerts stored without their optional `features` / model identity because those were
    # unusable (a newer or odd sensor); the alert itself is kept.
    features_dropped: int = 0
    model_info_dropped: int = 0


class AlertOut(BaseModel):
    """An alert without its explanation (lists and the live feed); see AlertDetail."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    sensor_id: int
    received_at: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    start_ms: int
    end_ms: int
    predicted_class: str
    confidence: float
    anomaly_score: float | None
    severity: Severity
    status: AlertStatus
    case_id: int | None
    # "ml" for model alerts (and every alert stored before sources existed), "rule" for Suricata.
    source: Source = SOURCE_ML
    rule: RuleInfo | None = None  # null for model alerts

    @field_validator("source", mode="before")
    @classmethod
    def _old_rows_are_ml(cls, value: Any) -> Any:
        return SOURCE_ML if value is None else value


class AlertDetail(AlertOut):
    explanation: dict[str, Any]
    model_sha256: str | None = None
    model_version: str | None = None
    true_class: str | None = None  # the analyst's corrected class (PATCH /alerts/{id})
    has_features: bool = False  # the feature vector itself is only in GET /training/feedback

    @model_validator(mode="before")
    @classmethod
    def _has_features(cls, data: Any) -> Any:
        if isinstance(data, Alert):
            out = {k: getattr(data, k) for k in cls.model_fields if hasattr(data, k)}
            out["has_features"] = data.features is not None
            return out
        return data


def consistent_true_class(status: AlertStatus, true_class: str) -> bool:
    """A confirmed alert is never BENIGN; a false positive is always BENIGN; other statuses
    may keep whatever the analyst noted."""
    if status == AlertStatus.CONFIRMED:
        return true_class != "BENIGN"
    if status == AlertStatus.FALSE_POSITIVE:
        return true_class == "BENIGN"
    return True


class AlertPatch(BaseModel):
    """`true_class`: the analyst's corrected class (a CIC-IDS2017 class or BENIGN). Sent as null
    it clears the correction; left out it is kept, unless it contradicts the new status (BENIGN on
    a confirmed alert, an attack class on a false positive), when the stored value is cleared."""

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    true_class: str | None = Field(default=None, max_length=64)

    @field_validator("true_class")
    @classmethod
    def _known_class(cls, value: str | None) -> str | None:
        if value is not None and value not in KNOWN_CLASSES:
            raise ValueError("true_class must be one of the known classes: "
                             + ", ".join(sorted(KNOWN_CLASSES)))
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if "true_class" in self.model_fields_set and self.true_class is not None:
            benign = self.true_class == "BENIGN"
            if self.status == AlertStatus.FALSE_POSITIVE and not benign:
                raise ValueError("a false positive is BENIGN; true_class must be BENIGN or null")
            if self.status == AlertStatus.CONFIRMED and benign:
                raise ValueError("a confirmed (true positive) alert cannot be BENIGN")
        return self


@router.post("/ingest/alerts", response_model=IngestResult, status_code=201)
def ingest_alerts(batch: AlertBatch, sensor: Sensor, request: Request,
                  db: Annotated[Session, Depends(get_db)]):
    settings = request.app.state.settings
    rows, skipped = [], 0
    features_dropped = sum(i._features_dropped for i in batch.alerts)
    model_dropped = sum(i._model_info_dropped for i in batch.alerts)
    for item in batch.alerts:
        if item.predicted_class.casefold() == "benign":
            skipped += 1  # BENIGN is never stored
            continue
        rows.append(Alert(
            sensor_id=sensor.id,
            severity=derive_severity(settings, item.predicted_class, item.confidence),
            **item.model_dump()))
    db.add_all(rows)
    audit(db, sensor, "ingest_alerts", f"sensor:{sensor.name}",
          {"received": len(batch.alerts), "stored": len(rows), "skipped_benign": skipped,
           **({"features_dropped": features_dropped} if features_dropped else {}),
           **({"model_info_dropped": model_dropped} if model_dropped else {})})
    db.commit()
    locator = request.app.state.geo
    # `src_geo` is only in the live message (not stored, not in GET /alerts): where the source is.
    request.app.state.broadcaster.publish_many(
        [AlertOut.model_validate(r).model_dump(mode="json") | {"src_geo": geo_out(locator, r.src_ip)}
         for r in rows])
    try:  # queue only: filtering and bounded in-memory queues, no I/O; never fails the ingest
        request.app.state.notifier.submit_alerts(rows, sensor.name)
    except Exception:
        log.exception("could not queue notifications")
    return IngestResult(accepted=len(rows), skipped_benign=skipped, ids=[r.id for r in rows],
                        features_dropped=features_dropped, model_info_dropped=model_dropped)


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(
    user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)],
    severity: Annotated[list[Severity] | None, Query(max_length=4)] = None,
    predicted_class: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    ip: Annotated[IPAddress | None, Query(description="matches source or destination")] = None,
    status: Annotated[AlertStatus | None, Query()] = None,
    source: Annotated[Source | None, Query(description="ml = the model, rule = Suricata")] = None,
    since: datetime | None = None, until: datetime | None = None,
    limit: Limit = 50, cursor: Cursor = None,
):
    for moment in (since, until):
        if moment is not None and moment.tzinfo is None:
            raise HTTPException(422, "since/until must include a timezone, e.g. 2026-01-01T00:00:00Z")
    query = select(Alert).order_by(Alert.id.desc()).limit(limit + 1)
    if severity:
        query = query.where(Alert.severity.in_(severity))
    if predicted_class:
        query = query.where(Alert.predicted_class == predicted_class)
    if ip:
        query = query.where(or_(Alert.src_ip == ip, Alert.dst_ip == ip))
    if status:
        query = query.where(Alert.status == status)
    if source == SOURCE_ML:
        query = query.where(ml_alerts_clause())  # NULL (stored before sources existed) counts
    elif source == SOURCE_RULE:
        query = query.where(Alert.source == SOURCE_RULE)
    if since:
        query = query.where(Alert.received_at >= since)
    if until:
        query = query.where(Alert.received_at <= until)
    if cursor:
        query = query.where(Alert.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    page = Page[AlertOut](items=[AlertOut.model_validate(r) for r in rows],
                          next_cursor=next_cursor)
    if ip:  # a search for one address is a look at that person's data: logged before it is served
        access_log.log_access(db, request.app.state.settings, user, "alert_search_by_ip",
                              target_type="alert_list", ips=[ip])
    return page


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, user: AnyUser, request: Request,
              db: Annotated[Session, Depends(get_db)]):
    alert = get_or_404(db, Alert, alert_id, "alert")
    out = AlertDetail.model_validate(alert)
    access_log.log_access(db, request.app.state.settings, user, "alert_view",
                          target_type="alert", target=str(alert.id),
                          ips=[alert.src_ip, alert.dst_ip])
    return out


@router.patch("/alerts/{alert_id}", response_model=AlertDetail)
def patch_alert(alert_id: int, body: AlertPatch, user: AnyUser,
                db: Annotated[Session, Depends(get_db)]):
    alert = get_or_404(db, Alert, alert_id, "alert")
    old = alert.status
    alert.status = body.status
    details = {"from": old.value, "to": body.status.value}
    if "true_class" in body.model_fields_set:
        new_class = body.true_class  # already checked against the new status (AlertPatch)
    else:  # keep the stored one unless it contradicts the new status
        new_class = alert.true_class
        if new_class is not None and not consistent_true_class(body.status, new_class):
            new_class = None
    if new_class != alert.true_class:
        details["true_class"] = [alert.true_class, new_class]
        alert.true_class = new_class
    audit(db, user, "alert_status", f"alert:{alert.id}", details)
    db.commit()
    return AlertDetail.model_validate(alert)
