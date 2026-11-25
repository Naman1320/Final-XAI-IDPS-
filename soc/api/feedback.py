"""Analyst feedback as training data: which alerts count, and with what label.

An alert is a training row when it is a MODEL alert (source "ml", never a Suricata rule alert),
an analyst judged it (status false_positive -> label BENIGN, or
confirmed -> label `true_class`, else the predicted class) and it carries the flow's model
features. Used by the admin endpoint GET /training/feedback and the offline export
`python -m soc.api.export_feedback`.

The same flow can be ingested twice (a sensor retries a batch the SOC stored but did not
acknowledge). Rows of one flow (sensor, 5-tuple, start and end time) count once: the first
(lowest id) judged alert wins.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import and_, exists, select
from sqlalchemy.orm import Session, aliased

from soc.api.models import Alert, AlertStatus, ml_alerts_clause

FEEDBACK_STATUSES = (AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED)
BENIGN = "BENIGN"
FLOW_KEY = ("sensor_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start_ms",
            "end_ms")


def feedback_label(alert: Alert) -> str:
    if alert.status == AlertStatus.FALSE_POSITIVE:
        return BENIGN
    # Confirmed means a real attack: never BENIGN, whatever a stale true_class says.
    if alert.true_class and alert.true_class != BENIGN:
        return alert.true_class
    return alert.predicted_class


def flow_key(alert: Alert) -> tuple:
    return tuple(getattr(alert, k) for k in FLOW_KEY)


def judged_alerts(db: Session, *, with_features_only: bool = False, after_id: int = 0,
                  model_sha256: str | None = None, limit: int | None = None,
                  dedupe: bool = False) -> Iterator[Alert]:
    """Judged alerts in id order. With `dedupe`, an alert is skipped when an earlier judged one
    (with features, if `with_features_only`) is the same flow; callers that scan everything
    anyway can dedupe themselves with flow_key() and count what they drop."""
    # Rule alerts (Suricata) are never training rows: they have no model features and a rule's
    # verdict says nothing about what the model should have predicted.
    query = (select(Alert).where(Alert.status.in_(FEEDBACK_STATUSES), Alert.id > after_id,
                                 ml_alerts_clause())
             .order_by(Alert.id))
    if with_features_only:
        query = query.where(Alert.features.is_not(None))
    if model_sha256:
        query = query.where(Alert.model_sha256 == model_sha256.lower())
    if dedupe:
        earlier = aliased(Alert)
        same = [getattr(earlier, k) == getattr(Alert, k) for k in FLOW_KEY]
        cond = and_(earlier.id < Alert.id, earlier.status.in_(FEEDBACK_STATUSES), *same)
        if with_features_only:
            cond = and_(cond, earlier.features.is_not(None))
        query = query.where(~exists().where(cond))
    if limit is not None:
        query = query.limit(limit)
    yield from db.scalars(query.execution_options(yield_per=1000))
