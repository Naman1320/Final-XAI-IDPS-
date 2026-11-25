"""Training data for the next model: analyst-judged alerts with their features. Admins only."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from soc.api import access_log
from soc.api.auth import AdminUser
from soc.api.common import audit
from soc.api.db import get_db
from soc.api.feedback import feedback_label, judged_alerts

router = APIRouter(tags=["training"])

MAX_ROWS = 1000


class FeedbackRow(BaseModel):
    alert_id: int
    label: str  # BENIGN for a false positive, else the analyst's class (or the predicted one)
    status: str
    predicted_class: str
    true_class: str | None
    model_sha256: str | None
    model_version: str | None
    start_ms: int
    end_ms: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    features: dict[str, float]


class FeedbackPage(BaseModel):
    rows: list[FeedbackRow]
    next_after_id: int | None  # pass as after_id for the next page; null at the end


@router.get("/training/feedback", response_model=FeedbackPage)
def training_feedback(
    admin: AdminUser, request: Request, db: Annotated[Session, Depends(get_db)],
    model_sha256: Annotated[str | None, Query(pattern=r"^[0-9a-fA-F]{64}$")] = None,
    after_id: Annotated[int, Query(ge=0, le=2**62)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_ROWS)] = 500,
):
    """Judged alerts (false_positive, confirmed) that have features, oldest first, from
    `after_id`. `model_sha256` keeps only alerts scored by that model. Every call is audited."""
    sha = model_sha256.lower() if model_sha256 else None
    rows = [FeedbackRow(
        alert_id=a.id, label=feedback_label(a), status=a.status.value,
        predicted_class=a.predicted_class, true_class=a.true_class,
        model_sha256=a.model_sha256, model_version=a.model_version, start_ms=a.start_ms,
        end_ms=a.end_ms, src_ip=a.src_ip, src_port=a.src_port, dst_ip=a.dst_ip,
        dst_port=a.dst_port, protocol=a.protocol, features=a.features)
        for a in judged_alerts(db, with_features_only=True, after_id=after_id,
                               model_sha256=sha, limit=limit + 1, dedupe=True)]
    more = len(rows) > limit
    rows = rows[:limit]
    audit(db, admin, "training_feedback_read", "training:feedback",
          {"rows": len(rows), "after_id": after_id, "model_sha256": sha})
    # the export carries source and destination addresses: logged (with the audit row, one commit)
    access_log.log_access(db, request.app.state.settings, admin, "training_feedback_export",
                          target_type="training", target="feedback")
    return FeedbackPage(rows=rows, next_after_id=rows[-1].alert_id if more and rows else None)
