"""Integrations: channel status and test buttons (admin) and source-IP reputation (analyst)."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from soc.api import access_log
from soc.api.auth import AdminUser, AnyUser
from soc.api.common import audit, get_or_404
from soc.api.db import get_db
from soc.api.models import Alert

router = APIRouter(tags=["integrations"])

ChannelName = Literal["webhook", "slack", "email", "syslog"]


class ChannelStatus(BaseModel):
    channel: ChannelName
    configured: bool
    enabled: bool
    min_severity: str
    include_rules: bool
    target_hint: str | None  # host only (or masked recipients); never a URL path, token or secret
    last_success_at: datetime | None
    last_error: str | None
    last_error_at: datetime | None
    queued: int
    sent: int
    failed: int
    dropped: int  # queue full
    rate_limited: int  # held back by the rate limit (covered by a digest message)
    deduped: int  # skipped as repeats


class AbuseIpdbStatus(BaseModel):
    configured: bool
    cache_hours: float


class IntegrationsOut(BaseModel):
    channels: list[ChannelStatus]
    abuseipdb: AbuseIpdbStatus


class TestResult(BaseModel):
    __test__ = False

    channel: ChannelName
    ok: bool
    error: str | None
    duration_ms: int
    tested_at: datetime


class Reputation(BaseModel):
    ip: str
    available: bool
    reason: str | None
    abuse_confidence: int | None
    total_reports: int | None
    country: str | None
    isp: str | None
    usage_type: str | None
    last_reported_at: str | None
    checked_at: str | None
    cached: bool


@router.get("/admin/integrations", response_model=IntegrationsOut)
def list_integrations(admin: AdminUser, request: Request):
    state = request.app.state
    return IntegrationsOut(
        channels=[ChannelStatus(**s) for s in state.notifier.status()],
        abuseipdb=AbuseIpdbStatus(configured=state.reputation.configured,
                                  cache_hours=state.settings.abuseipdb_cache_hours))


@router.post("/admin/integrations/{channel}/test", response_model=TestResult)
def test_integration(channel: ChannelName, admin: AdminUser, request: Request,
                     db: Annotated[Session, Depends(get_db)]):
    from soc.api.integrations.manager import NotConfigured, TestRateLimited

    try:
        result = request.app.state.notifier.send_test(channel)
    except NotConfigured:
        raise HTTPException(409, f"{channel} is not configured") from None
    except TestRateLimited:
        raise HTTPException(429, "too many test messages; wait a minute") from None
    audit(db, admin, "integration_test", f"integration:{channel}",
          {"ok": result["ok"], **({"error": result["error"]} if result["error"] else {})})
    db.commit()
    return TestResult(**result)


@router.get("/alerts/{alert_id}/reputation", response_model=Reputation)
def alert_reputation(alert_id: int, user: AnyUser, request: Request,
                     db: Annotated[Session, Depends(get_db)]):
    """AbuseIPDB's view of the alert's source address. Sends only that IP, only on request."""
    alert = get_or_404(db, Alert, alert_id, "alert")
    result, sent = request.app.state.reputation.lookup_ex(alert.src_ip)
    if sent:  # a real third-party lookup (not a cache hit): who sent which address where
        audit(db, user, "reputation_lookup", f"alert:{alert.id}",
              {"ip": alert.src_ip, "available": result["available"]})
    # one commit for the audit row (if any) and the access row; nothing is returned unlogged
    access_log.log_access(db, request.app.state.settings, user, "reputation_view",
                          target_type="alert", target=str(alert.id), ips=[alert.src_ip])
    return Reputation(**result)
