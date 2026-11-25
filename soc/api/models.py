"""Database tables. Auth tables are here; the SOC data tables follow below them."""

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    or_,
)
from sqlalchemy.orm import Mapped, mapped_column

from soc.api.db import Base, UtcDateTime


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    ANALYST = "analyst"  # triage alerts, confirm or reject actions, manage cases
    ADMIN = "admin"  # everything an analyst can do, plus users, sensors and policy


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=16))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Bumped on password change or disable: every token issued before it stops working.
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    # --- MFA (soc/api/mfa.py) ---------------------------------------------------------------
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # The TOTP secret, encrypted (AES-GCM, key from IDPS_SOC_MFA_KEY or the JWT secret).
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # A secret being enrolled, until the user proves it with a code (then it becomes totp_secret).
    totp_pending: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The last 30-second step a code was accepted for: a code is never accepted twice.
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # HMACs of the unused one-time recovery codes (the codes themselves are shown once).
    recovery_codes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Operator-assigned MFA mailbox and the latest challenge-bound code.
    mfa_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    email_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    email_sent_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    # --- single sign-on (soc/api/oidc.py): the identity provider account linked to this user
    oidc_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (Index("ux_users_oidc", "oidc_issuer", "oidc_subject", unique=True),)


class SensorToken(Base):
    """API token a sensor uses to send alerts. Only a SHA-256 of the token is stored."""

    __tablename__ = "sensor_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


# --- SOC data tables ---------------------------------------------------------------------

class Severity(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class AlertStatus(enum.StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    CONFIRMED = "confirmed"  # true positive: the analyst agrees with the detection


class CaseStatus(enum.StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class ActionKind(enum.StrEnum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"


class ActionStatus(enum.StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class BlockSource(enum.StrEnum):
    AUTO = "auto"
    ANALYST = "analyst"


def _enum(cls: type[enum.Enum]) -> Enum:
    return Enum(cls, native_enum=False, length=24, values_callable=lambda e: [m.value for m in e])


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[CaseStatus] = mapped_column(_enum(CaseStatus), default=CaseStatus.OPEN,
                                               index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Alert(Base):
    """One detection reported by a sensor. BENIGN flows are never stored."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_src_ip", "src_ip"), Index("ix_alerts_dst_ip", "dst_ip"),
        # The class-by-day heatmap (metrics.class_per_day) scans a week of alerts by these.
        Index("ix_alerts_received_class_anomaly", "received_at", "predicted_class",
              "anomaly_score"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    # Flow identity (idps.features.ID_COLUMNS); start_ms and end_ms are epoch milliseconds.
    src_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)
    start_ms: Mapped[int] = mapped_column(BigInteger)
    end_ms: Mapped[int] = mapped_column(BigInteger)
    predicted_class: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[Severity] = mapped_column(_enum(Severity), index=True)
    explanation: Mapped[dict] = mapped_column(JSON)
    status: Mapped[AlertStatus] = mapped_column(_enum(AlertStatus), default=AlertStatus.NEW,
                                                index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    # Learning from analysts: the flow's model features and which model scored it (sent by
    # sensors that know how), and the analyst's corrected class. All nullable: older alerts and
    # older sensors have none. Existing databases get them from migrations (soc/api/migrations).
    features: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    model_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    true_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Where the alert came from: "ml" (the model; also NULL, i.e. every row stored before this
    # column existed) or "rule" (Suricata, via the sensor's rule forwarder). `rule` describes the
    # rule that fired: {sid, rev, signature, category, severity 1-4, count}; null for model alerts.
    source: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    rule: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)


SOURCE_ML, SOURCE_RULE = "ml", "rule"


def ml_alerts_clause():
    """SQL condition: the alert came from the model (source "ml" or NULL = stored before sources
    existed). Anything that needs the model's features (training data) must use this."""
    return or_(Alert.source.is_(None), Alert.source == SOURCE_ML)


class Block(Base):
    """An IP block reported by a sensor. Active until unblocked or past expires_at."""

    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[BlockSource] = mapped_column(_enum(BlockSource))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True,
                                                  index=True)
    blocked_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    unblocked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


class Action(Base):
    """An action requested of a sensor. Assistant proposals start pending; analysts confirm."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[ActionKind] = mapped_column(_enum(ActionKind))
    params: Mapped[dict] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(String(500), default="")
    proposed_by: Mapped[str] = mapped_column(String(16))  # "user" or "assistant"
    proposed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    status: Mapped[ActionStatus] = mapped_column(_enum(ActionStatus), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


class AuditEntry(Base):
    """Who did what. One row per mutating request (ingest: one per batch)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(16))  # "user" or "sensor"
    actor_name: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class AssistantConversation(Base):
    """One analyst's chat with the SOC assistant. `messages` is the exact Messages API history
    (thinking and tool blocks included), sent back unchanged on the next turn."""

    __tablename__ = "assistant_conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(120), default="")
    messages: Mapped[list] = mapped_column(JSON, default=list)
    user_turns: Mapped[int] = mapped_column(Integer, default=0)
    # Set while a reply is running, so a second message can't race it (cleared when saved).
    busy_since: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class WouldBlock(Base):
    """A block a dry-run sensor decided on but did not apply. Kept apart from `blocks` on purpose:
    nothing here is in the firewall, so it never counts as an active block."""

    __tablename__ = "would_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[BlockSource] = mapped_column(_enum(BlockSource))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True,
                                                  index=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)


class SensorStatus(Base):
    """The latest status report of each sensor (one row per sensor, overwritten). `last_seen_at`
    is set by the server; the sensor's own clock (`sent_at` inside the payload) is not trusted."""

    __tablename__ = "sensor_status"

    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class ModelVersion(Base):
    """A model (by sha256) that a sensor has reported running. One row per (sensor, sha256);
    `last_seen` moves on every status report, so the newest row of a sensor is what it runs now."""

    __tablename__ = "model_versions"
    __table_args__ = (UniqueConstraint("sensor_id", "sha256", name="uq_model_sensor_sha"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(80))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


# --- privacy and reports (roadmap step 13) ----------------------------------------------------

class AccessLog(Base):
    """Who looked at personal data (soc/api/access_log.py). One row per subject IP address; the
    address itself is never stored here, only `subject_fp`, a keyed HMAC-SHA256 fingerprint of it.
    There is deliberately no foreign key to users: the log outlives account changes."""

    __tablename__ = "access_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target: Mapped[str] = mapped_column(String(128), default="")
    subject_fp: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class ErasureRecord(Base):
    """One erasure of an IP address on request (soc/api/privacy.py). Holds no address."""

    __tablename__ = "erasure_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    requested_by: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(500))
    subject_fp: Mapped[str] = mapped_column(String(64), index=True)
    counts: Mapped[dict] = mapped_column(JSON)


class ReportRun(Base):
    """The weekly report of one ISO week was claimed for emailing. `week` is unique, so a restart
    or a second process never sends the same week twice (soc/api/reports.py)."""

    __tablename__ = "report_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    week: Mapped[str] = mapped_column(String(8), unique=True, index=True)  # "2026-W45"
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    emailed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    recipients_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


# --- IAM / RBAC (soc/api/iam, migration 0004_iam) ---------------------------------------------
# SQLite does not enforce foreign keys here, so the code deletes dependent rows itself; the
# ON DELETE clauses are what PostgreSQL enforces.

class IamRole(Base):
    """A named set of permissions. The system roles "admin" and "analyst" are immutable."""

    __tablename__ = "iam_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(48), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class IamRolePermission(Base):
    __tablename__ = "iam_role_permissions"

    role_id: Mapped[int] = mapped_column(ForeignKey("iam_roles.id", ondelete="CASCADE"),
                                         primary_key=True)
    permission: Mapped[str] = mapped_column(String(64), primary_key=True)


class IamGroup(Base):
    __tablename__ = "iam_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(48), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class IamGroupMember(Base):
    __tablename__ = "iam_group_members"

    group_id: Mapped[int] = mapped_column(ForeignKey("iam_groups.id", ondelete="CASCADE"),
                                          primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"),
                                         primary_key=True, index=True)


class IamGroupRole(Base):
    __tablename__ = "iam_group_roles"

    group_id: Mapped[int] = mapped_column(ForeignKey("iam_groups.id", ondelete="CASCADE"),
                                          primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("iam_roles.id", ondelete="CASCADE"),
                                         primary_key=True, index=True)


class IamUserRole(Base):
    __tablename__ = "iam_user_roles"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"),
                                         primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("iam_roles.id", ondelete="CASCADE"),
                                         primary_key=True, index=True)


class IamPolicy(Base):
    """An allow or deny rule: permission patterns ("cloud.*") on resource globs (default "*")."""

    __tablename__ = "iam_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(48), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    effect: Mapped[str] = mapped_column(String(5))  # "allow" or "deny"
    permissions: Mapped[list] = mapped_column(JSON)
    resources: Mapped[list] = mapped_column(JSON)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class IamPolicyAttachment(Base):
    """A policy attached to a user, group or role. `subject_id` has no foreign key (it points at
    one of three tables): the code removes attachments when the subject is deleted."""

    __tablename__ = "iam_policy_attachments"

    policy_id: Mapped[int] = mapped_column(ForeignKey("iam_policies.id", ondelete="CASCADE"),
                                           primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(8), primary_key=True)  # user|group|role
    subject_id: Mapped[int] = mapped_column(Integer, primary_key=True)

    __table_args__ = (Index("ix_iam_policy_attachments_subject", "subject_type", "subject_id"),)


class LoginHistory(Base):
    """One sign-in attempt. Never holds a password or a token. `user_id` is NULL for an unknown
    username and after the user is deleted (the username stays)."""

    __tablename__ = "login_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(24))
    ip: Mapped[str] = mapped_column(String(45), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    mfa_used: Mapped[bool] = mapped_column(Boolean, default=False)


# --- Cloud management (soc/api/cloud, migration 0005_cloud) -----------------------------------
# MOCK inventory: nothing here describes a real cloud. As with IAM, SQLite does not enforce the
# foreign keys, so the code deletes dependent rows itself; the ON DELETE clauses are for PostgreSQL.
# State columns are plain strings checked by the code (the vocabularies are in cloud/catalog.py).

class CloudVpc(Base):
    __tablename__ = "cloud_vpcs"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # vpc-xxxxxxxx
    name: Mapped[str] = mapped_column(String(63))
    cidr: Mapped[str] = mapped_column(String(43))


class CloudSubnet(Base):
    __tablename__ = "cloud_subnets"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # subnet-xxxxxxxx
    vpc_id: Mapped[str] = mapped_column(ForeignKey("cloud_vpcs.id", ondelete="CASCADE"),
                                        index=True)
    name: Mapped[str] = mapped_column(String(63))
    cidr: Mapped[str] = mapped_column(String(43))
    az: Mapped[str] = mapped_column(String(24))
    public: Mapped[bool] = mapped_column(Boolean, default=False)  # instances get a public address


class CloudSecurityGroup(Base):
    __tablename__ = "cloud_security_groups"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # sg-xxxxxxxx
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), default="")
    vpc_id: Mapped[str] = mapped_column(ForeignKey("cloud_vpcs.id", ondelete="CASCADE"),
                                        index=True)


class CloudSgRule(Base):
    __tablename__ = "cloud_sg_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sg_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_security_groups.id", ondelete="CASCADE"), index=True)
    direction: Mapped[str] = mapped_column(String(3))  # in | out
    protocol: Mapped[str] = mapped_column(String(4))  # tcp | udp | icmp | all
    port_from: Mapped[int] = mapped_column(Integer)
    port_to: Mapped[int] = mapped_column(Integer)
    cidr: Mapped[str] = mapped_column(String(43))
    description: Mapped[str] = mapped_column(String(255), default="")


class CloudInstance(Base):
    __tablename__ = "cloud_instances"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # i-xxxxxxxx
    name: Mapped[str] = mapped_column(String(63))
    instance_type: Mapped[str] = mapped_column(String(24), index=True)
    state: Mapped[str] = mapped_column(String(12), index=True)  # running|stopped|pending|terminated
    az: Mapped[str] = mapped_column(String(24), index=True)
    vpc_id: Mapped[str] = mapped_column(String(24))
    subnet_id: Mapped[str] = mapped_column(String(24))
    private_ip: Mapped[str] = mapped_column(String(45))
    public_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os: Mapped[str] = mapped_column(String(48))
    vcpus: Mapped[int] = mapped_column(Integer)
    memory_gb: Mapped[float] = mapped_column(Float)
    disk_gb: Mapped[int] = mapped_column(Integer)
    tags: Mapped[dict] = mapped_column(JSON)
    launched_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class CloudInstanceSg(Base):
    """Which security groups an instance uses."""

    __tablename__ = "cloud_instance_sgs"

    instance_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_instances.id", ondelete="CASCADE"), primary_key=True)
    sg_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_security_groups.id", ondelete="CASCADE"), primary_key=True, index=True)


class CloudVolume(Base):
    __tablename__ = "cloud_volumes"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # vol-xxxxxxxx
    name: Mapped[str] = mapped_column(String(63))
    size_gb: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(8))
    state: Mapped[str] = mapped_column(String(10))  # available | in-use
    instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("cloud_instances.id", ondelete="SET NULL"), nullable=True, index=True)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)


class CloudBucket(Base):
    __tablename__ = "cloud_buckets"

    name: Mapped[str] = mapped_column(String(63), primary_key=True)
    region: Mapped[str] = mapped_column(String(24))
    versioning: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    public_access_blocked: Mapped[bool] = mapped_column(Boolean, default=True)
    object_count: Mapped[int] = mapped_column(Integer, default=0)
    size_gb: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class CloudAlert(Base):
    __tablename__ = "cloud_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    severity: Mapped[str] = mapped_column(String(8))  # info | warning | critical
    rule: Mapped[str] = mapped_column(String(32))  # which check raised it (dedupe key part)
    resource_type: Mapped[str] = mapped_column(String(24))
    resource_id: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(12), index=True)  # open|acknowledged|resolved
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CloudActivity(Base):
    """One row per change to the mock inventory (also in the audit log, which is the record of
    who did what; this one is the cloud module's own timeline)."""

    __tablename__ = "cloud_activity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(48), index=True)
    resource_type: Mapped[str] = mapped_column(String(24))
    resource_id: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[dict] = mapped_column(JSON)


class CloudCostDaily(Base):
    """Mock cost of one service on one day. `day` is an ISO date (YYYY-MM-DD, UTC)."""

    __tablename__ = "cloud_cost_daily"

    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    service: Mapped[str] = mapped_column(String(16), primary_key=True)
    amount_usd: Mapped[float] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
