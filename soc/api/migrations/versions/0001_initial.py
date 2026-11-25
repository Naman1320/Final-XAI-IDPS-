"""The SOC schema as of roadmap step 10.

Written out by hand and frozen: it must NOT import soc.api.models, so that later model changes
never alter what this revision creates (a new migration does that). Enums are plain VARCHARs
(the models use native_enum=False without a CHECK constraint); timestamps are timezone-aware.

Revision ID: 0001_initial
Revises:
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _table(metadata: sa.MetaData, name: str, *items) -> sa.Table:
    return sa.Table(name, metadata, *items)


def _index(metadata: sa.MetaData, name: str, table: str, columns: list[str],
           unique: bool = False) -> sa.Index:
    return sa.Index(name, *[metadata.tables[table].c[c] for c in columns], unique=unique)


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def tables(metadata: sa.MetaData) -> None:
    """The 0001 schema, defined on `metadata`. Used by upgrade() and, as the exact baseline, by
    soc.api.migrate (adoption checks); it depends on nothing but SQLAlchemy."""
    _table(metadata,
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        _ts("created_at"))
    _index(metadata, "ix_users_username", "users", ["username"], unique=True)

    _table(metadata,
        "sensor_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        _ts("created_at"),
        sa.UniqueConstraint("name"))
    _index(metadata, "ix_sensor_tokens_token_hash", "sensor_tokens", ["token_hash"], unique=True)

    _table(metadata,
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("at"),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_name", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False))
    _index(metadata, "ix_audit_log_at", "audit_log", ["at"])
    _index(metadata, "ix_audit_log_actor_name", "audit_log", ["actor_name"])
    _index(metadata, "ix_audit_log_action", "audit_log", ["action"])

    _table(metadata,
        "cases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id")),
        _ts("created_at"),
        _ts("updated_at"))
    _index(metadata, "ix_cases_status", "cases", ["status"])

    _table(metadata,
        "case_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("author_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("text", sa.Text(), nullable=False),
        _ts("created_at"))
    _index(metadata, "ix_case_notes_case_id", "case_notes", ["case_id"])

    _table(metadata,
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"), nullable=False),
        _ts("received_at"),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.Integer(), nullable=False),
        sa.Column("start_ms", sa.BigInteger(), nullable=False),
        sa.Column("end_ms", sa.BigInteger(), nullable=False),
        sa.Column("predicted_class", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("anomaly_score", sa.Float()),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id")),
        sa.Column("features", sa.JSON()),
        sa.Column("model_sha256", sa.String(64)),
        sa.Column("model_version", sa.String(80)),
        sa.Column("true_class", sa.String(64)),
        sa.Column("source", sa.String(8)),
        sa.Column("rule", sa.JSON()))
    for name, cols in (
            ("ix_alerts_sensor_id", ["sensor_id"]), ("ix_alerts_received_at", ["received_at"]),
            ("ix_alerts_src_ip", ["src_ip"]), ("ix_alerts_dst_ip", ["dst_ip"]),
            ("ix_alerts_predicted_class", ["predicted_class"]),
            ("ix_alerts_severity", ["severity"]), ("ix_alerts_status", ["status"]),
            ("ix_alerts_case_id", ["case_id"]), ("ix_alerts_model_sha256", ["model_sha256"]),
            ("ix_alerts_source", ["source"]),
            ("ix_alerts_received_class_anomaly",
             ["received_at", "predicted_class", "anomaly_score"])):
        _index(metadata, name, "alerts", cols)

    _table(metadata,
        "blocks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id")),
        _ts("blocked_at"),
        _ts("expires_at", True),
        _ts("unblocked_at", True))
    _index(metadata, "ix_blocks_sensor_id", "blocks", ["sensor_id"])
    _index(metadata, "ix_blocks_ip", "blocks", ["ip"])
    _index(metadata, "ix_blocks_alert_id", "blocks", ["alert_id"])

    _table(metadata,
        "actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("proposed_by", sa.String(16), nullable=False),
        sa.Column("proposed_by_user_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        _ts("created_at"),
        sa.Column("decided_by_id", sa.Integer(), sa.ForeignKey("users.id")),
        _ts("decided_at", True),
        sa.Column("result", sa.JSON()),
        _ts("completed_at", True))
    _index(metadata, "ix_actions_sensor_id", "actions", ["sensor_id"])
    _index(metadata, "ix_actions_status", "actions", ["status"])

    _table(metadata,
        "assistant_conversations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("title", sa.String(120), nullable=False),
        sa.Column("messages", sa.JSON(), nullable=False),
        sa.Column("user_turns", sa.Integer(), nullable=False),
        _ts("busy_since", True),
        _ts("created_at"),
        _ts("updated_at"))
    _index(metadata, "ix_assistant_conversations_user_id", "assistant_conversations", ["user_id"])

    _table(metadata,
        "would_blocks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id")),
        _ts("at"),
        sa.Column("ttl_seconds", sa.Integer()))
    _index(metadata, "ix_would_blocks_sensor_id", "would_blocks", ["sensor_id"])
    _index(metadata, "ix_would_blocks_ip", "would_blocks", ["ip"])
    _index(metadata, "ix_would_blocks_alert_id", "would_blocks", ["alert_id"])
    _index(metadata, "ix_would_blocks_at", "would_blocks", ["at"])

    _table(metadata,
        "sensor_status",
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"),
                  primary_key=True, autoincrement=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        _ts("last_seen_at"))

    _table(metadata,
        "model_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("sensor_tokens.id"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("version", sa.String(80), nullable=False),
        _ts("first_seen"),
        _ts("last_seen"),
        sa.UniqueConstraint("sensor_id", "sha256", name="uq_model_sensor_sha"))
    _index(metadata, "ix_model_versions_sensor_id", "model_versions", ["sensor_id"])
    _index(metadata, "ix_model_versions_sha256", "model_versions", ["sha256"])


def upgrade() -> None:
    metadata = sa.MetaData()
    tables(metadata)
    metadata.create_all(op.get_bind(), checkfirst=False)  # in dependency order, with indexes


def downgrade() -> None:
    for table in ("model_versions", "sensor_status", "would_blocks", "assistant_conversations",
                  "actions", "blocks", "alerts", "case_notes", "cases", "audit_log",
                  "sensor_tokens", "users"):
        op.drop_table(table)  # drops the table's indexes with it
