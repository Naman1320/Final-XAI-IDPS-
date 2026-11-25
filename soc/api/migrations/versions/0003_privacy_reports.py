"""Access log, erasure records and report runs (roadmap step 13, B7 reports and privacy).

Frozen like 0001: it does not import soc.api.models.

Revision ID: 0003_privacy_reports
Revises: 0002_mfa_oidc
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_privacy_reports"
down_revision: str | None = "0002_mfa_oidc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "access_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("at"),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column("subject_fp", sa.String(64), nullable=True))
    for name, column in (("ix_access_log_at", "at"), ("ix_access_log_username", "username"),
                         ("ix_access_log_action", "action"),
                         ("ix_access_log_subject_fp", "subject_fp")):
        op.create_index(name, "access_log", [column])

    op.create_table(
        "erasure_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("at"),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("subject_fp", sa.String(64), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False))
    op.create_index("ix_erasure_records_at", "erasure_records", ["at"])
    op.create_index("ix_erasure_records_subject_fp", "erasure_records", ["subject_fp"])

    op.create_table(
        "report_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("week", sa.String(8), nullable=False),
        _ts("generated_at"),
        _ts("emailed_at", nullable=True),
        sa.Column("recipients_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(300), nullable=True))
    op.create_index("ix_report_runs_week", "report_runs", ["week"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_report_runs_week", table_name="report_runs")
    op.drop_table("report_runs")
    op.drop_index("ix_erasure_records_subject_fp", table_name="erasure_records")
    op.drop_index("ix_erasure_records_at", table_name="erasure_records")
    op.drop_table("erasure_records")
    for name in ("ix_access_log_subject_fp", "ix_access_log_action", "ix_access_log_username",
                 "ix_access_log_at"):
        op.drop_index(name, table_name="access_log")
    op.drop_table("access_log")
