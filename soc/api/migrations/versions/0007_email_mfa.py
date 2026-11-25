"""Add an optional sign-in mailbox and one-time challenge state to each account."""

import sqlalchemy as sa
from alembic import op

revision = "0007_email_mfa"
down_revision = "0006_iam_sequence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_email", sa.String(254)))
    op.add_column("users", sa.Column("email_code_hash", sa.String(64)))
    op.add_column("users", sa.Column("email_sent_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    for name in ("email_sent_at", "email_code_hash", "mfa_email"):
        op.drop_column("users", name)
