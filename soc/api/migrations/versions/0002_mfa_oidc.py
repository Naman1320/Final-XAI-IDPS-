"""MFA (TOTP) and single sign-on (OIDC) columns on users (roadmap step 11).

Frozen like 0001: it does not import soc.api.models.

Revision ID: 0002_mfa_oidc
Revises: 0001_initial
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_mfa_oidc"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False,
                                     server_default=sa.false()))
    op.add_column("users", sa.Column("totp_secret", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("totp_pending", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("recovery_codes", sa.JSON(), nullable=True))
    op.add_column("users", sa.Column("oidc_issuer", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("oidc_subject", sa.String(255), nullable=True))
    op.create_index("ux_users_oidc", "users", ["oidc_issuer", "oidc_subject"], unique=True)


def downgrade() -> None:
    op.drop_index("ux_users_oidc", table_name="users")
    with op.batch_alter_table("users") as batch:  # SQLite: drop_column needs a table rebuild
        for column in ("oidc_subject", "oidc_issuer", "recovery_codes", "totp_last_step",
                       "totp_pending", "totp_secret", "mfa_enabled"):
            batch.drop_column(column)
