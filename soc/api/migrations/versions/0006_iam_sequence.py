"""Repair the PostgreSQL IAM role sequence on databases seeded by the original 0004."""

from alembic import op

revision = "0006_iam_sequence"
down_revision = "0005_cloud"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute("LOCK TABLE iam_roles IN SHARE ROW EXCLUSIVE MODE")
        op.execute("""
            SELECT setval(seq, highest)
            FROM (SELECT pg_get_serial_sequence('iam_roles', 'id')::regclass AS seq,
                         max(id) AS highest FROM iam_roles) AS roles
            WHERE highest >= nextval(seq)
        """)


def downgrade() -> None:
    # Sequence advancement is independent of the table schema.
    pass
