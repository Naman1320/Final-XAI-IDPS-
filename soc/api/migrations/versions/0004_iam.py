"""IAM / RBAC: roles, groups, policies and the login history.

Frozen like 0001: it does not import soc.api.models. Seeds the two system roles ("admin": every
permission; "analyst": cloud.view). Foreign keys cascade on delete; the login history keeps its
rows when a user is deleted (user_id becomes NULL).

Revision ID: 0004_iam
Revises: 0003_privacy_reports
"""
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0004_iam"
down_revision: str | None = "0003_privacy_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The catalog as of this revision (soc/api/iam/catalog.py is the live one).
_ALL = ("cloud.view", "cloud.instances.write", "cloud.storage.write", "cloud.network.write",
        "cloud.alerts.manage", "iam.users.view", "iam.users.write", "iam.users.delete",
        "iam.roles.view", "iam.roles.write", "iam.groups.view", "iam.groups.write",
        "iam.policies.view", "iam.policies.write", "iam.audit.view", "iam.logins.view")
_SYSTEM_ROLES = (("admin", "Every permission. Held by legacy administrators.", _ALL),
                 ("analyst", "Triage access. Held by legacy analysts.", ("cloud.view",)))


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(column: str, target: str, ondelete: str = "CASCADE", **kw) -> sa.Column:
    return sa.Column(column, sa.Integer(), sa.ForeignKey(target, ondelete=ondelete), **kw)


def upgrade() -> None:
    op.create_table(
        "iam_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(48), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("system", sa.Boolean(), nullable=False),
        _ts("created_at"), _ts("updated_at"),
        sa.UniqueConstraint("name"))
    op.create_table(
        "iam_role_permissions",
        _fk("role_id", "iam_roles.id", primary_key=True, nullable=False),
        sa.Column("permission", sa.String(64), primary_key=True, nullable=False))
    op.create_table(
        "iam_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(48), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        _ts("created_at"),
        sa.UniqueConstraint("name"))
    op.create_table(
        "iam_group_members",
        _fk("group_id", "iam_groups.id", primary_key=True, nullable=False),
        _fk("user_id", "users.id", primary_key=True, nullable=False))
    op.create_index("ix_iam_group_members_user_id", "iam_group_members", ["user_id"])
    op.create_table(
        "iam_group_roles",
        _fk("group_id", "iam_groups.id", primary_key=True, nullable=False),
        _fk("role_id", "iam_roles.id", primary_key=True, nullable=False))
    op.create_index("ix_iam_group_roles_role_id", "iam_group_roles", ["role_id"])
    op.create_table(
        "iam_user_roles",
        _fk("user_id", "users.id", primary_key=True, nullable=False),
        _fk("role_id", "iam_roles.id", primary_key=True, nullable=False))
    op.create_index("ix_iam_user_roles_role_id", "iam_user_roles", ["role_id"])
    op.create_table(
        "iam_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(48), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("effect", sa.String(5), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("resources", sa.JSON(), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        _ts("created_at"),
        sa.UniqueConstraint("name"))
    op.create_table(
        "iam_policy_attachments",
        _fk("policy_id", "iam_policies.id", primary_key=True, nullable=False),
        sa.Column("subject_type", sa.String(8), primary_key=True, nullable=False),
        sa.Column("subject_id", sa.Integer(), primary_key=True, autoincrement=False,
                  nullable=False))
    op.create_index("ix_iam_policy_attachments_subject", "iam_policy_attachments",
                    ["subject_type", "subject_id"])
    op.create_table(
        "login_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("at"),
        _fk("user_id", "users.id", ondelete="SET NULL", nullable=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(24), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.String(255), nullable=False),
        sa.Column("mfa_used", sa.Boolean(), nullable=False))
    for column in ("at", "user_id", "username"):
        op.create_index(f"ix_login_history_{column}", "login_history", [column])

    # Seed the system roles.
    now = datetime.now(UTC)
    roles = sa.table("iam_roles", sa.column("id", sa.Integer), sa.column("name", sa.String),
                     sa.column("description", sa.String), sa.column("system", sa.Boolean),
                     sa.column("created_at", sa.DateTime(timezone=True)),
                     sa.column("updated_at", sa.DateTime(timezone=True)))
    perms = sa.table("iam_role_permissions", sa.column("role_id", sa.Integer),
                     sa.column("permission", sa.String))
    for number, (name, description, granted) in enumerate(_SYSTEM_ROLES, start=1):
        op.bulk_insert(roles, [{"id": number, "name": name, "description": description,
                                "system": True, "created_at": now, "updated_at": now}])
        op.bulk_insert(perms, [{"role_id": number, "permission": p} for p in granted])
    if op.get_context().dialect.name == "postgresql":
        op.execute("SELECT setval(pg_get_serial_sequence('iam_roles', 'id'), MAX(id)) FROM iam_roles")


def downgrade() -> None:
    for column in ("username", "user_id", "at"):
        op.drop_index(f"ix_login_history_{column}", table_name="login_history")
    op.drop_table("login_history")
    op.drop_index("ix_iam_policy_attachments_subject", table_name="iam_policy_attachments")
    op.drop_table("iam_policy_attachments")
    op.drop_table("iam_policies")
    op.drop_index("ix_iam_user_roles_role_id", table_name="iam_user_roles")
    op.drop_table("iam_user_roles")
    op.drop_index("ix_iam_group_roles_role_id", table_name="iam_group_roles")
    op.drop_table("iam_group_roles")
    op.drop_index("ix_iam_group_members_user_id", table_name="iam_group_members")
    op.drop_table("iam_group_members")
    op.drop_table("iam_groups")
    op.drop_table("iam_role_permissions")
    op.drop_table("iam_roles")
