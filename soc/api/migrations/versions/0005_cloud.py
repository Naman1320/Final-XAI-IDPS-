"""Cloud management: the MOCK cloud inventory, alerts, activity and cost tables.

Frozen like 0001: it does not import soc.api.models. Creates no rows: the demo data is seeded by
the application on first access (soc/api/cloud/seed.py). Foreign keys cascade on delete.

Revision ID: 0005_cloud
Revises: 0004_iam
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_cloud"
down_revision: str | None = "0004_iam"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (index name, table, column), in creation order
_INDEXES = (
    ("ix_cloud_subnets_vpc_id", "cloud_subnets", "vpc_id"),
    ("ix_cloud_security_groups_vpc_id", "cloud_security_groups", "vpc_id"),
    ("ix_cloud_sg_rules_sg_id", "cloud_sg_rules", "sg_id"),
    ("ix_cloud_instances_instance_type", "cloud_instances", "instance_type"),
    ("ix_cloud_instances_state", "cloud_instances", "state"),
    ("ix_cloud_instances_az", "cloud_instances", "az"),
    ("ix_cloud_instance_sgs_sg_id", "cloud_instance_sgs", "sg_id"),
    ("ix_cloud_volumes_instance_id", "cloud_volumes", "instance_id"),
    ("ix_cloud_alerts_status", "cloud_alerts", "status"),
    ("ix_cloud_alerts_created_at", "cloud_alerts", "created_at"),
    ("ix_cloud_activity_at", "cloud_activity", "at"),
    ("ix_cloud_activity_actor", "cloud_activity", "actor"),
    ("ix_cloud_activity_action", "cloud_activity", "action"),
    ("ix_cloud_activity_resource_id", "cloud_activity", "resource_id"),
)


def _ts(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False)


def _str(name: str, length: int, **kw) -> sa.Column:
    kw.setdefault("nullable", False)
    return sa.Column(name, sa.String(length), **kw)


def upgrade() -> None:
    op.create_table(
        "cloud_vpcs",
        _str("id", 24, primary_key=True), _str("name", 63), _str("cidr", 43))
    op.create_table(
        "cloud_subnets",
        _str("id", 24, primary_key=True),
        _str("vpc_id", 24),
        _str("name", 63), _str("cidr", 43), _str("az", 24),
        sa.Column("public", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["vpc_id"], ["cloud_vpcs.id"], ondelete="CASCADE"))
    op.create_table(
        "cloud_security_groups",
        _str("id", 24, primary_key=True), _str("name", 64), _str("description", 255),
        _str("vpc_id", 24),
        sa.ForeignKeyConstraint(["vpc_id"], ["cloud_vpcs.id"], ondelete="CASCADE"))
    op.create_table(
        "cloud_sg_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        _str("sg_id", 24),
        _str("direction", 3), _str("protocol", 4),
        sa.Column("port_from", sa.Integer(), nullable=False),
        sa.Column("port_to", sa.Integer(), nullable=False),
        _str("cidr", 43), _str("description", 255),
        sa.ForeignKeyConstraint(["sg_id"], ["cloud_security_groups.id"], ondelete="CASCADE"))
    op.create_table(
        "cloud_instances",
        _str("id", 20, primary_key=True), _str("name", 63), _str("instance_type", 24),
        _str("state", 12), _str("az", 24), _str("vpc_id", 24), _str("subnet_id", 24),
        _str("private_ip", 45), _str("public_ip", 45, nullable=True), _str("os", 48),
        sa.Column("vcpus", sa.Integer(), nullable=False),
        sa.Column("memory_gb", sa.Float(), nullable=False),
        sa.Column("disk_gb", sa.Integer(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        _ts("launched_at"), _ts("updated_at"))
    op.create_table(
        "cloud_instance_sgs",
        _str("instance_id", 20, primary_key=True), _str("sg_id", 24, primary_key=True),
        sa.ForeignKeyConstraint(["instance_id"], ["cloud_instances.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["sg_id"], ["cloud_security_groups.id"], ondelete="CASCADE"))
    op.create_table(
        "cloud_volumes",
        _str("id", 24, primary_key=True), _str("name", 63),
        sa.Column("size_gb", sa.Integer(), nullable=False),
        _str("type", 8), _str("state", 10), _str("instance_id", 20, nullable=True),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["instance_id"], ["cloud_instances.id"], ondelete="SET NULL"))
    op.create_table(
        "cloud_buckets",
        _str("name", 63, primary_key=True), _str("region", 24),
        sa.Column("versioning", sa.Boolean(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.Column("public_access_blocked", sa.Boolean(), nullable=False),
        sa.Column("object_count", sa.Integer(), nullable=False),
        sa.Column("size_gb", sa.Float(), nullable=False),
        _ts("created_at"))
    op.create_table(
        "cloud_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        _str("severity", 8), _str("rule", 32), _str("resource_type", 24),
        _str("resource_id", 64), _str("message", 255), _str("status", 12),
        _ts("created_at"), _ts("updated_at"), _str("updated_by", 64, nullable=True))
    op.create_table(
        "cloud_activity",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("at"), _str("actor", 64), _str("action", 48), _str("resource_type", 24),
        _str("resource_id", 64), sa.Column("details", sa.JSON(), nullable=False))
    op.create_table(
        "cloud_cost_daily",
        _str("day", 10, primary_key=True), _str("service", 16, primary_key=True),
        sa.Column("amount_usd", sa.Float(), nullable=False), _str("currency", 3))
    for name, table, column in _INDEXES:
        op.create_index(name, table, [column])


def downgrade() -> None:
    for name, table, _column in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
    for table in ("cloud_cost_daily", "cloud_activity", "cloud_alerts", "cloud_buckets",
                  "cloud_volumes", "cloud_instance_sgs", "cloud_instances", "cloud_sg_rules",
                  "cloud_security_groups", "cloud_subnets", "cloud_vpcs"):
        op.drop_table(table)
