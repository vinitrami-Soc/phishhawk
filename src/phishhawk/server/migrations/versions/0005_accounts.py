"""accounts: profiles and invites

Users gain a profile (first and last name, location, job title), empty for the
users an upgraded server already has. An organization's admin can invite
people with a one-use link; only the token's SHA-256 is kept.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

PROFILE = ("first_name", "last_name", "location", "job_title")


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        for name in PROFILE:
            batch_op.add_column(sa.Column(name, sa.String(length=80), nullable=False, server_default=""))
    op.create_table(
        "invites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("note", sa.String(length=120), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["used_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    with op.batch_alter_table("invites", schema=None) as batch_op:
        batch_op.create_index("ix_invites_workspace_id", ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_table("invites")
    with op.batch_alter_table("users", schema=None) as batch_op:
        for name in PROFILE:
            batch_op.drop_column(name)
