"""email: an address on each account, confirmed by a link, and links to reset a password

Users gain an email address (empty for the users an upgraded server already has), when it was confirmed, and
when a reset link was last asked for. A link sent by email keeps only its token's SHA-256.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("email", sa.String(length=254), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("reset_requested_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index("ix_users_email", ["email"], unique=False)
    op.create_table(
        "email_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    with op.batch_alter_table("email_tokens", schema=None) as batch_op:
        batch_op.create_index("ix_email_tokens_user_id", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("email_tokens")
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_index("ix_users_email")
        batch_op.drop_column("reset_requested_at")
        batch_op.drop_column("email_verified_at")
        batch_op.drop_column("email")
