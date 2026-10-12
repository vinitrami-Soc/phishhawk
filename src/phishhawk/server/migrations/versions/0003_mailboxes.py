"""mailboxes

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mailboxes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=48), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("cursor", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_counts", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "mailbox_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("mailbox_id", sa.Integer(), nullable=False),
        sa.Column("remote_id", sa.String(length=255), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=True),
        sa.Column("message_id_hmac", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["mailbox_id"], ["mailboxes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mailbox_id", "remote_id", name="uq_mailbox_items_remote"),
    )
    with op.batch_alter_table("mailbox_items", schema=None) as batch_op:
        batch_op.create_index("ix_mailbox_items_message_id_hmac", ["message_id_hmac"], unique=False)
    with op.batch_alter_table("submissions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("mailbox_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_submissions_mailbox_id", "mailboxes", ["mailbox_id"], ["id"],
                                    ondelete="SET NULL")


def downgrade() -> None:
    with op.batch_alter_table("submissions", schema=None) as batch_op:
        batch_op.drop_constraint("fk_submissions_mailbox_id", type_="foreignkey")
        batch_op.drop_column("mailbox_id")
    with op.batch_alter_table("mailbox_items", schema=None) as batch_op:
        batch_op.drop_index("ix_mailbox_items_message_id_hmac")
    op.drop_table("mailbox_items")
    op.drop_table("mailboxes")
