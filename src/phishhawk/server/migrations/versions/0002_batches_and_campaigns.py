"""batches and campaigns

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.String(length=32), nullable=False),
        sa.Column("last_seen", sa.String(length=32), nullable=False),
        sa.Column("verdicts", sa.JSON(), nullable=False),
        sa.Column("worst_verdict", sa.String(length=32), nullable=False),
        sa.Column("shared", sa.JSON(), nullable=False),
        sa.Column("senders", sa.JSON(), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False),
        sa.Column("rebuilt_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "batches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("offline", sa.Boolean(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=False),
        sa.Column("files_deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "campaign_members",
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("campaign_id", "message_id"),
    )
    with op.batch_alter_table("campaign_members", schema=None) as batch_op:
        batch_op.create_index("ix_campaign_members_message", ["message_id"], unique=False)
    with op.batch_alter_table("analyses", schema=None) as batch_op:
        batch_op.add_column(sa.Column("state_blob", sa.String(length=32), nullable=True))
    with op.batch_alter_table("submissions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("batch_id", sa.Integer(), nullable=True))
        # submissions from M1 were never in a batch
        batch_op.add_column(sa.Column("position", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_index("ix_submissions_batch", ["batch_id", "position"], unique=False)
        batch_op.create_foreign_key("fk_submissions_batch_id", "batches", ["batch_id"], ["id"],
                                    ondelete="SET NULL")
    # The audit chain's head exists from the start, so several workers' first records cannot race to create it.
    op.execute("INSERT INTO audit_head (id, hash, count) SELECT 1, '%s', 0 "
               "WHERE NOT EXISTS (SELECT 1 FROM audit_head)" % ("0" * 64))


def downgrade() -> None:
    with op.batch_alter_table("submissions", schema=None) as batch_op:
        batch_op.drop_constraint("fk_submissions_batch_id", type_="foreignkey")
        batch_op.drop_index("ix_submissions_batch")
        batch_op.drop_column("position")
        batch_op.drop_column("batch_id")
    with op.batch_alter_table("analyses", schema=None) as batch_op:
        batch_op.drop_column("state_blob")
    with op.batch_alter_table("campaign_members", schema=None) as batch_op:
        batch_op.drop_index("ix_campaign_members_message")
    op.drop_table("campaign_members")
    op.drop_table("batches")
    op.drop_table("campaigns")
