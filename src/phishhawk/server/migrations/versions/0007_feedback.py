"""feedback: notes to the server's owner, and each person's word on a verdict

feedback holds a bug, an idea or a question, with the page it was sent from;
verdict_feedback holds one answer per person per analysis (right, missed or
false_alarm) and an optional note. Both go with their workspace and with the
account that wrote them.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("page", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("feedback", schema=None) as batch_op:
        batch_op.create_index("ix_feedback_workspace_id", ["workspace_id"], unique=False)
        batch_op.create_index("ix_feedback_user_id", ["user_id"], unique=False)
    op.create_table(
        "verdict_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("opinion", sa.String(length=16), nullable=False),
        sa.Column("note", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id", "user_id", name="uq_verdict_feedback_analysis_user"),
    )
    with op.batch_alter_table("verdict_feedback", schema=None) as batch_op:
        batch_op.create_index("ix_verdict_feedback_workspace_id", ["workspace_id"], unique=False)
        batch_op.create_index("ix_verdict_feedback_user_id", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("verdict_feedback")
    op.drop_table("feedback")
