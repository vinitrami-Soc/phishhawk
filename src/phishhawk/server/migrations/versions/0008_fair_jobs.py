"""fair jobs: each job names the workspace whose work it is

Workspaces then take turns at the queue. Jobs queued before this name none and
run as the server's own.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_jobs_workspace_id", "workspaces", ["workspace_id"], ["id"],
                                    ondelete="CASCADE")
        batch_op.create_index("ix_jobs_workspace_id", ["workspace_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.drop_index("ix_jobs_workspace_id")
        batch_op.drop_constraint("fk_jobs_workspace_id", type_="foreignkey")
        batch_op.drop_column("workspace_id")
