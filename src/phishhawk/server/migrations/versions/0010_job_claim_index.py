"""job claim index: when each workspace was last served, from an index

A claim asks, for every waiting job, when its workspace last had a job started. Finished jobs stay in the
table, so without an index on (workspace_id, started_at) each claim read the workspace's whole history once per
waiting job: 17 s a claim after a year of a mailbox polled every 5 minutes. The index replaces the one on
workspace_id alone, which it covers.

Revision ID: 0010
Revises: 0009
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.create_index("ix_jobs_workspace_started", ["workspace_id", "started_at"], unique=False)
        batch_op.drop_index("ix_jobs_workspace_id")


def downgrade() -> None:
    with op.batch_alter_table("jobs", schema=None) as batch_op:
        batch_op.create_index("ix_jobs_workspace_id", ["workspace_id"], unique=False)
        batch_op.drop_index("ix_jobs_workspace_started")
