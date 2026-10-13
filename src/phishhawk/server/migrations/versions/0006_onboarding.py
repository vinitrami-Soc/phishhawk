"""onboarding: when each person finished or skipped the setup after sign-up

The people an upgraded server already has have nothing to set up: they count as
done now. Everyone made from here on sees the setup once.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("onboarded_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE users SET onboarded_at = CURRENT_TIMESTAMP")


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("onboarded_at")
