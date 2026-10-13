"""workspaces

Every row that belongs to an organization or an individual gets its workspace.
An upgraded server's rows all go to one workspace, "Default organization", and
its first admin becomes the server's owner. Settings move to (workspace, key):
the trait key and the upload limits belong to the whole server (workspace 0),
the rest to the default workspace. Audit records written before keep a NULL
workspace, so their hashes still verify.

Revision ID: 0004
Revises: 0003
"""

import datetime as dt

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

SCOPED = ("users", "messages", "batches", "submissions", "analyses", "campaigns", "mailboxes")
UNIQUE = {"messages": ("sha256", "uq_messages_workspace_sha256"),
          "mailboxes": ("name", "uq_mailboxes_workspace_name")}
SERVER_SETTINGS = ("secret:trait_key", "max_upload_mb", "max_batch_messages")


def _old_unique(table: str, column: str) -> str:
    """The name the unnamed unique constraint of 0001 or 0003 has: Postgres names it; SQLite has no name, and
    batch mode reads it under the naming convention below."""
    if op.get_bind().dialect.name == "postgresql":
        return "%s_%s_key" % (table, column)
    return "uq_%s_%s" % (table, column)


NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    bind = op.get_bind()
    bind.execute(sa.text("INSERT INTO workspaces (name, kind, created_at) VALUES "
                         "('Default organization', 'organization', :now)"),
                 {"now": dt.datetime.now(dt.timezone.utc)})
    default = bind.execute(sa.text("SELECT min(id) FROM workspaces")).scalar()

    for table in SCOPED:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        bind.execute(sa.text("UPDATE %s SET workspace_id = :ws" % table), {"ws": default})
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING) as batch_op:
            batch_op.alter_column("workspace_id", existing_type=sa.Integer(), nullable=False)
            batch_op.create_foreign_key("fk_%s_workspace_id" % table, "workspaces", ["workspace_id"], ["id"],
                                        ondelete="CASCADE")
            if table in UNIQUE:
                column, name = UNIQUE[table]
                batch_op.drop_constraint(_old_unique(table, column), type_="unique")
                batch_op.create_unique_constraint(name, ["workspace_id", column])
            else:
                batch_op.create_index("ix_%s_workspace_id" % table, ["workspace_id"], unique=False)

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owner", sa.Boolean(), nullable=False, server_default=sa.false()))
    bind.execute(sa.text("UPDATE users SET owner = :yes "
                         "WHERE id = (SELECT min(id) FROM users WHERE role = 'admin')"), {"yes": True})

    op.create_table(
        "settings_ws",
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("workspace_id", "key"),
    )
    server = ", ".join("'%s'" % key for key in SERVER_SETTINGS)
    bind.execute(sa.text("INSERT INTO settings_ws (workspace_id, key, value) SELECT CASE WHEN key IN (%s) THEN 0 "
                         "ELSE :ws END, key, value FROM settings" % server), {"ws": default})
    op.drop_table("settings")
    op.rename_table("settings_ws", "settings")

    with op.batch_alter_table("audit_log", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_audit_log_workspace_id", ["workspace_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM workspaces")).scalar_one() > 1:
        raise RuntimeError("this server has more than one workspace: their data cannot go back into one")

    with op.batch_alter_table("audit_log", schema=None) as batch_op:
        batch_op.drop_index("ix_audit_log_workspace_id")
        batch_op.drop_column("workspace_id")

    op.create_table(
        "settings_one",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    bind.execute(sa.text("INSERT INTO settings_one (key, value) SELECT key, value FROM settings"))
    op.drop_table("settings")
    op.rename_table("settings_one", "settings")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("owner")

    for table in reversed(SCOPED):
        with op.batch_alter_table(table, schema=None, naming_convention=NAMING) as batch_op:
            if table in UNIQUE:
                column, name = UNIQUE[table]
                batch_op.drop_constraint(name, type_="unique")
                batch_op.create_unique_constraint(_old_unique(table, column), [column])
            else:
                batch_op.drop_index("ix_%s_workspace_id" % table)
            batch_op.drop_constraint("fk_%s_workspace_id" % table, type_="foreignkey")
            batch_op.drop_column("workspace_id")
    op.drop_table("workspaces")
