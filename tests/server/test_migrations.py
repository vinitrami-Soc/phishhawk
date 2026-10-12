"""The migrations build exactly the tables the models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from phishhawk.server.db import make_engine, migrate
from phishhawk.server.models import Base


def test_the_migrations_match_the_models(settings):
    migrate(settings.db_url)
    with make_engine(settings.db_url).connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


def test_an_m1_database_moves_to_m2_with_its_data(settings):
    from alembic import command
    from sqlalchemy import text

    from phishhawk.server.db import alembic_config

    command.upgrade(alembic_config(settings.db_url), "0001")
    engine = make_engine(settings.db_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO messages (id, sha256, size, raw_blob, first_seen_at, "
                                "deletion_reason, hold, sender, sender_domain, recipient_count) "
                                "VALUES (1, 'ab', 10, NULL, '2026-10-01 00:00:00', '', false, '', '', 0)"))
        connection.execute(text("INSERT INTO submissions (id, message_id, source, offline, status, error, "
                                "submitted_at) VALUES (1, 1, 'upload', false, 'done', '', '2026-10-01 00:00:00')"))
    migrate(settings.db_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT batch_id FROM submissions WHERE id = 1")).scalar() is None
        assert connection.execute(text("SELECT count(*) FROM batches")).scalar() == 0
        assert connection.execute(text("SELECT count(*) FROM campaigns")).scalar() == 0


def test_the_audit_chain_starts_with_the_schema(settings):
    """Two workers' first audit records must not race to create the chain's head (Postgres, several workers)."""
    from sqlalchemy import text

    migrate(settings.db_url)
    with make_engine(settings.db_url).connect() as connection:
        assert connection.execute(text("SELECT id, count FROM audit_head")).all() == [(1, 0)]


def test_an_m2_database_moves_to_m3_with_its_data(settings):
    from alembic import command
    from sqlalchemy import text

    from phishhawk.server.db import alembic_config

    command.upgrade(alembic_config(settings.db_url), "0002")
    engine = make_engine(settings.db_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO messages (id, sha256, size, raw_blob, first_seen_at, "
                                "deletion_reason, hold, sender, sender_domain, recipient_count) "
                                "VALUES (1, 'ab', 10, NULL, '2026-10-01 00:00:00', '', false, '', '', 0)"))
        connection.execute(text("INSERT INTO submissions (id, message_id, source, offline, status, error, "
                                "submitted_at, position) "
                                "VALUES (1, 1, 'batch', false, 'done', '', '2026-10-01 00:00:00', 1)"))
    migrate(settings.db_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT mailbox_id, source FROM submissions WHERE id = 1")).one() == (
            None, "batch")
        assert connection.execute(text("SELECT count(*) FROM mailboxes")).scalar() == 0
        assert connection.execute(text("SELECT count(*) FROM mailbox_items")).scalar() == 0


def test_the_migrations_go_down_and_up_again(settings):
    from alembic import command

    from phishhawk.server.db import alembic_config

    migrate(settings.db_url)
    command.downgrade(alembic_config(settings.db_url), "0002")
    migrate(settings.db_url)
    with make_engine(settings.db_url).connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
