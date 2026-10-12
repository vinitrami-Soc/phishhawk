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
                                "VALUES (1, 'ab', 10, NULL, '2026-10-01 00:00:00', '', 0, '', '', 0)"))
        connection.execute(text("INSERT INTO submissions (id, message_id, source, offline, status, error, "
                                "submitted_at) VALUES (1, 1, 'upload', 0, 'done', '', '2026-10-01 00:00:00')"))
    migrate(settings.db_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT batch_id FROM submissions WHERE id = 1")).scalar() is None
        assert connection.execute(text("SELECT count(*) FROM batches")).scalar() == 0
        assert connection.execute(text("SELECT count(*) FROM campaigns")).scalar() == 0
