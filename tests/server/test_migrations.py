"""The migrations build exactly the tables the models describe."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from phishhawk.server.db import make_engine, migrate
from phishhawk.server.models import Base


def test_the_migrations_match_the_models(settings):
    migrate(settings.db_url)
    with make_engine(settings.db_url).connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
