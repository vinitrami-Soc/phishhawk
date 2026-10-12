"""SQLite runs in WAL mode with foreign keys on, and a transaction commits
everything or nothing."""

import pytest
from sqlalchemy import select, text

from phishhawk.server.db import make_engine, transaction
from phishhawk.server.models import Setting


def test_sqlite_uses_wal_and_enforces_foreign_keys(settings, db):
    with make_engine(settings.db_url).connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_a_transaction_commits_on_success_and_rolls_back_on_error(db):
    with transaction(db) as s:
        s.add(Setting(key="kept", value=1))
    with pytest.raises(RuntimeError), transaction(db) as s:
        s.add(Setting(key="lost", value=2))
        s.flush()
        raise RuntimeError("stop")
    with transaction(db) as s:
        assert [row.key for row in s.scalars(select(Setting))] == ["kept"]
