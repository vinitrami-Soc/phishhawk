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


def _m3_with_data(settings):
    """A database at 0003 (M3) with two admins and an analyst, a message analysed, a mailbox, settings and two
    audit records chained the way M3 chained them."""
    import datetime as dt

    from alembic import command
    from sqlalchemy import text

    from phishhawk.server import audit
    from phishhawk.server.db import alembic_config
    from phishhawk.server.models import AuditRecord

    command.upgrade(alembic_config(settings.db_url), "0003")
    engine = make_engine(settings.db_url)
    at = "2026-10-01 00:00:00"
    with engine.begin() as c:
        c.execute(text("INSERT INTO users (id, username, password_hash, role, disabled, created_at) VALUES "
                       f"(1, 'root', 'x', 'admin', false, '{at}'), (2, 'ana', 'x', 'analyst', false, '{at}'), "
                       f"(3, 'second', 'x', 'admin', false, '{at}')"))
        c.execute(text("INSERT INTO messages (id, sha256, size, raw_blob, first_seen_at, deletion_reason, hold, "
                       f"sender, sender_domain, recipient_count) VALUES (1, 'ab', 10, NULL, '{at}', '', false, "
                       "'', '', 0)"))
        c.execute(text("INSERT INTO batches (id, user_id, offline, total, status, error, files, created_at) "
                       f"VALUES (1, 1, false, 1, 'done', '', '[]', '{at}')"))
        c.execute(text("INSERT INTO submissions (id, message_id, user_id, batch_id, position, source, offline, "
                       f"status, error, submitted_at) VALUES (1, 1, 2, 1, 1, 'batch', false, 'done', '', '{at}')"))
        c.execute(text("INSERT INTO analyses (id, message_id, submission_id, engine_version, report_id, verdict, "
                       "score, providers, lookups, techniques, traits, files, created_at) VALUES (1, 1, 1, '2.2', "
                       f"'PH-1', 'SUSPICIOUS', 4, '[]', '[]', '[]', '{{}}', '[]', '{at}')"))
        c.execute(text("INSERT INTO campaigns (id, size, first_seen, last_seen, verdicts, worst_verdict, shared, "
                       f"senders, recipient_count, rebuilt_at) VALUES (1, 1, '', '', '{{}}', 'SUSPICIOUS', '[]', "
                       f"'[]', 0, '{at}')"))
        c.execute(text("INSERT INTO mailboxes (id, name, kind, enabled, interval_minutes, config, cursor, status, "
                       f"error, failures, last_counts, created_at) VALUES (1, 'reports', 'imap', true, 5, '{{}}', "
                       f"'{{}}', 'never', '', 0, '{{}}', '{at}')"))
        c.execute(text("INSERT INTO settings (key, value) VALUES ('providers', '[\"rdap\"]'), "
                       "('secret:trait_key', '\"sealed\"'), ('max_upload_mb', '30'), "
                       "('max_batch_messages', '50'), ('retention_days', '14')"))
        prev = audit.GENESIS
        for number, action in enumerate(("login", "submit"), start=1):
            record = AuditRecord(at=dt.datetime(2026, 10, 1), actor="root", action=action, object_type="",
                                 object_id="", details={})
            digest = audit._digest(prev, record)
            c.execute(text("INSERT INTO audit_log (id, at, actor, action, object_type, object_id, details, "
                           f"prev_hash, hash) VALUES ({number}, '{at}', 'root', '{action}', '', '', '{{}}', "
                           f"'{prev}', '{digest}')"))
            prev = digest
        c.execute(text(f"UPDATE audit_head SET hash = '{prev}', count = 2 WHERE id = 1"))
    return engine


def test_an_m3_database_moves_to_workspaces_with_its_data(settings):
    """Every row goes to "Default organization", the first admin owns the server, server-wide settings move to
    workspace 0, and the audit chain written before still verifies."""
    from sqlalchemy import text

    from phishhawk.server import audit
    from phishhawk.server.db import make_sessionmaker

    engine = _m3_with_data(settings)
    migrate(settings.db_url)
    with engine.connect() as c:
        assert c.execute(text("SELECT id, name, kind FROM workspaces")).all() == [
            (1, "Default organization", "organization")]
        for table in ("users", "messages", "batches", "submissions", "analyses", "campaigns", "mailboxes"):
            assert c.execute(text(f"SELECT DISTINCT workspace_id FROM {table}")).scalars().all() == [1], table
        assert dict(c.execute(text("SELECT id, owner FROM users")).all()) == {1: True, 2: False, 3: False}
        assert sorted(c.execute(text("SELECT workspace_id, key FROM settings")).all()) == [
            (0, "max_batch_messages"), (0, "max_upload_mb"), (0, "secret:trait_key"), (1, "providers"),
            (1, "retention_days")]
        assert c.execute(text("SELECT DISTINCT workspace_id FROM audit_log")).scalars().all() == [None]
    with make_sessionmaker(engine)() as db:
        assert audit.verify(db) == []


def test_a_message_is_unique_within_its_workspace_only(settings):
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    engine = _m3_with_data(settings)
    migrate(settings.db_url)
    with engine.begin() as c:
        c.execute(text("INSERT INTO workspaces (id, name, kind, created_at) VALUES "
                       "(2, 'Someone', 'individual', '2026-10-02 00:00:00')"))
        c.execute(text("INSERT INTO messages (id, workspace_id, sha256, size, first_seen_at, deletion_reason, "
                       "hold, sender, sender_domain, recipient_count) "
                       "VALUES (2, 2, 'ab', 10, '2026-10-02 00:00:00', '', false, '', '', 0)"))
    with pytest.raises(IntegrityError), engine.begin() as c:
        c.execute(text("INSERT INTO messages (id, workspace_id, sha256, size, first_seen_at, deletion_reason, "
                       "hold, sender, sender_domain, recipient_count) "
                       "VALUES (3, 2, 'ab', 10, '2026-10-02 00:00:00', '', false, '', '', 0)"))


def test_going_back_below_workspaces_needs_a_single_workspace(settings):
    import pytest
    from alembic import command
    from sqlalchemy import text

    from phishhawk.server.db import alembic_config

    engine = _m3_with_data(settings)
    migrate(settings.db_url)
    with engine.begin() as c:
        c.execute(text("INSERT INTO workspaces (id, name, kind, created_at) VALUES "
                       "(2, 'Someone', 'individual', '2026-10-02 00:00:00')"))
    with pytest.raises(Exception, match="more than one workspace"):
        command.downgrade(alembic_config(settings.db_url), "0003")
    with engine.begin() as c:
        c.execute(text("DELETE FROM workspaces WHERE id = 2"))
    command.downgrade(alembic_config(settings.db_url), "0003")
    with engine.connect() as c:
        assert c.execute(text("SELECT key FROM settings ORDER BY key")).scalars().all() == [
            "max_batch_messages", "max_upload_mb", "providers", "retention_days", "secret:trait_key"]
        assert c.execute(text("SELECT count(*) FROM messages")).scalar() == 1
