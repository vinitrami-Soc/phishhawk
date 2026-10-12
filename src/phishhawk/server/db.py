"""Engine, sessions and migrations. SQLite runs every transaction as BEGIN
IMMEDIATE, so the web and worker processes never interleave writes (the
audit chain depends on it); Postgres locks the audit head row instead."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str) -> Engine:
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _sqlite_connect(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None  # let us issue BEGIN ourselves
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _sqlite_begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session, session.begin():
        yield session


def alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("phishhawk.server") / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def migrate(url: str) -> None:
    """Bring the database to the newest schema."""
    command.upgrade(alembic_config(url), "head")
