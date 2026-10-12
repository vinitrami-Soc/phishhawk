"""Fixtures for the web app's tests, all in a temporary directory."""

import pytest

from phishhawk.server.config import ServerSettings
from phishhawk.server.crypto import Box, new_key
from phishhawk.server.db import make_engine, make_sessionmaker, migrate
from phishhawk.server.store import BlobStore

from .serverkit import PASSWORD, fresh_database, login


@pytest.fixture
def settings(tmp_path):
    with fresh_database() as url:  # SQLite in tmp_path, or Postgres (serverkit.TEST_DATABASE)
        yield ServerSettings(data_dir=tmp_path, database_url=url, secret_key=new_key(),
                             encryption_key=new_key(), cookie_secure=False)


@pytest.fixture
def db(settings):
    migrate(settings.db_url)
    return make_sessionmaker(make_engine(settings.db_url))


@pytest.fixture
def box(settings):
    return Box.from_b64(settings.encryption_key.get_secret_value())


@pytest.fixture
def store(settings, box):
    return BlobStore(settings.data_dir / "blobs", box)


@pytest.fixture
def services(settings, db, box, store):
    from phishhawk.server.processing import Services

    return Services(settings, db, box, store)


@pytest.fixture
def app(services):
    from phishhawk.server import auth
    from phishhawk.server.app import create_app
    from phishhawk.server.db import transaction

    with transaction(services.sessions) as s:
        auth.create_user(s, "admin", PASSWORD, "admin")
        auth.create_user(s, "alice", PASSWORD, "analyst")
        auth.create_user(s, "bob", PASSWORD, "analyst")
    return create_app(services=services)


@pytest.fixture
def anon(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def admin(app):
    return login(app, "admin")


@pytest.fixture
def alice(app):
    return login(app, "alice")


@pytest.fixture
def bob(app):
    return login(app, "bob")
