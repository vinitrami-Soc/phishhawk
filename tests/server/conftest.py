"""Fixtures for the web app's tests, all in a temporary directory."""

import pytest

from phishhawk.server.config import ServerSettings
from phishhawk.server.crypto import Box, new_key


@pytest.fixture
def settings(tmp_path):
    return ServerSettings(data_dir=tmp_path, secret_key=new_key(),
                          encryption_key=new_key(), cookie_secure=False)


@pytest.fixture
def box(settings):
    return Box.from_b64(settings.encryption_key.get_secret_value())
