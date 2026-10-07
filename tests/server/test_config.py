"""Settings come from PHISHHAWK_* variables and Docker secret files; the
keys have no defaults."""

import pytest
from pydantic import ValidationError

from phishhawk.server import config
from phishhawk.server.crypto import new_key


@pytest.fixture
def secrets_dir(monkeypatch, tmp_path):
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY", "PHISHHAWK_RETENTION_DAYS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config, "SECRETS_DIR", str(tmp_path))
    return tmp_path


def test_settings_come_from_the_environment_with_defaults_for_the_rest(secrets_dir, monkeypatch):
    key = new_key()
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", "s" * 32)
    monkeypatch.setenv("PHISHHAWK_ENCRYPTION_KEY", key)
    monkeypatch.setenv("PHISHHAWK_RETENTION_DAYS", "7")
    settings = config.load_settings()
    assert settings.encryption_key.get_secret_value() == key and settings.retention_days == 7
    assert settings.max_upload_mb == 25 and settings.host == "127.0.0.1" and settings.cookie_secure
    assert settings.db_url == "sqlite:///%s" % (settings.data_dir / "phishhawk.sqlite3")
    assert key not in repr(settings)


def test_docker_secret_files_are_read_and_a_variable_wins_over_a_file(secrets_dir, monkeypatch):
    key = new_key()
    (secrets_dir / "phishhawk_secret_key").write_text("from-the-file\n")
    (secrets_dir / "phishhawk_encryption_key").write_text(key + "\n")
    assert config.load_settings().encryption_key.get_secret_value() == key
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", "from-the-variable")
    assert config.load_settings().secret_key.get_secret_value() == "from-the-variable"


def test_the_keys_have_no_defaults(secrets_dir):
    with pytest.raises(ValidationError) as caught:
        config.load_settings()
    assert {error["loc"][0] for error in caught.value.errors()} == {"secret_key", "encryption_key"}
