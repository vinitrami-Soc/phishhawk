"""phishhawk server: migrate, create-admin, audit verify and rotate-key, run
in-process against a temporary data directory."""

import io

import pytest
from sqlalchemy import select, update

from phishhawk import cli as main_cli
from phishhawk.server import appsettings, cli
from phishhawk.server.crypto import Box, new_key
from phishhawk.server.db import make_engine, make_sessionmaker, transaction
from phishhawk.server.models import AuditRecord, User

from .serverkit import PASSWORD

KEY = new_key()


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHHAWK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", new_key())
    monkeypatch.setenv("PHISHHAWK_ENCRYPTION_KEY", KEY)
    monkeypatch.delenv("PHISHHAWK_NEW_ENCRYPTION_KEY", raising=False)
    return make_sessionmaker(make_engine("sqlite:///%s" % (tmp_path / "phishhawk.sqlite3")))


def test_migrate_then_create_the_first_admin(env, monkeypatch, capsys):
    assert cli.main(["migrate"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "root", "--password-stdin"]) == 0
    with transaction(env) as s:
        assert s.scalars(select(User)).one().role == "admin"
        entry = s.scalars(select(AuditRecord)).one()
        assert (entry.actor, entry.action, entry.details) == ("cli", "user_create", {"username": "root",
                                                                                   "role": "admin"})
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "root", "--password-stdin"]) == 3
    assert "that username is taken" in capsys.readouterr().err


def test_missing_settings_are_named_and_never_echoed(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PHISHHAWK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHHAWK_RETENTION_DAYS", "not-a-number-s3cret")
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert cli.main(["migrate"]) == 3
    err = capsys.readouterr().err
    for name in ("PHISHHAWK_SECRET_KEY", "PHISHHAWK_ENCRYPTION_KEY", "PHISHHAWK_RETENTION_DAYS"):
        assert name in err
    assert "s3cret" not in err


def test_audit_verify_exits_1_after_tampering(env, monkeypatch, capsys):
    cli.main(["migrate"])
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    cli.main(["create-admin", "root", "--password-stdin"])
    assert cli.main(["audit", "verify"]) == 0
    assert "audit log verified: 1 record" in capsys.readouterr().out
    with transaction(env) as s:
        s.execute(update(AuditRecord).values(actor="someone-else"))
    assert cli.main(["audit", "verify"]) == 1
    assert "record 1 was changed" in capsys.readouterr().out


def test_rotate_key_needs_the_new_key_and_moves_secrets(env, monkeypatch, capsys):
    cli.main(["migrate"])
    with transaction(env) as s:
        appsettings.set_secret(s, Box.from_b64(KEY), "key:urlscan", "us-key-9876")
    assert cli.main(["rotate-key"]) == 3
    assert "PHISHHAWK_NEW_ENCRYPTION_KEY" in capsys.readouterr().err
    new = new_key()
    monkeypatch.setenv("PHISHHAWK_NEW_ENCRYPTION_KEY", new)
    assert cli.main(["rotate-key"]) == 0
    assert "0 blobs and 1 secret" in capsys.readouterr().out
    with transaction(env) as s:
        assert appsettings.get_secret(s, Box.from_b64(new), "key:urlscan") == "us-key-9876"


def test_the_main_cli_hands_server_commands_over(env, capsys):
    assert main_cli.main(["server", "migrate"]) == 0
    assert "database is up to date" in capsys.readouterr().out
    assert "server" in main_cli.COMMANDS


def test_help_server_lists_every_action(capsys):
    with pytest.raises(SystemExit) as done:
        main_cli.main(["help", "server"])
    assert done.value.code == 0
    out = capsys.readouterr().out
    for action in ("run", "worker", "migrate", "create-admin", "rotate-key", "audit"):
        assert action in out
