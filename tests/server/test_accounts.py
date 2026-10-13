"""Setup, sign-up, invites and profiles (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md,
section 5): getting into PhishHawk without an admin typing anyone's password."""

import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from phishhawk.server import accounts, appsettings, auth, cli
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER, AuditRecord, User, Workspace

from .serverkit import PASSWORD

OWNER = {"username": "olivia", "password": PASSWORD, "first_name": "Olivia", "last_name": "Hart",
         "location": "Pune", "organization": "Example Corp", "job_title": "SOC lead", "signup_open": True}


@pytest.fixture
def fresh(services):
    """The web app of a server no one has an account on yet."""
    from phishhawk.server.app import create_app

    return TestClient(create_app(services=services))


def _code(services):
    with transaction(services.sessions) as s:
        return accounts.setup_code(s, services.box)


def test_the_setup_code_is_made_once_and_only_while_no_one_has_an_account(db, box):
    with transaction(db) as s:
        first = accounts.setup_code(s, box)
    with transaction(db) as s:
        assert accounts.setup_code(s, box) == first and len(first) >= 19
        auth.create_user(s, "root", PASSWORD, "admin")
    with transaction(db) as s:
        assert accounts.setup_code(s, box) is None


def test_setup_needs_the_code_makes_the_owner_and_then_closes(fresh, services):
    assert fresh.get("/api/v1/setup").json() == {"open": True}
    assert fresh.post("/api/v1/setup", json=OWNER | {"code": "WRONG-CODE"}).status_code == 403
    answer = fresh.post("/api/v1/setup", json=OWNER | {"code": _code(services)})
    assert answer.status_code == 201, answer.text
    fresh.headers["X-CSRF-Token"] = answer.json()["csrf"]
    me = fresh.get("/api/v1/session").json()
    assert (me["username"], me["role"], me["owner"]) == ("olivia", "admin", True)
    assert me["workspace"]["name"] == "Example Corp" and me["workspace"]["kind"] == "organization"
    assert fresh.get("/api/v1/setup").json() == {"open": False}
    assert fresh.post("/api/v1/setup", json=OWNER | {"code": "ANY-CODE"}).status_code == 404
    with transaction(services.sessions) as s:
        assert accounts.setup_code(s, services.box) is None
        assert appsettings.get_value(s, SERVER, "signup_open") is True
        assert [w.name for w in s.scalars(select(Workspace))] == ["Example Corp"]  # the default one, renamed
        user = s.scalars(select(User)).one()
        assert (user.first_name, user.last_name, user.location, user.job_title) == ("Olivia", "Hart", "Pune",
                                                                                    "SOC lead")
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "setup")).one()
        assert (record.actor, record.workspace_id, record.details) == ("olivia", SERVER, {"signup_open": True})


def test_wrong_setup_codes_are_throttled(fresh, services):
    for _ in range(3):
        assert fresh.post("/api/v1/setup", json=OWNER | {"code": "WRONG-CODE"}).status_code == 403
    assert fresh.post("/api/v1/setup", json=OWNER | {"code": _code(services)}).status_code == 429


def test_setup_checks_every_field_and_names_the_one_that_is_wrong(fresh, services):
    code = _code(services)
    for field, value, says in (("username", "A", "username"), ("password", "short", "password"),
                               ("first_name", " ", "first_name"), ("last_name", "", "last_name"),
                               ("location", "x" * 81, "location"), ("organization", "", "organization"),
                               ("job_title", "a\x00b", "job_title")):
        answer = fresh.post("/api/v1/setup", json=OWNER | {"code": code, field: value})
        assert answer.status_code == 422 and says in answer.json()["detail"], (field, answer.text)
    assert fresh.get("/api/v1/setup").json() == {"open": True}


def test_the_command_line_prints_the_setup_code_until_setup_is_done(monkeypatch, tmp_path, capsys):
    from phishhawk.server.crypto import new_key

    monkeypatch.setenv("PHISHHAWK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHHAWK_SECRET_KEY", new_key())
    monkeypatch.setenv("PHISHHAWK_ENCRYPTION_KEY", new_key())
    assert cli.main(["migrate"]) == 0 and cli.main(["setup-code"]) == 0
    code = capsys.readouterr().out.strip().splitlines()[-1]
    assert cli.main(["setup-code"]) == 0 and capsys.readouterr().out.strip().splitlines()[-1] == code
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli.main(["create-admin", "root", "--password-stdin"]) == 0
    capsys.readouterr()
    assert cli.main(["setup-code"]) == 1
    assert "set up already" in capsys.readouterr().err


def test_a_server_no_one_has_an_account_on_prints_its_setup_code_at_start(tmp_path):
    import re

    from .serverkit import running_server

    with running_server(tmp_path) as server:  # it makes "root" once the server answers
        log = server.log.read_text("utf-8", "replace")
    assert re.search(r"setup code [A-Z2-7]{4}(-[A-Z2-7]{4}){3} \(it works once\)", log), log
