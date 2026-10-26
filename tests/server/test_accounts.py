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


def test_a_server_no_one_has_an_account_on_says_how_to_get_the_setup_code_but_keeps_it_out_of_its_log(tmp_path):
    # Logs are often shipped elsewhere, and whoever enters the code first owns the server.
    import re

    from .serverkit import running_server

    with running_server(tmp_path) as server:  # it makes "root" once the server answers
        log = server.log.read_text("utf-8", "replace")
    assert "no one has an account yet" in log and "phishhawk server setup-code" in log, log
    assert not re.search(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){3}", log), log


PERSON = {"username": "sam", "password": PASSWORD, "first_name": "Sam", "last_name": "Lee", "location": "Leeds",
          "job_title": "", "organization": ""}


def _open_signup(services, cap=None):
    with transaction(services.sessions) as s:
        appsettings.set_value(s, SERVER, "signup_open", True)
        if cap is not None:
            appsettings.set_value(s, SERVER, "signup_daily_cap", cap)


def _signed_in(client, answer):
    assert answer.status_code == 201, answer.text
    client.headers["X-CSRF-Token"] = answer.json()["csrf"]
    return client.get("/api/v1/session").json()


def test_sign_up_is_closed_until_the_owner_opens_it(anon):
    assert anon.get("/api/v1/signup").json() == {"open": False}
    assert anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}).status_code == 404


def test_an_individual_gets_a_workspace_of_their_own(anon, services, admin):
    _open_signup(services)
    assert anon.get("/api/v1/signup").json() == {"open": True}
    me = _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    assert (me["username"], me["role"], me["owner"]) == ("sam", "admin", False)
    assert (me["workspace"]["name"], me["workspace"]["kind"]) == ("Sam Lee", "individual")
    assert [u["username"] for u in anon.get("/api/v1/users").json()] == ["sam"]
    assert "sam" not in [u["username"] for u in admin.get("/api/v1/users").json()]
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "signup")).one()
        assert (record.actor, record.workspace_id) == ("sam", SERVER)
        assert record.details == {"kind": "individual", "workspace": me["workspace"]["id"]}


def test_an_organization_is_named_after_itself_and_needs_its_name(anon, services):
    _open_signup(services)
    missing = anon.post("/api/v1/signup", json=PERSON | {"kind": "organization"})
    assert missing.status_code == 422 and "organization" in missing.json()["detail"]
    me = _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "organization",
                                                                     "organization": "Acme SOC"}))
    assert (me["workspace"]["name"], me["workspace"]["kind"]) == ("Acme SOC", "organization")


def test_sign_up_names_the_field_that_is_wrong(anon, services):
    _open_signup(services)
    for field, value in (("kind", "team"), ("username", "Sam Lee"), ("password", "short"), ("first_name", ""),
                         ("last_name", " "), ("location", ""), ("job_title", "x" * 81),
                         ("first_name", "Sam‮")):
        answer = anon.post("/api/v1/signup", json=PERSON | {"kind": "individual", field: value})
        assert answer.status_code == 422 and answer.json()["detail"].startswith(field), (field, answer.text)
    taken = anon.post("/api/v1/signup", json=PERSON | {"kind": "individual", "username": "alice"})
    assert taken.status_code == 409 and "taken" in taken.json()["detail"]


def test_three_sign_ups_an_hour_from_one_address(anon, services):
    _open_signup(services)
    for name in ("sam", "kim", "lee"):
        answer = anon.post("/api/v1/signup", json=PERSON | {"kind": "individual", "username": name})
        assert answer.status_code == 201, answer.text
    fourth = anon.post("/api/v1/signup", json=PERSON | {"kind": "individual", "username": "max"})
    assert fourth.status_code == 429 and int(fourth.headers["retry-after"]) > 3000


def test_the_daily_cap_holds_for_the_whole_server(app, services):
    _open_signup(services, cap=2)  # the default organization counts: it was made today
    first = TestClient(app).post("/api/v1/signup", json=PERSON | {"kind": "individual"})
    assert first.status_code == 201
    second = TestClient(app).post("/api/v1/signup", json=PERSON | {"kind": "individual", "username": "kim"})
    assert second.status_code == 429 and "today" in second.json()["detail"]
    assert int(second.headers["retry-after"]) > 0


def _invite(client, role="analyst", note=""):
    made = client.post("/api/v1/invites", json={"role": role, "note": note})
    assert made.status_code == 201, made.text
    return made.json()


def test_an_organization_admin_invites_with_a_link_shown_once(admin, alice):
    made = _invite(admin, note="for Priya, SOC team")
    assert made["link"] == "/join/" + made["token"] and len(made["token"]) >= 40
    pending = admin.get("/api/v1/invites").json()
    assert [(i["id"], i["role"], i["note"], i["created_by_name"]) for i in pending] == [
        (made["id"], "analyst", "for Priya, SOC team", "admin")]
    assert made["token"] not in str(pending)
    assert alice.post("/api/v1/invites", json={"role": "analyst"}).status_code == 403
    assert admin.post("/api/v1/invites", json={"role": "owner"}).status_code == 422


def test_an_individual_works_alone(anon, services):
    _open_signup(services)
    _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    refused = anon.post("/api/v1/invites", json={"role": "analyst"})
    assert refused.status_code == 403 and "individual" in refused.json()["detail"]


def test_an_invite_brings_its_role_into_its_organization_once(app, admin, services):
    made = _invite(admin, role="analyst")
    guest = TestClient(app)
    assert guest.get("/api/v1/join/" + made["token"]).json() == {"organization": "Default organization",
                                                                  "role": "analyst"}
    me = _signed_in(guest, guest.post("/api/v1/join/" + made["token"], json=PERSON | {"username": "priya"}))
    assert (me["username"], me["role"], me["workspace"]["name"]) == ("priya", "analyst", "Default organization")
    assert "priya" in [u["username"] for u in admin.get("/api/v1/users").json()]
    assert admin.get("/api/v1/invites").json() == []
    late = TestClient(app)
    assert late.get("/api/v1/join/" + made["token"]).status_code == 404
    assert late.post("/api/v1/join/" + made["token"], json=PERSON | {"username": "pat"}).status_code == 404
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "join")).one()
        assert (record.actor, record.workspace_id, record.details) == ("priya", me["workspace"]["id"],
                                                                       {"role": "analyst"})


def test_an_invite_over_seven_days_old_or_withdrawn_does_not_open(app, admin, services):
    import datetime as dt

    from phishhawk.server.models import Invite

    old, withdrawn = _invite(admin), _invite(admin)
    with transaction(services.sessions) as s:
        s.get(Invite, old["id"]).expires_at -= dt.timedelta(days=7, seconds=1)
    assert admin.delete("/api/v1/invites/%d" % withdrawn["id"]).status_code == 204
    guest = TestClient(app)
    for made in (old, withdrawn):
        assert guest.get("/api/v1/join/" + made["token"]).status_code == 404
        assert guest.post("/api/v1/join/" + made["token"], json=PERSON).status_code == 404
    assert guest.get("/api/v1/join/not-a-token").status_code == 404
    assert admin.get("/api/v1/invites").json() == []


def test_joining_checks_the_fields_before_the_invite_is_used(app, admin):
    made = _invite(admin)
    guest = TestClient(app)
    bad = guest.post("/api/v1/join/" + made["token"], json=PERSON | {"last_name": ""})
    assert bad.status_code == 422 and bad.json()["detail"].startswith("last_name")
    taken = guest.post("/api/v1/join/" + made["token"], json=PERSON | {"username": "alice"})
    assert taken.status_code == 409
    assert guest.post("/api/v1/join/" + made["token"], json=PERSON).status_code == 201


ALICE = {"first_name": "Alice", "last_name": "Rao", "location": "Delhi", "job_title": "Analyst"}


def test_everyone_edits_their_own_profile(alice):
    me = alice.get("/api/v1/me").json()
    assert (me["username"], me["role"], me["workspace"]["name"]) == ("alice", "analyst", "Default organization")
    assert me["profile"] == {"first_name": "", "last_name": "", "location": "", "job_title": ""}  # upgraded
    changed = alice.patch("/api/v1/me", json=ALICE)
    assert changed.status_code == 200 and changed.json()["profile"] == ALICE
    assert alice.get("/api/v1/session").json()["profile"] == ALICE
    cleared = alice.patch("/api/v1/me", json={"last_name": " "})
    assert cleared.status_code == 422 and cleared.json()["detail"].startswith("last_name")
    assert alice.patch("/api/v1/me", json={"job_title": ""}).json()["profile"]["job_title"] == ""


def test_only_an_organizations_admin_renames_it(alice, admin):
    refused = alice.patch("/api/v1/me", json={"organization": "Renamed"})
    assert refused.status_code == 403
    assert admin.patch("/api/v1/me", json={"organization": "Example Corp"}).json()["workspace"]["name"] == \
        "Example Corp"
    assert alice.get("/api/v1/session").json()["workspace"]["name"] == "Example Corp"


def test_a_new_password_needs_the_current_one_and_ends_the_other_sessions(app, alice, services):
    from .serverkit import login

    elsewhere = login(app, "alice")
    new = "a much longer password"
    wrong = alice.patch("/api/v1/me", json={"password": new, "current_password": "not it"})
    assert wrong.status_code == 403 and "current password" in wrong.json()["detail"]
    short = alice.patch("/api/v1/me", json={"password": "short", "current_password": PASSWORD})
    assert short.status_code == 422 and short.json()["detail"].startswith("password")
    assert alice.patch("/api/v1/me", json={"password": new, "current_password": PASSWORD}).status_code == 200
    assert alice.get("/api/v1/session").status_code == 200
    assert elsewhere.get("/api/v1/session").status_code == 401
    assert TestClient(app).post("/api/v1/session", json={"username": "alice", "password": new}).status_code == 200
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "password_change")).one()
        assert record.actor == "alice" and record.workspace_id != SERVER


def test_the_server_settings_are_the_owners_alone(admin, anon, services):
    daily = {"daily_messages_organization": 500, "daily_messages_individual": 100}
    assert admin.get("/api/v1/server-settings").json() == {"signup_open": False, "signup_daily_cap": 100,
                                                           "max_upload_mb": 25, "max_batch_messages": 500} | daily
    changed = admin.patch("/api/v1/server-settings", json={"signup_open": True, "signup_daily_cap": 5,
                                                          "max_upload_mb": 10})
    assert changed.status_code == 200
    assert changed.json() == {"signup_open": True, "signup_daily_cap": 5, "max_upload_mb": 10,
                              "max_batch_messages": 500} | daily
    assert anon.get("/api/v1/signup").json() == {"open": True}
    assert admin.patch("/api/v1/server-settings", json={"signup_daily_cap": 0}).status_code == 422
    _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    assert anon.get("/api/v1/server-settings").status_code == 403  # an admin, of their own workspace only
    assert anon.patch("/api/v1/server-settings", json={"signup_open": False}).status_code == 403
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "server_settings")).one()
        assert record.workspace_id == SERVER and record.details["changed"] == ["signup_open", "signup_daily_cap",
                                                                             "max_upload_mb"]


# the built-in pages: every form works without JavaScript


def _form(fields):
    return {name: str(value) for name, value in fields.items() if not isinstance(value, bool)}


def test_the_setup_page(fresh, services):
    page = fresh.get("/setup").text
    assert '<label for="code">' in page and 'name="signup_open"' in page and page.count("<h1") == 1
    wrong = fresh.post("/setup", data=_form(OWNER) | {"code": "WRONG-CODE"})
    assert wrong.status_code == 403 and "setup code is not right" in wrong.text and 'value="olivia"' in wrong.text
    done = fresh.post("/setup", data=_form(OWNER) | {"code": _code(services), "signup_open": "true"},
                      follow_redirects=False)
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert "olivia" in fresh.get("/").text
    assert fresh.get("/setup").status_code == 404
    with transaction(services.sessions) as s:
        assert accounts.signup_open(s)


def test_the_login_page_offers_sign_up_only_while_it_is_open(anon, services):
    assert "/signup" not in anon.get("/login").text
    assert anon.get("/signup").status_code == 404
    _open_signup(services)
    assert 'href="/signup"' in anon.get("/login").text


def test_the_sign_up_page(anon, services):
    _open_signup(services)
    page = anon.get("/signup").text
    assert 'value="individual"' in page and 'value="organization"' in page and '<label for="location">' in page
    bad = anon.post("/signup", data=_form(PERSON) | {"kind": "organization"})
    assert bad.status_code == 422 and "organization: required" in bad.text and 'value="Leeds"' in bad.text
    done = anon.post("/signup", data=_form(PERSON) | {"kind": "individual"}, follow_redirects=False)
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert "sam" in anon.get("/").text


def test_invites_on_the_users_page_and_the_join_page(app, admin):
    import re

    csrf = admin.headers.pop("X-CSRF-Token")
    page = admin.post("/invites", data={"csrf_token": csrf, "role": "analyst", "note": "for Priya"}).text
    token = re.search(r"/join/([A-Za-z0-9_-]{40,})", page).group(1)
    listed = admin.get("/users").text
    assert "for Priya" in listed and token not in listed
    guest = TestClient(app)
    invited = guest.get("/join/" + token).text
    assert "Default organization" in invited and "analyst" in invited
    joined = guest.post("/join/" + token, data=_form(PERSON) | {"username": "priya"}, follow_redirects=False)
    assert joined.status_code == 303 and "priya" in guest.get("/").text
    assert TestClient(app).get("/join/" + token).status_code == 404
    second = re.search(r"/join/([A-Za-z0-9_-]{40,})", admin.post(
        "/invites", data={"csrf_token": csrf, "role": "admin"}).text).group(1)
    invite_id = admin.get("/api/v1/invites", headers={"X-CSRF-Token": csrf}).json()[0]["id"]
    assert admin.post("/invites/%d/revoke" % invite_id, data={"csrf_token": csrf},
                      follow_redirects=False).status_code == 303
    assert TestClient(app).get("/join/" + second).status_code == 404


def test_the_profile_page(alice):
    csrf = alice.headers.pop("X-CSRF-Token")
    page = alice.get("/profile").text
    assert '<label for="first_name">' in page and '<label for="current_password">' in page
    assert 'href="/profile"' in page  # from every page's top bar
    saved = alice.post("/profile", data={"csrf_token": csrf, **ALICE}, follow_redirects=False)
    assert saved.status_code == 303 and saved.headers["location"] == "/profile?saved=1"
    assert 'value="Rao"' in alice.get("/profile?saved=1").text
    wrong = alice.post("/profile", data={"csrf_token": csrf, **ALICE, "last_name": "Changed",
                                         "password": "a much longer password", "current_password": "not it"})
    assert wrong.status_code == 403 and "current password is not right" in wrong.text
    assert 'value="Changed"' in wrong.text  # shown again, but not saved: all of it, or none
    assert alice.get("/api/v1/me", headers={"X-CSRF-Token": csrf}).json()["profile"]["last_name"] == "Rao"


def test_an_individual_workspace_has_one_member(anon, services):
    _open_signup(services)
    _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    refused = anon.post("/api/v1/users", json={"username": "friend", "password": PASSWORD, "role": "analyst"})
    assert refused.status_code == 403 and "individual" in refused.json()["detail"]
    assert [u["username"] for u in anon.get("/api/v1/users").json()] == ["sam"]


def test_the_setup_after_sign_up_shows_until_it_is_finished_or_skipped(anon, services):
    _open_signup(services)
    _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    assert anon.get("/api/v1/session").json()["onboarded"] is False
    assert anon.post("/api/v1/me/onboarded").status_code == 204
    assert anon.get("/api/v1/session").json()["onboarded"] is True
    assert anon.post("/api/v1/me/onboarded").status_code == 204  # finished already: nothing changes
    assert anon.get("/api/v1/session").json()["onboarded"] is True


def test_an_account_an_admin_adds_or_the_command_line_makes_has_no_setup_to_go_through(app, admin):
    from .serverkit import login

    assert admin.get("/api/v1/session").json()["onboarded"] is True  # made as the command line makes one
    added = admin.post("/api/v1/users", json={"username": "kim", "password": PASSWORD, "role": "analyst"})
    assert added.status_code == 201, added.text
    assert login(app, "kim").get("/api/v1/session").json()["onboarded"] is True
