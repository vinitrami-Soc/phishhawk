"""An email address on each account, confirmed by a link, and a forgotten password reset by email (docs/SERVER.md,
"Email and password reset"). Mail goes out through the worker; the tests catch it instead of sending it."""

import datetime as dt
import re

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, update

from phishhawk.server import jobs, mailer, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditRecord, EmailToken, User

from .serverkit import PASSWORD, login
from .test_accounts import PERSON, _open_signup, _signed_in

SITE = "https://phishhawk.example.org"
LINK_RE = re.compile(re.escape(SITE) + r"/app/(reset|verify-email)/([A-Za-z0-9_-]{40,})")


@pytest.fixture
def mail(services, monkeypatch):
    """This server sends mail; what it would send is kept here, one (to, subject, body) each."""
    services.settings.public_url = SITE
    services.settings.smtp_host = "smtp.example.org"
    services.settings.smtp_from = "PhishHawk <no-reply@example.org>"
    sent = []
    monkeypatch.setattr(mailer, "send", lambda settings, to, subject, body: sent.append((to, subject, body)))
    return sent


def _deliver(services):
    while worker.run_one(services):
        pass


def _link(sent, kind):
    found = [m for _, _, body in sent for m in LINK_RE.findall(body) if m[0] == kind]
    assert found, sent
    return found[-1][1]


def _verified(services, username, email):
    with transaction(services.sessions) as s:
        s.execute(update(User).where(User.username == username)
                  .values(email=email, email_verified_at=dt.datetime.now(dt.timezone.utc)))


def test_the_mailer_sends_plain_text_over_starttls_and_signs_in(settings, monkeypatch):
    seen = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            seen.update(host=host, port=port, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            seen["starttls"] = context is not None

        def login(self, user, password):
            seen["login"] = (user, password)

        def send_message(self, message):
            seen["message"] = message

    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host, settings.smtp_port, settings.smtp_username = "smtp-relay.example.org", 587, "apikey"
    settings.smtp_password = SecretStr("smtp-key")
    settings.smtp_from = "PhishHawk <no-reply@example.org>"
    mailer.send(settings, "sam@example.org", "Reset your PhishHawk password", "Open https://x.example/a")
    message = seen["message"]
    assert (seen["host"], seen["port"], seen["starttls"], seen["login"]) == (
        "smtp-relay.example.org", 587, True, ("apikey", "smtp-key"))
    assert (message["To"], message["From"], message["Subject"]) == (
        "sam@example.org", "PhishHawk <no-reply@example.org>", "Reset your PhishHawk password")
    assert message["Auto-Submitted"] == "auto-generated" and message.get_content_type() == "text/plain"
    assert "https://x.example/a" in message.get_content()


def test_a_mistyped_smtp_security_stops_the_server_instead_of_sending_in_clear(settings):
    from pydantic import ValidationError

    from phishhawk.server.config import ServerSettings

    with pytest.raises(ValidationError, match="smtp_security"):
        ServerSettings(**settings.model_dump() | {"smtp_security": "tls"})


def test_without_mail_there_is_no_reset_and_no_email_is_needed(anon, services):
    assert anon.get("/api/v1/password-reset").json() == {"available": False}
    assert anon.post("/api/v1/password-reset", json={"login": "alice"}).status_code == 404
    _open_signup(services)
    assert anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}).status_code == 201


def test_an_email_is_confirmed_by_its_link_before_a_reset_can_use_it(alice, mail, services):
    assert alice.patch("/api/v1/me", json={"email": "alice@corp.example"}).status_code == 403  # password first
    changed = alice.patch("/api/v1/me", json={"email": " Alice@Corp.Example ", "current_password": PASSWORD})
    assert changed.status_code == 200, changed.text
    assert (changed.json()["email"], changed.json()["email_verified"]) == ("alice@corp.example", False)
    _deliver(services)
    confirm = ("alice@corp.example", "Confirm your email for PhishHawk")
    assert [(to, subject) for to, subject, _ in mail] == [confirm]

    assert TestClient(alice.app).post("/api/v1/password-reset", json={"login": "alice"}).status_code == 202
    _deliver(services)
    assert len(mail) == 1  # not confirmed yet: no reset link goes to it

    token = _link(mail, "verify-email")
    assert alice.post("/api/v1/verify-email/" + token).status_code == 204
    assert alice.get("/api/v1/session").json()["email_verified"] is True
    assert alice.post("/api/v1/verify-email/" + token).status_code == 404  # once
    for bad in ("not an address", "a@b", "x" * 250 + "@example.org", "a‮@example.org"):
        refused = alice.patch("/api/v1/me", json={"email": bad, "current_password": PASSWORD})
        assert refused.status_code == 422 and refused.json()["detail"].startswith("email: "), bad


def test_a_reset_link_sets_a_new_password_once_and_signs_out_everywhere(app, alice, mail, services):
    _verified(services, "alice", "alice@corp.example")
    stranger = TestClient(app)
    asked = stranger.post("/api/v1/password-reset", json={"login": "alice"}, headers={"Host": "evil.example"})
    assert asked.status_code == 202
    _deliver(services)
    (to, subject, body), = mail
    assert (to, subject) == ("alice@corp.example", "Reset your PhishHawk password")
    assert "evil.example" not in body and "alice" in body  # the link is this server's, whatever the request said
    token = _link(mail, "reset")
    assert stranger.get("/api/v1/password-reset/" + token).json() == {"username": "alice"}
    assert stranger.post("/api/v1/password-reset/" + token, json={"password": "short"}).status_code == 422
    done = stranger.post("/api/v1/password-reset/" + token, json={"password": "a brand new long password"})
    assert done.status_code == 204, done.text
    assert alice.get("/api/v1/session").status_code == 401  # every session of the account ended
    assert stranger.post("/api/v1/session", json={"username": "alice", "password": PASSWORD}).status_code == 401
    assert login(app, "alice", "a brand new long password").get("/api/v1/session").status_code == 200
    assert stranger.post("/api/v1/password-reset/" + token, json={"password": "another long password"}
                         ).status_code == 404  # once
    assert stranger.get("/api/v1/password-reset/" + token).status_code == 404
    with transaction(services.sessions) as s:
        records = s.execute(select(AuditRecord.actor, AuditRecord.action).where(AuditRecord.object_type == "user",
                                                                               AuditRecord.action.like("password%"))
                            ).all()
    assert sorted(records) == [("alice", "password_reset"), ("anonymous", "password_reset_request")]


def test_a_reset_by_email_reaches_each_account_with_that_confirmed_address(app, mail, services):
    _verified(services, "alice", "team@corp.example")
    _verified(services, "bob", "team@corp.example")
    assert TestClient(app).post("/api/v1/password-reset", json={"login": "TEAM@corp.example"}).status_code == 202
    _deliver(services)
    assert sorted(to for to, _, _ in mail) == ["team@corp.example"] * 2
    assert sorted(re.search(r"account (\w+)", body).group(1) for _, _, body in mail) == ["alice", "bob"]


def test_a_reset_request_says_nothing_about_who_has_an_account(app, mail, services):
    _verified(services, "alice", "alice@corp.example")
    client = TestClient(app)
    answers = [client.post("/api/v1/password-reset", json={"login": login_}) for login_ in
               ("alice", "nobody-here", "nobody@corp.example", "")]
    assert {a.status_code for a in answers} == {202} and len({a.text for a in answers}) == 1
    _deliver(services)
    assert len(mail) == 1


def test_reset_requests_are_limited_per_address_and_per_account(app, mail, services):
    _verified(services, "alice", "alice@corp.example")
    client = TestClient(app)
    statuses = [client.post("/api/v1/password-reset", json={"login": "alice"}).status_code for _ in range(6)]
    assert statuses == [202] * 5 + [429]
    _deliver(services)
    assert len(mail) == 1  # one link at a time: a new one only after a few minutes


def test_an_account_gets_at_most_five_links_an_hour_of_each_kind(alice, mail, services):
    """Saving the same address again sends its link again, but no one can make the server mail a stranger
    without end; nor can requests from many addresses."""
    for _ in range(7):
        again = alice.patch("/api/v1/me", json={"email": "someone@else.example", "current_password": PASSWORD})
        assert again.status_code == 200, again.text
    _deliver(services)
    assert len(mail) == 5
    _verified(services, "alice", "alice@corp.example")
    with transaction(services.sessions) as s:
        me = s.scalars(select(User).where(User.username == "alice")).one()
        for _ in range(7):
            jobs.enqueue(s, "email_reset", {"user_id": me.id}, me.workspace_id)
    _deliver(services)
    assert sum(subject.startswith("Reset") for _, subject, _ in mail) == 5


def test_a_reset_link_lasts_an_hour_and_a_disabled_account_gets_none(app, admin, mail, services):
    _verified(services, "alice", "alice@corp.example")
    _verified(services, "bob", "bob@corp.example")
    client = TestClient(app)
    client.post("/api/v1/password-reset", json={"login": "alice"})
    _deliver(services)
    token = _link(mail, "reset")
    with transaction(services.sessions) as s:
        s.execute(update(EmailToken).values(expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)))
    assert client.get("/api/v1/password-reset/" + token).status_code == 404
    bob = next(u for u in admin.get("/api/v1/users").json() if u["username"] == "bob")
    admin.patch("/api/v1/users/%d" % bob["id"], json={"disabled": True})
    client.post("/api/v1/password-reset", json={"login": "bob"})
    _deliver(services)
    assert len(mail) == 1


def test_sign_up_and_joining_need_an_email_when_the_server_sends_mail(app, anon, admin, mail, services):
    _open_signup(services)
    missing = anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"})
    assert missing.status_code == 422 and missing.json()["detail"].startswith("email: ")
    me = _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual",
                                                                       "email": "sam@example.org"}))
    assert (me["email"], me["email_verified"]) == ("sam@example.org", False)
    made = admin.post("/api/v1/invites", json={"role": "analyst"}).json()
    guest = TestClient(app)
    joiner = PERSON | {"username": "priya"}
    assert guest.post("/api/v1/join/" + made["token"], json=joiner).status_code == 422
    assert guest.post("/api/v1/join/" + made["token"], json=joiner | {"email": "priya@corp.example"}
                      ).status_code == 201
    _deliver(services)
    assert sorted(to for to, _, _ in mail) == ["priya@corp.example", "sam@example.org"]
    assert anon.get("/api/v1/password-reset").json() == {"available": True}
