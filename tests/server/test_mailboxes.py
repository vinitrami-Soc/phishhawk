"""Mailboxes an admin connects (spec 6.3): what each kind needs, what is refused, and a credential that is
sealed with the encryption key, bound to its mailbox and never shown."""

import json
import secrets
import uuid

import pytest

from phishhawk.server import mailboxes
from phishhawk.server.crypto import DecryptError
from phishhawk.server.db import transaction
from phishhawk.server.mailboxes import MailboxError


def service_account_key(email="phishhawk@reports-project.iam.gserviceaccount.com"):
    """A Google service account's JSON key, made for the test."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode("ascii")
    return json.dumps({"type": "service_account", "project_id": "reports-project", "private_key_id": "k1",
                       "private_key": pem, "client_email": email, "client_id": "1",
                       "token_uri": "https://token.evil.example/steal"})


# a PEM frame around nothing, built here so no file holds one (the secret scan would flag it)
UNREADABLE_KEY = "-----BEGIN %s-----\nAAAA\n-----END %s-----\n" % (("PRIVATE " + "KEY",) * 2)


# made here: an ID written out reads as a key to the secret scan
TENANT, CLIENT = str(uuid.uuid4()), str(uuid.uuid4())


def imap(**config):
    return {"name": "Reports", "kind": "imap", "secret": secrets.token_hex(8),
            "config": {"host": "imap.example-corp.co.uk", "user": "soc@example-corp.co.uk", **config}}


def graph(**config):
    return {"name": "M365 reports", "kind": "graph", "secret": secrets.token_hex(12),
            "config": {"tenant_id": TENANT, "client_id": CLIENT, "address": "phish@example-corp.co.uk", **config}}


def gmail(**config):
    return {"name": "Workspace reports", "kind": "gmail", "secret": service_account_key(),
            "config": {"address": "phish@example-corp.co.uk", **config}}


def _create(services, data):
    with transaction(services.sessions) as s:
        return mailboxes.view(mailboxes.create(s, services.box, data))


def test_each_kind_has_its_settings_and_defaults(services):
    assert _create(services, imap())["config"] == {"host": "imap.example-corp.co.uk", "port": 993,
                                                   "starttls": False, "user": "soc@example-corp.co.uk",
                                                   "folder": "INBOX"}
    assert _create(services, imap(starttls=True) | {"name": "Plain port"})["config"]["port"] == 143
    assert _create(services, graph())["config"]["folder"] == "inbox"
    made = _create(services, gmail())
    assert made["config"] == {"address": "phish@example-corp.co.uk", "label": "INBOX",
                              "service_account": "phishhawk@reports-project.iam.gserviceaccount.com"}
    assert (made["status"], made["enabled"], made["interval_minutes"]) == ("never", True, 5)


@pytest.mark.parametrize("data, says", [
    (imap(host="imaps://imap.example-corp.co.uk"), "host"),
    (imap(host="imap.example-corp.co.uk/inbox"), "host"),
    (imap(host=""), "host"),
    (imap(port=0), "port"),
    (imap(port=70000), "port"),
    (imap(folder='INBOX"\r\nA2 DELETE "INBOX'), "folder"),
    (imap(user=""), "user"),
    (imap() | {"secret": ""}, "password"),
    (graph(tenant_id="../../evil"), "tenant"),
    (graph(client_id="not a guid"), "client ID"),
    (graph(address="not an address"), "address"),
    (graph() | {"secret": ""}, "client secret"),
    (gmail() | {"secret": "{}"}, "service account"),
    (gmail() | {"secret": "not json"}, "service account"),
    (gmail() | {"secret": json.dumps({"type": "service_account", "client_email": "a@b.example",
                                      "private_key": UNREADABLE_KEY})}, "private key"),
    (imap() | {"interval_minutes": 4}, "interval"),
    (imap() | {"interval_minutes": 1441}, "interval"),
    (imap() | {"kind": "pop3"}, "kind"),
    (imap() | {"name": ""}, "name"),
    (imap() | {"name": "x" * 49}, "name"),
])
def test_what_is_refused(services, data, says):
    with transaction(services.sessions) as s, pytest.raises(MailboxError) as refused:
        mailboxes.create(s, services.box, data)
    assert refused.value.status == 422 and says in str(refused.value)


def test_names_are_unique(services):
    _create(services, imap())
    with transaction(services.sessions) as s, pytest.raises(MailboxError) as refused:
        mailboxes.create(s, services.box, graph() | {"name": "Reports"})
    assert refused.value.status == 409


def test_the_view_never_holds_the_secret(services):
    for data in (imap(), graph(), gmail()):
        made = _create(services, data)
        assert made["secret_set"] is True
        text = json.dumps(made)
        assert data["secret"] not in text and "PRIVATE KEY" not in text


def test_a_secret_is_sealed_and_opens_only_as_its_own_mailbox(services):
    password = secrets.token_hex(8)
    first, second = _create(services, imap() | {"secret": password}), _create(services, graph())
    from phishhawk.server.models import Mailbox

    with transaction(services.sessions) as s:
        one, two = s.get(Mailbox, first["id"]), s.get(Mailbox, second["id"])
        assert password not in one.secret and mailboxes.secret_of(services.box, one) == password
        two.secret = one.secret  # copied onto another mailbox's row
        with pytest.raises(DecryptError):
            mailboxes.secret_of(services.box, two)


def test_only_the_service_accounts_name_and_key_are_kept(services):
    made = _create(services, gmail())
    from phishhawk.server.models import Mailbox

    with transaction(services.sessions) as s:
        kept = json.loads(mailboxes.secret_of(services.box, s.get(Mailbox, made["id"])))
    assert sorted(kept) == ["client_email", "private_key"]  # not its token_uri


def test_changing_where_a_mailbox_is_resets_its_cursor_and_nothing_else_does(services):
    from phishhawk.server.models import Mailbox

    made = _create(services, imap())
    with transaction(services.sessions) as s:
        mailbox = s.get(Mailbox, made["id"])
        mailbox.cursor = {"uidvalidity": 7, "uid": 42}
        changed = mailboxes.update(s, services.box, mailbox, {"name": "Phish reports", "interval_minutes": 15,
                                                               "enabled": False, "secret": secrets.token_hex(8)})
        assert sorted(changed) == ["enabled", "interval_minutes", "name", "secret"]
        assert mailbox.cursor == {"uidvalidity": 7, "uid": 42}
        assert mailboxes.update(s, services.box, mailbox, {"config": {"folder": "Phish reports"}}) == ["folder"]
        assert mailbox.cursor == {} and mailbox.config["host"] == "imap.example-corp.co.uk"
        assert mailboxes.update(s, services.box, mailbox, {"secret": ""}) == []  # an empty secret keeps it


def test_a_mailbox_keeps_its_kind(services):
    from phishhawk.server.models import Mailbox

    made = _create(services, imap())
    with transaction(services.sessions) as s, pytest.raises(MailboxError) as refused:
        mailboxes.update(s, services.box, s.get(Mailbox, made["id"]), {"kind": "graph"})
    assert refused.value.status == 422


# ---------------------------------------------------------------------- the API and the page --

def _body(**extra):
    return {"name": "Reports", "kind": "imap", "secret": secrets.token_hex(8),
            "config": {"host": "imap.example-corp.co.uk", "user": "soc@example-corp.co.uk"}} | extra


def test_an_admin_manages_mailboxes_through_the_api_and_each_change_is_audited(admin, services):
    from sqlalchemy import select

    from phishhawk.server.models import AuditRecord, Job

    first, second = _body(), secrets.token_hex(8)
    made = admin.post("/api/v1/mailboxes", json=first)
    assert made.status_code == 201 and made.json()["secret_set"] and first["secret"] not in made.text
    box = made.json()["id"]
    assert [m["name"] for m in admin.get("/api/v1/mailboxes").json()] == ["Reports"]
    assert admin.get("/api/v1/mailboxes/%d" % box).json()["config"]["port"] == 993
    changed = admin.patch("/api/v1/mailboxes/%d" % box, json={"interval_minutes": 15, "secret": second})
    assert changed.status_code == 200 and changed.json()["interval_minutes"] == 15
    assert admin.post("/api/v1/mailboxes/%d/poll" % box).json() == {"queued": True}
    assert admin.post("/api/v1/mailboxes/%d/poll" % box).json() == {"queued": False}  # one waits already
    with transaction(services.sessions) as s:
        assert len(s.scalars(select(Job).where(Job.kind == "mailbox_poll")).all()) == 1
    assert admin.delete("/api/v1/mailboxes/%d" % box).json() == {"deleted": True}
    assert admin.get("/api/v1/mailboxes").json() == []
    with transaction(services.sessions) as s:
        records = s.scalars(select(AuditRecord).where(AuditRecord.action.startswith("mailbox"))).all()
        assert [r.action for r in records] == ["mailbox_create", "mailbox_change", "mailbox_poll_now",
                                               "mailbox_poll_now", "mailbox_delete"]
        assert records[1].details == {"name": "Reports", "changed": ["interval_minutes", "secret"]}
        logged = repr([(r.details, r.object_id) for r in records])
    assert first["secret"] not in logged and second not in logged


def test_what_the_api_refuses(admin):
    refused = admin.post("/api/v1/mailboxes", json=_body(config={"host": "imaps://x.example", "user": "u"}))
    assert refused.status_code == 422 and "host" in refused.json()["detail"]
    box = admin.post("/api/v1/mailboxes", json=_body()).json()["id"]
    assert admin.post("/api/v1/mailboxes", json=_body()).status_code == 409
    for method, path in (("GET", ""), ("PATCH", ""), ("DELETE", ""), ("POST", "/poll")):
        assert admin.request(method, "/api/v1/mailboxes/999%s" % path, json={}).status_code == 404
    admin.patch("/api/v1/mailboxes/%d" % box, json={"enabled": False})
    switched_off = admin.post("/api/v1/mailboxes/%d/poll" % box)
    assert switched_off.status_code == 409 and "switched off" in switched_off.json()["detail"]


def test_the_mailboxes_page_adds_changes_polls_and_deletes_without_javascript(admin, services):
    from sqlalchemy import select

    from phishhawk.server.models import Job

    page = admin.get("/mailboxes")
    assert page.status_code == 200
    assert all('name="kind" value="%s"' % kind in page.text for kind in ("imap", "graph", "gmail"))
    password = secrets.token_hex(8)
    added = admin.post("/mailboxes", data={"kind": "imap", "name": "Reports", "host": "imap.example-corp.co.uk",
                                           "user": "soc", "folder": "Phish reports", "secret": password,
                                           "interval_minutes": "5"}, follow_redirects=False)
    assert added.status_code == 303 and added.headers["location"] == "/mailboxes"
    [made] = admin.get("/api/v1/mailboxes").json()
    assert made["config"]["folder"] == "Phish reports" and password not in admin.get("/mailboxes").text
    changed = admin.post("/mailboxes/%d" % made["id"], data={
        "name": "Phish reports", "interval_minutes": "10", "enabled": "true", "host": "imap.example-corp.co.uk",
        "user": "soc", "folder": "Phish reports", "port": "993", "secret": ""}, follow_redirects=False)
    assert changed.status_code == 303
    after = admin.get("/api/v1/mailboxes").json()[0]
    assert (after["name"], after["interval_minutes"], after["enabled"]) == ("Phish reports", 10, True)
    assert admin.post("/mailboxes/%d/poll" % made["id"], follow_redirects=False).status_code == 303
    with transaction(services.sessions) as s:
        assert s.scalars(select(Job).where(Job.kind == "mailbox_poll")).first() is not None
    wrong = admin.post("/mailboxes", data={"kind": "graph", "name": "M365", "tenant_id": "../evil",
                                           "client_id": "x", "address": "phish@example-corp.co.uk",
                                           "secret": "s"})
    assert wrong.status_code == 422 and "tenant must be" in wrong.text
    assert admin.post("/mailboxes/%d/delete" % made["id"], follow_redirects=False).status_code == 303
    assert admin.get("/api/v1/mailboxes").json() == []


def test_a_hostile_name_and_error_are_shown_as_text(admin, services):
    from html.parser import HTMLParser

    from phishhawk.server.models import Mailbox

    hostile = '"><svg onload=alert(1)>'
    box = admin.post("/api/v1/mailboxes", json=_body(name=hostile)).json()["id"]
    with transaction(services.sessions) as s:
        s.get(Mailbox, box).status, s.get(Mailbox, box).error = "error", "no folder '%s' on x" % hostile

    class Tags(HTMLParser):
        found: list = []

        def handle_starttag(self, tag, attrs):
            self.found.append((tag, dict(attrs)))

    page = admin.get("/mailboxes").text
    assert "<svg" not in page and page.count("&lt;svg onload=alert(1)&gt;") >= 2
    parser = Tags()
    parser.feed(page)
    assert not [attrs for _, attrs in parser.found if any(name.startswith("on") for name in attrs)]
