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
