"""Mailbox import through the Gmail API (spec 6.3, 11 M3), against a fake Gmail that allows only GET and one POST
for the token (fakehttp.py): a service account's signed JWT for gmail.readonly only, impersonating the report
mailbox; the history ID as the cursor; and the same guarantees as IMAP and Graph."""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy import select

from phishhawk.server import appsettings, mailbox, mailboxes
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER, AuditRecord, Mailbox, Submission

from .fakehttp import GMAIL, GOOGLE_TOKEN, READONLY, FakeGmail
from .serverkit import home
from .test_mailbox_imap import report
from .test_mailboxes import service_account_key

ADDRESS = "phish@example-corp.co.uk"
ACCOUNT = "phishhawk@reports-project.iam.gserviceaccount.com"


@pytest.fixture
def gmail():
    key = service_account_key(ACCOUNT)
    public = load_pem_private_key(json.loads(key)["private_key"].encode("ascii"), password=None).public_key()
    fake = FakeGmail(ACCOUNT, public, ADDRESS)
    fake.key = key
    yield fake
    assert fake.violations == []  # GET to Gmail and one POST to the token URL, nothing else


def _mailbox(services, fake, name="Workspace reports", key=None, **config):
    with transaction(services.sessions) as s:
        return mailboxes.create(s, services.box, {"name": name, "kind": "gmail", "secret": key or fake.key,
                                                  "config": {"address": ADDRESS, **config}}, home(s)).id


def _state(services, mailbox_id):
    with transaction(services.sessions) as s:
        return mailboxes.view(s.get(Mailbox, mailbox_id)) | {"cursor": dict(s.get(Mailbox, mailbox_id).cursor)}


def test_the_token_comes_for_a_signed_jwt_for_gmail_readonly_only(services, gmail):
    gmail.add(report(1))
    before = int(time.time())
    assert mailbox.poll(services, _mailbox(services, gmail), session=gmail)["imported"] == 1
    [(header, claims)] = gmail.assertions  # its signature checked with the key's public half
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert (claims["iss"], claims["sub"], claims["scope"], claims["aud"]) == (ACCOUNT, ADDRESS, READONLY,
                                                                              GOOGLE_TOKEN)
    assert claims["exp"] - claims["iat"] == 3600 and abs(claims["iat"] - before) < 60
    posts = [c for c in gmail.calls if c[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == GOOGLE_TOKEN  # not the key file's token_uri
    assert posts[0][4]["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    gets = [c for c in gmail.calls if c[0] == "GET"]
    assert all(c[1].startswith(GMAIL + "/") and c[3]["Authorization"] == "Bearer " + gmail.token for c in gets)
    with transaction(services.sessions) as s:
        assert [sub.source for sub in s.scalars(select(Submission))] == ["mailbox"]


def test_the_first_poll_takes_the_history_id_first_then_imports_the_newest_50(services, gmail):
    ids = [gmail.add(report(number)) for number in range(60)]
    box = _mailbox(services, gmail)
    assert mailbox.poll(services, box, session=gmail)["imported"] == 50
    paths = [c[1].rsplit("/", 1)[1] for c in gmail.calls if c[0] == "GET"]
    assert paths.index("profile") < paths.index("messages")  # nothing that arrives in between is missed
    assert sorted(gmail.downloads()) == sorted(ids[10:])
    assert _state(services, box)["cursor"] == {"history": str(gmail.history_id), "label": "INBOX"}

    gmail.calls.clear()
    new = [gmail.add(report(60)), gmail.add(report(61))]
    assert mailbox.poll(services, box, session=gmail)["imported"] == 2
    assert gmail.downloads() == new
    history = [c for c in gmail.calls if c[1].endswith("/history")]
    assert history and history[0][2]["historyTypes"] == "messageAdded" and history[0][2]["labelId"] == "INBOX"


def test_a_label_is_found_by_its_name(services, gmail):
    gmail.add(report(1), label="Phish reports")
    gmail.add(report(2))
    box = _mailbox(services, gmail, label="Phish reports")
    assert mailbox.poll(services, box, session=gmail)["imported"] == 1
    listed = [c for c in gmail.calls if c[1].endswith("/messages")]
    assert listed[0][2]["labelIds"] == "Label_7"


def test_a_missing_label_is_an_error(services, gmail):
    box = _mailbox(services, gmail, label="Nowhere")
    mailbox.poll(services, box, session=gmail)
    assert "no label called 'Nowhere'" in _state(services, box)["error"]


def test_the_history_is_followed_page_by_page(services, gmail):
    box = _mailbox(services, gmail)
    mailbox.poll(services, box, session=gmail)
    gmail.page_size = 2
    for number in range(5):
        gmail.add(report(number))
    assert mailbox.poll(services, box, session=gmail)["imported"] == 5


def test_a_history_id_too_old_starts_again_without_duplicates(services, gmail):
    for number in range(3):
        gmail.add(report(number))
    box = _mailbox(services, gmail)
    mailbox.poll(services, box, session=gmail)
    gmail.add(report(3))
    gmail.oldest_history = gmail.history_id  # the stored history ID is now too old
    assert mailbox.poll(services, box, session=gmail) == {"imported": 1, "duplicates": 0, "skipped": 0}
    assert len(gmail.downloads()) == 4  # nothing downloaded twice


def test_more_than_a_poll_takes_waits_for_the_next_poll(services, gmail):
    box = _mailbox(services, gmail)
    mailbox.poll(services, box, session=gmail)
    with transaction(services.sessions) as s:
        appsettings.set_value(s, SERVER, "max_batch_messages", 2)
    for number in range(5):
        gmail.add(report(number))
    assert [mailbox.poll(services, box, session=gmail)["imported"] for _ in range(4)] == [2, 2, 1, 0]
    assert len(gmail.downloads()) == len(set(gmail.downloads())) == 5


def test_a_message_over_the_limit_is_skipped_before_it_is_downloaded(services, gmail):
    with transaction(services.sessions) as s:
        appsettings.set_value(s, SERVER, "max_upload_mb", 1)
    from conftest import build_eml

    gmail.add(build_eml(subject="Large", text="x" * (2 * 1024 * 1024)))
    assert mailbox.poll(services, _mailbox(services, gmail), session=gmail) == {"imported": 0, "duplicates": 0,
                                                                                 "skipped": 1}
    assert gmail.downloads() == []


def test_a_key_google_does_not_know_is_refused_without_showing_it(services, gmail):
    other = service_account_key(ACCOUNT)  # the same account's name, another key
    box = _mailbox(services, gmail, key=other)
    mailbox.poll(services, box, session=gmail)
    state = _state(services, box)
    assert state["status"] == "error" and "sign-in refused (invalid_grant)" in state["error"]
    assert "domain-wide delegation" in state["error"]
    with transaction(services.sessions) as s:
        audit = repr([r.details for r in s.scalars(select(AuditRecord))])
    private = json.loads(other)["private_key"]
    for line in private.splitlines()[1:-1]:
        assert line not in repr(state) + audit


def test_the_assertion_is_a_well_formed_jwt():
    """Three base64url parts without padding, as RFC 7515 writes them."""
    import secrets

    key = json.loads(service_account_key(ACCOUNT))
    token = mailbox.gmail_assertion(key, ADDRESS, 1_800_000_000)
    parts = token.split(".")
    assert len(parts) == 3 and not any("=" in p or "+" in p or "/" in p for p in parts)
    claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    assert claims == {"iss": ACCOUNT, "sub": ADDRESS, "scope": READONLY, "aud": GOOGLE_TOKEN,
                      "iat": 1_800_000_000, "exp": 1_800_003_600}
    assert secrets.compare_digest(token, mailbox.gmail_assertion(key, ADDRESS, 1_800_000_000))  # deterministic


def test_the_double_refuses_anything_but_reads(gmail):
    gmail.post(GMAIL + "/users/%s/messages/x/modify" % ADDRESS, data={"removeLabelIds": ["UNREAD"]})
    gmail.delete(GMAIL + "/users/%s/messages/x" % ADDRESS)
    assert len(gmail.violations) == 2
    gmail.violations.clear()
