"""Polling a report mailbox, read-only (spec 6.3, 7.5): fetch what arrived after the cursor, skip what was seen,
and submit each new message as an upload is submitted. A failure leaves the mailbox in "error" with a reason in
PhishHawk's own words, never a credential, and backs its polling off up to an hour.

IMAP is read through `imapfetch` (EXAMINE, BODY.PEEK[]); Graph and Gmail through their HTTP APIs with GET only,
after one POST for a token."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import imaplib
import re
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from email.parser import BytesHeaderParser
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import imapfetch
from ..report.common import printable
from . import appsettings, audit, intake, jobs, mailboxes
from .crypto import DecryptError
from .db import transaction
from .models import Job, Mailbox, MailboxItem, Message, utcnow
from .processing import Services

FIRST_POLL = 50  # the newest messages a first poll (or a resync) imports
BACKOFF_CAP = dt.timedelta(hours=1)
REASON_LIMIT = 300
MB = 1024 * 1024


class PollError(Exception):
    """Why a poll stopped, in PhishHawk's words."""


@dataclass
class Item:
    remote_id: str
    raw: bytes | None  # None: skipped for good (too large, or not a message)
    reason: str = ""
    cursor: dict[str, Any] | None = None  # the mailbox's cursor once this item is handled; None: unchanged


@dataclass
class Source:
    """What a connector is given; `items()` yields what is new, and sets `final` once it has gone through all."""
    config: dict[str, Any]
    secret: str
    cursor: dict[str, Any]
    max_bytes: int
    session: Any = None  # an HTTP session (Graph, Gmail); requests.Session() when None
    final: dict[str, Any] | None = field(default=None)

    def items(self, seen: Callable[[str], bool]) -> Generator[Item, None, None]:
        raise NotImplementedError


# -------------------------------------------------------------------- IMAP --

class ImapSource(Source):
    def items(self, seen: Callable[[str], bool]) -> Generator[Item, None, None]:
        c = self.config
        source = imapfetch.ImapSource(host=c["host"], user=c["user"], password=self.secret, folder=c["folder"],
                                      port=int(c["port"]), starttls=bool(c["starttls"]), limit=0)
        try:
            folder = imapfetch.quote_folder(source.folder)
            connection = imapfetch.connect(source)
        except imapfetch.ImapError as exc:
            if str(exc).startswith("login to"):
                raise PollError("sign-in refused for %s at %s: check the user and the password"
                                % (source.user, source.host)) from exc
            raise PollError(str(exc)) from exc
        try:
            status, _ = connection.select(folder, readonly=True)  # EXAMINE
            if status != "OK":
                raise PollError("no folder %r on %s" % (source.folder, source.host))
            validity = imapfetch.uidvalidity(connection)
            resync = self.cursor.get("uidvalidity") != validity
            after = 0 if resync else int(self.cursor.get("uid", 0))
            status, data = connection.uid("SEARCH", *(["ALL"] if after == 0 else ["UID", "%d:*" % (after + 1)]))
            if status != "OK":
                raise PollError("the search failed in %r on %s" % (source.folder, source.host))
            uids = sorted({int(u) for u in (data[0] or b"").split() if u.isdigit() and int(u) > after})
            top = max(uids, default=after)
            for uid in uids[-FIRST_POLL:] if resync else uids:
                raw = imapfetch.fetch_uid(connection, uid, self.max_bytes)
                if isinstance(raw, (imaplib.IMAP4.error, OSError)):
                    raise PollError("the connection to %s was lost: %s" % (source.host, raw))
                remote_id, cursor = "%d:%d" % (validity, uid), {"uidvalidity": validity, "uid": uid}
                if isinstance(raw, Exception):
                    yield Item(remote_id, None, str(raw), cursor)
                else:
                    yield Item(remote_id, raw, "", cursor)
            self.final = {"uidvalidity": validity, "uid": top}
        except (imaplib.IMAP4.error, OSError) as exc:
            raise PollError("the connection to %s was lost: %s" % (source.host, exc)) from exc
        finally:
            imapfetch.close(connection)


SOURCES: dict[str, type[Source]] = {"imap": ImapSource}


# -------------------------------------------------------------------- poll --

def sanitise(reason: str, secrets: list[str]) -> str:
    """The reason as shown and audited: no credential or token in it, printable, and short."""
    parts = [p.strip() for secret in secrets for p in [secret, *secret.splitlines()]]
    for part in sorted({p for p in parts if len(p) >= 6}, key=len, reverse=True):
        reason = reason.replace(part, "***")
    reason = re.sub(r"(?i)\bbearer\s+\S+", "Bearer ***", printable(reason))
    for part in sorted({p for p in parts if len(p) >= 6}, key=len, reverse=True):
        reason = reason.replace(part, "***")
    return reason[:REASON_LIMIT]


def _message_id_hmac(raw: bytes, key: bytes) -> str:
    try:
        value = str(BytesHeaderParser().parsebytes(raw[: 256 * 1024]).get("Message-ID") or "").strip()
    except Exception:  # noqa: BLE001 - an unreadable header is no Message-ID, not a failed poll
        return ""
    if not value or len(value) > 998:
        return ""
    text = ("message-id:" + value).encode("utf-8", "surrogateescape")
    return hmac.new(key, text, hashlib.sha256).hexdigest()


def _handle(services: Services, mailbox_id: int, name: str, config: dict[str, Any], item: Item, key: bytes,
            max_bytes: int) -> str:
    """Record one item: imported, a duplicate, or skipped. Its cursor is kept in the same transaction."""
    with transaction(services.sessions) as db:
        mailbox = db.get(Mailbox, mailbox_id)
        if mailbox is None:
            raise PollError("the mailbox was deleted while it was polled")
        outcome = "skipped"
        if _seen(db, mailbox_id, item.remote_id):
            outcome = "duplicates"
        elif item.raw is None:
            db.add(MailboxItem(mailbox_id=mailbox_id, remote_id=item.remote_id, outcome="skipped"))
        else:
            sha256, mid = hashlib.sha256(item.raw).hexdigest(), _message_id_hmac(item.raw, key)
            message = db.scalars(select(Message).where(Message.sha256 == sha256)).first()
            known = mid and db.scalars(select(MailboxItem.id).where(
                MailboxItem.message_id_hmac == mid, MailboxItem.outcome.in_(("imported", "duplicate")))).first()
            if message is not None or known:
                db.add(MailboxItem(mailbox_id=mailbox_id, remote_id=item.remote_id, outcome="duplicate",
                                   message_id=message.id if message is not None else None, message_id_hmac=mid))
                outcome = "duplicates"
            else:
                try:
                    submission = intake.accept(db, services.store, item.raw, source="mailbox", user_id=None,
                                               actor="mailbox:" + name, offline=False, max_bytes=max_bytes,
                                               mailbox_id=mailbox_id)
                except intake.IntakeError:
                    db.add(MailboxItem(mailbox_id=mailbox_id, remote_id=item.remote_id, outcome="skipped"))
                else:
                    db.add(MailboxItem(mailbox_id=mailbox_id, remote_id=item.remote_id, outcome="imported",
                                       message_id=submission.message_id, message_id_hmac=mid))
                    outcome = "imported"
        if item.cursor is not None and mailbox.config == config:  # not if it was moved meanwhile
            mailbox.cursor = item.cursor
        return outcome


def _seen(db: Session, mailbox_id: int, remote_id: str) -> bool:
    return db.scalars(select(MailboxItem.id).where(MailboxItem.mailbox_id == mailbox_id,
                                                   MailboxItem.remote_id == remote_id)).first() is not None


def _failed(db: Session, mailbox: Mailbox, reason: str, counts: dict[str, int]) -> None:
    now = utcnow()
    mailbox.status, mailbox.error, mailbox.failures = "error", reason, mailbox.failures + 1
    mailbox.last_poll_at, mailbox.last_counts = now, dict(counts)
    wait = dt.timedelta(minutes=mailbox.interval_minutes) * 2 ** min(mailbox.failures, 12)
    mailbox.next_poll_at = now + min(wait, BACKOFF_CAP)
    audit.record(db, "system", "mailbox_poll_failed", "mailbox", mailbox.id,
                 {"name": mailbox.name, "reason": reason, "imported": counts.get("imported", 0)})


def poll(services: Services, mailbox_id: int, heartbeat: Callable[[], None] | None = None,
         session: Any = None) -> dict[str, int]:
    """One poll of one mailbox; the counts of what it imported, skipped as duplicates, and skipped for good."""
    s = services
    counts = {"imported": 0, "duplicates": 0, "skipped": 0}
    with transaction(s.sessions) as db:
        mailbox = db.get(Mailbox, mailbox_id)
        if mailbox is None or not mailbox.enabled:
            return counts
        kind, name, config, cursor = mailbox.kind, mailbox.name, dict(mailbox.config), dict(mailbox.cursor or {})
        try:
            secret = mailboxes.secret_of(s.box, mailbox)
        except DecryptError:
            _failed(db, mailbox, "the stored credential cannot be opened with the encryption key: enter it again",
                    counts)
            return counts
        max_bytes = appsettings.limit(db, s.settings, "max_upload_mb") * MB
        cap = appsettings.limit(db, s.settings, "max_batch_messages")
        key = appsettings.trait_key(db, s.box)
    source = SOURCES[kind](config, secret, cursor, max_bytes, session)
    error, complete = "", False
    try:
        def seen(remote_id: str) -> bool:
            with transaction(s.sessions) as db:
                return _seen(db, mailbox_id, remote_id)

        with contextlib.closing(source.items(seen)) as items:
            for item in items:
                outcome = _handle(s, mailbox_id, name, config, item, key, max_bytes)
                counts[outcome] += 1
                if heartbeat is not None:
                    heartbeat()
                if sum(counts.values()) >= cap:  # the rest at the next poll
                    break
            else:
                complete = True
    except PollError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 - its text may quote a server's answer; its type is enough
        error = "the poll stopped: %s" % type(exc).__name__
    with transaction(s.sessions) as db:
        mailbox = db.get(Mailbox, mailbox_id)
        if mailbox is None:
            return counts
        if error:
            _failed(db, mailbox, sanitise(error, [secret]), counts)
            return counts
        now = utcnow()
        if complete and source.final is not None and mailbox.config == config:
            mailbox.cursor = source.final
        mailbox.status, mailbox.error, mailbox.failures = "ok", "", 0
        mailbox.last_poll_at, mailbox.last_counts = now, dict(counts)
        mailbox.next_poll_at = now + dt.timedelta(minutes=mailbox.interval_minutes)
    return counts


# --------------------------------------------------------------- schedule --

def _waiting(db: Session) -> set[int]:
    return {int(job.payload.get("mailbox_id", 0)) for job in db.scalars(select(Job).where(
        Job.kind == "mailbox_poll", Job.status.in_(("queued", "running"))))}


def due(db: Session, now: dt.datetime | None = None) -> list[int]:
    """Enabled mailboxes whose next poll has come and that have none waiting."""
    now, waiting = now or utcnow(), _waiting(db)
    return [m.id for m in db.scalars(select(Mailbox).where(Mailbox.enabled.is_(True)).order_by(Mailbox.id))
            if m.id not in waiting and (m.next_poll_at is None or m.next_poll_at <= now)]


def queue_poll(db: Session, mailbox_id: int) -> bool:
    """Queue a poll, unless one is waiting already."""
    if mailbox_id in _waiting(db):
        return False
    jobs.enqueue(db, "mailbox_poll", {"mailbox_id": mailbox_id})
    return True


def gave_up(db: Session, mailbox_id: int, error: str) -> None:
    """A poll whose worker died too often: a failure like any other, so the mailbox backs off."""
    mailbox = db.get(Mailbox, mailbox_id)
    if mailbox is not None:
        _failed(db, mailbox, sanitise("the poll stopped: " + error, []), {"imported": 0, "duplicates": 0,
                                                                         "skipped": 0})
