"""Read reported mail straight from an IMAP folder (a shared "report
phishing" mailbox, say), without changing it.

The folder is opened read-only (EXAMINE) and messages are fetched with
BODY.PEEK[], so nothing is marked read, moved or deleted. TLS certificates
are always verified. The password is never taken on the command line,
where other users could read it from the process list: it comes from
$PHISHHAWK_IMAP_PASSWORD or a prompt, or an OAuth token from
$PHISHHAWK_IMAP_TOKEN (XOAUTH2, for Gmail and Microsoft 365).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import imaplib
import re
import ssl
from collections.abc import Iterator
from dataclasses import dataclass

MAX_UIDS = 10_000


class ImapError(Exception):
    pass


@dataclass
class ImapSource:
    host: str
    user: str
    password: str = ""
    token: str = ""
    folder: str = "INBOX"
    port: int = 993
    starttls: bool = False
    since: dt.date | None = None
    unseen: bool = False
    limit: int = 50
    timeout: float = 30


def quote_folder(folder: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in folder):  # a CR or LF would end the command early
        raise ImapError("folder name %r has control characters" % folder)
    return '"%s"' % folder.replace("\\", "\\\\").replace('"', '\\"')


def connect(source: ImapSource) -> imaplib.IMAP4:
    context = ssl.create_default_context()
    try:
        if source.starttls:
            connection = imaplib.IMAP4(source.host, source.port, timeout=source.timeout)
            connection.starttls(ssl_context=context)
        else:
            connection = imaplib.IMAP4_SSL(source.host, source.port, ssl_context=context, timeout=source.timeout)
    except (OSError, imaplib.IMAP4.error) as exc:
        raise ImapError("cannot connect to %s:%d: %s" % (source.host, source.port, exc)) from exc
    try:
        if source.token:
            auth = "user=%s\x01auth=Bearer %s\x01\x01" % (source.user, source.token)
            connection.authenticate("XOAUTH2", lambda _: auth.encode())
        else:
            connection.login(source.user, source.password)
    except imaplib.IMAP4.error as exc:
        close(connection)
        raise ImapError("login to %s refused for %s" % (source.host, source.user)) from exc
    return connection


def close(connection: imaplib.IMAP4) -> None:
    with contextlib.suppress(Exception):  # the server may already have hung up
        connection.logout()


def _criteria(source: ImapSource, after_uid: int = 0) -> list[str]:
    criteria = ["UNSEEN"] if source.unseen else ["ALL"]
    if source.since:
        criteria += ["SINCE", source.since.strftime("%d-%b-%Y")]
    if after_uid:
        criteria += ["UID", "%d:*" % (after_uid + 1)]
    return criteria


_SIZE_RE = re.compile(rb"RFC822\.SIZE (\d+)")


def uidvalidity(connection: imaplib.IMAP4) -> int:
    """The open folder's UIDVALIDITY, from the server's answer to EXAMINE; 0 if it sent none."""
    _, data = connection.response("UIDVALIDITY")
    value = data[-1] if data else None
    return int(value) if isinstance(value, bytes) and value.isdigit() else 0


LITERAL_SLACK = 64 * 1024  # a server's RFC822.SIZE and the message it then sends may differ a little


def _limit_literals(connection: imaplib.IMAP4, limit: int) -> None:
    """imaplib reads a literal of whatever size the server announces, so a server that said a message was
    small could still send gigabytes as one. A literal over the limit now stops the connection unread."""
    read = getattr(connection, "_phishhawk_read", None) or getattr(connection, "read", None)
    if read is None:
        return

    def bounded(size: int) -> bytes:
        if size > limit:
            raise imaplib.IMAP4.abort("the server sent %d bytes for one message, more than the %d it may"
                                      % (size, limit))
        data: bytes = read(size)
        return data

    setattr(connection, "_phishhawk_read", read)  # noqa: B010 - set once, so the wrappers do not pile up
    setattr(connection, "read", bounded)  # noqa: B010 - imaplib calls self.read for every literal


def fetch_uid(connection: imaplib.IMAP4, uid: int, max_bytes: int) -> bytes | Exception:
    """One message, or why it was not fetched: its size first, then BODY.PEEK[], so it is not marked read."""
    try:
        status, data = connection.uid("FETCH", str(uid), "(RFC822.SIZE)")
        size = _SIZE_RE.search(data[0] if data and isinstance(data[0], bytes) else b"")
        if size and int(size.group(1)) > max_bytes:
            return ValueError("larger than %d MB" % (max_bytes // (1024 * 1024)))
        _limit_literals(connection, max_bytes + LITERAL_SLACK)
        status, data = connection.uid("FETCH", str(uid), "(BODY.PEEK[])")
        message = next((part[1] for part in data or [] if isinstance(part, tuple) and len(part) > 1), None)
        if status != "OK" or not isinstance(message, bytes):
            return ValueError("the server returned no message")
        return message[: max_bytes + 1]
    except (imaplib.IMAP4.error, OSError) as exc:
        return exc


def fetch(source: ImapSource, max_bytes: int, after_uid: int = 0) -> Iterator[tuple[str, int, bytes | Exception]]:
    """(label, uid, raw message or why it was skipped), newest last."""
    folder = quote_folder(source.folder)  # checked before anything is sent
    connection = connect(source)
    try:
        try:
            status, _ = connection.select(folder, readonly=True)
            if status != "OK":
                raise ImapError("no folder %r on %s" % (source.folder, source.host))
            status, data = connection.uid("SEARCH", *_criteria(source, after_uid))
        except (imaplib.IMAP4.error, OSError) as exc:  # the server hung up or refused: not a crash
            raise ImapError("%s: %s" % (source.host, exc)) from exc
        if status != "OK":
            raise ImapError("search failed in %r" % source.folder)
        uids = [int(u) for u in (data[0] or b"").split() if u.isdigit()][-MAX_UIDS:]
        uids = [u for u in uids if u > after_uid][-source.limit:] if source.limit else uids
        for uid in uids:
            label = "imap://%s/%s;UID=%d" % (source.host, source.folder, uid)
            yield label, uid, fetch_uid(connection, uid, max_bytes)
    finally:
        close(connection)
