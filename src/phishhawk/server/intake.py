"""Accepting a message: size and type checks, deduplication by SHA-256 within
its workspace, sealing the raw bytes, and queueing the analysis."""

from __future__ import annotations

import hashlib
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, jobs
from .models import Message, Submission
from .store import BlobStore

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # Outlook .msg
HEADER_RE = re.compile(rb"^[A-Za-z0-9-]{1,76}:[ \t]", re.M)


class IntakeError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def kind_of(raw: bytes) -> str:
    """'msg', 'eml', or '' for anything else (an .mbox or a .zip is a batch: batches.py)."""
    if raw.startswith(OLE_MAGIC):
        return "msg"
    head = raw[:4096].lstrip(b"\r\n")
    if HEADER_RE.match(head) and len(HEADER_RE.findall(head)) >= 2:
        return "eml"
    return ""


def accept(db: Session, store: BlobStore, raw: bytes, *, workspace_id: int, source: str, user_id: int | None,
           actor: str, offline: bool, max_bytes: int, batch_id: int | None = None, position: int = 0,
           known_message: bool = False, mailbox_id: int | None = None) -> Submission:
    """known_message: batches.split() found it as a message (an mbox says where each one starts), so its type is
    not checked again."""
    if not raw:
        raise IntakeError(400, "the message is empty")
    if len(raw) > max_bytes:
        raise IntakeError(413, "the message is larger than %d MB" % (max_bytes // (1024 * 1024)))
    if not known_message and not kind_of(raw):
        raise IntakeError(415, "this is not an .eml or .msg message")
    sha256 = hashlib.sha256(raw).hexdigest()
    message = db.scalars(select(Message).where(Message.workspace_id == workspace_id,
                                               Message.sha256 == sha256)).first()
    if message is None:
        message = Message(workspace_id=workspace_id, sha256=sha256, size=len(raw), raw_blob=store.put(raw))
        db.add(message)
        db.flush()
    elif message.raw_blob is None:  # submitted again after its tier 1 was deleted
        message.raw_blob, message.tier1_deleted_at, message.deletion_reason = store.put(raw), None, ""
    submission = Submission(workspace_id=workspace_id, message_id=message.id, user_id=user_id, source=source,
                            offline=offline, batch_id=batch_id, position=position, mailbox_id=mailbox_id)
    db.add(submission)
    db.flush()
    jobs.enqueue(db, "analyze", {"submission_id": submission.id})
    details = {"sha256": sha256, "source": source, "offline": offline}
    if batch_id is not None:
        details["batch"] = batch_id
    if mailbox_id is not None:
        details["mailbox"] = mailbox_id
    audit.record(db, actor, "submit", "submission", submission.id, details, workspace_id=workspace_id)
    return submission
