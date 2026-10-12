"""Batches: several messages uploaded together, as several files, an .mbox or
a .zip (spec 6.2). They are split in the web process, in memory and within
limits; a name inside an archive is never used, as a path or otherwise. Each
message becomes a submission of the batch, analysed on its own."""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, intake
from .models import Analysis, Batch, Message, Submission
from .store import BlobStore

MB = 1024 * 1024
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
CENTRAL_ENTRY = b"PK\x01\x02"


class BatchError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Split:
    messages: list[bytes]
    skipped: int  # files in an archive that are not messages


def mbox_messages(data: bytes) -> list[bytes]:
    """The messages of an mbox, exactly as Python's mailbox.mbox reads them
    (and so the CLI): each starts after a line beginning "From ", and the
    blank line before the next one is not part of it."""
    starts: list[int] = []
    stops: list[int] = []
    last_was_empty, position = False, 0
    while True:
        line_start = position
        end = data.find(b"\n", position)
        line = data[position:] if end < 0 else data[position:end + 1]
        position = len(data) if end < 0 else end + 1
        if line.startswith(b"From "):
            if len(stops) < len(starts):
                stops.append(line_start - 1 if last_was_empty else line_start)
            starts.append(line_start)
            last_was_empty = False
        elif not line:
            stops.append(line_start - 1 if last_was_empty else line_start)
            break
        else:
            last_was_empty = line == b"\n"
    messages = []
    for start, stop in zip(starts, stops[:len(starts)], strict=True):  # the end of the file adds a stop
        body = data.find(b"\n", start)
        body = len(data) if body < 0 else body + 1
        messages.append(data[body:max(body, stop)])
    return messages


class _Limits:
    def __init__(self, max_messages: int, max_message_bytes: int, max_total: int) -> None:
        self.max_messages, self.max_message_bytes, self.max_total = max_messages, max_message_bytes, max_total
        self.total = 0

    def take(self, data: bytes) -> bytes:
        if len(data) > self.max_message_bytes:
            raise BatchError(413, "a message is larger than %d MB" % (self.max_message_bytes // MB))
        self.total += len(data)
        if self.total > self.max_total:
            raise BatchError(413, "the messages are larger than %d MB in all" % (self.max_total // MB))
        return data


def _zip_messages(data: bytes, limits: _Limits) -> tuple[list[bytes], int]:
    # Each entry takes memory when the archive is opened: count them first, from their signatures.
    if data.count(CENTRAL_ENTRY) > 2 * limits.max_messages + 50:
        raise BatchError(413, "the archive holds too many files")
    messages: list[bytes] = []
    skipped = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:  # encrypted: nothing to read
                    skipped += 1
                    continue
                with archive.open(info) as member:
                    # one byte past the limit is enough to refuse it: an archive bomb is never inflated
                    content = limits.take(member.read(limits.max_message_bytes + 1))
                if content.startswith(b"From "):
                    messages += [limits.take(m) for m in mbox_messages(content)]
                elif intake.kind_of(content):
                    messages.append(content)
                else:
                    skipped += 1
    except BatchError:
        raise
    except (zipfile.BadZipFile, NotImplementedError, EOFError, ValueError) as exc:  # damaged, or a method we lack
        raise BatchError(415, "the .zip file could not be read") from exc
    return messages, skipped


def split(files: list[bytes], *, max_messages: int, max_message_bytes: int, max_total: int) -> Split:
    """The messages in the uploaded files, in order: an .mbox gives each one it
    holds, a .zip each .eml, .msg or .mbox inside it (not archives inside)."""
    limits = _Limits(max_messages, max_message_bytes, max_total)
    messages: list[bytes] = []
    skipped = 0
    for index, data in enumerate(files):
        if data.startswith(ZIP_MAGIC):
            found, ignored = _zip_messages(data, limits)
            messages += found
            skipped += ignored
        elif data.startswith(b"From "):
            messages += [limits.take(m) for m in mbox_messages(data)]
        elif intake.kind_of(data):
            messages.append(limits.take(data))
        elif data:
            raise BatchError(415, "this is not an .eml, .msg, .mbox or .zip file")
        if len(messages) > max_messages:
            counted = ("%d messages" % len(messages) if index == len(files) - 1
                       else "more than %d messages" % max_messages)
            raise BatchError(413, "%s: the limit is %d" % (counted, max_messages))
    if not messages:
        raise BatchError(415 if skipped or any(files) else 400, "no .eml or .msg message was found")
    return Split(messages, skipped)


def accept(db: Session, store: BlobStore, messages: list[bytes], *, user_id: int | None, actor: str,
           offline: bool, max_bytes: int) -> Batch:
    batch = Batch(user_id=user_id, offline=offline, total=len(messages))
    db.add(batch)
    db.flush()
    for position, raw in enumerate(messages, 1):
        intake.accept(db, store, raw, source="batch", user_id=user_id, actor=actor, offline=offline,
                      max_bytes=max_bytes, batch_id=batch.id, position=position, known_message=True)
    audit.record(db, actor, "submit_batch", "batch", batch.id, {"messages": len(messages), "offline": offline})
    return batch


def created_view(db: Session, batch: Batch, skipped: int) -> dict[str, Any]:
    ids = list(db.scalars(select(Submission.id).where(Submission.batch_id == batch.id)
                          .order_by(Submission.position)))
    return {"batch_id": batch.id, "total": batch.total, "submission_ids": ids, "skipped": skipped}


def view(db: Session, batch: Batch, submitter: str | None) -> dict[str, Any]:
    """The batch with one row per message: status, and the verdict once there is one (no subject: that would
    mean opening every message's report)."""
    rows = db.execute(
        select(Submission, Analysis, Message).join(Message, Submission.message_id == Message.id)
        .outerjoin(Analysis, Analysis.submission_id == Submission.id)
        .where(Submission.batch_id == batch.id).order_by(Submission.position)).all()
    counts = {status: 0 for status in ("queued", "running", "done", "failed")}
    verdicts: dict[str, int] = {}
    messages = []
    for submission, analysis, message in rows:
        counts[submission.status] = counts.get(submission.status, 0) + 1
        if analysis is not None:
            verdicts[analysis.verdict] = verdicts.get(analysis.verdict, 0) + 1
        messages.append({"position": submission.position, "submission_id": submission.id,
                         "status": submission.status, "error": submission.error, "message_id": message.id,
                         "analysis_id": analysis.id if analysis else None,
                         "verdict": analysis.verdict if analysis else None,
                         "score": analysis.score if analysis else None, "sender": message.sender,
                         "sender_domain": message.sender_domain})
    return {"id": batch.id, "created_at": batch.created_at.isoformat(), "submitted_by": batch.user_id,
            "submitted_by_name": submitter, "offline": batch.offline, "total": batch.total, "status": batch.status,
            "error": batch.error, "counts": counts, "verdicts": verdicts, "messages": messages,
            "finished_at": batch.finished_at.isoformat() if batch.finished_at else None}
