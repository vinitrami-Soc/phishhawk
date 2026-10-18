"""Batches: several messages uploaded together, as several files, an .mbox or
a .zip (spec 6.2). They are split in the web process, in memory and within
limits; a name inside an archive is never used, as a path or otherwise. Each
message becomes a submission of the batch, analysed on its own."""

from __future__ import annotations

import io
import lzma
import zipfile
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..analysis import render_saved
from . import audit, intake, jobs
from .db import transaction
from .limits import ChildFailed, LimitExceeded, run_limited
from .models import Analysis, Batch, Message, Submission, utcnow
from .store import BlobStore

if TYPE_CHECKING:
    from .processing import Services

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
    except (zipfile.BadZipFile, NotImplementedError, EOFError, ValueError,  # damaged, or a method we lack
            zlib.error, lzma.LZMAError, OSError) as exc:  # a damaged deflate, LZMA or bzip2 (OSError) stream
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


def accept(db: Session, store: BlobStore, messages: list[bytes], *, workspace_id: int, user_id: int | None,
           actor: str, offline: bool, max_bytes: int) -> Batch:
    batch = Batch(workspace_id=workspace_id, user_id=user_id, offline=offline, total=len(messages))
    db.add(batch)
    db.flush()
    for position, raw in enumerate(messages, 1):
        intake.accept(db, store, raw, workspace_id=workspace_id, source="batch", user_id=user_id, actor=actor,
                      offline=offline, max_bytes=max_bytes, batch_id=batch.id, position=position,
                      known_message=True)
    audit.record(db, actor, "submit_batch", "batch", batch.id, {"messages": len(messages), "offline": offline},
                 workspace_id=workspace_id)
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
            "finished_at": batch.finished_at.isoformat() if batch.finished_at else None,
            "files": [{k: f[k] for k in ("name", "kind", "type", "size", "sha256")}
                      | {"available": bool(f["blob"])} for f in batch.files],
            "files_deleted_at": batch.files_deleted_at.isoformat() if batch.files_deleted_at else None}


def after_submission(db: Session, submission: Submission) -> None:
    """When the last message of a batch is done or failed, its combined exports are queued."""
    batch = db.get(Batch, submission.batch_id) if submission.batch_id else None
    if batch is None or batch.status != "running":
        return
    waiting = db.scalar(select(func.count()).select_from(Submission).where(
        Submission.batch_id == batch.id, Submission.status.in_(("queued", "running"))))
    if not waiting:
        batch.status = "finalizing"
        jobs.enqueue(db, "batch_finalize", {"batch_id": batch.id}, batch.workspace_id)


def failed(db: Session, batch_id: int, reason: str) -> None:
    batch = db.get(Batch, batch_id)
    if batch is not None and batch.status == "finalizing":
        batch.status, batch.error, batch.finished_at = "failed", reason, utcnow()


def child_render(states: list[bytes]) -> list[tuple[bytes, dict[str, Any]]]:
    """Runs in the child process: every format for the saved analyses together."""
    return [(f.content, f.entry()) for f in render_saved(states)]


def finalize(services: Services, batch_id: int, heartbeat: Any = None) -> None:
    """The batch's combined exports, rendered in a limited child process from the analyses saved for its messages
    (those deleted meanwhile are left out), then sealed as tier 1."""
    s = services
    with transaction(s.sessions) as db:
        batch = db.get(Batch, batch_id)
        if batch is None or batch.status != "finalizing":
            return
        kept = db.execute(select(Analysis.id, Analysis.state_blob)
                          .join(Submission, Analysis.submission_id == Submission.id)
                          .where(Submission.batch_id == batch_id, Analysis.state_blob.is_not(None))
                          .order_by(Submission.position)).all()
        states = [s.store.get(blob) for _, blob in kept if blob]
    stored: list[dict[str, Any]] = []
    error = ""
    if states:
        try:
            rendered = run_limited(child_render, (states,), s.settings.analysis_memory_mb,
                                   s.settings.analysis_cpu_seconds + len(states), heartbeat)
            stored = [dict(entry, blob=s.store.put(content)) for content, entry in rendered]
        except (LimitExceeded, ChildFailed) as exc:
            error = "the combined exports could not be made: %s" % exc
    with transaction(s.sessions) as db:
        batch = db.get(Batch, batch_id)
        still = set(db.scalars(select(Analysis.id).where(Analysis.id.in_([i for i, _ in kept]),
                                                         Analysis.state_blob.is_not(None))))
        if batch is None or still != {i for i, _ in kept}:  # a message in them was deleted meanwhile
            for entry in stored:
                s.store.delete(entry["blob"])
            stored = []
            if batch is not None:
                batch.files_deleted_at = utcnow()
        if batch is None:
            return
        batch.files, batch.finished_at = stored, utcnow()
        batch.status, batch.error = ("failed", error) if error else ("done", "" if states else
                                                                      "no message in the batch was analysed")
        audit.record(db, "system", "batch_finalize", "batch", batch_id,
                     {"messages": len(states), "files": len(stored)}, workspace_id=batch.workspace_id)
