"""Append-only audit log. Each record's hash covers the previous record's
hash, and the audit_head row keeps the newest hash and the count, so an
edited, removed, reordered or cut-off record is reported by verify().

One chain for the whole server. Each record says whose it is: a workspace's,
the server's own (SERVER), or None for records written before workspaces. The
hash covers the workspace whenever there is one, so those older records still
verify."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.orm import Session

from .auth import Actor
from .models import SERVER, AuditHead, AuditRecord, Workspace, utcnow

GENESIS = "0" * 64


def _stamp(at: dt.datetime) -> str:
    """UTC, without an offset: SQLite hands datetimes back without one."""
    if at.tzinfo is not None:
        at = at.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return at.isoformat()


def _digest(prev_hash: str, record: AuditRecord) -> str:
    body: dict[str, Any] = {"at": _stamp(record.at), "actor": record.actor, "action": record.action,
                            "object_type": record.object_type, "object_id": record.object_id,
                            "details": record.details}
    if record.workspace_id is not None:
        body["workspace"] = record.workspace_id
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def record(db: Session, actor: str, action: str, object_type: str = "", object_id: object = "",
           details: dict[str, Any] | None = None, *, workspace_id: int) -> AuditRecord:
    """Append one record inside the caller's transaction, for a workspace or for the server (SERVER)."""
    head = db.scalars(select(AuditHead).with_for_update()).first()
    if head is None:
        head = AuditHead(id=1, hash=GENESIS, count=0)
        db.add(head)
    entry = AuditRecord(at=utcnow().replace(microsecond=0), actor=actor, action=action, object_type=object_type,
                        object_id=str(object_id), details=details or {}, prev_hash=head.hash,
                        workspace_id=workspace_id)
    entry.hash = _digest(head.hash, entry)
    db.add(entry)
    head.hash, head.count = entry.hash, head.count + 1
    db.flush()
    return entry


def visible_to(db: Session, actor: Actor) -> ColumnElement[bool]:
    """The records an admin may read: their workspace's; the records from before workspaces too, for the
    organization that data went to; and the server's own for its owner."""
    seen: list[ColumnElement[bool]] = [AuditRecord.workspace_id == actor.workspace_id]
    legacy = db.scalars(select(Workspace.id).where(Workspace.kind == "organization")
                        .order_by(Workspace.id)).first()
    if legacy == actor.workspace_id:
        seen.append(AuditRecord.workspace_id.is_(None))
    if actor.owner:
        seen.append(AuditRecord.workspace_id == SERVER)
    return or_(*seen)


def verify(db: Session) -> list[str]:
    """Problems found, or an empty list when the log is intact."""
    problems: list[str] = []
    prev, count = GENESIS, 0
    for entry in db.scalars(select(AuditRecord).order_by(AuditRecord.id)):
        count += 1
        if entry.prev_hash != prev:
            problems.append("record %d does not follow the one before it" % entry.id)
        if entry.hash != _digest(entry.prev_hash, entry):
            problems.append("record %d was changed" % entry.id)
        prev = entry.hash
    head = db.scalars(select(AuditHead)).first()
    if head is not None and (head.hash != prev or head.count != count):
        problems.append("the newest records are missing (%d recorded, %d found)" % (head.count, count))
    return problems
