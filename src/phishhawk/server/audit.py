"""Append-only audit log. Each record's hash covers the previous record's
hash, and the audit_head row keeps the newest hash and the count, so an
edited, removed, reordered or cut-off record is reported by verify()."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditHead, AuditRecord, utcnow

GENESIS = "0" * 64


def _stamp(at: dt.datetime) -> str:
    """UTC, without an offset: SQLite hands datetimes back without one."""
    if at.tzinfo is not None:
        at = at.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return at.isoformat()


def _digest(prev_hash: str, record: AuditRecord) -> str:
    body = {"at": _stamp(record.at), "actor": record.actor, "action": record.action,
            "object_type": record.object_type, "object_id": record.object_id, "details": record.details}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def record(db: Session, actor: str, action: str, object_type: str = "", object_id: object = "",
           details: dict[str, Any] | None = None) -> AuditRecord:
    """Append one record inside the caller's transaction."""
    head = db.scalars(select(AuditHead).with_for_update()).first()
    if head is None:
        head = AuditHead(id=1, hash=GENESIS, count=0)
        db.add(head)
    entry = AuditRecord(at=utcnow().replace(microsecond=0), actor=actor, action=action, object_type=object_type,
                        object_id=str(object_id), details=details or {}, prev_hash=head.hash)
    entry.hash = _digest(head.hash, entry)
    db.add(entry)
    head.hash, head.count = entry.hash, head.count + 1
    db.flush()
    return entry


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
