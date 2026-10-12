"""Tier-1 deletion: by the hourly sweep after the retention period, by hand
("Delete now"), or with tier 2 as well ("Delete completely", admins only).
A message on hold is skipped by the sweep."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Analysis, Message, utcnow
from .store import BlobStore


def delete_tier1(db: Session, store: BlobStore, message: Message, reason: str) -> None:
    if message.tier1_deleted_at is not None:
        return
    store.delete(message.raw_blob)
    for analysis in db.scalars(select(Analysis).where(Analysis.message_id == message.id)):
        store.delete(analysis.data_blob)
        store.delete(analysis.state_blob)
        for entry in analysis.files:
            store.delete(entry.get("blob"))
        analysis.data_blob = analysis.state_blob = None
        analysis.files = [dict(entry, blob=None) for entry in analysis.files]
    message.raw_blob = None
    message.tier1_deleted_at, message.deletion_reason = utcnow(), reason


def delete_completely(db: Session, store: BlobStore, message: Message) -> str:
    delete_tier1(db, store, message, "manual")
    sha256 = message.sha256
    db.delete(message)  # submissions, analyses and indicators go with it (ON DELETE CASCADE)
    return sha256


def sweep(db: Session, store: BlobStore, days: int, now: dt.datetime | None = None) -> int:
    cutoff = (now or utcnow()) - dt.timedelta(days=days)
    due = db.scalars(select(Message).where(Message.tier1_deleted_at.is_(None), Message.hold.is_(False),
                                           Message.first_seen_at < cutoff)).all()
    for message in due:
        delete_tier1(db, store, message, "retention")
    return len(due)
