"""Key rotation: every tier-1 blob and every stored secret (mailbox credentials too) re-encrypted under
a new key, then one audit record. Run it with the server stopped. What already
opens under the new key is left alone, so it can be run again after a crash;
a value that neither key opens stops it before anything is deleted."""

from __future__ import annotations

import base64

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .crypto import Box, DecryptError
from .models import Analysis, Batch, Mailbox, Message, Setting
from .store import BlobStore


def _blob_ids(db: Session) -> list[str]:
    ids = [m.raw_blob for m in db.scalars(select(Message)) if m.raw_blob]
    for analysis in db.scalars(select(Analysis)):
        ids += [blob for blob in (analysis.data_blob, analysis.state_blob) if blob]
        ids += [f["blob"] for f in analysis.files if f.get("blob")]
    for batch in db.scalars(select(Batch)):
        ids += [f["blob"] for f in batch.files if f.get("blob")]
    return ids


def _resealed(value: str, bound_to: str, old_box: Box, new_box: Box) -> str | None:
    """The value sealed under the new key, or None when it already is."""
    sealed = base64.b64decode(value)
    try:
        new_box.open(sealed, bound_to)
        return None
    except DecryptError:
        pass
    return base64.b64encode(new_box.seal(old_box.open(sealed, bound_to), bound_to)).decode("ascii")


def _reseal_secret(row: Setting, old_box: Box, new_box: Box) -> bool:
    value = _resealed(row.value, "setting:" + row.key.removeprefix("secret:"), old_box, new_box)
    if value is None:
        return False
    row.value = value
    return True


def _reseal_mailbox(mailbox: Mailbox, old_box: Box, new_box: Box) -> bool:
    value = _resealed(mailbox.secret or "", "mailbox:%d" % mailbox.id, old_box, new_box)
    if value is None:
        return False
    mailbox.secret = value
    return True


def rotate(db: Session, store: BlobStore, new_box: Box, actor: str) -> dict[str, int]:
    blobs = sum(store.reseal(blob_id, new_box) for blob_id in _blob_ids(db))
    rows = db.scalars(select(Setting).where(Setting.key.startswith("secret:"))).all()
    secrets = sum(_reseal_secret(row, store.box, new_box) for row in rows if row.value)
    secrets += sum(_reseal_mailbox(m, store.box, new_box) for m in db.scalars(select(Mailbox)) if m.secret)
    counts = {"blobs": blobs, "secrets": secrets}
    if blobs or secrets:
        audit.record(db, actor, "rotate_key", details=counts)
    return counts
