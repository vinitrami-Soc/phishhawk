"""Deleting accounts and workspaces (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md,
section 9). An admin deletes a member of their workspace: what the member submitted stays the workspace's, their
feedback and answers on verdicts go. The server's owner deletes a workspace with everything in it, its blobs
too; an individual deletes their own account, and with it their workspace. The audit log keeps its records: they
are the account of what was done, and the chain must still verify."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .models import Analysis, Batch, Message, Setting, User, Workspace
from .store import BlobStore


def workspaces(db: Session) -> list[dict[str, Any]]:
    """For the owner: each workspace's name, kind and how many members it has, and no one's profile."""
    members = {ws: n for ws, n in db.execute(select(User.workspace_id, func.count()).group_by(User.workspace_id))}
    return [{"id": w.id, "name": w.name, "kind": w.kind, "created_at": w.created_at.isoformat(),
             "members": members.get(w.id, 0)} for w in db.scalars(select(Workspace).order_by(Workspace.id))]


def _blobs(db: Session, workspace_id: int) -> list[str]:
    """Every blob the workspace's rows name: raw messages, reports, saved states, files and combined exports."""
    found: list[str | None] = list(db.scalars(select(Message.raw_blob)
                                              .where(Message.workspace_id == workspace_id)))
    for analysis in db.scalars(select(Analysis).where(Analysis.workspace_id == workspace_id)):
        found += [analysis.data_blob, analysis.state_blob, *(entry.get("blob") for entry in analysis.files)]
    for batch in db.scalars(select(Batch).where(Batch.workspace_id == workspace_id)):
        found += [entry.get("blob") for entry in batch.files]
    return [blob for blob in found if blob]


def delete_workspace(db: Session, store: BlobStore, workspace: Workspace) -> dict[str, Any]:
    """Its rows go by ON DELETE CASCADE, its settings (which name it without a foreign key) here, and its blobs
    from the store. What went, for the audit record."""
    gone = {"workspace": workspace.id, "name": workspace.name, "kind": workspace.kind,
            "members": db.scalar(select(func.count()).select_from(User).where(User.workspace_id == workspace.id)),
            "messages": db.scalar(select(func.count()).select_from(Message)
                                  .where(Message.workspace_id == workspace.id))}
    blobs = _blobs(db, workspace.id)
    db.execute(delete(Setting).where(Setting.workspace_id == workspace.id))
    db.delete(workspace)
    db.flush()
    for blob in blobs:
        store.delete(blob)
    return gone
