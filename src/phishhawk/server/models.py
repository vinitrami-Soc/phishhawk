"""Database tables. Tier-2 data only: message content lives in encrypted
blobs (store.py), referred to here by blob ID."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Dialect, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class UTCDateTime(TypeDecorator[dt.datetime]):
    """Always an aware UTC datetime in Python, whatever the database keeps
    (SQLite keeps none)."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None:
        return value.astimezone(dt.timezone.utc) if value is not None and value.tzinfo else value

    def process_result_value(self, value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None:
        return value.replace(tzinfo=dt.timezone.utc) if value is not None and value.tzinfo is None else value


class Base(DeclarativeBase):
    type_annotation_map = {dt.datetime: UTCDateTime()}


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # "admin" or "analyst"
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 of the cookie value
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scope: Mapped[str] = mapped_column(String(16))  # "read" or "submit"
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    raw_blob: Mapped[str | None] = mapped_column(String(32))  # None once tier 1 is deleted
    first_seen_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    tier1_deleted_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    deletion_reason: Mapped[str] = mapped_column(String(16), default="")  # "retention" or "manual"
    hold: Mapped[bool] = mapped_column(Boolean, default=False)
    sender: Mapped[str] = mapped_column(String(320), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="")
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)


class Batch(Base):
    """Several messages uploaded together (several files, an .mbox or a .zip), and their combined exports."""
    __tablename__ = "batches"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    total: Mapped[int] = mapped_column(Integer)  # messages in it
    status: Mapped[str] = mapped_column(String(16), default="running")  # running, finalizing, done, failed
    error: Mapped[str] = mapped_column(Text, default="")
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)  # combined exports: manifest entries plus "blob"
    files_deleted_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Submission(Base):
    __tablename__ = "submissions"
    __table_args__ = (Index("ix_submissions_batch", "batch_id", "position"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("batches.id", ondelete="SET NULL"), default=None)
    position: Mapped[int] = mapped_column(Integer, default=0)  # its place in the batch, from 1
    source: Mapped[str] = mapped_column(String(16))  # "upload", "paste", "batch" (M3: "mailbox")
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    error: Mapped[str] = mapped_column(Text, default="")
    submitted_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    submission_id: Mapped[int] = mapped_column(ForeignKey("submissions.id", ondelete="CASCADE"))
    engine_version: Mapped[str] = mapped_column(String(32))
    report_id: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str] = mapped_column(String(32))
    score: Mapped[int] = mapped_column(Integer)
    providers: Mapped[list[Any]] = mapped_column(JSON, default=list)  # provider names asked
    lookups: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{"provider", "method", "url"}]
    techniques: Mapped[list[Any]] = mapped_column(JSON, default=list)
    traits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # campaign record, subject and name as HMAC
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)  # manifest entries plus "blob"
    data_blob: Mapped[str | None] = mapped_column(String(32))  # full JSON report (tier 1)
    state_blob: Mapped[str | None] = mapped_column(String(32), default=None)  # analysis.save_state() (tier 1)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (Index("ix_indicators_value", "value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)


class Campaign(Base):
    """Messages that share infrastructure (campaign.correlate_records()), rebuilt from tier 2 as a whole."""
    __tablename__ = "campaigns"
    # the ID of its oldest message, so a link to the campaign stays while it grows
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    size: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[str] = mapped_column(String(32), default="")  # from the messages' Date lines, ISO
    last_seen: Mapped[str] = mapped_column(String(32), default="")
    verdicts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # verdict -> messages
    worst_verdict: Mapped[str] = mapped_column(String(32))
    shared: Mapped[list[Any]] = mapped_column(JSON, default=list)  # [{kind, value, messages}]; subject: HMAC
    senders: Mapped[list[Any]] = mapped_column(JSON, default=list)
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)  # summed over its messages
    rebuilt_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class CampaignMember(Base):
    __tablename__ = "campaign_members"
    __table_args__ = (Index("ix_campaign_members_message", "message_id"),)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status", "status", "id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)  # secrets: base64 of a sealed value


class AuditRecord(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))  # a username, "system" or "token:<name>"
    action: Mapped[str] = mapped_column(String(48))
    object_type: Mapped[str] = mapped_column(String(32), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditHead(Base):
    """One row: the newest record's hash, so a cut-off tail is noticed too."""
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(primary_key=True)
    hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer)
