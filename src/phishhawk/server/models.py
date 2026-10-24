"""Database tables. Tier-2 data only: message content lives in encrypted
blobs (store.py), referred to here by blob ID."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Dialect, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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


SERVER = 0  # the workspace_id of settings and audit records that belong to the whole server


class Workspace(Base):
    """An organization or an individual. Every message, analysis, mailbox, setting and user belongs to one, and no
    workspace reads another's (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md)."""
    __tablename__ = "workspaces"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(16))  # "organization" or "individual"
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


def workspace_column(index: bool = True) -> Mapped[int]:
    """The workspace a row belongs to; its rows go with it. Tables with a unique key that starts with it need no
    index of their own."""
    return mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=index)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
    username: Mapped[str] = mapped_column(String(64), unique=True)  # one across the server: it signs in
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # "admin" or "analyst", in its workspace
    owner: Mapped[bool] = mapped_column(Boolean, default=False)  # runs the server: sign-up, server limits
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    onboarded_at: Mapped[dt.datetime | None] = mapped_column(default=None)  # finished or skipped the setup
    email: Mapped[str] = mapped_column(String(254), default="", index=True)  # lowercase; "" for none
    email_verified_at: Mapped[dt.datetime | None] = mapped_column(default=None)  # its confirmation link opened
    reset_requested_at: Mapped[dt.datetime | None] = mapped_column(default=None)  # the last reset link asked for
    # the profile: seen only inside the workspace
    first_name: Mapped[str] = mapped_column(String(80), default="")
    last_name: Mapped[str] = mapped_column(String(80), default="")
    location: Mapped[str] = mapped_column(String(80), default="")
    job_title: Mapped[str] = mapped_column(String(80), default="")


class Invite(Base):
    """A link that lets one person join an organization, once, within its time. Only the token's SHA-256 is
    kept."""
    __tablename__ = "invites"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(16))
    note: Mapped[str] = mapped_column(String(120), default="")  # "for Priya, SOC team"
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column()
    used_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    used_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class EmailToken(Base):
    """A link sent by email, to confirm an address or to set a new password; it works once, within its time.
    Only the token's SHA-256 is kept."""
    __tablename__ = "email_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))  # "verify" or "reset"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(254))  # the address it was sent to
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column()
    used_at: Mapped[dt.datetime | None] = mapped_column(default=None)


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
    # the same email reported in two workspaces is two messages, each with its own copy, retention and hold
    __table_args__ = (UniqueConstraint("workspace_id", "sha256", name="uq_messages_workspace_sha256"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column(index=False)
    sha256: Mapped[str] = mapped_column(String(64))
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
    workspace_id: Mapped[int] = workspace_column()
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    total: Mapped[int] = mapped_column(Integer)  # messages in it
    status: Mapped[str] = mapped_column(String(16), default="running")  # running, finalizing, done, failed
    error: Mapped[str] = mapped_column(Text, default="")
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)  # combined exports: manifest entries plus "blob"
    files_deleted_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Mailbox(Base):
    """A report mailbox the worker reads, read-only (spec 6.3). Its credential is sealed, bound to its ID."""
    __tablename__ = "mailboxes"
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_mailboxes_workspace_name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column(index=False)
    name: Mapped[str] = mapped_column(String(48))
    kind: Mapped[str] = mapped_column(String(8))  # imap, graph or gmail
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=5)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # where it is; no secret
    secret: Mapped[str | None] = mapped_column(Text, default=None)  # base64 of the sealed credential
    cursor: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # where the last poll stopped
    status: Mapped[str] = mapped_column(String(16), default="never")  # never, ok or error
    error: Mapped[str] = mapped_column(Text, default="")  # sanitised
    failures: Mapped[int] = mapped_column(Integer, default=0)  # in a row
    last_poll_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    next_poll_at: Mapped[dt.datetime | None] = mapped_column(default=None)  # None: due now
    last_counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # imported, duplicates, skipped
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class MailboxItem(Base):
    """A message a mailbox has seen, so it is never imported twice."""
    __tablename__ = "mailbox_items"
    __table_args__ = (UniqueConstraint("mailbox_id", "remote_id", name="uq_mailbox_items_remote"),
                      Index("ix_mailbox_items_message_id_hmac", "message_id_hmac"))
    id: Mapped[int] = mapped_column(primary_key=True)
    mailbox_id: Mapped[int] = mapped_column(ForeignKey("mailboxes.id", ondelete="CASCADE"))
    remote_id: Mapped[str] = mapped_column(String(255))  # IMAP UIDVALIDITY:UID, a Graph or Gmail message ID
    message_id: Mapped[int | None] = mapped_column(ForeignKey("messages.id", ondelete="SET NULL"), default=None)
    message_id_hmac: Mapped[str] = mapped_column(String(64), default="")  # its Message-ID, under the trait key
    outcome: Mapped[str] = mapped_column(String(16))  # imported, duplicate or skipped
    seen_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Submission(Base):
    __tablename__ = "submissions"
    __table_args__ = (Index("ix_submissions_batch", "batch_id", "position"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("batches.id", ondelete="SET NULL"), default=None)
    position: Mapped[int] = mapped_column(Integer, default=0)  # its place in the batch, from 1
    mailbox_id: Mapped[int | None] = mapped_column(ForeignKey("mailboxes.id", ondelete="SET NULL"), default=None)
    source: Mapped[str] = mapped_column(String(16))  # "upload", "paste", "batch" or "mailbox"
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    error: Mapped[str] = mapped_column(Text, default="")
    submitted_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
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
    workspace_id: Mapped[int] = workspace_column()  # rebuilt per workspace: a campaign never mixes two
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
    # when a workspace was last served is read for every waiting job at each claim: from this index, not by
    # reading the workspace's whole history
    __table_args__ = (Index("ix_jobs_status", "status", "id"),
                      Index("ix_jobs_workspace_started", "workspace_id", "started_at"))
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # whose work it is, for fair turns; None for the server's own (the retention sweep)
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), default=None)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued, running, done, failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(default=None)
    finished_at: Mapped[dt.datetime | None] = mapped_column(default=None)


class Feedback(Base):
    """A bug, an idea or a question for the server's owner, from the page it was sent from. It goes with its
    sender's account."""
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # bug, idea, question or other
    message: Mapped[str] = mapped_column(Text)
    page: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open or done (the owner's)
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class VerdictFeedback(Base):
    """One person's word on one analysis's verdict: right, missed (it was phishing) or false_alarm (it was not)."""
    __tablename__ = "verdict_feedback"
    __table_args__ = (UniqueConstraint("analysis_id", "user_id", name="uq_verdict_feedback_analysis_user"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = workspace_column()
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    opinion: Mapped[str] = mapped_column(String(16))
    note: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[dt.datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(default=utcnow)


class Setting(Base):
    __tablename__ = "settings"
    # a workspace's own (providers and their keys, domains, retention), or SERVER's (sign-up, upload limits)
    workspace_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)  # secrets: base64 of a sealed value


class AuditRecord(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    # SERVER for the server's own events; None for records written before workspaces (Default organization's).
    # Not a foreign key: the record outlives a deleted workspace.
    workspace_id: Mapped[int | None] = mapped_column(Integer, default=None, index=True)
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
