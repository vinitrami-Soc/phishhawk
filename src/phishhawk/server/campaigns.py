"""Campaigns: the stored records of the last CAMPAIGN_WINDOW_DAYS correlated
as the CLI's 'phishhawk campaign' does (campaign.correlate_records()),
rebuilt as a whole by one job at a time (spec 6.4). A subject or display name
is kept only as a keyed hash: it is shown in clear while the content of one
of its messages still exists, and so are recipient addresses."""

from __future__ import annotations

import datetime as dt
import email.utils
import hashlib
import hmac
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..analysis import hidden_traits
from ..campaign import correlate_records
from . import jobs, views
from .models import Analysis, Campaign, CampaignMember, Job, Message, utcnow
from .store import BlobStore

HIDDEN = ("subject", "display name")  # kept as HMAC values (processing.protect_traits)


def queue_rebuild(db: Session, workspace_id: int) -> None:
    """At most one rebuild of a workspace waits at a time: it reads every record of the workspace anyway."""
    waiting = db.scalars(select(Job.payload).where(Job.kind == "campaign_rebuild", Job.status == "queued"))
    if not any(payload.get("workspace_id") == workspace_id for payload in waiting):
        jobs.enqueue(db, "campaign_rebuild", {"workspace_id": workspace_id}, workspace_id)


def rebuild(db: Session, workspace_id: int, window_days: int, now: dt.datetime | None = None) -> int:
    """Every campaign of a workspace made again from the latest analysis of each of its messages first seen in the
    window; a campaign never mixes workspaces. A campaign's ID is its oldest message's, so a link to it stays while
    it grows."""
    since = (now or utcnow()) - dt.timedelta(days=window_days)
    latest = (select(func.max(Analysis.id)).join(Message, Analysis.message_id == Message.id)
              .where(Message.workspace_id == workspace_id, Message.first_seen_at >= since)
              .group_by(Analysis.message_id))
    rows = db.execute(select(Analysis, Message).join(Message, Analysis.message_id == Message.id)
                      .where(Analysis.id.in_(latest)).order_by(Message.id)).all()
    records = [{"traits": a.traits.get("traits", {}), "under": a.traits.get("under", {}),
                "flagged": a.traits.get("flagged", a.verdict != "NO STRONG INDICATORS"),
                "date": a.traits.get("date", ""), "verdict": a.verdict, "sender": m.sender,
                "summary": {"path": "%012d" % m.id, "message_id": m.id, "analysis_id": a.id,
                            "recipient_count": m.recipient_count}}
               for a, m in rows]
    result = correlate_records(records)
    mine = select(Campaign.id).where(Campaign.workspace_id == workspace_id)
    db.execute(delete(CampaignMember).where(CampaignMember.campaign_id.in_(mine)))
    db.execute(delete(Campaign).where(Campaign.workspace_id == workspace_id))
    db.flush()
    for cluster in result["clusters"]:
        members = cluster["messages"]
        campaign = Campaign(id=members[0]["message_id"], workspace_id=workspace_id, size=cluster["size"],
                            first_seen=cluster["first_seen"],
                            last_seen=cluster["last_seen"], verdicts=cluster["verdicts"],
                            worst_verdict=cluster["worst_verdict"], shared=cluster["shared"],
                            senders=cluster["senders"],
                            recipient_count=sum(m["recipient_count"] for m in members))
        db.add(campaign)
        db.add_all(CampaignMember(campaign_id=campaign.id, message_id=m["message_id"],
                                  analysis_id=m["analysis_id"]) for m in members)
    return len(result["clusters"])


def _hidden(shared: list[dict[str, Any]], clear: dict[str, str]) -> list[dict[str, Any]]:
    """Shared traits as the pages show them: a hidden one's value is its clear text when known, else None."""
    return [dict(item, value=clear.get(item["value"])) if item["kind"] in HIDDEN else dict(item)
            for item in shared]


def summary(campaign: Campaign) -> dict[str, Any]:
    return {"id": campaign.id, "size": campaign.size, "first_seen": campaign.first_seen,
            "last_seen": campaign.last_seen, "verdicts": campaign.verdicts,
            "worst_verdict": campaign.worst_verdict, "shared": _hidden(campaign.shared, {}),
            "senders": campaign.senders, "recipient_count": campaign.recipient_count,
            "rebuilt_at": campaign.rebuilt_at.isoformat()}


def listing(db: Session, workspace_id: int) -> list[dict[str, Any]]:
    query = (select(Campaign).where(Campaign.workspace_id == workspace_id)
             .order_by(Campaign.size.desc(), Campaign.last_seen.desc(), Campaign.id))
    return [summary(c) for c in db.scalars(query)]


def _recipients(report: dict[str, Any]) -> set[str]:
    try:
        pairs = email.utils.getaddresses([report.get("to") or ""])
    except Exception:  # a malformed To line names nobody
        return set()
    return {address.lower() for _, address in pairs if "@" in address}


def detail(db: Session, store: BlobStore, campaign: Campaign, trait_key: bytes) -> dict[str, Any]:
    rows = db.execute(select(Analysis, Message).join(CampaignMember, CampaignMember.analysis_id == Analysis.id)
                      .join(Message, Message.id == CampaignMember.message_id)
                      .where(CampaignMember.campaign_id == campaign.id).order_by(Message.id)).all()
    clear: dict[str, str] = {}
    recipients: set[str] = set()
    messages = []
    for analysis, message in rows:
        report = views.report_data(store, analysis)
        if report is not None:
            recipients |= _recipients(report)
            for value in hidden_traits(report).values():
                if value:
                    clear[hmac.new(trait_key, value.encode("utf-8"), hashlib.sha256).hexdigest()] = value
        messages.append({"message_id": message.id, "analysis_id": analysis.id, "sha256": message.sha256,
                         "verdict": analysis.verdict, "score": analysis.score, "sender": message.sender,
                         "subject": report["subject"] if report else None,
                         "date": analysis.traits.get("date", "")})
    view = summary(campaign)
    view.update(shared=_hidden(campaign.shared, clear), messages=messages, recipients=sorted(recipients),
                recipients_complete=all(m["subject"] is not None for m in messages))
    return view
