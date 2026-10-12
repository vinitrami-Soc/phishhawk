"""What the worker does with one submission: decrypt the message in memory,
analyse it in a limited child process, then store tier 1 sealed and tier 2
in the database."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..analysis import AnalysisOptions, analyze
from . import appsettings, audit
from .config import ServerSettings
from .crypto import Box
from .db import transaction
from .limits import ChildFailed, LimitExceeded, run_limited
from .models import Analysis, Indicator, Message, Submission
from .store import BlobStore

PROTECTED_TRAITS = ("subject", "display name")  # kept only as HMAC values (spec 5.1)


@dataclass
class Services:
    """Everything a handler needs; the web app and the worker build the same one."""
    settings: ServerSettings
    sessions: sessionmaker[Session]
    box: Box
    store: BlobStore


def child_analyze(raw: bytes, name: str, options: AnalysisOptions) -> dict[str, Any]:
    """Runs in the child process; returns only plain data."""
    result = analyze(raw, name, options)
    return {"data": result.data, "files": [(f.name, f.kind, f.content, f.entry()) for f in result.files],
            "summary": result.summary, "traits": result.traits, "lookups": result.lookups,
            "providers": sorted(options.providers), "state": result.state}


def protect_traits(traits: dict[str, Any], key: bytes) -> dict[str, Any]:
    kept = {"traits": dict(traits["traits"]), "under": traits["under"], "flagged": traits["flagged"]}
    for kind in PROTECTED_TRAITS:
        if kind in kept["traits"]:
            kept["traits"][kind] = sorted(hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
                                          for value in kept["traits"][kind])
    return kept


def process_submission(services: Services, submission_id: int, heartbeat: Any = None) -> None:
    s = services
    with transaction(s.sessions) as db:
        submission = db.get(Submission, submission_id)
        if submission is None or submission.status not in ("queued", "running"):
            return
        message = db.get(Message, submission.message_id)
        if message is None or message.raw_blob is None:
            submission.status, submission.error = "failed", "the message was deleted before it was analysed"
            return
        raw = s.store.get(message.raw_blob)
        options = appsettings.analysis_options(db, s.box, s.settings, submission.offline)
        submission.status = "running"
    try:
        result = run_limited(child_analyze, (raw, "submission %d" % submission_id, options),
                             s.settings.analysis_memory_mb, s.settings.analysis_cpu_seconds, heartbeat)
    except (LimitExceeded, ChildFailed) as exc:
        reason = ("this message exceeded the analysis limits (%s)" % exc if isinstance(exc, LimitExceeded)
                  else "the message could not be analysed: %s" % exc)
        with transaction(s.sessions) as db:
            submission = db.get(Submission, submission_id)
            if submission is not None:
                submission.status, submission.error = "failed", reason
            audit.record(db, "system", "analyze_failed", "submission", submission_id, {"reason": reason})
        return
    data_blob = s.store.put(json.dumps(result["data"], ensure_ascii=False).encode("utf-8"))
    state_blob = s.store.put(result["state"])
    files = [dict(entry, blob=s.store.put(content)) for _, _, content, entry in result["files"]]
    summary = result["summary"]
    with transaction(s.sessions) as db:
        submission = db.get(Submission, submission_id)
        message = db.get(Message, submission.message_id) if submission is not None else None
        if submission is None or message is None:  # deleted while it was being analysed
            for blob in [data_blob, state_blob] + [f["blob"] for f in files]:
                s.store.delete(blob)
            return
        analysis = Analysis(message_id=message.id, submission_id=submission.id,
                            engine_version=summary["engine_version"], report_id=summary["report_id"],
                            verdict=summary["verdict"], score=summary["score"], providers=result["providers"],
                            lookups=result["lookups"], techniques=summary["techniques"],
                            traits=protect_traits(result["traits"], appsettings.trait_key(db, s.box)),
                            files=files, data_blob=data_blob, state_blob=state_blob)
        db.add(analysis)
        db.flush()
        db.add_all(Indicator(analysis_id=analysis.id, type=i["type"], value=i["value"])
                   for i in summary["indicators"])
        message.sender, message.sender_domain = summary["sender"], summary["sender_domain"]
        message.recipient_count = summary["recipient_count"]
        submission.status, submission.error = "done", ""
        audit.record(db, "system", "analyze", "analysis", analysis.id,
                     {"submission": submission.id, "verdict": analysis.verdict,
                      "providers": result["providers"], "lookups": len(result["lookups"])})
