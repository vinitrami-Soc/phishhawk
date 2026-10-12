"""A submission from upload to stored analysis, through the worker."""

import io
import json
import time
import zipfile

import pytest
from sqlalchemy import select

from phishhawk.server import audit, intake, retention, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis, Indicator, Job, Message, Submission

from conftest import build_eml, sample


def _raw(name="sample_bec_smuggling.eml"):
    with open(sample(name), "rb") as handle:
        return handle.read()


def _submit(services, raw=None, offline=True):
    with transaction(services.sessions) as s:
        return intake.accept(s, services.store, raw or _raw(), source="upload", user_id=None, actor="alice",
                             offline=offline, max_bytes=25 * 1024 * 1024).id


def test_intake_refuses_what_is_not_a_message(services):
    with transaction(services.sessions) as s:
        for raw, status in ((b"", 400), (b"%PDF-1.7\n", 415), (b"x" * 30, 415)):
            with pytest.raises(intake.IntakeError) as caught:
                intake.accept(s, services.store, raw, source="paste", user_id=None, actor="a", offline=True,
                              max_bytes=1000)
            assert caught.value.status == status
        with pytest.raises(intake.IntakeError) as caught:
            intake.accept(s, services.store, _raw(), source="upload", user_id=None, actor="a", offline=True,
                          max_bytes=100)
        assert caught.value.status == 413


def test_the_same_message_twice_is_one_message_with_two_submissions(services):
    _submit(services)
    _submit(services)
    with transaction(services.sessions) as s:
        assert len(s.scalars(select(Message)).all()) == 1
        assert len(s.scalars(select(Submission)).all()) == 2
        assert len(s.scalars(select(Job)).all()) == 2


def test_the_worker_analyses_a_submission_and_stores_both_tiers(services):
    submission_id = _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        submission = s.get(Submission, submission_id)
        assert submission.status == "done", submission.error
        analysis = s.scalars(select(Analysis)).one()
        assert analysis.verdict == "LIKELY PHISHING" and analysis.report_id.startswith("PH-")
        assert [f["kind"] for f in analysis.files] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]
        assert analysis.providers == [] and analysis.lookups == []
        report = json.loads(services.store.get(analysis.data_blob))
        assert report["verdict"] == "LIKELY PHISHING"
        html = services.store.get(next(f["blob"] for f in analysis.files if f["kind"] == "html"))
        assert b"<!doctype html>" in html
        assert s.scalars(select(Indicator).where(Indicator.value == "examp1e-corp.co.uk")).first() is not None
        message = s.get(Message, submission.message_id)
        assert message.sender == "it-servicedesk@examp1e-corp.co.uk" and message.recipient_count == 1
        # subject and display name are kept only as HMAC values
        traits = analysis.traits["traits"]
        assert all(len(v) == 64 for v in traits["subject"] + traits["display name"])
        assert "password expires" not in json.dumps(traits) and "IT Service Desk" not in json.dumps(traits)
        assert [r.action for r in s.scalars(select(audit.AuditRecord))] == ["submit", "analyze"]


def test_a_message_that_breaks_the_limits_fails_safely(services, monkeypatch):
    services.settings.analysis_memory_mb = 64  # far too little for the engine
    submission_id = _submit(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        submission = s.get(Submission, submission_id)
        assert submission.status == "failed" and "limits" in submission.error
        assert s.scalars(select(Analysis)).first() is None


def test_retention_deletes_tier1_keeps_tier2_and_skips_held_messages(services):
    held_id, kept_id = _submit(services), _submit(services, _raw("sample_phish.eml"))
    worker.run_one(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        for message in s.scalars(select(Message)):
            message.first_seen_at = message.first_seen_at.replace(year=2000)
        s.get(Message, s.get(Submission, held_id).message_id).hold = True
        raw_blob = s.get(Message, s.get(Submission, kept_id).message_id).raw_blob
    with transaction(services.sessions) as s:
        assert retention.sweep(s, services.store, days=30) == 1
    with transaction(services.sessions) as s:
        gone = s.get(Message, s.get(Submission, kept_id).message_id)
        assert gone.raw_blob is None and gone.deletion_reason == "retention"
        analysis = s.scalars(select(Analysis).where(Analysis.message_id == gone.id)).one()
        assert analysis.data_blob is None and all(f["blob"] is None for f in analysis.files)
        assert analysis.verdict == "LIKELY PHISHING" and analysis.traits  # tier 2 stays
        assert not services.store._path(raw_blob).exists()
        held = s.get(Message, s.get(Submission, held_id).message_id)
        assert held.raw_blob is not None and services.store._path(held.raw_blob).exists()


def test_delete_completely_removes_tier2_but_audit_keeps_the_hash(services):
    submission_id = _submit(services)
    worker.run_one(services)
    with transaction(services.sessions) as s:
        message = s.get(Message, s.get(Submission, submission_id).message_id)
        sha256 = retention.delete_completely(s, services.store, message)
        audit.record(s, "admin", "delete_completely", "message", message.id, {"sha256": sha256})
    with transaction(services.sessions) as s:
        assert s.scalars(select(Message)).first() is None
        assert s.scalars(select(Analysis)).first() is None and s.scalars(select(Indicator)).first() is None
        assert audit.verify(s) == []


def test_a_decompression_bomb_stays_inside_the_limits_and_the_worker_carries_on(services):
    """The engine's read budgets stop the unpacking long before the child's
    512 MB memory limit; the message is analysed and the next one is too."""
    services.settings.analysis_memory_mb = 512
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("invoice.pdf", b"\0" * (300 * 1024 * 1024))  # 300 MB of zeros, under 1 MB packed
    bomb = build_eml(subject="Invoice", attachments=[(packed.getvalue(), "application", "zip", "invoice.zip")])
    bomb_id, normal_id = _submit(services, bomb), _submit(services, _raw("sample_phish.eml"))
    started = time.monotonic()
    assert worker.run_one(services) and worker.run_one(services)
    assert time.monotonic() - started < 60
    with transaction(services.sessions) as s:
        bomb_status = s.get(Submission, bomb_id)
        assert bomb_status.status == "done", bomb_status.error
        assert s.get(Submission, normal_id).status == "done"
