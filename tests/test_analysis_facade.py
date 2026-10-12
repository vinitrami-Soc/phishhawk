"""The engine as one call: what the web app gets back for one message."""

import hashlib
import json

import pytest

from phishhawk import analysis
from phishhawk.analysis import AnalysisOptions, analyze
from phishhawk.report.bundle import render_bundle

from conftest import FakeResponse, FakeSession, sample


def _raw(name):
    with open(sample(name), "rb") as handle:
        return handle.read()


def test_offline_analysis_returns_every_format_the_record_and_no_lookups():
    raw = _raw("sample_bec_smuggling.eml")
    result = analyze(raw, name="bec.eml")
    assert result.analysis.verdict == "LIKELY PHISHING"
    assert [f.kind for f in result.files] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]
    manifest = json.loads(result.files[-1].content)
    assert [f["sha256"] for f in manifest["files"]] == [f.sha256 for f in result.files[:-1]]
    assert result.summary["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result.summary["report_id"].startswith("PH-") and result.summary["recipient_count"] == 1
    assert {"type": "domain", "value": "examp1e-corp.co.uk"} in result.summary["indicators"]
    assert "T1566.001" in result.summary["techniques"]
    assert result.traits["flagged"] and "sender" in result.traits["traits"]
    assert result.lookups == []
    # the record kept after deletion holds no recipient address or subject
    kept = json.dumps(result.summary)
    assert "vinit.rami" not in kept and result.analysis.subject not in kept


def test_every_request_to_a_provider_is_recorded_without_its_key(monkeypatch):
    monkeypatch.setattr(analysis, "new_session", lambda: FakeSession(lambda m, u, k: FakeResponse(404)))
    options = AnalysisOptions(providers=frozenset({"abuseipdb", "rdap"}), keys={"abuseipdb": "SECRET-KEY"})
    result = analyze(_raw("sample_bec_smuggling.eml"), options=options)
    providers = {entry["provider"] for entry in result.lookups}
    assert providers == {"abuseipdb", "rdap"}
    assert any("ipAddress=45.148.10.77" in entry["url"] for entry in result.lookups)
    assert "SECRET-KEY" not in json.dumps(result.lookups)


SAMPLES = ("sample_bec_smuggling.eml", "sample_benign.eml", "sample_phish.eml", "sample_quishing.eml",
           "sample_reported.eml")


@pytest.fixture
def frozen(monkeypatch):
    """Reports name the time they were made, and a STIX bundle has a random ID: both fixed, so renders compare."""
    import datetime as real
    import uuid

    from phishhawk.report import bundle, common, html, markdown, stix

    class Clock(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return real.datetime(2026, 10, 12, 9, 0, tzinfo=real.timezone.utc)

    for module in (common, html, markdown):
        monkeypatch.setattr(module, "utc_now", lambda: "2026-10-12 09:00 UTC")
    monkeypatch.setattr(stix, "_timestamp", lambda: "2026-10-12T09:00:00.000Z")
    monkeypatch.setattr(bundle.datetime, "datetime", Clock)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=1))


def _contents(files):
    return [(f.name, f.content) for f in files]


def test_a_saved_analysis_renders_every_report_as_the_original_does(frozen):
    for name in SAMPLES:
        result = analyze(_raw(name), name=name)
        again = analysis.load_state(result.state)
        assert _contents(render_bundle([again])) == _contents(render_bundle([result.analysis])), name
        # no report shows the body text, so it is not kept
        assert again.body_text == "" and json.loads(result.state)["analysis"]["body_text"] == ""


def test_the_reports_for_several_saved_analyses_are_those_for_the_analyses(frozen):
    results = [analyze(_raw(name), name=name) for name in SAMPLES]
    combined = analysis.render_saved([r.state for r in results])
    assert _contents(combined) == _contents(render_bundle([r.analysis for r in results]))
    assert [f.kind for f in combined] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]


def test_a_state_from_another_format_is_refused():
    with pytest.raises(ValueError):
        analysis.load_state(json.dumps({"version": 99, "analysis": {}}).encode())


def test_the_hidden_traits_of_a_report_are_those_its_record_hides():
    for name in SAMPLES:
        result = analyze(_raw(name), name=name)
        clear = analysis.hidden_traits(result.data)
        for kind in ("subject", "display name"):
            kept = result.traits["traits"].get(kind, [])
            assert ([clear[kind]] if clear[kind] else []) == kept, (name, kind)
