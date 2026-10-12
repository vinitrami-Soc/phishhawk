"""The engine as one call: what the web app gets back for one message."""

import hashlib
import json

from phishhawk import analysis
from phishhawk.analysis import AnalysisOptions, analyze

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
