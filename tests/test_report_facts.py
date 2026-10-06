"""Facts every report format shares: what to do next, whether the analysis
was complete, whose authentication results were read, and what the report
cannot tell. HTML, Markdown and JSON take them from one place, so they agree."""

import copy
import json
import os

import pytest

from phishhawk.models import MIME_TOO_DEEP, UrlIoc
from phishhawk.pipeline import Options, triage_bytes, triage_file
from phishhawk.report import markdown
from phishhawk.report.common import analysis_status, limitations, recommendations, to_dict

from conftest import build_eml, sample

AUTH = ("mx.example-corp.co.uk; spf=fail smtp.mailfrom=sender.example; dkim=none; "
        "dmarc=fail header.from=sender.example")


@pytest.fixture(scope="module")
def phish():
    return triage_file(sample("sample_phish.eml"))


@pytest.fixture(scope="module")
def benign():
    return triage_file(sample("sample_benign.eml"))


def test_actions_never_read_as_automatic_or_destructive():
    # PhishHawk is read-only: an action is something the analyst does, after
    # confirming, through the organisation's own process.
    for name in ("sample_phish.eml", "sample_bec_smuggling.eml", "sample_quishing.eml", "sample_reported.eml"):
        actions = recommendations(triage_file(sample(name)))
        text = " ".join(actions).lower()
        assert "purge" not in text and "hold the message in quarantine" not in text
        if triage_file(sample(name)).verdict in ("LIKELY PHISHING", "MALICIOUS"):
            assert actions[0].startswith("Search every mailbox for copies")
            assert "approved" in actions[0] and "phishhawk sweep" in actions[0]
            assert any(a.startswith("After confirming them, block") for a in actions)


def test_a_fully_read_message_is_complete(benign):
    assert analysis_status(benign) == {"status": "complete", "reasons": [],
                                       "reputation": "not checked",
                                       "reputation_detail": "offline: no reputation service was asked"}


def test_an_incomplete_analysis_says_what_was_not_checked(phish):
    partial = copy.deepcopy(phish)
    partial.urls_dropped = 3
    partial.mime_depth = MIME_TOO_DEEP
    status = analysis_status(partial)
    assert status["status"] == "incomplete"
    assert any("3 links" in r and "not checked" in r for r in status["reasons"])
    assert any("MIME" in r for r in status["reasons"])


def test_reputation_status_separates_failed_lookups_from_clean_ones(phish):
    checked = copy.deepcopy(phish)
    checked.enrichment_sources = ["virustotal"]
    checked.urls = [UrlIoc(url="http://a.example/", host="a.example", domain="a.example",
                           vt={"status": "ok", "malicious": 0})]
    assert analysis_status(checked)["reputation"] == "checked"
    checked.urls.append(UrlIoc(url="http://b.example/", host="b.example", domain="b.example",
                               vt={"status": "rate_limited", "detail": "virustotal quota exhausted"}))
    status = analysis_status(checked)
    assert status["reputation"] == "partially checked"
    assert "1 lookup failed" in status["reputation_detail"]
    assert status["status"] == "complete"  # the message itself was read in full


def test_limitations_follow_the_message(phish, benign):
    notes = " ".join(limitations(phish))
    assert "investigation aid" in notes
    assert "does not mean an indicator is safe" in notes  # offline: no reputation data
    assert "proxy and EDR" in notes  # the message has links
    assert "Authentication-Results" in notes
    assert "does not prove who wrote the message" in notes  # it carries a SHA-256
    assert "proxy and EDR" not in " ".join(limitations(triage_bytes(build_eml(text="no links here"))))


def test_the_authentication_source_is_recorded():
    eml = build_eml(headers=[("Authentication-Results", AUTH)])
    a = triage_bytes(eml)
    assert (a.auth_header, a.auth_receiver, a.auth_pinned) == ("Authentication-Results", "mx.example-corp.co.uk",
                                                                False)
    pinned = triage_bytes(eml, options=Options(trusted_authserv=["mx.example-corp.co.uk"]))
    assert (pinned.auth_receiver, pinned.auth_pinned) == ("mx.example-corp.co.uk", True)
    # Exchange Online names no server: the first clause is already a result
    exo = triage_bytes(build_eml(headers=[("Authentication-Results", "spf=pass (sender IP is 192.0.2.1) "
                                                                     "smtp.mailfrom=sender.example; dmarc=pass")]))
    assert (exo.auth_header, exo.auth_receiver) == ("Authentication-Results", "")
    spf_only = triage_bytes(build_eml(headers=[("Received-SPF", "pass (domain of sender.example) "
                                                                "envelope-from=a@sender.example")]))
    assert (spf_only.auth_header, spf_only.auth_receiver) == ("Received-SPF", "")
    assert (triage_bytes(build_eml()).auth_header, triage_bytes(build_eml()).auth_receiver) == ("", "")


def test_json_carries_the_shared_facts_and_matches_the_schema(phish):
    jsonschema = pytest.importorskip("jsonschema")
    payload = json.loads(json.dumps(to_dict(phish)))
    assert payload["analysis_status"]["status"] == "complete"
    assert payload["limitations"] == limitations(phish)
    with open(os.path.join(os.path.dirname(__file__), "..", "docs", "report.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.validate(payload, schema)
    payload["analysis_status"]["status"] = "mostly"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)


def test_markdown_shows_the_shared_facts(phish):
    text = markdown.render(phish)
    assert "| **Analysis** | Complete |" in text
    assert "| **Reputation** | Not checked (offline: no reputation service was asked) |" in text
    assert "### Limitations" in text and limitations(phish)[0] in text
    assert "Purge" not in text
