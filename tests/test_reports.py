import csv
import io
import json
import re

import pytest

from phishhawk.pipeline import triage_bytes, triage_file
from phishhawk.report import console, csvout, html, markdown, stix
from phishhawk.report.common import recommendations, to_dict

from conftest import build_eml, sample

HOSTILE_SUBJECT = '<script>alert(1)</script> =HYPERLINK("http://x") | pipe'
HOSTILE_FILE = '"><img src=x onerror=alert(1)>.html'


@pytest.fixture(scope="module")
def phish():
    return triage_file(sample("sample_phish.eml"))


@pytest.fixture(scope="module")
def hostile():
    eml = build_eml(subject=HOSTILE_SUBJECT, text="go https://evil-login.top/verify now",
                    attachments=[(b"<html><form><input type=password></form></html>", "text", "html",
                                  HOSTILE_FILE)])
    return triage_bytes(eml, path="hostile.eml")


def test_console_without_colour_has_no_escape_codes(phish):
    text = console.render(phish, console.Palette(False), verbose=True)
    assert "\033[" not in text
    for section in ("SENDER", "LOOKALIKE DOMAINS", "URLS", "ATTACHMENTS", "SIGNALS", "MITRE ATT&CK", "SUMMARY"):
        assert "-- " + section in text
    assert "MD5    :" in text  # verbose only


def test_colour_codes_never_break_column_alignment():
    """Padding must happen before colouring, or the escape bytes eat it."""
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    text = re.sub(r"\033\[[0-9;]*m", "", console.render(bec, console.Palette(True)))

    def rows(section):
        block = text.split("-- " + section, 1)[1].split("\n\n", 1)[0]
        return [line for line in block.splitlines()[1:] if line.strip()]

    assert all(line[9] == "]" for line in rows("SIGNALS"))                       # "  [medium] ..."
    assert all(line[12] == " " and line[13] != " " for line in rows("MITRE ATT&CK"))
    assert all(line[32:34] == "  " and line[34] != " " for line in rows("LOOKALIKE DOMAINS"))


def test_json_is_complete_and_serialisable(phish):
    payload = json.loads(json.dumps(to_dict(phish)))
    assert payload["verdict"] == "LIKELY PHISHING"
    assert {row["id"] for row in payload["techniques"]} >= {"T1566.002", "T1656"}
    assert payload["iocs"] and payload["recommendations"]
    assert payload["urls"][0]["defanged"].startswith("hxxp")


def test_recommendations_escalate_with_the_evidence():
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    actions = " ".join(recommendations(bec))
    assert "BEC" in actions and "EDR" in actions and "revoke" in actions
    assert recommendations(triage_file(sample("sample_benign.eml")))[0].startswith("Close")


def test_stix_bundle_is_spec_valid_and_deduplicated(phish):
    stix2 = pytest.importorskip("stix2")
    reported = triage_file(sample("sample_reported.eml"))  # same campaign, reported separately
    bundle = stix.build_bundle([phish, reported])
    parsed = stix2.parse(json.loads(json.dumps(bundle)), allow_custom=False)
    indicators = [o for o in parsed.objects if o.type == "indicator"]
    # The forwarded copy carries the same Message-ID: one message, one report,
    # one set of indicators - however many users report it.
    assert len(indicators) == len(phish.iocs())
    assert len([o for o in parsed.objects if o.type == "report"]) == 1
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    two = stix2.parse(json.loads(json.dumps(stix.build_bundle([phish, bec]))), allow_custom=False)
    assert len([o for o in two.objects if o.type == "report"]) == 2
    patterns = {o.pattern for o in indicators}
    assert "[domain-name:value = 'micros0ft-verify-support.top']" in patterns


def test_stix_pattern_escaping():
    assert stix._escape("it's \\ here") == "it\\'s \\\\ here"


def test_html_escapes_attacker_content_and_locks_itself_down(hostile):
    page = html.render([hostile])
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert 'src="http' not in page and "<script" not in page.lower().replace("&lt;script", "")
    assert "https://evil-login.top" not in page  # malicious URLs appear defanged only


def test_html_batch_has_an_index(phish):
    benign = triage_file(sample("sample_benign.eml"))
    page = html.render([phish, benign])
    assert 'href="#msg-1"' in page and 'href="#msg-2"' in page


def test_markdown_escapes_table_pipes(hostile):
    note = markdown.render(hostile)
    assert "\\| pipe" in note
    assert "- [ ] " in note


def test_csv_neutralises_formula_injection(hostile):
    rows = list(csv.DictReader(io.StringIO(csvout.render([hostile]))))
    assert rows, "hostile mail should produce indicators"
    assert all(row["subject"].startswith("'<script>") or row["subject"].startswith("'=")
               or not row["subject"].startswith(("=", "+", "-", "@")) for row in rows)
    formula = triage_bytes(build_eml(subject="=HYPERLINK(\"http://x\")",
                                     text="https://evil-login.top/verify",
                                     headers=[("Reply-To", "a@other.example")]))
    rows = list(csv.DictReader(io.StringIO(csvout.render([formula]))))
    assert rows and all(row["subject"].startswith("'=") for row in rows)
