"""Unit tests for phishing_ioc_extractor — run with: python -m unittest discover tests

Everything here is offline: the VirusTotal and urlscan.io clients are driven by
fake sessions, so the suite never touches the network.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phishing_ioc_extractor as pie  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


class TextHelpers(unittest.TestCase):
    def test_refang_restores_defanged_urls(self):
        self.assertEqual(pie.refang("hxxps://evil[.]com/a"), "https://evil.com/a")
        self.assertEqual(pie.refang("hxxp://evil(.)com"), "http://evil.com")
        self.assertEqual(pie.refang("bad[at]evil[dot]com"), "bad@evil.com")

    def test_defang_only_touches_the_host(self):
        self.assertEqual(
            pie.defang_url("https://evil.com/path.php?a=1.2"),
            "hxxps://evil[.]com/path.php?a=1.2",
        )

    def test_registrable_domain_handles_multi_label_tlds(self):
        self.assertEqual(pie.registrable_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(pie.registrable_domain("a.b.c.example.com"), "example.com")
        self.assertEqual(pie.registrable_domain("185.243.115.22"), "185.243.115.22")

    def test_url_extraction_strips_trailing_punctuation(self):
        found = pie.urls_from_text("Go to https://evil.com/login. Or (https://b.com/x) now")
        self.assertIn("https://evil.com/login", found)
        self.assertIn("https://b.com/x", found)

    def test_url_extraction_upgrades_bare_www(self):
        self.assertEqual(pie.urls_from_text("visit www.evil.com today"), ["http://www.evil.com"])

    def test_html_parsing_captures_href_text_and_resources(self):
        html = ('<a href="https://evil.com/go">https://login.microsoft.com</a>'
                '<img src="https://tracker.tld/p.gif">'
                '<meta http-equiv="refresh" content="0;url=https://evil.com/next">')
        anchors, resources = pie.parse_html(html)
        self.assertEqual(anchors, [("https://evil.com/go", "https://login.microsoft.com")])
        self.assertIn("https://tracker.tld/p.gif", resources)
        self.assertIn("https://evil.com/next", resources)


class PhishingSample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = pie.parse_eml(os.path.join(SAMPLES, "sample_phish.eml"))

    def test_sender_fields(self):
        self.assertEqual(self.parsed.from_address,
                         "security-alert@micros0ft-verify-support.top")
        self.assertEqual(self.parsed.from_domain, "micros0ft-verify-support.top")
        self.assertEqual(self.parsed.reply_to_domain, "mail-secure-recovery.xyz")
        self.assertEqual(self.parsed.return_path_domain, "mail-relay-07.sendgrid-bulk.top")

    def test_auth_results_and_originating_ip(self):
        self.assertEqual(self.parsed.auth.get("spf"), "fail")
        self.assertEqual(self.parsed.auth.get("dkim"), "none")
        self.assertEqual(self.parsed.auth.get("dmarc"), "fail")
        # The private Exchange hop must not be mistaken for the origin.
        self.assertEqual(self.parsed.originating_ip, "185.243.115.22")

    def test_urls_from_every_source(self):
        hosts = {ioc.host for ioc in self.parsed.urls}
        self.assertIn("micros0ft-verify-support.top", hosts)  # body + href
        self.assertIn("bit.ly", hosts)                        # shortener
        self.assertIn("185.243.115.22", hosts)                # raw IP
        self.assertIn("mail-secure-recovery.xyz", hosts)      # List-Unsubscribe header

    def test_link_text_href_mismatch_is_detected(self):
        target = next(i for i in self.parsed.urls
                      if i.host == "micros0ft-verify-support.top" and "login" in i.url)
        self.assertTrue(target.flagged)
        self.assertTrue(any("link text shows" in note for note in target.notes))

    def test_attachment_hashes_and_double_extension(self):
        self.assertEqual(len(self.parsed.attachments), 1)
        attachment = self.parsed.attachments[0]
        self.assertEqual(attachment.filename, "Voicemail_Transcript.pdf.html")
        self.assertEqual(len(attachment.sha256), 64)
        self.assertEqual(len(attachment.md5), 32)
        self.assertTrue(any("double extension" in note for note in attachment.notes))

    def test_verdict_without_any_api_key(self):
        self.assertIn(pie.verdict_of(self.parsed), ("LIKELY PHISHING", "MALICIOUS"))
        self.assertTrue(any(s.severity == "high" for s in self.parsed.signals))

    def test_json_payload_is_serialisable(self):
        payload = pie.to_dict(self.parsed)
        json.dumps(payload)  # must not raise
        self.assertEqual(payload["tool_version"], pie.__version__)
        self.assertIn("verdict", payload)


class BenignSample(unittest.TestCase):
    def test_clean_mail_raises_no_high_signals(self):
        parsed = pie.parse_eml(os.path.join(SAMPLES, "sample_benign.eml"))
        self.assertEqual(parsed.auth.get("spf"), "pass")
        self.assertEqual(pie.verdict_of(parsed), "NO STRONG INDICATORS")
        self.assertFalse([s for s in parsed.signals if s.severity == "high"])
        self.assertFalse([ioc for ioc in parsed.urls if ioc.flagged])


# --------------------------------------------------------------------------
# Enrichment clients, driven by fake sessions
# --------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


VT_MALICIOUS = {
    "data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 2, "harmless": 60,
                                "undetected": 5, "timeout": 0},
        "reputation": -34,
        "last_analysis_date": 1758000000,
    }}
}


class VirusTotalClientTests(unittest.TestCase):
    def test_url_id_matches_virustotal_scheme(self):
        # VT identifies a URL by unpadded base64url of the URL itself.
        self.assertEqual(pie.VirusTotalClient.url_id("http://a.com/"), "aHR0cDovL2EuY29tLw")

    def test_malicious_url_report_is_summarised(self):
        session = _FakeSession([_FakeResponse(200, VT_MALICIOUS)])
        client = pie.VirusTotalClient("key", rate_per_minute=0, session=session)
        report = client.lookup_url("https://evil.com/login")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["malicious"], 7)
        self.assertEqual(report["engines"], 74)
        self.assertTrue(pie.vt_is_malicious(report))
        self.assertTrue(report["link"].startswith("https://www.virustotal.com/gui/url/"))

    def test_results_are_cached_so_duplicate_iocs_cost_one_lookup(self):
        session = _FakeSession([_FakeResponse(200, VT_MALICIOUS)])
        client = pie.VirusTotalClient("key", rate_per_minute=0, session=session)
        client.lookup_url("https://evil.com/login")
        client.lookup_url("https://evil.com/login")
        self.assertEqual(len(session.calls), 1)

    def test_unknown_and_throttled_responses_degrade_gracefully(self):
        session = _FakeSession([_FakeResponse(404), _FakeResponse(429), _FakeResponse(401)])
        client = pie.VirusTotalClient("key", rate_per_minute=0, session=session)
        self.assertEqual(client.lookup_url("https://a.com/1")["status"], "not_found")
        self.assertEqual(client.lookup_url("https://a.com/2")["status"], "rate_limited")
        self.assertEqual(client.lookup_file("f" * 64)["status"], "auth_error")

    def test_file_lookup_uses_sha256_endpoint(self):
        session = _FakeSession([_FakeResponse(200, VT_MALICIOUS)])
        client = pie.VirusTotalClient("key", rate_per_minute=0, session=session)
        digest = "a" * 64
        client.lookup_file(digest)
        self.assertTrue(session.calls[0][0].endswith("/files/" + digest))
        self.assertEqual(session.calls[0][1]["headers"]["x-apikey"], "key")


class UrlScanClientTests(unittest.TestCase):
    def test_search_summarises_prior_scans(self):
        payload = {"total": 3, "results": [
            {"page": {"url": "https://evil.com/"}, "task": {"time": "2026-09-01T10:00:00.000Z"},
             "result": "https://urlscan.io/result/abc/", "verdicts": {"overall": {"malicious": True}}},
            {"page": {"url": "https://evil.com/x"}, "task": {"time": "2026-08-30T10:00:00.000Z"},
             "result": "https://urlscan.io/result/def/", "verdicts": {"overall": {"malicious": False}}},
        ]}
        session = _FakeSession([_FakeResponse(200, payload)])
        client = pie.UrlScanClient(session=session, rate_per_minute=0)
        report = client.search_domain("evil.com")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["malicious_hits"], 1)
        self.assertEqual(report["latest_scan"]["report"], "https://urlscan.io/result/abc/")

    def test_submission_requires_a_key(self):
        client = pie.UrlScanClient(session=_FakeSession([]), rate_per_minute=0)
        self.assertEqual(client.submit("https://evil.com")["status"], "auth_error")

    def test_submission_defaults_to_unlisted(self):
        session = _FakeSession([_FakeResponse(200, {"result": "https://urlscan.io/result/xyz/"})])
        client = pie.UrlScanClient(api_key="k", session=session, rate_per_minute=0)
        report = client.submit("https://evil.com")
        self.assertEqual(report["status"], "submitted")
        self.assertEqual(session.calls[0][1]["json"]["visibility"], "unlisted")


class EnrichmentTests(unittest.TestCase):
    def test_vt_malicious_url_drives_the_verdict_and_summary(self):
        parsed = pie.parse_eml(os.path.join(SAMPLES, "sample_benign.eml"))
        session = _FakeSession([_FakeResponse(200, VT_MALICIOUS)])
        client = pie.VirusTotalClient("key", rate_per_minute=0, session=session)
        pie.enrich(parsed, client, None)
        self.assertEqual(pie.verdict_of(parsed), "MALICIOUS")
        self.assertIn("1 URL found, 1 flagged as malicious by VirusTotal.",
                      pie.summary_sentences(parsed))

    def test_report_renders_without_colour(self):
        parsed = pie.parse_eml(os.path.join(SAMPLES, "sample_phish.eml"))
        text = pie.render_report(parsed, pie.Palette(enabled=False))
        self.assertIn("PHISHING IOC EXTRACTION REPORT", text)
        self.assertNotIn("\033[", text)  # --no-color must emit no ANSI codes


class CliTests(unittest.TestCase):
    def test_offline_run_returns_suspicious_exit_code(self):
        code = pie.main([os.path.join(SAMPLES, "sample_phish.eml"), "--offline",
                         "--no-color", "--quiet"])
        self.assertEqual(code, 1)

    def test_offline_run_on_benign_mail_is_clean(self):
        code = pie.main([os.path.join(SAMPLES, "sample_benign.eml"), "--offline",
                         "--no-color", "--quiet"])
        self.assertEqual(code, 0)

    def test_missing_file_is_reported_not_raised(self):
        code = pie.main(["definitely-not-here.eml", "--offline", "--no-color", "--quiet"])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
