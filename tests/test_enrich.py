import datetime as dt

import pytest

from phishhawk.cache import Cache
from phishhawk.enrich import AbuseIPDB, Enricher, RateLimiter, Rdap, UrlScan, VirusTotal
from phishhawk.models import vt_is_malicious, vt_is_suspicious
from phishhawk.pipeline import triage_bytes, triage_file
from phishhawk.report.common import summary_sentences

from conftest import FakeResponse, FakeSession, build_eml, sample, vt_stats


def test_vt_url_id_matches_the_v3_scheme():
    assert VirusTotal.url_id("http://a.com/") == "aHR0cDovL2EuY29tLw"


def test_vt_report_is_summarised():
    session = FakeSession(queue=[FakeResponse(200, vt_stats(7, 2, "phishing.o365"))])
    report = VirusTotal("key", rate_per_minute=0, session=session).lookup_url("https://evil.com/")
    assert report["malicious"] == 7 and report["engines"] == 74
    assert report["threat_label"] == "phishing.o365"
    assert report["link"].startswith("https://www.virustotal.com/gui/url/")
    assert session.calls[0][2]["headers"]["x-apikey"] == "key"


@pytest.mark.parametrize("malicious, suspicious, bad, odd", [
    (0, 0, False, False), (1, 0, False, True), (0, 3, False, True), (2, 0, True, False)])
def test_one_engine_is_suspicious_two_is_malicious(malicious, suspicious, bad, odd):
    report = VirusTotal.summarise({"status": "ok", "body": vt_stats(malicious, suspicious)}, "")
    assert vt_is_malicious(report) is bad
    assert vt_is_suspicious(report) is odd


def test_http_failures_are_data_not_crashes():
    def boom(method, url, kwargs):
        raise ConnectionError("proxy said no")
    session = FakeSession(queue=[FakeResponse(404), FakeResponse(429), FakeResponse(401), FakeResponse(500)])
    vt = VirusTotal("key", rate_per_minute=0, session=session)
    assert [vt.lookup_url("https://a.com/%d" % i)["status"] for i in range(4)] == \
        ["not_found", "rate_limited", "auth_error", "error"]
    assert VirusTotal("k", rate_per_minute=0, session=FakeSession(boom)).lookup_file("f" * 64)["status"] == "error"


def test_cache_serves_repeat_lookups_and_never_stores_errors(tmp_path):
    cache = Cache(str(tmp_path / "c.sqlite3"))
    session = FakeSession(queue=[FakeResponse(200, vt_stats(3)), FakeResponse(429),
                                 FakeResponse(200, vt_stats(0))])
    VirusTotal("k", rate_per_minute=0, session=session, cache=cache).lookup_file("a" * 64)
    again = VirusTotal("k", rate_per_minute=0, session=session, cache=cache).lookup_file("a" * 64)
    assert again["cached"] is True and len(session.calls) == 1
    VirusTotal("k", rate_per_minute=0, session=session, cache=cache).lookup_file("b" * 64)  # 429
    retry = VirusTotal("k", rate_per_minute=0, session=session, cache=cache).lookup_file("b" * 64)
    assert retry["status"] == "ok" and len(session.calls) == 3


def test_rate_limiter_waits_once_the_window_is_full():
    slept = []
    limiter = RateLimiter(2, sleep=lambda seconds: (slept.append(seconds), limiter._hits.clear()))
    for _ in range(3):
        limiter.wait()
    assert len(slept) == 1 and 0 < slept[0] <= 60.1


RDAP_BODY = {"events": [{"eventAction": "registration", "eventDate": "2026-09-14T08:00:00Z"}],
             "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [
                 ["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc"]]]}]}


def test_rdap_age_is_computed_at_read_time(tmp_path):
    cache = Cache(str(tmp_path / "c.sqlite3"))
    session = FakeSession(queue=[FakeResponse(200, RDAP_BODY)])
    first = Rdap(today=lambda: dt.date(2026, 9, 23), session=session, cache=cache, rate_per_minute=0)
    record = first.domain_age("evil.top")
    assert record == {"status": "ok", "registered": "2026-09-14", "registrar": "Example Registrar Inc",
                      "link": "https://rdap.org/domain/evil.top", "age_days": 9}
    later = Rdap(today=lambda: dt.date(2026, 12, 23), session=session, cache=cache, rate_per_minute=0)
    assert later.domain_age("evil.top")["age_days"] == 100  # from cache, still correct
    assert len(session.calls) == 1


def test_abuseipdb_mapping():
    body = {"data": {"abuseConfidenceScore": 91, "totalReports": 212, "countryCode": "NL",
                     "isp": "Example Hosting", "isTor": True}}
    session = FakeSession(queue=[FakeResponse(200, body)])
    report = AbuseIPDB("key", session=session, rate_per_minute=0).check_ip("185.243.115.22")
    assert report["score"] == 91 and report["is_tor"] is True
    assert session.calls[0][2]["params"]["ipAddress"] == "185.243.115.22"


def test_urlscan_search_submit_and_key_requirement():
    search = {"total": 3, "results": [
        {"page": {"url": "https://evil.com/"}, "task": {"time": "2026-09-01T10:00:00Z"},
         "result": "https://urlscan.io/result/abc/", "verdicts": {"overall": {"malicious": True}}}]}
    session = FakeSession(queue=[FakeResponse(200, search), FakeResponse(200, {"result": "r"})])
    scan = UrlScan(api_key="k", session=session, rate_per_minute=0)
    report = scan.search_host("evil.com")
    assert report["total"] == 3 and report["malicious_hits"] == 1
    assert scan.submit("https://evil.com/")["status"] == "submitted"
    assert session.calls[1][2]["json"]["visibility"] == "unlisted"
    assert UrlScan(session=FakeSession(), rate_per_minute=0).submit("https://x.com")["status"] == "auth_error"
    ip_session = FakeSession(queue=[FakeResponse(200, {"total": 0, "results": []})])
    UrlScan(session=ip_session, rate_per_minute=0).search_host("185.243.115.22")
    assert ip_session.calls[0][2]["params"]["q"].startswith("page.ip:")


def _responder(method, url, kwargs):
    if "virustotal" in url:
        return FakeResponse(200, vt_stats(9 if "/files/" in url else 0))
    if "rdap" in url:
        return FakeResponse(200, RDAP_BODY)
    if "abuseipdb" in url:
        return FakeResponse(200, {"data": {"abuseConfidenceScore": 91, "totalReports": 5}})
    return FakeResponse(200, {"total": 0, "results": []})


def test_full_enrichment_never_leaks_trusted_or_protected_domains():
    session = FakeSession(_responder)
    common = {"session": session, "rate_per_minute": 0}
    enricher = Enricher(virustotal=VirusTotal("k", **common), urlscan=UrlScan(**common),
                        rdap=Rdap(today=lambda: dt.date(2026, 9, 23), **common),
                        abuseipdb=AbuseIPDB("k", **common))
    a = triage_file(sample("sample_phish.eml"), enricher=enricher)
    contacted = " ".join(url + str(kwargs.get("params", "")) for _, url, kwargs in session.calls)
    assert "microsoftonline" not in contacted
    assert "example-corp" not in contacted
    decoy = next(u for u in a.urls if u.host == "login.microsoftonline.com")
    assert decoy.vt["status"] == "skipped"
    assert a.verdict == "MALICIOUS"
    assert a.domain_intel["micros0ft-verify-support.top"]["age_days"] == 9
    assert any("registered 9 day(s) ago" in s.label for s in a.signals)
    assert any("AbuseIPDB confidence 91%" in s.label for s in a.signals)
    assert "1 attachment found, 1 flagged as malicious by VirusTotal." in summary_sentences(a)
    assert "6 URLs found, 0 flagged as malicious by VirusTotal." in summary_sentences(a)


def test_vt_budget_caps_network_lookups():
    session = FakeSession(lambda m, u, k: FakeResponse(404))
    enricher = Enricher(virustotal=VirusTotal("k", session=session, rate_per_minute=0), vt_budget=2)
    a = triage_file(sample("sample_phish.eml"), enricher=enricher)
    assert len(session.calls) == 2
    assert sum(1 for u in a.urls if (u.vt or {}).get("detail", "").startswith("per-message")) >= 3


RDAP_IP_BODY = {"objectClassName": "ip network", "handle": "NET-192-29-0-0-1", "name": "ORACLE-4",
                "country": "US", "startAddress": "192.29.0.0", "endAddress": "192.29.255.255",
                "cidr0_cidrs": [{"v4prefix": "192.29.0.0", "length": 16}],
                "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"], ["fn", {}, "text", "Oracle Corporation"]]]}]}


def test_rdap_names_who_holds_an_ip_address():
    session = FakeSession(queue=[FakeResponse(200, RDAP_IP_BODY)])
    record = Rdap(session=session, rate_per_minute=0).ip_owner("192.29.103.188")
    assert record == {"status": "ok", "organisation": "Oracle Corporation", "network": "192.29.0.0/16",
                      "name": "ORACLE-4", "country": "US", "link": "https://rdap.org/ip/192.29.103.188"}


def test_the_originating_ip_s_holder_is_looked_up_and_reported():
    session = FakeSession(lambda m, url, k: FakeResponse(200, RDAP_IP_BODY if "/ip/" in url else RDAP_BODY))
    enricher = Enricher(rdap=Rdap(today=lambda: dt.date(2026, 9, 23), session=session, rate_per_minute=0))
    a = triage_file(sample("sample_phish.eml"), enricher=enricher)
    assert a.ip_owner["organisation"] == "Oracle Corporation"
    assert any(url == "https://rdap.org/ip/185.243.115.22" for _, url, _ in session.calls)
    from phishhawk.report import html, markdown
    assert "Oracle Corporation" in markdown.render(a) and "Oracle Corporation" in html.render([a])


def test_a_young_domain_named_only_in_the_text_is_a_medium_signal():
    # A recruitment scam's signature names its website without linking it.
    session = FakeSession(lambda m, url, k: FakeResponse(200, RDAP_BODY))
    enricher = Enricher(rdap=Rdap(today=lambda: dt.date(2026, 9, 23), session=session, rate_per_minute=0))
    a = triage_bytes(build_eml(sender='"A" <a.recruiter@gmail.com>',
                               text="Regards, Adekunle\nMoreGrow Global Search | moregrow-search.top"),
                     enricher=enricher)
    assert a.domain_intel["moregrow-search.top"]["where"] == "named in the text"
    assert ("medium", "the message names moregrow-search[.]top, registered 9 day(s) ago") in \
        [(s.severity, s.label) for s in a.signals]


def test_rdap_does_not_look_up_the_mail_service_a_phish_was_sent_through():
    session = FakeSession(lambda m, url, k: FakeResponse(200, RDAP_BODY))
    enricher = Enricher(rdap=Rdap(today=lambda: dt.date(2026, 9, 23), session=session, rate_per_minute=0))
    triage_bytes(build_eml(sender='"A" <a@inside.crevax-mail.top>', text="Pay https://renew-licence.top/pay",
                           headers=[("Return-Path", "<bounces@phx1.rp.oracleemaildelivery.com>"),
                                    ("List-Unsubscribe", "<https://cell0.track.email.us-phoenix-1.oci.oraclecloud"
                                                         ".com/track/unsubscribe?V=20>")]), enricher=enricher)
    asked = " ".join(url for _, url, _ in session.calls)
    assert "crevax-mail.top" in asked and "renew-licence.top" in asked
    assert "oracleemaildelivery" not in asked and "oraclecloud" not in asked
