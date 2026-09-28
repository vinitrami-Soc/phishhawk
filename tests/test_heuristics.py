from phishhawk.pipeline import triage_bytes, triage_file

from conftest import build_eml, sample


def labels(a):
    return [s.label for s in a.signals]


def test_classic_phish():
    a = triage_file(sample("sample_phish.eml"))
    assert a.verdict == "LIKELY PHISHING"
    assert {"T1566.002", "T1656", "T1036", "T1036.007", "T1583.001"} <= set(a.techniques)
    assert any("homoglyph lookalike of microsoft" in label for label in labels(a))
    assert any("link text/href mismatch" in label for label in labels(a))


def test_benign_mail_is_quiet():
    a = triage_file(sample("sample_benign.eml"))
    assert a.verdict == "NO STRONG INDICATORS"
    assert a.signals == []
    assert a.iocs() == []


def test_bec_with_passing_auth_is_still_caught():
    a = triage_file(sample("sample_bec_smuggling.eml"))
    assert a.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert a.verdict == "LIKELY PHISHING"
    assert {"T1027.006", "T1036.008", "T1598.002", "T1036.007"} <= set(a.techniques)
    own = [h for h in a.lookalikes if h.target == "example-corp.co.uk"]
    assert own and own[0].method == "homoglyph"


def test_signals_are_deduplicated():
    a = triage_file(sample("sample_phish.eml"))
    assert len(labels(a)) == len(set(labels(a)))


def test_credential_path_on_a_trusted_domain_is_not_flagged():
    a = triage_bytes(build_eml(text="Sign in at https://login.microsoftonline.com/common/login"))
    assert not any("credential-harvesting" in label for label in labels(a))


def test_rtl_override_filename():
    name = "invoice‮fdp.exe"
    a = triage_bytes(build_eml(attachments=[(b"MZ", "application", "octet-stream", name)]))
    assert "T1036.002" in a.techniques


def test_reply_to_diversion():
    eml = build_eml(headers=[("Reply-To", "ceo.private@proton.me")], sender='"CEO" <ceo@corp.example>')
    a = triage_bytes(eml)
    assert ("high", "Reply-To domain (proton[.]me) differs from From domain (corp[.]example)") in \
        [(s.severity, s.label) for s in a.signals]


def severity_of(a, prefix):
    return [s.severity for s in a.signals if s.label.startswith(prefix)]


def test_a_mailing_list_replying_to_itself_is_not_diversion():
    # Real list mail (SpamAssassin ham): the list sets Reply-To to its own address.
    a = triage_bytes(build_eml(sender='"Tim" <timc@2ubh.example>', headers=[
        ("Reply-To", "forteana@yahoogroups.example"),
        ("Mailing-List", "list forteana@yahoogroups.example; contact forteana-owner@yahoogroups.example")]))
    assert a.mailing_list and a.list_domains == ["yahoogroups.example"]
    assert severity_of(a, "Reply-To goes to the mailing list") == ["low"]
    assert severity_of(a, "Reply-To domain") == []
    assert a.verdict == "NO STRONG INDICATORS"


def test_a_list_elsewhere_or_a_bulk_sender_keeps_reply_to_diversion():
    elsewhere = triage_bytes(build_eml(sender='"News" <news@site.example>', headers=[
        ("Reply-To", "person@other.example"), ("List-Post", "<mailto:list@lists.site.example>")]))
    assert severity_of(elsewhere, "Reply-To domain") == ["medium"]
    # List-Id and Precedence: bulk are set by every bulk-mail service, the ones phishers rent included.
    rented = triage_bytes(build_eml(sender='"Bank" <alerts@bank.example>', headers=[
        ("Reply-To", "help@attacker.example"), ("List-Id", "<123.xt.local>"), ("Precedence", "bulk")]))
    assert not rented.mailing_list
    assert severity_of(rented, "Reply-To domain") == ["high"]


def test_a_missing_authentication_header_is_not_scored():
    a = triage_bytes(build_eml())
    assert a.auth == {}
    assert not any("Authentication" in label for label in labels(a))


def mismatch(a):
    return severity_of(a, "link text/href mismatch")


def test_a_click_tracker_is_a_medium_mismatch_and_counts_once():
    html = "".join('<a href="http://clickthru.tracker.example/c?%d">%s</a> ' % (i, site)
                   for i, site in enumerate(("news.example", "builder.example", "shop.example")))
    a = triage_bytes(build_eml(html=html))
    assert mismatch(a) == ["medium"]


def test_a_mismatch_borrowing_a_brand_or_going_somewhere_suspect_is_high():
    brand = triage_bytes(build_eml(html='<a href="https://secure.pay-help.example/">paypal.com</a>'))
    assert mismatch(brand) == ["high"]
    government = triage_bytes(build_eml(html='<a href="https://x.example/">detran.gov.br</a>'))
    assert mismatch(government) == ["high"]
    suspect = triage_bytes(build_eml(html='<a href="https://pay.example.top/">shop.example</a>'))
    assert mismatch(suspect) == ["high"]


def test_an_address_in_link_text_is_not_a_claimed_website():
    a = triage_bytes(build_eml(
        html='This was sent to <a href="http://lists.example/unsubscribe">you@example-corp.co.uk</a>'))
    assert mismatch(a) == []


def test_iocs_skip_trusted_shorteners_and_freemail_domains():
    a = triage_file(sample("sample_phish.eml"))
    values = {(i["type"], i["value"]) for i in a.iocs()}
    assert ("domain", "micros0ft-verify-support.top") in values
    assert ("url", "https://bit.ly/3xQvErT") in values           # the URL is blockable...
    assert ("domain", "bit.ly") not in values                     # ...the shortener is not
    assert not any("microsoftonline" in v for _, v in values)     # the decoy stays out
    assert ("ipv4", "185.243.115.22") in values
    assert any(t == "sha256" for t, _ in values)


def test_no_url_no_attachment_mail_hints_at_bec():
    a = triage_bytes(build_eml(text="Can you process a wire transfer today? Reply asap."))
    assert any("possible BEC" in label for label in labels(a))
