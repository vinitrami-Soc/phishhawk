"""DNS lookups of the sender's domain, over Cloudflare's DNS over HTTPS (JSON)."""


from phishhawk.enrich import Dns, Enricher
from phishhawk.pipeline import triage_bytes

from conftest import FakeResponse, FakeSession, build_eml

MX = {"Status": 0, "Answer": [{"name": "inside.crevax-mail.top.", "type": 15, "TTL": 300,
                               "data": "10 mx1.crevax-mail.top."}]}
NO_RECORDS = {"Status": 0, "Answer": []}
NXDOMAIN = {"Status": 3}
A = {"Status": 0, "Answer": [{"name": "x.", "type": 1, "TTL": 300, "data": "185.243.115.22"}]}


def answering(table):
    """table: {(name, type): payload}; anything else has no records."""
    def respond(method, url, kwargs):
        params = kwargs["params"]
        return FakeResponse(200, table.get((params["name"], params["type"]), NO_RECORDS))
    return FakeSession(respond)


def test_a_domain_s_mail_servers_are_read_from_its_mx_records():
    session = answering({("inside.crevax-mail.top", "MX"): MX})
    record = Dns(session=session, rate_per_minute=0).records("inside.crevax-mail.top")
    assert record == {"status": "ok", "exists": True, "mx": ["mx1.crevax-mail.top"], "address": False}
    method, url, kwargs = session.calls[0]
    assert (method, url) == ("get", "https://cloudflare-dns.com/dns-query")
    assert kwargs["headers"]["Accept"] == "application/dns-json"
    assert len(session.calls) == 1  # with an MX record there is no need to ask for an address


def test_without_mx_records_an_address_record_still_receives_mail():
    session = answering({("crevax-mail.top", "A"): A})
    assert Dns(session=session, rate_per_minute=0).records("crevax-mail.top") == \
        {"status": "ok", "exists": True, "mx": [], "address": True}


def test_a_name_that_does_not_exist_is_reported_as_such():
    session = answering({("gone.top", "MX"): NXDOMAIN})
    assert Dns(session=session, rate_per_minute=0).records("gone.top") == {"status": "ok", "exists": False}


def test_a_resolver_failure_is_not_taken_for_a_missing_domain():
    session = FakeSession(lambda m, u, k: FakeResponse(200, {"Status": 2}))  # SERVFAIL
    assert Dns(session=session, rate_per_minute=0).records("x.top")["status"] == "error"


def phish(sender):
    return build_eml(subject="Invoice overdue", sender=sender,
                     text="Pay the overdue invoice today: wire transfer.")


def test_a_sender_domain_that_does_not_exist_is_a_medium_signal():
    enricher = Enricher(dns=Dns(session=answering({("ghost-billing.top", "MX"): NXDOMAIN}), rate_per_minute=0))
    a = triage_bytes(phish('"Billing" <billing@ghost-billing.top>'), enricher=enricher)
    assert a.dns_intel["ghost-billing.top"] == {"status": "ok", "exists": False}
    assert ("medium", "sender domain ghost-billing[.]top does not exist in DNS") in \
        [(s.severity, s.label) for s in a.signals]


def test_a_sender_domain_that_cannot_receive_mail_is_a_low_signal():
    enricher = Enricher(dns=Dns(session=answering({}), rate_per_minute=0))
    a = triage_bytes(phish('"Billing" <billing@no-mx-billing.top>'), enricher=enricher)
    assert ("low", "sender domain no-mx-billing[.]top has no mail server (no MX or A record)") in \
        [(s.severity, s.label) for s in a.signals]


def test_a_sender_domain_with_a_mail_server_raises_nothing():
    enricher = Enricher(dns=Dns(session=answering({("inside.crevax-mail.top", "MX"): MX}), rate_per_minute=0))
    a = triage_bytes(phish('"Billing" <billing@inside.crevax-mail.top>'), enricher=enricher)
    assert a.dns_intel["inside.crevax-mail.top"]["exists"] is True
    assert not any("in DNS" in s.label or "mail server" in s.label for s in a.signals)


def test_free_mail_brands_and_your_own_domains_are_never_looked_up():
    session = answering({})
    enricher = Enricher(dns=Dns(session=session, rate_per_minute=0))
    triage_bytes(phish('"A" <a.person@gmail.com>'), enricher=enricher)
    triage_bytes(build_eml(sender='"IT" <it@example-corp.co.uk>', to="staff@example-corp.co.uk"),
                 enricher=enricher)
    triage_bytes(build_eml(sender='"Microsoft" <account-security-noreply@microsoft.com>'), enricher=enricher)
    assert session.calls == []


def test_dns_is_a_provider_the_web_app_and_the_command_line_know():
    from phishhawk.analysis import PROVIDERS
    from phishhawk.cli import build_parser
    from phishhawk.report.common import PROVIDER_NAMES
    assert "dns" in PROVIDERS and PROVIDER_NAMES["dns"] == "DNS"
    args = build_parser().parse_args(["scan", "x.eml", "--no-dns"])
    assert args.no_dns is True


def test_the_html_report_lists_the_dns_answer():
    from phishhawk.report import html
    enricher = Enricher(dns=Dns(session=answering({("ghost-billing.top", "MX"): NXDOMAIN}), rate_per_minute=0))
    a = triage_bytes(phish('"Billing" <billing@ghost-billing.top>'), enricher=enricher)
    page = html.render([a])
    assert "DNS records" in page and "Does not exist" in page
