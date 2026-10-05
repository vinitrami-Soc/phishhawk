"""Campaign correlation: which reported messages belong together, what links
them, who received them and when, all offline."""

import csv
import io
import json

from phishhawk.campaign import correlate, normalise_subject
from phishhawk.cli import main
from phishhawk.pipeline import triage_bytes

from conftest import build_eml


def _mail(subject="Hello", sender="<a@sender.example>", to="alice@corp.example", html=None, text="hi",
          attachments=(), headers=(), date="Mon, 05 Oct 2026 09:00:00 +0000"):
    data = build_eml(subject=subject, sender=sender, to=to, text=text, html=html, attachments=attachments,
                     headers=[("Date", date), *headers])
    return data


def _lure(href):
    """A link in a message PhishHawk judges suspicious or worse: web addresses only link those."""
    return ('<p>Your mailbox is full. Verify your account now or it will be suspended.</p>'
            '<a href="%s">https://outlook.office.com/verify</a>' % href)


def _run(*messages):
    return correlate([("m%d.eml" % i, triage_bytes(data, "m%d.eml" % i)) for i, data in enumerate(messages, 1)])


def _members(cluster):
    return sorted(m["path"] for m in cluster["messages"])


def test_a_shared_attachment_links_otherwise_unrelated_messages():
    doc = (b"%PDF-1.4 invoice", "application", "pdf", "invoice.pdf")
    result = _run(_mail(subject="One", sender="<x@one.example>", attachments=[doc]),
                  _mail(subject="Two", sender="<y@two.example>", attachments=[doc]),
                  _mail(subject="Three", sender="<z@three.example>"))
    [cluster] = result["clusters"]
    assert _members(cluster) == ["m1.eml", "m2.eml"]
    assert cluster["shared"][0]["kind"] == "attachment"
    assert [m["path"] for m in result["unclustered"]] == ["m3.eml"]


def test_a_shared_phishing_domain_links_different_links_and_senders():
    links = [_lure("https://login.evil-portal.example/%s" % path) for path in ("a1", "b2", "c3")]
    result = _run(*[_mail(sender="<s%d@sender%d.example>" % (i, i), html=link) for i, link in enumerate(links)])
    [cluster] = result["clusters"]
    assert cluster["size"] == 3
    assert {"kind": "domain", "value": "evil-portal.example", "messages": 3} in cluster["shared"]


def test_links_are_followed_transitively():
    result = _run(_mail(sender="<a@one.example>", html=_lure("https://evil-portal.example/x")),
                  _mail(sender="<b@crook.example>", html=_lure("https://evil-portal.example/y")),
                  _mail(sender="<b@crook.example>", subject="Other"))
    [cluster] = result["clusters"]
    assert cluster["size"] == 3


def test_well_known_services_do_not_link_unrelated_messages():
    result = _run(
        _mail(sender="<one@gmail.com>", subject="Lunch",
              html='<a href="https://www.microsoft.com/privacy">p</a> <a href="https://bit.ly/abc">s</a>'),
        _mail(sender="<two@gmail.com>", subject="Payroll",
              html='<a href="https://www.microsoft.com/privacy">p</a> <a href="https://bit.ly/xyz">s</a>'),
        _mail(sender="<n@news.example>", subject="Deals",
              html='<a href="https://u123.ct.sendgrid.net/ls/click?upn=1">deal</a>'),
        _mail(sender="<m@shop.example>", subject="Sale",
              html='<a href="https://u123.ct.sendgrid.net/ls/click?upn=2">sale</a>'))
    assert result["clusters"] == []


def test_the_same_free_mail_account_is_the_same_actor():
    result = _run(_mail(sender="<payroll.dept.2026@gmail.com>", subject="Update your details"),
                  _mail(sender="<payroll.dept.2026@gmail.com>", subject="Final notice"))
    [cluster] = result["clusters"]
    assert cluster["shared"][0] == {"kind": "sender", "value": "payroll.dept.2026@gmail.com", "messages": 2}


def test_free_hosting_links_by_host_not_by_provider():
    def page(host):
        return _lure("https://%s.web.app/login" % host)
    result = _run(_mail(sender="<a@one.example>", html=page("acme-billing")),
                  _mail(sender="<b@two.example>", html=page("other-thing")),
                  _mail(sender="<c@three.example>", html=page("acme-billing")))
    [cluster] = result["clusters"]
    assert _members(cluster) == ["m1.eml", "m3.eml"]


def test_a_subject_alone_is_not_enough_but_two_weak_traits_are():
    lone = _run(_mail(subject="Invoice 4471 overdue", sender="<a@one.example>"),
                _mail(subject="RE: Invoice 9120 overdue", sender="<b@two.example>"))
    assert lone["clusters"] == []
    pair = _run(_mail(subject="Invoice 4471 overdue", sender='"Accounts Team" <a@one.example>'),
                _mail(subject="RE: Invoice 9120 overdue", sender='"Accounts Team" <b@two.example>'))
    [cluster] = pair["clusters"]
    kinds = {item["kind"] for item in cluster["shared"]}
    assert kinds == {"subject", "display name"}


def test_subjects_are_normalised():
    assert normalise_subject("RE: Fwd:  Invoice #4471 OVERDUE ") == normalise_subject("Invoice #9120 overdue")
    assert normalise_subject("Hi") == ""  # too short to mean anything


def test_blast_radius_and_first_and_last_sightings():
    doc = (b"%PDF-1.4 x", "application", "pdf", "x.pdf")
    result = _run(_mail(to="Alice <alice@corp.example>, bob@corp.example", attachments=[doc],
                        date="Mon, 05 Oct 2026 09:00:00 +0200"),
                  _mail(to="carol@corp.example, alice@corp.example", attachments=[doc],
                        date="Tue, 06 Oct 2026 18:30:00 +0000"),
                  _mail(to="dave@corp.example", attachments=[doc], date="not a date"))
    [cluster] = result["clusters"]
    assert cluster["recipients"] == ["alice@corp.example", "bob@corp.example", "carol@corp.example",
                                     "dave@corp.example"]
    assert (cluster["first_seen"], cluster["last_seen"]) == ("2026-10-05T07:00:00Z", "2026-10-06T18:30:00Z")


def test_clusters_are_ordered_and_numbered_largest_first():
    a = (b"%PDF-1.4 a", "application", "pdf", "a.pdf")
    b = (b"%PDF-1.4 b", "application", "pdf", "b.pdf")
    result = _run(*[_mail(sender="<s%d@sender%d.example>" % (i, i), attachments=[doc])
                    for i, doc in enumerate([a, b, b, a, b])])
    assert [(c["id"], c["size"]) for c in result["clusters"]] == [("C1", 3), ("C2", 2)]
    assert result["clusters"][0]["worst_verdict"] in ("NO STRONG INDICATORS", "SUSPICIOUS", "LIKELY PHISHING")


def test_a_very_common_weak_trait_is_ignored():
    messages = [_mail(subject="Your account statement", sender='"Customer Service" <x%d@s%d.example>' % (i, i))
                for i in range(6)]
    result = correlate([("m%d" % i, triage_bytes(m, "m%d" % i)) for i, m in enumerate(messages)], weak_cap=5)
    assert result["clusters"] == []


def test_the_command_writes_json_csv_and_markdown(tmp_path, capsys):
    doc = (b"%PDF-1.4 shared", "application", "pdf", "statement.pdf")
    for i in range(3):
        message = _mail(subject="Statement %d" % i, sender="<s%d@x%d.example>" % (i, i),
                        attachments=[doc] if i < 2 else [])
        (tmp_path / ("r%d.eml" % i)).write_bytes(message)
    out = tmp_path / "c.csv"
    md = tmp_path / "c.md"
    assert main(["campaign", str(tmp_path), "--json", "-", "--csv", str(out), "--md", str(md), "--no-color"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["messages"] == 3 and len(payload["clusters"]) == 1
    rows = list(csv.DictReader(io.StringIO(out.read_text())))
    assert sorted(row["cluster"] for row in rows) == ["", "C1", "C1"]
    assert "## Campaign C1" in md.read_text()


def test_the_console_summary_names_each_cluster(tmp_path, capsys):
    doc = (b"%PDF-1.4 shared", "application", "pdf", "statement.pdf")
    for i in range(2):
        (tmp_path / ("r%d.eml" % i)).write_bytes(_mail(attachments=[doc]))
    assert main(["campaign", str(tmp_path), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "C1" in out and "2 messages" in out and "attachment" in out


def test_an_unreadable_input_is_an_error_but_the_rest_is_correlated(tmp_path, capsys):
    (tmp_path / "ok.eml").write_bytes(_mail())
    assert main(["campaign", str(tmp_path / "ok.eml"), str(tmp_path / "missing.eml"), "--no-color"]) == 3
    assert "missing.eml" in capsys.readouterr().err


def test_reserved_and_dotless_domains_never_link():
    result = _run(_mail(sender="<a@one.example>", headers=[("Reply-To", "<no-reply@example.com>")]),
                  _mail(sender="<b@two.example>", headers=[("Reply-To", "<no-reply@example.com>")]),
                  _mail(sender="<contato@correios>", subject="Pedido retido"),
                  _mail(sender="<info@correios>", subject="Outra coisa"))
    assert result["clusters"] == []


def _platform_mail(i, host):
    return _mail(sender="<s%d@sender%d.example>" % (i, i), subject="Message number %d" % i,
                 html=_lure("https://%s/login" % host))


def test_a_platform_shared_by_many_tenants_links_only_by_host():
    hosts = ["tenant%d-abc.a.cloudrun.example" % i for i in range(6)] + ["tenant0-abc.a.cloudrun.example"]
    result = _run(*[_platform_mail(i, host) for i, host in enumerate(hosts)])
    [cluster] = result["clusters"]
    assert _members(cluster) == ["m1.eml", "m7.eml"]
    assert result["platforms"] == [{"domain": "cloudrun.example", "messages": 7, "hosts": 6}]


def test_a_campaign_on_its_own_domain_is_still_one_campaign():
    hosts = ["login.evil-portal.example"] * 5 + ["www.evil-portal.example", "secure.evil-portal.example"]
    result = _run(*[_platform_mail(i, host) for i, host in enumerate(hosts)])
    [cluster] = result["clusters"]
    assert cluster["size"] == 7 and result["platforms"] == []


def test_a_copied_brand_template_image_does_not_link():
    image = '<img src="https://static.xx.cdn-brand.example/rsrc.php/logo.png"> Hello'
    result = _run(_mail(sender="<a@one.example>", subject="First thing here", html=image),
                  _mail(sender="<b@two.example>", subject="Second thing there", html=image))
    assert result["clusters"] == []


def test_registry_zones_link_by_host_even_in_small_numbers():
    result = _run(_mail(sender="<a@alpha.sa.com>", subject="First thing here"),
                  _mail(sender="<b@beta.sa.com>", subject="Second thing there"))
    assert result["clusters"] == []


def test_a_mail_gateways_rewritten_links_do_not_link_a_whole_mailbox():
    def wrapped(target):
        return _lure("https://clicktime.symantec.com/%s?u=https%%3A%%2F%%2F%s" % (target, target))
    result = _run(_mail(sender="<a@one.example>", subject="First thing here", html=wrapped("abc")),
                  _mail(sender="<b@two.example>", subject="Second thing there", html=wrapped("xyz")),
                  _mail(sender="<c@three.example>", subject="Third thing", html=wrapped("abc")))
    [cluster] = result["clusters"]
    assert _members(cluster) == ["m1.eml", "m3.eml"]


def test_an_ordinary_website_in_clean_messages_does_not_link():
    site = '<p>Interesting read: <a href="https://www.news-site.example/story">story</a></p>'
    result = _run(_mail(sender="<a@one.example>", subject="Weekend plans and more", html=site),
                  _mail(sender="<b@two.example>", subject="Minutes of the meeting", html=site))
    assert result["clusters"] == []


def test_a_mailing_lists_own_links_do_not_link_its_posts():
    # Both posts are suspicious (each links to its own raw IP), yet the list's links are the list's.
    footer = '%s<a href="https://lists.club.example/mailman/listinfo/talk">unsubscribe</a>'
    headers = [("List-Id", "<talk.lists.club.example>"), ("List-Post", "<mailto:talk@lists.club.example>"),
               ("List-Unsubscribe", "<https://lists.club.example/mailman/listinfo/talk>")]
    messages = [_mail(sender="<s%d@sender%d.example>" % (i, i), subject=subject, headers=headers,
                      html=footer % _lure("http://198.51.100.%d/login" % i))
                for i, subject in enumerate(("Weekend plans and more", "Minutes of the meeting"))]
    analyses = [triage_bytes(m, "m%d" % i) for i, m in enumerate(messages)]
    assert all(a.verdict != "NO STRONG INDICATORS" and a.mailing_list for a in analyses)
    assert correlate([("m%d" % i, a) for i, a in enumerate(analyses)])["clusters"] == []


def test_web_plumbing_never_links():
    plumbing = ('<p>Schema http://www.w3.org/1999/xhtml and fonts https://fonts.googleapis.com/css2?f=x</p>%s')
    result = _run(_mail(sender="<a@one.example>", subject="First thing here",
                        html=plumbing % _lure("http://198.51.100.1/a")),
                  _mail(sender="<b@two.example>", subject="Second thing there",
                        html=plumbing % _lure("http://198.51.100.2/b")))
    assert result["clusters"] == []


def test_cloud_storage_links_by_bucket():
    def bucket(name, page):
        return _lure("https://storage.googleapis.com/%s/%s.html" % (name, page))
    result = _run(_mail(sender="<a@one.example>", subject="First thing here", html=bucket("koin", "a")),
                  _mail(sender="<b@two.example>", subject="Second thing there", html=bucket("koin", "b")),
                  _mail(sender="<c@three.example>", subject="Third thing", html=bucket("other", "a")))
    [cluster] = result["clusters"]
    assert _members(cluster) == ["m1.eml", "m2.eml"]
    assert {"kind": "host", "value": "storage.googleapis.com/koin", "messages": 2} in cluster["shared"]
