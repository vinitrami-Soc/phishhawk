"""A message with a markup payload in every field a sender controls, sent
through the web app: no page may turn any of it into markup (spec 7.3)."""

from html.parser import HTMLParser

from phishhawk.server import worker

from conftest import build_eml

P = '"><svg onload=alert(1)>'
APP_TAGS = {"html", "head", "meta", "title", "link", "body", "a", "header", "nav", "form", "input", "span",
            "button", "main", "h1", "h2", "p", "div", "label", "textarea", "table", "caption", "thead", "tbody",
            "tr", "th", "td", "em", "strong", "section", "dl", "dt", "dd", "ul", "li", "details", "summary",
            "iframe", "footer", "script", "select", "option", "fieldset", "legend", "code", "br"}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = []

    def handle_starttag(self, tag, attrs):
        self.found.append((tag, dict(attrs)))


def _hostile_eml():
    return build_eml(subject=P, sender='"' + P + '" <ceo@evil-login.top>', to=P + " <victim@example-corp.co.uk>",
                     text="see https://evil-login.top/" + P,
                     html='<a href="javascript:alert(1)">' + P + '</a><script>alert(1)</script>',
                     headers=[("Reply-To", P + " <x@evil-login.top>"),
                              ("Message-ID", "<" + P + "@evil-login.top>")],
                     attachments=[(b"<html>" + P.encode(), "text", "html", P + ".html")])


def test_no_page_turns_attacker_text_into_markup(alice, services):
    response = alice.post("/api/v1/submissions", files={"file": ("m.eml", _hostile_eml(), "message/rfc822")},
                          data={"offline": "true"})
    worker.run_one(services)
    analysis = alice.get("/api/v1/submissions/%d" % response.json()["id"]).json()["analysis_id"]
    assert analysis, "the hostile message was not analysed"
    other = _hostile_eml().replace(b"evil-login", b"evil-other")
    batch = alice.post("/api/v1/submissions", data={"offline": "true"},
                       files=[("files", (P + ".eml", _hostile_eml(), "message/rfc822")),
                              ("files", (P + ".eml", other, "message/rfc822"))])
    while worker.run_one(services):
        pass
    [campaign] = alice.get("/api/v1/campaigns").json()  # the three share their attachment
    assert campaign["size"] == 3
    shown = alice.get("/api/v1/campaigns/%d" % campaign["id"]).json()["shared"]
    assert any(s["kind"] == "subject" and "<svg onload" in s["value"] for s in shown)  # in clear, as text
    for path in ("/", "/queue", "/analyses/%d" % analysis, "/audit", "/queue?q=" + P,
                 "/batches/%d" % batch.json()["batch_id"], "/campaigns", "/campaigns/%d" % campaign["id"]):
        page = alice.get(path).text
        text = page.replace("onload=alert(1)&gt;", "").replace("onload=alert(#)&gt;", "")  # escaped: text
        assert "<svg" not in page and "onload=alert" not in text, path
        parser = _Tags()
        parser.feed(page)
        for tag, attrs in parser.found:
            assert tag in APP_TAGS, (path, tag)
            assert not [name for name in attrs if name.startswith("on")], (path, tag, attrs)
            if tag == "script":
                assert attrs == {"src": "/static/app.js"}, (path, attrs)
            for name in ("href", "src", "action"):
                if name in attrs:
                    assert attrs[name].startswith(("/", "#", "?")), (path, tag, attrs)
