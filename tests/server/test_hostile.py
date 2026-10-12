"""A message with a markup payload in every field a sender controls, sent
through the web app: no page may turn any of it into markup (spec 7.3)."""

from html.parser import HTMLParser

from phishhawk.server import worker

from conftest import build_eml

P = '"><svg onload=alert(1)>'
APP_TAGS = {"html", "head", "meta", "title", "link", "body", "a", "header", "nav", "form", "input", "span",
            "button", "main", "h1", "h2", "p", "div", "label", "textarea", "table", "caption", "thead", "tbody",
            "tr", "th", "td", "em", "strong", "section", "dl", "dt", "dd", "ul", "li", "details", "summary",
            "iframe", "footer", "script", "select", "option", "fieldset", "legend"}


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
    for path in ("/", "/queue", "/analyses/%d" % analysis, "/audit", "/queue?q=" + P):
        page = alice.get(path).text
        assert "<svg" not in page and "onload=alert" not in page.replace("onload=alert(1)&gt;", ""), path
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
