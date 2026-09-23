import pytest

from phishtriage.extract import (
    defang_url,
    parse_html,
    refang,
    registrable_domain,
    sniff_type,
    urls_from_pdf,
    urls_from_text,
)


@pytest.mark.parametrize("raw, expected", [
    ("hxxps://evil[.]com/a", "https://evil.com/a"),
    ("hxxp://evil(.)com", "http://evil.com"),
    ("bad[at]evil[dot]com", "bad@evil.com"),
    ("hXXps[:]//evil[.]com", "https://evil.com"),
])
def test_refang(raw, expected):
    assert refang(raw) == expected


def test_defang_touches_only_the_host():
    assert defang_url("https://evil.com/path.php?a=1.2") == "hxxps://evil[.]com/path.php?a=1.2"


@pytest.mark.parametrize("host, expected", [
    ("mail.example.co.uk", "example.co.uk"),
    ("a.b.c.example.com", "example.com"),
    ("185.243.115.22", "185.243.115.22"),
    ("example.com", "example.com"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_url_extraction_trims_punctuation_and_parens():
    found = urls_from_text("Go to https://evil.com/login. Or (https://b.com/x) now")
    assert found == ["https://evil.com/login", "https://b.com/x"]


def test_url_extraction_upgrades_bare_www_and_refangs():
    assert urls_from_text("visit www.evil.com today") == ["http://www.evil.com"]
    assert urls_from_text("see hxxps://evil[.]com/p") == ["https://evil.com/p"]


def test_html_parser_collects_everything_a_phish_hides():
    html = """
      <a href="https://evil.com/go">https://login.microsoft.com</a>
      <img src="https://tracker.tld/p.gif">
      <meta http-equiv="refresh" content="0;url=https://evil.com/next">
      <form action="https://harvest.tld/post" method="POST"><input type="password" name="p"></form>
      <script>window.location.href = "https://evil.com/js"; var x = atob("aGk="); new Blob([x]);</script>
    """
    found = parse_html(html)
    assert found.anchors == [("https://evil.com/go", "https://login.microsoft.com")]
    assert "https://tracker.tld/p.gif" in found.resources
    assert "https://evil.com/next" in found.redirects
    assert "https://evil.com/js" in found.redirects
    assert found.forms == [{"action": "https://harvest.tld/post", "method": "post", "has_password": True}]
    assert found.password_inputs == 1
    assert "base64 decoding (atob)" in found.smuggling_markers
    assert "Blob construction" in found.smuggling_markers


def test_malformed_html_does_not_raise():
    parse_html("<a href='x'><<<script>>>" * 50)


def test_pdf_uri_extraction_handles_escaped_parens():
    data = b"%PDF-1.4\n1 0 obj << /A << /S /URI /URI (https://evil.com/doc\\(1\\)) >> >>\nendobj"
    assert urls_from_pdf(data) == ["https://evil.com/doc(1)"]


@pytest.mark.parametrize("data, expected", [
    (b"MZ\x90\x00", "pe"),
    (b"PK\x03\x04rest", "zip"),
    (b"%PDF-1.7", "pdf"),
    (b"\xef\xbb\xbf<!DOCTYPE html><html>", "html"),
    (b"\x89PNG\r\n", "png"),
    (b"just text", ""),
])
def test_sniff_type(data, expected):
    assert sniff_type(data) == expected
