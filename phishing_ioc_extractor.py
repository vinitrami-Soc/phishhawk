#!/usr/bin/env python3
"""Automated Phishing IOC Extractor.

Parses a suspicious email (.eml) and pulls out the indicators an L1 analyst
needs during phishing triage:

  * sender / return-path / reply-to addresses and their domains
  * SPF, DKIM and DMARC results plus the originating IP from the Received chain
  * every URL in the body (plain text + HTML hrefs, resources, meta refresh)
  * attachment names, sizes and MD5 / SHA1 / SHA256 hashes

It then optionally enriches those indicators with VirusTotal and urlscan.io and
prints a triage-ready summary, e.g. "3 URLs found, 1 flagged as malicious by
VirusTotal."

Usage
-----
    python phishing_ioc_extractor.py samples/sample_phish.eml
    export VT_API_KEY=<your free VirusTotal key>
    python phishing_ioc_extractor.py mail.eml --json report.json
    python phishing_ioc_extractor.py *.eml --offline      # no network at all

Exit codes: 0 = nothing notable, 1 = suspicious, 2 = malicious, 3 = error.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import email.utils
import hashlib
import json
import os
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

__version__ = "1.0.0"

VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
DEFAULT_TIMEOUT = 20
VT_FREE_RATE = 4  # requests/minute allowed by the free VirusTotal API tier

# ---------------------------------------------------------------------------
# Static triage knowledge
# ---------------------------------------------------------------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly",
    "lnkd.in", "s.id", "bl.ink", "short.io",
}

# Extensions that are effectively "open and you are owned" in a mail context.
RISKY_EXTENSIONS = {
    ".html", ".htm", ".shtml", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".ps1", ".bat", ".cmd", ".com", ".exe", ".scr", ".pif", ".cpl", ".msi",
    ".jar", ".lnk", ".iso", ".img", ".vhd", ".one", ".chm", ".reg",
    ".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xll", ".svg",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace"}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "icu", "cfd", "rest", "gq",
    "tk", "ml", "cf", "ga", "work", "fit", "monster", "quest", "sbs", "buzz",
    "live", "shop", "online", "site", "store", "cam", "lol", "ru", "su",
}

CREDENTIAL_WORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "password", "passwd", "auth",
    "authenticate", "recover", "unlock", "validate", "wallet", "mfa", "otp",
    "session", "webmail", "owa", "office365", "docusign", "invoice", "payment",
}

URGENCY_WORDS = {
    "urgent", "immediately", "action required", "final notice", "suspend",
    "suspended", "deactivat", "expire", "expiring", "within 24 hours",
    "verify your account", "unusual activity", "unauthorized", "last warning",
    "payment failed", "overdue", "your account will be", "click here",
    "confirm your identity", "security alert", "password expires",
}

# Brands that are impersonated constantly; used only for display-name checks.
COMMON_BRANDS = {
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com",
                  "microsoftonline.com", "office365.com", "sharepoint.com"},
    "office 365": {"microsoft.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazonses.com"},
    "paypal": {"paypal.com", "paypal.co.uk"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "meta": {"meta.com", "facebook.com", "facebookmail.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"},
    "nhs": {"nhs.uk", "nhs.net"},
    "barclays": {"barclays.co.uk"},
    "hsbc": {"hsbc.co.uk", "hsbc.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

# Two-label public suffixes we care about when guessing a registrable domain.
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "co.za", "com.br", "com.mx", "com.sg", "com.hk", "co.jp",
    "com.tr", "com.cn", "com.tw", "co.kr", "com.my", "co.id", "com.ph",
}

PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|255\.)"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
URL_RE = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>\"'`\\\u00a0]+", re.I)
DOMAINISH_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I
)

# ---------------------------------------------------------------------------
# Small text utilities
# ---------------------------------------------------------------------------

_REFANG_RULES = [
    (re.compile(r"h(?:xx|X X|\*\*)p(s?)\s*(?::|\[:\])//", re.I), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\\\."), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*(?:dot|DOT)\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*(?:at|AT)\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]


def refang(text: str) -> str:
    """Turn analyst-defanged text (hxxp://evil[.]com) back into real URLs."""
    out = text or ""
    for pattern, repl in _REFANG_RULES:
        out = pattern.sub(repl, out)
    return out


def defang_host(host: str) -> str:
    return (host or "").replace(".", "[.]")


def defang_url(url: str) -> str:
    """Make a URL safe to paste into a ticket or a chat window."""
    if not url:
        return ""
    out = re.sub(r"^http(s?)://", lambda m: "hxxp%s://" % m.group(1), url, flags=re.I)
    match = re.match(r"^(hxxps?://|ftp://)([^/?#]+)(.*)$", out, re.I)
    if match:
        return match.group(1) + defang_host(match.group(2)) + match.group(3)
    return defang_host(out)


def host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without pulling in a public-suffix dependency."""
    host = (host or "").lower().strip(".")
    if not host or IPV4_RE.fullmatch(host):
        return host
    labels = host.split(".")
    if len(labels) < 3:
        return host
    if ".".join(labels[-2:]) in MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of_address(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower().rstrip(".")


def _clean_url(raw: str) -> str:
    url = (raw or "").strip().strip("\u200b\u200c\ufeff")
    url = url.rstrip(".,;:!?\"'*_")
    while url and url[-1] in ")]}":
        opener = {")": "(", "]": "[", "}": "{"}[url[-1]]
        if url.count(opener) >= url.count(url[-1]):
            break
        url = url[:-1]
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _usable_url(url: str) -> bool:
    if not url or "://" not in url:
        return False
    scheme = url.split("://", 1)[0].lower()
    if scheme not in ("http", "https", "ftp"):
        return False
    host = host_of(url)
    return bool(host) and ("." in host or host == "localhost")


def urls_from_text(text: str) -> list[str]:
    found = []
    for match in URL_RE.finditer(refang(text or "")):
        url = _clean_url(match.group(0))
        if _usable_url(url):
            found.append(url)
    return found


class _HtmlLinkParser(HTMLParser):
    """Collects <a href> + anchor text, plus src/action/meta-refresh targets."""

    RESOURCE_ATTRS = ("src", "background", "action", "data-href", "poster")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[list[str]] = []
        self.resources: list[str] = []
        self._anchor_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a":
            self.anchors.append([values.get("href", "").strip(), ""])
            self._anchor_depth += 1
        for key in self.RESOURCE_ATTRS:
            if values.get(key):
                self.resources.append(values[key].strip())
        if tag == "meta" and "refresh" in values.get("http-equiv", "").lower():
            match = re.search(r"url\s*=\s*([^;\s]+)", values.get("content", ""), re.I)
            if match:
                self.resources.append(match.group(1).strip("'\" "))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() == "a" and self._anchor_depth:
            self._anchor_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchor_depth:
            self._anchor_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._anchor_depth and self.anchors:
            self.anchors[-1][1] += data


def parse_html(html: str) -> tuple[list[tuple[str, str]], list[str]]:
    parser = _HtmlLinkParser()
    try:
        parser.feed(refang(html or ""))
        parser.close()
    except Exception:  # malformed HTML is the norm in phishing mail
        pass
    anchors = [(href, " ".join(text.split())) for href, text in parser.anchors if href]
    return anchors, parser.resources

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class UrlIoc:
    url: str
    host: str
    domain: str
    sources: list[str] = field(default_factory=list)
    anchor_texts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    flagged: bool = False  # true only for notes that would change triage
    vt: dict[str, Any] | None = None
    urlscan: dict[str, Any] | None = None

    @property
    def defanged(self) -> str:
        return defang_url(self.url)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    notes: list[str] = field(default_factory=list)
    vt: dict[str, Any] | None = None


@dataclass
class Signal:
    severity: str  # high | medium | low
    label: str

    @property
    def weight(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}.get(self.severity, 1)


@dataclass
class ParsedEmail:
    path: str
    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    to: str = ""
    originating_ip: str = ""
    received_hops: int = 0
    auth: dict[str, str] = field(default_factory=dict)
    urls: list[UrlIoc] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    body_emails: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(signal.weight for signal in self.signals)

# ---------------------------------------------------------------------------
# .eml parsing
# ---------------------------------------------------------------------------


def _header(msg: Any, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        return ""
    if value is None:
        return ""
    try:
        return " ".join(str(value).split())
    except Exception:
        return ""


def _decode_part(part: Any) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _auth_results(msg: Any) -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        headers = msg.get_all("Authentication-Results", []) or []
    except Exception:
        headers = []
    for header in headers:
        text = str(header)
        for mechanism in ("spf", "dkim", "dmarc", "compauth"):
            if mechanism in results:
                continue
            match = re.search(r"\b%s\s*=\s*([a-z]+)" % mechanism, text, re.I)
            if match:
                results[mechanism] = match.group(1).lower()
    if "spf" not in results:
        received_spf = _header(msg, "Received-SPF")
        if received_spf:
            results["spf"] = received_spf.split()[0].lower().strip(";")
    return results


def _originating_ip(msg: Any) -> str:
    for header_name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        value = _header(msg, header_name)
        for candidate in IPV4_RE.findall(value):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    try:
        received = [str(h) for h in (msg.get_all("Received", []) or [])]
    except Exception:
        received = []
    # Received headers are newest-first, so the origin is at the bottom.
    for header in reversed(received):
        for candidate in IPV4_RE.findall(header):
            if not PRIVATE_IP_RE.match(candidate):
                return candidate
    return ""


def _collect_bodies(msg: Any) -> tuple[list[str], list[str], list[Any]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachment_parts: list[Any] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = (part.get_content_type() or "").lower()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and content_type not in ("text/plain", "text/html")):
            attachment_parts.append(part)
            continue
        if content_type == "text/plain":
            text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))
        elif filename:
            attachment_parts.append(part)
    return text_parts, html_parts, attachment_parts


def _part_bytes(part: Any) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload:
        return payload
    try:  # message/rfc822 and friends
        return part.as_bytes()
    except Exception:
        return b""


def _add_url(bucket: dict[str, UrlIoc], url: str, source: str, anchor: str = "") -> None:
    url = _clean_url(url)
    if not _usable_url(url):
        return
    key = url.rstrip("/").lower()
    ioc = bucket.get(key)
    if ioc is None:
        host = host_of(url)
        ioc = UrlIoc(url=url, host=host, domain=registrable_domain(host))
        bucket[key] = ioc
    if source not in ioc.sources:
        ioc.sources.append(source)
    if anchor and anchor not in ioc.anchor_texts:
        ioc.anchor_texts.append(anchor)


def parse_eml(path: str) -> ParsedEmail:
    parsed = ParsedEmail(path=path)
    with open(path, "rb") as handle:
        msg = email.message_from_binary_file(handle, policy=email.policy.default)

    parsed.subject = _header(msg, "Subject")
    parsed.date = _header(msg, "Date")
    parsed.message_id = _header(msg, "Message-ID")
    parsed.to = _header(msg, "To")

    display, address = email.utils.parseaddr(_header(msg, "From"))
    parsed.from_display = display
    parsed.from_address = address.lower()
    parsed.from_domain = domain_of_address(address)

    _, reply_to = email.utils.parseaddr(_header(msg, "Reply-To"))
    parsed.reply_to = reply_to.lower()
    parsed.reply_to_domain = domain_of_address(reply_to)

    _, return_path = email.utils.parseaddr(_header(msg, "Return-Path"))
    parsed.return_path = return_path.lower()
    parsed.return_path_domain = domain_of_address(return_path)

    parsed.auth = _auth_results(msg)
    parsed.originating_ip = _originating_ip(msg)
    try:
        parsed.received_hops = len(msg.get_all("Received", []) or [])
    except Exception:
        parsed.received_hops = 0

    text_parts, html_parts, attachment_parts = _collect_bodies(msg)

    bucket: dict[str, UrlIoc] = {}
    for body in text_parts:
        for url in urls_from_text(body):
            _add_url(bucket, url, "body-text")
    for body in html_parts:
        anchors, resources = parse_html(body)
        for href, anchor_text in anchors:
            if href.lower().startswith(("mailto:", "tel:", "cid:", "data:", "#", "javascript:")):
                continue
            _add_url(bucket, href, "html-href", anchor_text)
        for resource in resources:
            if resource.lower().startswith(("cid:", "data:", "#")):
                continue
            _add_url(bucket, resource, "html-resource")
        # Anything the HTML printed as visible text but never linked.
        for url in urls_from_text(re.sub(r"<[^>]+>", " ", body)):
            _add_url(bucket, url, "html-text")

    for header_name in ("List-Unsubscribe", "X-Originating-URL"):
        for url in urls_from_text(_header(msg, header_name)):
            _add_url(bucket, url, "header:%s" % header_name)

    parsed.urls = list(bucket.values())

    for part in attachment_parts:
        data = _part_bytes(part)
        filename = part.get_filename() or "(unnamed)"
        parsed.attachments.append(
            Attachment(
                filename=" ".join(str(filename).split()),
                content_type=(part.get_content_type() or "application/octet-stream"),
                size=len(data),
                md5=hashlib.md5(data).hexdigest(),
                sha1=hashlib.sha1(data).hexdigest(),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )

    body_blob = "\n".join(text_parts + html_parts)
    seen_emails: list[str] = []
    for address in EMAIL_RE.findall(refang(body_blob)):
        address = address.lower()
        if address not in seen_emails:
            seen_emails.append(address)
    parsed.body_emails = seen_emails[:25]

    domains: list[str] = []
    for candidate in [parsed.from_domain, parsed.reply_to_domain, parsed.return_path_domain]:
        if candidate and candidate not in domains:
            domains.append(candidate)
    for ioc in parsed.urls:
        if ioc.host and ioc.host not in domains:
            domains.append(ioc.host)
    parsed.domains = domains

    analyse(parsed, body_blob)
    return parsed

# ---------------------------------------------------------------------------
# Offline heuristics — these run with or without API keys
# ---------------------------------------------------------------------------


def _looks_like_brand_spoof(display: str, from_domain: str) -> str:
    lowered = (display or "").lower()
    base = registrable_domain(from_domain)
    for brand, legit_domains in COMMON_BRANDS.items():
        if brand in lowered and base and base not in legit_domains:
            return brand
    return ""


def analyse(parsed: ParsedEmail, body_blob: str = "") -> None:
    """Attach heuristic signals and per-IOC notes."""
    signals = parsed.signals
    from_base = registrable_domain(parsed.from_domain)

    auth = parsed.auth
    for mechanism, bad_values in (
        ("spf", {"fail", "softfail", "permerror", "temperror", "none"}),
        ("dkim", {"fail", "permerror", "temperror", "none"}),
        ("dmarc", {"fail", "permerror", "temperror"}),
    ):
        value = auth.get(mechanism)
        if value and value in bad_values:
            severity = "high" if value == "fail" else "medium"
            if mechanism == "dmarc" and value == "fail":
                severity = "high"
            signals.append(Signal(severity, "%s=%s" % (mechanism.upper(), value)))
    if not auth:
        signals.append(Signal("low", "no Authentication-Results header present"))

    if parsed.reply_to_domain and from_base and registrable_domain(parsed.reply_to_domain) != from_base:
        signals.append(
            Signal("high", "Reply-To domain (%s) differs from From domain (%s)"
                   % (defang_host(parsed.reply_to_domain), defang_host(parsed.from_domain)))
        )
    if parsed.return_path_domain and from_base and registrable_domain(parsed.return_path_domain) != from_base:
        signals.append(
            Signal("medium", "Return-Path domain (%s) differs from From domain (%s)"
                   % (defang_host(parsed.return_path_domain), defang_host(parsed.from_domain)))
        )

    brand = _looks_like_brand_spoof(parsed.from_display, parsed.from_domain)
    if brand:
        signals.append(
            Signal("high", "display name claims '%s' but the domain is %s"
                   % (brand, defang_host(parsed.from_domain)))
        )
    if EMAIL_RE.search(parsed.from_display or "") and parsed.from_display.lower() != parsed.from_address:
        signals.append(Signal("medium", "display name contains a different email address"))

    subject_lower = (parsed.subject or "").lower()
    hits = sorted({word for word in URGENCY_WORDS if word in subject_lower})
    if hits:
        signals.append(Signal("low", "urgency wording in subject: %s" % ", ".join(hits[:3])))

    if from_base and "xn--" in parsed.from_domain:
        signals.append(Signal("high", "sender domain uses punycode (possible homograph)"))

    for ioc in parsed.urls:
        host = ioc.host
        base = ioc.domain
        if IPV4_RE.fullmatch(host or ""):
            ioc.notes.append("raw IP address instead of a hostname")
            ioc.flagged = True
            signals.append(Signal("high", "URL points at a raw IP: %s" % defang_url(ioc.url)))
        if "xn--" in (host or ""):
            ioc.notes.append("punycode hostname")
            ioc.flagged = True
            signals.append(Signal("high", "punycode URL host: %s" % defang_host(host)))
        if base in SHORTENERS:
            ioc.notes.append("URL shortener")
            ioc.flagged = True
            signals.append(Signal("medium", "shortened link: %s" % defang_url(ioc.url)))
        tld = base.rsplit(".", 1)[-1] if "." in base else ""
        if tld in SUSPICIOUS_TLDS:
            ioc.notes.append("high-abuse TLD .%s" % tld)
            signals.append(Signal("low", "high-abuse TLD in %s" % defang_host(host)))
        path_and_query = (urlsplit(ioc.url).path + "?" + (urlsplit(ioc.url).query or "")).lower()
        cred_hits = sorted({word for word in CREDENTIAL_WORDS if word in path_and_query})
        if cred_hits:
            ioc.notes.append("credential-themed path (%s)" % ", ".join(cred_hits[:3]))
        if len(host.split(".")) >= 5:
            ioc.notes.append("deeply nested subdomains")
        if "@" in ioc.url.split("://", 1)[-1].split("/", 1)[0]:
            ioc.notes.append("userinfo '@' trick in the authority")
            ioc.flagged = True
            signals.append(Signal("high", "URL hides its real host behind '@': %s" % defang_url(ioc.url)))

        # Classic mismatch: the anchor text shows one domain, the href goes elsewhere.
        for anchor_text in ioc.anchor_texts:
            shown = ""
            for candidate in urls_from_text(anchor_text):
                shown = host_of(candidate)
                break
            if not shown:
                match = DOMAINISH_RE.search(anchor_text)
                if match and "." in match.group(0):
                    shown = match.group(0).lower()
            if shown and base and registrable_domain(shown) != base:
                ioc.notes.append("link text shows %s but href goes to %s"
                                 % (defang_host(shown), defang_host(host)))
                ioc.flagged = True
                signals.append(
                    Signal("high", "link text/href mismatch: %s vs %s"
                           % (defang_host(shown), defang_host(host)))
                )
                break

    for attachment in parsed.attachments:
        name = attachment.filename.lower()
        extension = os.path.splitext(name)[1]
        if extension in RISKY_EXTENSIONS:
            attachment.notes.append("high-risk extension %s" % extension)
            signals.append(Signal("high", "risky attachment: %s" % attachment.filename))
        elif extension in ARCHIVE_EXTENSIONS:
            attachment.notes.append("archive — contents unscanned by this tool")
            signals.append(Signal("low", "archive attachment: %s" % attachment.filename))
        if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$", name):
            attachment.notes.append("double extension")
            signals.append(Signal("high", "double extension: %s" % attachment.filename))
        if "\u202e" in attachment.filename:
            attachment.notes.append("right-to-left override character in filename")
            signals.append(Signal("high", "RTL-override filename trick"))

    if body_blob and not parsed.urls and not parsed.attachments:
        signals.append(Signal("low", "no URLs or attachments — possible BEC / reply-chain lure"))

# ---------------------------------------------------------------------------
# Enrichment clients
# ---------------------------------------------------------------------------


class RateLimiter:
    """Naive sliding-window limiter so the free VT tier is not blown through."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(0, int(per_minute))
        self._hits: deque[float] = deque()

    def wait(self) -> None:
        if not self.per_minute:
            return
        while True:
            now = time.monotonic()
            while self._hits and now - self._hits[0] >= 60:
                self._hits.popleft()
            if len(self._hits) < self.per_minute:
                self._hits.append(now)
                return
            time.sleep(max(0.1, 60 - (now - self._hits[0]) + 0.1))


def _requests():
    try:
        import requests  # imported lazily so --offline needs no dependency
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "the 'requests' library is required for enrichment "
            "(pip install -r requirements.txt), or run with --offline"
        ) from exc
    return requests


class VirusTotalClient:
    def __init__(self, api_key: str, rate_per_minute: int = VT_FREE_RATE,
                 timeout: int = DEFAULT_TIMEOUT, session: Any = None) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.limiter = RateLimiter(rate_per_minute)
        self._cache: dict[str, dict[str, Any]] = {}
        self._session = session or _requests().Session()

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _get(self, path: str) -> dict[str, Any]:
        requests = _requests()
        self.limiter.wait()
        try:
            response = self._session.get(
                VT_BASE + path,
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"status": "error", "detail": str(exc)}
        if response.status_code == 404:
            return {"status": "not_found"}
        if response.status_code == 429:
            return {"status": "rate_limited", "detail": "VirusTotal quota exhausted"}
        if response.status_code in (401, 403):
            return {"status": "auth_error", "detail": "VirusTotal rejected the API key"}
        if response.status_code >= 400:
            return {"status": "error", "detail": "HTTP %s" % response.status_code}
        try:
            return {"status": "ok", "body": response.json()}
        except ValueError:
            return {"status": "error", "detail": "invalid JSON from VirusTotal"}

    @staticmethod
    def _summarise(result: dict[str, Any], gui_link: str) -> dict[str, Any]:
        summary: dict[str, Any] = {"status": result["status"], "link": gui_link}
        if result["status"] != "ok":
            if result.get("detail"):
                summary["detail"] = result["detail"]
            return summary
        attributes = (result["body"].get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        summary.update(
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            engines=sum(int(v) for v in stats.values() if isinstance(v, (int, float))),
            reputation=attributes.get("reputation"),
        )
        last_seen = attributes.get("last_analysis_date")
        if last_seen:
            summary["last_analysis"] = time.strftime(
                "%Y-%m-%d %H:%M UTC", time.gmtime(int(last_seen))
            )
        for key in ("meaningful_name", "type_description", "creation_date"):
            if attributes.get(key):
                summary[key] = attributes[key]
        return summary

    def _cached(self, cache_key: str, path: str, gui_link: str) -> dict[str, Any]:
        if cache_key in self._cache:
            return self._cache[cache_key]
        summary = self._summarise(self._get(path), gui_link)
        self._cache[cache_key] = summary
        return summary

    def lookup_url(self, url: str) -> dict[str, Any]:
        identifier = self.url_id(url)
        return self._cached(
            "url:" + identifier,
            "/urls/" + identifier,
            "https://www.virustotal.com/gui/url/" + identifier,
        )

    def lookup_file(self, sha256: str) -> dict[str, Any]:
        return self._cached(
            "file:" + sha256,
            "/files/" + sha256,
            "https://www.virustotal.com/gui/file/" + sha256,
        )

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        return self._cached(
            "domain:" + domain,
            "/domains/" + domain,
            "https://www.virustotal.com/gui/domain/" + domain,
        )


class UrlScanClient:
    """Search-only by default: searching never publishes anything."""

    def __init__(self, api_key: str = "", timeout: int = DEFAULT_TIMEOUT,
                 rate_per_minute: int = 30, session: Any = None) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.limiter = RateLimiter(rate_per_minute)
        self._cache: dict[str, dict[str, Any]] = {}
        self._session = session or _requests().Session()

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        return headers

    def search_domain(self, domain: str) -> dict[str, Any]:
        if domain in self._cache:
            return self._cache[domain]
        requests = _requests()
        self.limiter.wait()
        try:
            response = self._session.get(
                URLSCAN_BASE + "/search/",
                params={"q": 'page.domain:"%s"' % domain, "size": 5},
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            summary = {"status": "error", "detail": str(exc)}
            self._cache[domain] = summary
            return summary
        if response.status_code == 429:
            summary = {"status": "rate_limited", "detail": "urlscan.io quota exhausted"}
        elif response.status_code >= 400:
            summary = {"status": "error", "detail": "HTTP %s" % response.status_code}
        else:
            try:
                body = response.json()
            except ValueError:
                body = {}
            results = body.get("results") or []
            summary = {
                "status": "ok",
                "total": int(body.get("total", len(results))),
                "malicious_hits": sum(
                    1 for item in results
                    if ((item.get("verdicts") or {}).get("overall") or {}).get("malicious")
                ),
                "search_link": "https://urlscan.io/search/#" + domain,
            }
            if results:
                newest = results[0]
                summary["latest_scan"] = {
                    "url": (newest.get("page") or {}).get("url", ""),
                    "time": (newest.get("task") or {}).get("time", ""),
                    "report": newest.get("result", ""),
                }
        self._cache[domain] = summary
        return summary

    def submit(self, url: str, visibility: str = "unlisted") -> dict[str, Any]:
        """Submit a URL for scanning. Requires an API key and opt-in."""
        if not self.api_key:
            return {"status": "auth_error", "detail": "urlscan.io submission needs an API key"}
        requests = _requests()
        self.limiter.wait()
        try:
            response = self._session.post(
                URLSCAN_BASE + "/scan/",
                json={"url": url, "visibility": visibility},
                headers={**self._headers(), "Content-Type": "application/json"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"status": "error", "detail": str(exc)}
        if response.status_code >= 400:
            return {"status": "error", "detail": "HTTP %s" % response.status_code}
        try:
            body = response.json()
        except ValueError:
            return {"status": "error", "detail": "invalid JSON from urlscan.io"}
        return {"status": "submitted", "report": body.get("result", ""),
                "visibility": visibility}


def enrich(parsed: ParsedEmail, vt: VirusTotalClient | None,
           urlscan: UrlScanClient | None, submit_urls: bool = False,
           progress: Any = None) -> None:
    def note(message: str) -> None:
        if progress:
            progress(message)

    if vt:
        for index, ioc in enumerate(parsed.urls, 1):
            note("VirusTotal: URL %d/%d" % (index, len(parsed.urls)))
            ioc.vt = vt.lookup_url(ioc.url)
        for index, attachment in enumerate(parsed.attachments, 1):
            note("VirusTotal: attachment %d/%d" % (index, len(parsed.attachments)))
            attachment.vt = vt.lookup_file(attachment.sha256)

    if urlscan:
        seen: set[str] = set()
        for ioc in parsed.urls:
            if not ioc.host or ioc.host in seen:
                continue
            seen.add(ioc.host)
            note("urlscan.io: %s" % ioc.host)
            ioc.urlscan = urlscan.search_domain(ioc.host)
            if submit_urls:
                ioc.urlscan["submission"] = urlscan.submit(ioc.url)

    for ioc in parsed.urls:
        if vt_is_malicious(ioc.vt):
            parsed.signals.append(
                Signal("high", "VirusTotal flags %s as malicious (%d engines)"
                       % (defang_url(ioc.url), ioc.vt.get("malicious", 0)))
            )
        elif vt_is_suspicious(ioc.vt):
            parsed.signals.append(
                Signal("medium", "VirusTotal flags %s as suspicious" % defang_url(ioc.url))
            )
        if ioc.urlscan and ioc.urlscan.get("malicious_hits"):
            parsed.signals.append(
                Signal("medium", "urlscan.io has malicious verdicts for %s" % defang_host(ioc.host))
            )
    for attachment in parsed.attachments:
        if vt_is_malicious(attachment.vt):
            parsed.signals.append(
                Signal("high", "VirusTotal flags %s as malicious (%d engines)"
                       % (attachment.filename, attachment.vt.get("malicious", 0)))
            )
        elif vt_is_suspicious(attachment.vt):
            parsed.signals.append(
                Signal("medium", "VirusTotal flags %s as suspicious" % attachment.filename)
            )


def vt_is_malicious(report: dict[str, Any] | None) -> bool:
    return bool(report and report.get("status") == "ok" and report.get("malicious", 0) > 0)


def vt_is_suspicious(report: dict[str, Any] | None) -> bool:
    return bool(report and report.get("status") == "ok"
                and not report.get("malicious", 0) and report.get("suspicious", 0) > 0)

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class Palette:
    CODES = {"red": "31;1", "yellow": "33;1", "green": "32;1",
             "cyan": "36;1", "dim": "2", "bold": "1"}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, colour: str) -> str:
        if not self.enabled or colour not in self.CODES:
            return text
        return "\033[%sm%s\033[0m" % (self.CODES[colour], text)


def verdict_of(parsed: ParsedEmail) -> str:
    if any(vt_is_malicious(ioc.vt) for ioc in parsed.urls) or \
       any(vt_is_malicious(a.vt) for a in parsed.attachments):
        return "MALICIOUS"
    high = sum(1 for signal in parsed.signals if signal.severity == "high")
    if high >= 2 or parsed.score >= 6:
        return "LIKELY PHISHING"
    if high or parsed.score >= 3:
        return "SUSPICIOUS"
    return "NO STRONG INDICATORS"


def _short(detail: Any, limit: int = 90) -> str:
    text = " ".join(str(detail or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _vt_line(report: dict[str, Any] | None, colour: Palette) -> str:
    if not report:
        return colour("VT: not queried", "dim")
    status = report.get("status")
    if status == "ok":
        text = "VT: %d/%d malicious" % (report.get("malicious", 0), report.get("engines", 0))
        if report.get("suspicious"):
            text += ", %d suspicious" % report["suspicious"]
        if report.get("last_analysis"):
            text += "  (last scan %s)" % report["last_analysis"]
        if report.get("malicious", 0):
            return colour(text + "  [MALICIOUS]", "red")
        if report.get("suspicious", 0):
            return colour(text + "  [SUSPICIOUS]", "yellow")
        return colour(text + "  [clean]", "green")
    messages = {
        "not_found": "VT: no record — never submitted to VirusTotal",
        "rate_limited": "VT: rate limited (free tier is 4 lookups/min)",
        "auth_error": "VT: API key rejected",
    }
    return colour(messages.get(status, "VT: %s" % _short(report.get("detail", status))), "dim")


def _urlscan_line(report: dict[str, Any] | None, colour: Palette) -> str:
    if not report:
        return ""
    if report.get("status") != "ok":
        return colour("urlscan: %s" % _short(report.get("detail", report.get("status"))), "dim")
    text = "urlscan: %d prior scan(s)" % report.get("total", 0)
    if report.get("malicious_hits"):
        text += ", %d with malicious verdicts" % report["malicious_hits"]
        return colour(text, "yellow")
    latest = report.get("latest_scan") or {}
    if latest.get("time"):
        text += "  (latest %s)" % latest["time"][:10]
    return colour(text, "dim")


def _severity_colour(severity: str) -> str:
    return {"high": "red", "medium": "yellow"}.get(severity, "dim")


def summary_sentences(parsed: ParsedEmail) -> list[str]:
    lines: list[str] = []
    url_count = len(parsed.urls)
    if url_count:
        sentence = "%d URL%s found" % (url_count, "" if url_count == 1 else "s")
        if any(ioc.vt for ioc in parsed.urls):
            flagged = sum(1 for ioc in parsed.urls if vt_is_malicious(ioc.vt))
            sentence += ", %d flagged as malicious by VirusTotal" % flagged
        lines.append(sentence + ".")
    else:
        lines.append("No URLs found in the message body.")

    attachment_count = len(parsed.attachments)
    if attachment_count:
        sentence = "%d attachment%s found" % (attachment_count, "" if attachment_count == 1 else "s")
        if any(a.vt for a in parsed.attachments):
            flagged = sum(1 for a in parsed.attachments if vt_is_malicious(a.vt))
            sentence += ", %d flagged as malicious by VirusTotal" % flagged
        lines.append(sentence + ".")

    domain_count = len({ioc.domain for ioc in parsed.urls if ioc.domain})
    if domain_count:
        lines.append("%d distinct URL domain%s observed."
                     % (domain_count, "" if domain_count == 1 else "s"))
    high = sum(1 for s in parsed.signals if s.severity == "high")
    if high:
        lines.append("%d high-severity heuristic signal%s raised."
                     % (high, "" if high == 1 else "s"))
    return lines


def render_report(parsed: ParsedEmail, colour: Palette, show_all_signals: bool = False) -> str:
    out: list[str] = []
    rule = "=" * 72
    out.append(colour(rule, "cyan"))
    out.append(colour("  PHISHING IOC EXTRACTION REPORT", "cyan"))
    out.append(colour(rule, "cyan"))
    out.append("File       : %s" % parsed.path)
    out.append("Subject    : %s" % (parsed.subject or "(none)"))
    out.append("Date       : %s" % (parsed.date or "(none)"))
    out.append("Message-ID : %s" % (parsed.message_id or "(none)"))
    if parsed.to:
        out.append("To         : %s" % parsed.to)

    out.append("")
    out.append(colour(_section("SENDER"), "bold"))
    out.append("Display name : %s" % (parsed.from_display or "(none)"))
    out.append("From         : %s" % (defang_host(parsed.from_address) or "(none)"))
    out.append("From domain  : %s" % (defang_host(parsed.from_domain) or "(none)"))
    if parsed.reply_to:
        out.append("Reply-To     : %s" % defang_host(parsed.reply_to))
    if parsed.return_path:
        out.append("Return-Path  : %s" % defang_host(parsed.return_path))
    if parsed.originating_ip:
        out.append("Originating  : %s  (%d Received hop(s))"
                   % (defang_host(parsed.originating_ip), parsed.received_hops))
    if parsed.auth:
        auth_bits = []
        for mechanism in ("spf", "dkim", "dmarc", "compauth"):
            if mechanism in parsed.auth:
                value = parsed.auth[mechanism]
                rendered = "%s=%s" % (mechanism, value)
                if value in ("fail", "softfail", "permerror", "temperror"):
                    rendered = colour(rendered, "red")
                elif value == "pass":
                    rendered = colour(rendered, "green")
                auth_bits.append(rendered)
        out.append("Auth         : %s" % "  ".join(auth_bits))
    else:
        out.append("Auth         : %s" % colour("no Authentication-Results header", "dim"))

    out.append("")
    out.append(colour(_section("URLS (%d)" % len(parsed.urls)), "bold"))
    if not parsed.urls:
        out.append("  (none)")
    for index, ioc in enumerate(parsed.urls, 1):
        marker = "!" if (ioc.flagged or vt_is_malicious(ioc.vt)
                         or vt_is_suspicious(ioc.vt)) else " "
        out.append(" %s[%d] %s" % (marker, index, ioc.defanged))
        out.append("      host: %s   seen in: %s"
                   % (defang_host(ioc.host), ", ".join(ioc.sources)))
        for note in ioc.notes:
            out.append("      %s" % colour("! " + note, "yellow"))
        out.append("      %s" % _vt_line(ioc.vt, colour))
        urlscan_line = _urlscan_line(ioc.urlscan, colour)
        if urlscan_line:
            out.append("      %s" % urlscan_line)

    out.append("")
    out.append(colour(_section("ATTACHMENTS (%d)" % len(parsed.attachments)), "bold"))
    if not parsed.attachments:
        out.append("  (none)")
    for attachment in parsed.attachments:
        out.append("  %s   %s   %s"
                   % (attachment.filename, attachment.content_type,
                      _human_size(attachment.size)))
        out.append("      MD5    : %s" % attachment.md5)
        out.append("      SHA256 : %s" % attachment.sha256)
        for note in attachment.notes:
            out.append("      %s" % colour("! " + note, "yellow"))
        out.append("      %s" % _vt_line(attachment.vt, colour))

    if parsed.signals:
        out.append("")
        out.append(colour(_section("HEURISTIC SIGNALS (%d)" % len(parsed.signals)), "bold"))
        shown = parsed.signals if show_all_signals else parsed.signals[:15]
        for signal in shown:
            out.append("  [%-6s] %s"
                       % (colour(signal.severity, _severity_colour(signal.severity)), signal.label))
        if len(shown) < len(parsed.signals):
            out.append("  ... %d more (use --verbose)" % (len(parsed.signals) - len(shown)))

    if parsed.errors:
        out.append("")
        out.append(colour(_section("ERRORS"), "bold"))
        for error in parsed.errors:
            out.append("  %s" % colour(error, "red"))

    out.append("")
    out.append(colour(_section("SUMMARY"), "bold"))
    for line in summary_sentences(parsed):
        out.append("  " + line)
    verdict = verdict_of(parsed)
    verdict_colour = {"MALICIOUS": "red", "LIKELY PHISHING": "red",
                      "SUSPICIOUS": "yellow"}.get(verdict, "green")
    out.append("  Verdict: %s  (risk score %d)"
               % (colour(verdict, verdict_colour), parsed.score))
    out.append("  Next step: %s" % _recommendation(verdict))
    out.append(colour(rule, "cyan"))
    return "\n".join(out)


def _recommendation(verdict: str) -> str:
    return {
        "MALICIOUS": "escalate to L2, block the sender domain and URLs, hunt for other recipients",
        "LIKELY PHISHING": "quarantine the mail, block the URLs, confirm with L2 before closing",
        "SUSPICIOUS": "detonate the URLs in a sandbox and confirm the sender with the recipient",
    }.get(verdict, "no action beyond closing the ticket unless the user reports harm")


def _section(title: str, width: int = 72) -> str:
    head = "-- %s " % title
    return head + "-" * max(3, width - len(head))


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return "%.0f %s" % (value, unit) if unit == "B" else "%.1f %s" % (value, unit)
        value /= 1024
    return "%d B" % size


def to_dict(parsed: ParsedEmail) -> dict[str, Any]:
    payload = asdict(parsed)
    payload["signals"] = [{"severity": s.severity, "label": s.label} for s in parsed.signals]
    payload["score"] = parsed.score
    payload["verdict"] = verdict_of(parsed)
    payload["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload["tool_version"] = __version__
    for item, ioc in zip(payload["urls"], parsed.urls):
        item["defanged"] = ioc.defanged
    return payload

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing_ioc_extractor.py",
        description="Extract and enrich phishing IOCs from .eml files.",
        epilog="Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 error.",
    )
    parser.add_argument("eml", nargs="+", help="one or more .eml files to triage")
    parser.add_argument("--json", metavar="PATH",
                        help="write the full machine-readable report to PATH")
    parser.add_argument("--offline", action="store_true",
                        help="never touch the network (header/URL/hash extraction only)")
    parser.add_argument("--vt-key", default="",
                        help="VirusTotal API key (default: $VT_API_KEY / $VIRUSTOTAL_API_KEY)")
    parser.add_argument("--vt-rate", type=int, default=VT_FREE_RATE,
                        help="VirusTotal lookups per minute (default: %d, the free tier limit)"
                             % VT_FREE_RATE)
    parser.add_argument("--no-virustotal", action="store_true", help="skip VirusTotal lookups")
    parser.add_argument("--urlscan-key", default="",
                        help="urlscan.io API key (default: $URLSCAN_API_KEY)")
    parser.add_argument("--no-urlscan", action="store_true",
                        help="skip urlscan.io searches (they are read-only by default)")
    parser.add_argument("--urlscan-submit", action="store_true",
                        help="submit URLs to urlscan.io as unlisted scans (needs a key; "
                             "this sends the URL to a third party)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="HTTP timeout in seconds (default: %d)" % DEFAULT_TIMEOUT)
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the summary block per file")
    parser.add_argument("--verbose", action="store_true", help="list every heuristic signal")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    colour = Palette(enabled=not args.no_color and sys.stdout.isatty()
                     and os.environ.get("TERM") != "dumb")

    vt_key = args.vt_key or os.environ.get("VT_API_KEY", "") or \
        os.environ.get("VIRUSTOTAL_API_KEY", "")
    urlscan_key = args.urlscan_key or os.environ.get("URLSCAN_API_KEY", "")

    vt_client: VirusTotalClient | None = None
    urlscan_client: UrlScanClient | None = None
    notices: list[str] = []

    if args.offline:
        notices.append("offline mode: no reputation lookups performed")
    else:
        try:
            if vt_key and not args.no_virustotal:
                vt_client = VirusTotalClient(vt_key, args.vt_rate, args.timeout)
            elif not args.no_virustotal:
                notices.append("no VirusTotal key found (set VT_API_KEY) - skipping VT lookups")
            if not args.no_urlscan:
                urlscan_client = UrlScanClient(urlscan_key, args.timeout)
                notices.append("urlscan.io search is read-only; it sends only the hostname")
        except RuntimeError as exc:
            notices.append(str(exc))
            vt_client = urlscan_client = None

    if args.urlscan_submit and not urlscan_key:
        notices.append("--urlscan-submit ignored: no urlscan.io API key")

    reports: list[dict[str, Any]] = []
    worst = 0
    progress = None
    if not args.quiet and sys.stderr.isatty():
        def progress(message: str) -> None:
            sys.stderr.write("\r  ... %-50s" % message)
            sys.stderr.flush()

    for notice in notices:
        print(colour("[i] " + notice, "dim"))
    if notices:
        print("")

    for path in args.eml:
        try:
            parsed = parse_eml(path)
        except FileNotFoundError:
            print(colour("[!] %s: file not found" % path, "red"), file=sys.stderr)
            worst = max(worst, 3)
            continue
        except OSError as exc:
            print(colour("[!] %s: %s" % (path, exc), "red"), file=sys.stderr)
            worst = max(worst, 3)
            continue
        except Exception as exc:  # a malformed .eml must not kill a batch run
            print(colour("[!] %s: could not parse (%s)" % (path, exc), "red"), file=sys.stderr)
            worst = max(worst, 3)
            continue

        if vt_client or urlscan_client:
            try:
                enrich(parsed, vt_client, urlscan_client,
                       submit_urls=args.urlscan_submit and bool(urlscan_key),
                       progress=progress)
            except RuntimeError as exc:
                parsed.errors.append(str(exc))
            finally:
                if progress:
                    sys.stderr.write("\r%-58s\r" % "")
                    sys.stderr.flush()

        if args.quiet:
            print(colour("== %s" % path, "cyan"))
            for line in summary_sentences(parsed):
                print("  " + line)
            print("  Verdict: %s (risk score %d)" % (verdict_of(parsed), parsed.score))
        else:
            print(render_report(parsed, colour, show_all_signals=args.verbose))
        print("")

        reports.append(to_dict(parsed))
        verdict = verdict_of(parsed)
        if verdict == "MALICIOUS":
            worst = max(worst, 2)
        elif verdict in ("LIKELY PHISHING", "SUSPICIOUS"):
            worst = max(worst, 1)

    if args.json:
        payload = reports[0] if len(reports) == 1 else {"reports": reports}
        try:
            with open(args.json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
            print(colour("[i] JSON report written to %s" % args.json, "dim"))
        except OSError as exc:
            print(colour("[!] could not write %s: %s" % (args.json, exc), "red"), file=sys.stderr)
            worst = max(worst, 3)

    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
