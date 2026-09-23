"""Offline detection logic. Every signal carries a severity and the MITRE
ATT&CK techniques it evidences; enrichment results add further signals in
apply_enrichment()."""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from .extract import (
    DANGEROUS_TYPES,
    DOMAINISH_RE,
    EMAIL_RE,
    EXPECTED_TYPES,
    TYPE_DESCRIPTIONS,
    defang_host,
    defang_url,
    host_of,
    is_ip,
    registrable_domain,
    urls_from_text,
)
from .knowledge import (
    ARCHIVE_EXTENSIONS,
    BRANDS,
    CREDENTIAL_WORDS,
    RISKY_EXTENSIONS,
    SHORTENERS,
    SUSPICIOUS_TLDS,
    URGENCY_WORDS,
)
from .lookalike import HIGH_METHODS, find_lookalikes
from .models import Analysis, vt_is_malicious, vt_is_suspicious

NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 90
_DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv|rtf|wav|mp3|mp4)\.[a-z0-9]{2,5}$")


def analyse(analysis: Analysis) -> Analysis:
    _authentication(analysis)
    _sender(analysis)
    _lookalikes(analysis)
    _urls(analysis)
    _attachments(analysis)
    _body(analysis)
    return analysis


# ---------------------------------------------------------------------------
# Header checks
# ---------------------------------------------------------------------------

def _authentication(a: Analysis) -> None:
    for mechanism, bad in (("spf", {"fail", "softfail", "permerror", "temperror", "none"}),
                           ("dkim", {"fail", "permerror", "temperror", "none"}),
                           ("dmarc", {"fail", "permerror", "temperror"})):
        value = a.auth.get(mechanism)
        if value in bad:
            a.add_signal("high" if value == "fail" else "medium", "%s=%s" % (mechanism.upper(), value))
    if not a.auth:
        a.add_signal("low", "no Authentication-Results header present")


def _brand_claimed(display: str, from_domain: str) -> str:
    lowered = (display or "").lower()
    base = registrable_domain(from_domain)
    for brand, legit in BRANDS.items():
        if re.search(r"\b%s\b" % re.escape(brand), lowered) and base and base not in legit:
            return brand
    return ""


def _sender(a: Analysis) -> None:
    from_base = registrable_domain(a.from_domain)
    if a.reply_to_domain and from_base and registrable_domain(a.reply_to_domain) != from_base:
        a.add_signal("high", "Reply-To domain (%s) differs from From domain (%s)"
                     % (defang_host(a.reply_to_domain), defang_host(a.from_domain)), ("T1656",))
    if a.return_path_domain and from_base and registrable_domain(a.return_path_domain) != from_base:
        a.add_signal("low", "Return-Path domain (%s) differs from From domain (%s)"
                     % (defang_host(a.return_path_domain), defang_host(a.from_domain)))

    brand = _brand_claimed(a.from_display, a.from_domain)
    if brand:
        a.add_signal("high", "display name claims '%s' but the domain is %s"
                     % (brand, defang_host(a.from_domain)), ("T1656",))
    shown = EMAIL_RE.search(a.from_display or "")
    if shown and shown.group(0).lower() != a.from_address:
        a.add_signal("medium", "display name shows a different address (%s)"
                     % defang_host(shown.group(0).lower()), ("T1656",))

    subject = (a.subject or "").lower()
    hits = sorted(word for word in URGENCY_WORDS if word in subject)
    if hits:
        a.add_signal("low", "urgency wording in subject: %s" % ", ".join(hits[:3]), ("T1566",))


def _lookalikes(a: Analysis) -> None:
    targets = [(a.from_domain, "sender"), (a.reply_to_domain, "reply-to"),
               (a.return_path_domain, "return-path")]
    targets += [(ioc.host, "url") for ioc in a.urls]
    seen: set[tuple[str, str]] = set()
    protected = set(a.protected_domains)
    for domain, where in targets:
        for hit in find_lookalikes(domain, where, a.protected_domains):
            key = (registrable_domain(hit.domain), hit.target)
            if key in seen:
                continue
            seen.add(key)
            a.lookalikes.append(hit)
            own = hit.target in protected
            severity = "high" if hit.method in HIGH_METHODS or own or hit.method == "subdomain" else "medium"
            techniques = ("T1583.001", "T1656") + (("T1036",) if hit.method == "homoglyph" else ())
            whose = "YOUR domain " if own else ""
            a.add_signal(severity, "%s domain %s is a %s lookalike of %s%s"
                         % (where, defang_host(hit.domain), hit.method, whose,
                            defang_host(hit.target)), techniques)
            for ioc in a.urls:
                if registrable_domain(ioc.host) == registrable_domain(hit.domain):
                    ioc.flagged = True
                    note = "%s lookalike of %s" % (hit.method, defang_host(hit.target))
                    if note not in ioc.notes:
                        ioc.notes.append(note)


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

def _shown_domain(anchor_text: str) -> str:
    for candidate in urls_from_text(anchor_text):
        return host_of(candidate)
    match = DOMAINISH_RE.search(anchor_text)
    return match.group(0).lower() if match else ""


def _urls(a: Analysis) -> None:
    for ioc in a.urls:
        host, base = ioc.host, ioc.domain
        trusted = a.is_trusted_domain(host)
        if is_ip(host):
            ioc.notes.append("raw IP address instead of a hostname")
            ioc.flagged = True
            a.add_signal("high", "URL points at a raw IP: %s" % defang_url(ioc.url), ("T1608.005",))
        if "xn--" in host:
            ioc.notes.append("punycode hostname")
            ioc.flagged = True
            a.add_signal("high", "punycode URL host: %s" % defang_host(host), ("T1583.001",))
        if base in SHORTENERS:
            ioc.notes.append("URL shortener hides the destination")
            ioc.flagged = True
            a.add_signal("medium", "shortened link: %s" % defang_url(ioc.url), ("T1608.005",))
        tld = base.rsplit(".", 1)[-1] if "." in base else ""
        if tld in SUSPICIOUS_TLDS:
            ioc.notes.append("high-abuse TLD .%s" % tld)
            a.add_signal("low", "high-abuse TLD in %s" % defang_host(host), ("T1583.001",))
        parts = urlsplit(ioc.url)
        path = ((parts.path or "") + "?" + (parts.query or "")).lower()
        words = sorted(w for w in CREDENTIAL_WORDS if w in path)
        if words and not trusted:
            ioc.notes.append("credential-themed path (%s)" % ", ".join(words[:3]))
            a.add_signal("low", "credential-harvesting path on %s" % defang_host(host), ("T1598.003",))
        if host.count(".") >= 4:
            ioc.notes.append("deeply nested subdomains")
        if "@" in ioc.url.split("://", 1)[-1].split("/", 1)[0]:
            ioc.notes.append("userinfo '@' trick hides the real host")
            ioc.flagged = True
            a.add_signal("high", "URL hides its real host behind '@': %s" % defang_url(ioc.url), ("T1036",))
        if any(source.endswith("form-action") for source in ioc.sources):
            ioc.notes.append("an HTML form submits data here")
        for anchor in ioc.anchor_texts:
            shown = _shown_domain(anchor)
            if shown and base and registrable_domain(shown) != base:
                ioc.notes.append("link text shows %s but goes to %s" % (defang_host(shown), defang_host(host)))
                ioc.flagged = True
                a.add_signal("high", "link text/href mismatch: %s shown, %s real"
                             % (defang_host(shown), defang_host(host)), ("T1036", "T1566.002"))
                break
        if not trusted and any(" atob-decoded" in s for s in ioc.sources):
            ioc.flagged = True


# ---------------------------------------------------------------------------
# Attachment checks
# ---------------------------------------------------------------------------

def _attachments(a: Analysis) -> None:
    for f in a.attachments:
        if f.inline:
            continue
        name = f.filename.lower()
        where = " (inside %s)" % f.parent if f.parent else ""
        extension = os.path.splitext(name)[1]
        if extension in RISKY_EXTENSIONS:
            f.notes.append("high-risk extension %s" % extension)
            f.flagged = True
            a.add_signal("high", "risky attachment: %s%s" % (f.filename, where), ("T1566.001", "T1204.002"))
        elif extension in ARCHIVE_EXTENSIONS and not f.archive:
            f.notes.append("archive the tool cannot open (%s)" % extension)
            a.add_signal("low", "archive attachment: %s" % f.filename, ("T1566.001",))
        if _DOUBLE_EXT_RE.search(name):
            f.notes.append("double extension")
            f.flagged = True
            a.add_signal("high", "double extension: %s%s" % (f.filename, where), ("T1036.007",))
        if "‮" in f.filename:
            f.notes.append("right-to-left override character in filename")
            f.flagged = True
            a.add_signal("high", "RTL-override filename trick%s" % where, ("T1036.002",))
        expected = EXPECTED_TYPES.get(extension)
        if expected is not None and f.true_type in DANGEROUS_TYPES and f.true_type not in expected:
            description = TYPE_DESCRIPTIONS.get(f.true_type, f.true_type)
            f.notes.append("claims %s but is really %s" % (extension, description))
            f.flagged = True
            a.add_signal("high", "%s claims to be %s but is %s" % (f.filename, extension, description),
                         ("T1036.008",))
        if "contains a VBA macro project" in f.notes:
            a.add_signal("high", "macro-enabled document: %s%s" % (f.filename, where), ("T1204.002",))
        if f.archive:
            _archive(a, f)
        if f.html:
            _html_attachment(a, f)


def _archive(a: Analysis, f) -> None:
    summary = f.archive
    f.notes.append("archive with %d file(s)" % summary["members"])
    a.add_signal("low", "archive attachment: %s" % f.filename, ("T1566.001",))
    if summary["encrypted"]:
        f.notes.append("password-protected: contents hidden from gateway scanning")
        f.flagged = True
        a.add_signal("high", "password-protected archive: %s" % f.filename, ("T1027.013",))
        extracted = {m.filename for m in a.attachments if m.parent == f.filename}
        for member in summary["listing"]:
            if member in extracted:
                continue
            if os.path.splitext(member.lower())[1] in RISKY_EXTENSIONS:
                a.add_signal("high", "encrypted archive %s hides %s" % (f.filename, member),
                             ("T1566.001", "T1204.002"))


def _html_attachment(a: Analysis, f) -> None:
    html = f.html
    credential_forms = [form for form in html["forms"] if form["has_password"]]
    if credential_forms or html["password_inputs"]:
        target = ""
        for form in credential_forms:
            if host_of(form["action"]):
                target = " posting to %s" % defang_host(host_of(form["action"]))
                break
        f.notes.append("credential form%s" % target)
        f.flagged = True
        a.add_signal("high", "HTML attachment %s contains a credential form%s" % (f.filename, target),
                     ("T1598.002",))
    if len(html["smuggling"]) >= 2:
        f.notes.append("HTML smuggling code: %s" % ", ".join(html["smuggling"][:4]))
        f.flagged = True
        a.add_signal("high", "HTML smuggling code in %s" % f.filename, ("T1027.006",))
    for redirect in html["redirects"][:1]:
        f.notes.append("redirects the browser to %s" % defang_url(redirect))
        a.add_signal("medium", "HTML attachment %s redirects to %s" % (f.filename, defang_url(redirect)),
                     ("T1608.005",))
    if html["decoded_urls"]:
        f.notes.append("%d URL(s) recovered from base64 in scripts" % len(html["decoded_urls"]))
        f.flagged = True
        a.add_signal("high", "obfuscated URL decoded from base64 in %s: %s"
                     % (f.filename, defang_url(html["decoded_urls"][0])), ("T1027",))


# ---------------------------------------------------------------------------
# Body checks
# ---------------------------------------------------------------------------

def _body(a: Analysis) -> None:
    if a.zero_width_chars >= 3:
        a.add_signal("medium", "%d zero-width characters hidden in the body (filter evasion)"
                     % a.zero_width_chars, ("T1027",))
    if not a.urls and not [f for f in a.attachments if not f.inline]:
        a.add_signal("low", "no URLs or attachments: possible BEC or reply-chain lure", ("T1656",))


# ---------------------------------------------------------------------------
# Enrichment-driven signals
# ---------------------------------------------------------------------------

def apply_enrichment(a: Analysis) -> Analysis:
    for ioc in a.urls:
        if vt_is_malicious(ioc.vt):
            ioc.flagged = True
            a.add_signal("high", "VirusTotal: %s flagged by %d engines"
                         % (defang_url(ioc.url), ioc.vt["malicious"]), ("T1566.002", "T1204.001"))
        elif vt_is_suspicious(ioc.vt):
            a.add_signal("medium", "VirusTotal: %s has minority detections" % defang_url(ioc.url),
                         ("T1566.002",))
        if ioc.urlscan and ioc.urlscan.get("malicious_hits"):
            a.add_signal("medium", "urlscan.io: malicious verdicts on %s" % defang_host(ioc.host),
                         ("T1608.005",))
    for f in a.attachments:
        if vt_is_malicious(f.vt):
            f.flagged = True
            a.add_signal("high", "VirusTotal: %s flagged by %d engines" % (f.filename, f.vt["malicious"]),
                         ("T1566.001", "T1204.002"))
        elif vt_is_suspicious(f.vt):
            a.add_signal("medium", "VirusTotal: %s has minority detections" % f.filename, ("T1566.001",))
    for domain, info in a.domain_intel.items():
        age = info.get("age_days") if info.get("status") == "ok" else None
        if age is None:
            continue
        if age < NEW_DOMAIN_DAYS:
            a.add_signal("high", "%s was registered %d day(s) ago" % (defang_host(domain), age), ("T1583.001",))
        elif age < YOUNG_DOMAIN_DAYS:
            a.add_signal("medium", "%s is only %d days old" % (defang_host(domain), age), ("T1583.001",))
    intel = a.ip_intel
    if intel and intel.get("status") == "ok":
        score = intel.get("score", 0)
        if score >= 75:
            a.add_signal("high", "originating IP %s has AbuseIPDB confidence %d%%"
                         % (defang_host(a.originating_ip), score))
        elif score >= 25:
            a.add_signal("medium", "originating IP %s has AbuseIPDB confidence %d%%"
                         % (defang_host(a.originating_ip), score))
    return a
