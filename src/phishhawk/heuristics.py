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
from .hosting import hosting_kind
from .knowledge import (
    ACCOUNT_CONTEXT,
    ARCHIVE_EXTENSIONS,
    BRANDS,
    CREDENTIAL_WORDS,
    FREEMAIL,
    LURES,
    ORG_WORDS,
    RISKY_EXTENSIONS,
    SHORTENERS,
    SUSPICIOUS_TLDS,
    TOKEN_ONLY_BRANDS,
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
    _language(analysis)
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
    squashed = re.sub(r"[^a-z0-9]", "", lowered)  # "Trust-Wallet", "Pay Pal" -> trustwallet, paypal
    base = registrable_domain(from_domain)
    for brand, legit in BRANDS.items():
        named = re.search(r"\b%s\b" % re.escape(brand), lowered) or \
            (brand not in TOKEN_ONLY_BRANDS and len(brand) >= 5 and brand in squashed)
        if named and base and base not in legit:
            return brand
    return ""


def _brand_tokens(text: str) -> set[str]:
    lowered = (text or "").lower()
    return set(re.split(r"[^a-z0-9]+", lowered)) | {lowered.replace(" ", "")}


def _subject_brand(a: Analysis) -> str:
    """A brand the subject names in an account/transaction context, when
    nothing about the message actually belongs to that brand."""
    subject = (a.subject or "").lower()
    tokens = set(re.split(r"[^a-z0-9-]+", subject))
    if not tokens & ACCOUNT_CONTEXT and "sign-in" not in subject:
        return ""
    squashed = re.sub(r"[^a-z0-9]", "", subject)
    domains = {registrable_domain(a.from_domain)} | {ioc.domain for ioc in a.urls}
    for brand, legit in BRANDS.items():
        named = brand in tokens if brand in TOKEN_ONLY_BRANDS or len(brand) < 5 else brand in squashed
        if named and not domains & legit:
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

    base = registrable_domain(a.from_domain)
    display_tokens = set(re.split(r"[^a-z0-9]+", (a.from_display or "").lower()))
    if base in FREEMAIL and (display_tokens & ORG_WORDS or display_tokens & set(BRANDS)):
        a.add_signal("medium", "display name '%s' reads as an organisation but the address is free-mail (%s)"
                     % (a.from_display[:40], base), ("T1656",))

    subject_brand = _subject_brand(a)
    if subject_brand and subject_brand != brand:
        credential_ask = _lure_hits(a).get("credential") or _lure_hits(a).get("foreign-language")
        severity = "high" if credential_ask and a.urls else "medium"
        a.add_signal(severity, "subject poses as a %s notice, but neither the sender nor any link is %s"
                     % (subject_brand, subject_brand), ("T1656",))

    original = a.forwarded_from
    if original:
        claimed = _brand_claimed(original["display"], original["domain"])
        if claimed:
            a.add_signal("high", "forwarded original: display name claims '%s' but the address is %s"
                         % (claimed, defang_host(original["address"])), ("T1656",))
        tokens = set(re.split(r"[^a-z0-9]+", original["display"].lower()))
        if registrable_domain(original["domain"]) in FREEMAIL and tokens & (ORG_WORDS | set(BRANDS)):
            a.add_signal("medium", "forwarded original: '%s' writes from free-mail (%s)"
                         % (original["display"][:40], registrable_domain(original["domain"])), ("T1656",))


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
            if hit.method == "tld-swap":  # organisations often own several TLDs of their name
                severity = "medium"
            elif hit.method in HIGH_METHODS or own or hit.method == "subdomain":
                severity = "high"
            else:
                severity = "medium"
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
        if ioc.redirect_to:
            target = host_of(ioc.redirect_to)
            ioc.notes.append("%s redirects to %s" % (ioc.wrapped_by, defang_host(target)))
            if not a.is_trusted_domain(target):
                ioc.flagged = True
                a.add_signal("medium", "%s hides the real destination: %s"
                             % (ioc.wrapped_by, defang_host(target)), ("T1608.005",))
        kind = hosting_kind(ioc.url)
        if kind:
            ioc.notes.append("%s host" % kind)
            if kind == "tunnel or IPFS":
                ioc.flagged = True
            a.add_signal("medium" if kind == "tunnel or IPFS" else "low",
                         "link to %s: %s" % (kind, defang_host(host)), ("T1583.006",))


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
# Language: lure phrases, callback phishing, hash-busting
# ---------------------------------------------------------------------------

_PHONE_RE = re.compile(r"(?<![\w.])\+?\(?\d{1,4}\)?(?:[\s.-]?\(?\d{2,4}\)?){2,4}(?![\w.])")
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9]{12,40}\b")
SEVERE_LURES = {"advance-fee", "extortion"}


def _case_flips(token: str) -> int:
    return sum(1 for x, y in zip(token, token[1:], strict=False) if x.islower() and y.isupper())


_SPACED_LETTERS_RE = re.compile(r"(?:\b[^\W\d_] ){10,}")
_EMAIL_GREETING_RE = re.compile(
    r"\b(?:dear|hello|hi|hey|ol[aá]|hola|hallo|bonjour|prezado|caro|estimado)\b[\s,]{0,3}"
    r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){0,4}", re.I)


def _lure_hits(a: Analysis) -> dict[str, list[str]]:
    cached = getattr(a, "_lure_cache", None)
    if cached is not None:
        return cached
    text = ("%s\n%s" % (a.subject, a.body_text)).lower()
    squeezed = re.sub(r"\s+", "", text)
    hits: dict[str, list[str]] = {}
    for category, phrases in LURES.items():
        found = [p for p in phrases if p in text or (" " in p and p.replace(" ", "") in squeezed)]
        if found:
            hits[category] = found
    a._lure_cache = hits  # noqa: SLF001 - analysis-scoped memo, not a dataclass field
    return hits


def _language(a: Analysis) -> None:
    hits = _lure_hits(a)

    for category, found in hits.items():
        if category in ("callback", "qr-code"):
            continue
        if category in SEVERE_LURES:
            severity = "high" if len(found) >= 2 else "medium"
        elif category == "prize":
            severity = "medium" if len(found) >= 2 else "low"
        else:
            severity = "medium" if len(found) >= 2 else "low"
        a.add_signal(severity, "%s lure wording: %s" % (category, ", ".join(found[:3])), ("T1566",))

    # Callback phishing (TOAD): a fake renewal or order plus a phone number to
    # ring, usually with no link at all for a filter to inspect.
    phones = [p for p in _PHONE_RE.findall(a.body_text) if sum(ch.isdigit() for ch in p) >= 10]
    if hits.get("callback") and phones:
        severity = "high" if not a.urls or registrable_domain(a.from_domain) in FREEMAIL else "medium"
        a.add_signal(severity, "callback-phishing pattern: %s, and a number to call (%s)"
                     % (hits["callback"][0], phones[0].strip()), ("T1566", "T1656"))

    # Quishing: the link is inside an image, so there is no URL to inspect.
    # The tell is the instruction to scan plus an image and nothing clickable.
    images = [f for f in a.attachments
              if f.content_type.startswith("image/") or f.true_type in ("png", "jpeg", "gif")]
    if hits.get("qr-code") and images:
        severity = "high" if not a.urls and (hits.get("credential") or "mfa" in a.body_text.lower()
                                               or "authenticat" in a.body_text.lower()) else "medium"
        a.add_signal(severity, "QR-code lure: '%s' with an image and %s" % (
            hits["qr-code"][0], "no clickable link" if not a.urls else "few links"), ("T1566.002",))

    # BEC from free-mail: a payment or gift-card request from an outside
    # personal address, with nothing clickable for a gateway to judge.
    money = hits.get("payment") or [p for p in hits.get("prize", []) if "gift card" in p]
    if money and registrable_domain(a.from_domain) in FREEMAIL and not a.urls:
        a.add_signal("medium", "free-mail sender asks for money (%s): business email compromise pattern"
                     % money[0], ("T1656",))

    spaced = _SPACED_LETTERS_RE.search(a.body_text)
    if spaced:
        a.add_signal("medium", "text split into single letters to dodge keyword filters: '%s...'"
                     % spaced.group(0)[:30], ("T1027",))
    if _EMAIL_GREETING_RE.search(a.body_text[:600]):
        a.add_signal("low", "greets the recipient by email address instead of by name", ("T1566",))

    # Hash-busting: random mixed-case tokens make every copy of a campaign unique.
    for token in _TOKEN_RE.findall(a.subject or ""):
        if _case_flips(token) >= 4 and sum(ch.islower() for ch in token) >= 3:
            a.add_signal("low", "random token in subject (filter evasion): %s" % token, ("T1027",))
            break
    recipients = {address.lower() for address in EMAIL_RE.findall(a.to or "")}
    recipients |= {m.lower() for m in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*", a.to or "")}
    if any(address and address in (a.subject or "").lower() for address in recipients):
        a.add_signal("low", "recipient's address pasted into the subject (mail-merge lure)", ("T1566",))


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
