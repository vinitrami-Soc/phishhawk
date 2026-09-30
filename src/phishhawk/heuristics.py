"""Offline detection logic. Every signal carries a severity and the MITRE
ATT&CK techniques it evidences; enrichment results add further signals in
apply_enrichment()."""

from __future__ import annotations

import os
import re
import unicodedata
from urllib.parse import urlsplit

from .extract import (
    DANGEROUS_TYPES,
    DOMAINISH_RE,
    EMAIL_RE,
    EXPECTED_TYPES,
    TYPE_DESCRIPTIONS,
    defang_host,
    defang_url,
    domain_label,
    host_of,
    is_ip,
    raw_host,
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
    known_legit_domains,
)
from .lookalike import HIGH_METHODS, find_lookalikes, strong_subdomain
from .models import MIME_TOO_DEEP, Analysis, vt_is_malicious, vt_is_suspicious

NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 90
_GOVERNMENT_RE = re.compile(r"(^|\.)(gov|gob|gouv|govt|mil|nic)(\.[a-z]{2})?$")
_DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv|rtf|wav|mp3|mp4)\.[a-z0-9]{2,5}$")


def analyse(analysis: Analysis) -> Analysis:
    _block_list(analysis)
    _authentication(analysis)
    _sender(analysis)
    _lookalikes(analysis)
    _urls(analysis)
    _attachments(analysis)
    _calendar(analysis)
    _body(analysis)
    _structure(analysis)
    _language(analysis)
    _qr_codes(analysis)
    _yara(analysis)
    return analysis


# ---------------------------------------------------------------------------
# Header checks
# ---------------------------------------------------------------------------

def _block_list(a: Analysis) -> None:
    """Domains your organisation has already decided are hostile."""
    if not a.blocked_domains:
        return
    blocked = set(a.blocked_domains)
    for domain, role in [(a.from_domain, "sender"), (a.reply_to_domain, "reply-to"),
                         (a.return_path_domain, "return-path")] + [(u.host, "link") for u in a.urls]:
        if domain and registrable_domain(domain) in blocked:
            a.add_signal("high", "%s domain %s is on your block list" % (role, defang_host(domain)), ("T1566",))
            for ioc in a.urls:
                if registrable_domain(ioc.host) in blocked:
                    ioc.flagged = True

def _authentication(a: Analysis) -> None:
    for mechanism, bad in (("spf", {"fail", "softfail", "permerror", "temperror", "none"}),
                           ("dkim", {"fail", "permerror", "temperror", "none"}),
                           ("dmarc", {"fail", "permerror", "temperror"})):
        value = a.auth.get(mechanism)
        if value in bad:
            a.add_signal("high" if value == "fail" else "medium", "%s=%s" % (mechanism.upper(), value))
    # No Authentication-Results header is not scored: it is missing from mail
    # exported by many clients and from all older mail, phishing or not.

    # A pass claimed below the receiving server's own results was written
    # before delivery. Reusing the receiver's name is forgery; another
    # server's name may be a legitimate upstream hop, so that one is low.
    grouped: dict[tuple[str, bool], list[str]] = {}
    for claim in a.forged_auth:
        grouped.setdefault((claim["authserv"], claim["impersonates"]), []).append(claim["claim"])
    for (server, impersonates), claims in grouped.items():
        if impersonates:
            a.add_signal("medium", "forged Authentication-Results: %s claimed in the name of %s, below "
                                   "that server's real results (ignored)" % (", ".join(claims), server),
                         ("T1036",))
        else:
            a.add_signal("low", "an earlier Authentication-Results header from %s claims %s (ignored)"
                         % (server, ", ".join(claims)))


def _spoofed_brand_sender(a: Analysis) -> None:
    """Mail really from a big brand is always DKIM-signed and passes DMARC.
    When the From domain is the brand's own and the receiving server could
    verify neither, someone else wrote that From line."""
    if not a.auth or not a.from_domain or a.is_protected(a.from_domain):
        return
    base = registrable_domain(a.from_domain)
    if base in FREEMAIL or base not in known_legit_domains():
        return
    dkim, dmarc = a.auth.get("dkim", ""), a.auth.get("dmarc", "")
    if dkim != "pass" and dmarc in ("fail", "none", "") and (dkim or dmarc):
        a.add_signal("high", "sender address uses %s, but the message is not authenticated for it "
                             "(DKIM %s, DMARC %s): the From line is probably forged"
                     % (defang_host(base), dkim or "missing", dmarc or "missing"), ("T1656", "T1036"))


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


# Letters from other alphabets that render as Latin ones, and digits used as
# letters inside a word ("Amaz0n"). Display names only: a bare "10" stays 10.
_LETTER_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ӏ": "l",
    "ԁ": "d", "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ո": "n", "ս": "u", "ı": "i", "в": "b",
    "к": "k", "м": "m", "н": "h", "т": "t", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i",
    "κ": "k", "ε": "e", "υ": "u", "β": "b", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "А": "A",
    "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
})
_DIGIT_LETTERS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
_WORD_RE = re.compile(r"[^\W_]{3,}")


def _skeleton(text: str) -> str:
    """What a reader sees in a display name: accents dropped, Cyrillic and
    Greek look-alikes read as Latin, digits inside words read as letters."""
    text = unicodedata.normalize("NFKD", (text or "")[:200])
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).translate(_LETTER_CONFUSABLES)
    return _WORD_RE.sub(lambda m: m.group(0).translate(_DIGIT_LETTERS)
                        if re.search(r"[A-Za-z]", m.group(0)) and re.search(r"\d", m.group(0)) else m.group(0),
                        text)


def _script_of(ch: str) -> str:
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"):
        if name.startswith(script):
            return script
    return ""


def _mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin with Cyrillic, Greek or Armenian letters: nobody
    types that, but a spoofer writing "Micrоsoft" with a Cyrillic "о" does."""
    found = []
    for word in re.findall(r"[^\W\d_]{3,}", (text or "")[:2000]):
        scripts = {_script_of(ch) for ch in word} - {""}
        if "LATIN" in scripts and len(scripts) > 1:
            found.append(word)
    return found


def _script_note(word: str) -> str:
    foreign = sorted({_script_of(ch).capitalize() for ch in word} - {"Latin", ""})
    return "'%s' has %s letters" % (word[:30], "/".join(foreign))


_STYLED_RE = re.compile("[\U0001D400-\U0001D7FF\U0001F130-\U0001F189\uFF21-\uFF3A\uFF41-\uFF5A]")
_DISGUISE_RE = re.compile(r"[A-Za-z0-9]{4,24}")


def _disguised_brand(word: str) -> str:
    """The brand a word imitates with a capital I for an l ("Iedger",
    "PayPaI") or a digit for a letter ("Amaz0n"), else ''."""
    lowered = word.lower()
    if lowered in BRANDS:
        return ""
    candidates = {word.replace("I", "l").lower(), lowered.translate(_DIGIT_LETTERS),
                  word.replace("I", "l").lower().translate(_DIGIT_LETTERS)}
    for candidate in candidates - {lowered}:
        if candidate in BRANDS and len(candidate) >= 5:
            return candidate
    return ""


def _subject_tricks(a: Analysis) -> None:
    subject = a.subject or ""
    styled = len(_STYLED_RE.findall(subject))
    if styled >= 4:
        a.add_signal("medium", "subject written in styled Unicode letters ('%s'), which keyword filters do not "
                               "read as text" % reading_text(subject)[:40], ("T1027",))
    invisible = len(_INVISIBLE_RE.findall(subject))
    if invisible >= 2:
        a.add_signal("medium", "%d invisible characters inside the subject ('%s') to break up words for filters"
                     % (invisible, reading_text(subject)[:40]), ("T1027",))
    for where, text in (("subject", subject), ("display name", a.from_display or "")):
        for word in _DISGUISE_RE.findall(text[:300]):
            brand = _disguised_brand(word)
            if brand and not a.is_trusted_domain(a.from_domain):
                a.add_signal("high", "%s spells '%s' as '%s' with look-alike characters" % (where, brand, word),
                             ("T1036", "T1656"))
                break


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
    reply_base = registrable_domain(a.reply_to_domain)
    if a.reply_to_domain and from_base and reply_base != from_base:
        if reply_base in a.list_domains:  # a mailing list sets Reply-To to itself
            a.add_signal("low", "Reply-To goes to the mailing list at %s" % defang_host(a.reply_to_domain))
        else:
            a.add_signal("medium" if a.mailing_list else "high",
                         "Reply-To domain (%s) differs from From domain (%s)"
                         % (defang_host(a.reply_to_domain), defang_host(a.from_domain)), ("T1656",))
    _spoofed_brand_sender(a)
    # A Return-Path on another domain is how every mailing service sends
    # (on the tuning sets: 59% of legitimate mail, 16% of phishing), so it is
    # shown in the report but not scored.

    brand = _brand_claimed(a.from_display, a.from_domain)
    if brand:
        a.add_signal("high", "display name claims '%s' but the domain is %s"
                     % (brand, defang_host(a.from_domain)), ("T1656",))
    else:
        disguised = _brand_claimed(_skeleton(a.from_display), a.from_domain)
        if disguised:
            brand = disguised
            a.add_signal("high", "display name imitates '%s' with look-alike characters (%s), and the domain is %s"
                         % (disguised, a.from_display[:40], defang_host(a.from_domain)), ("T1656", "T1036"))
    mixed = _mixed_script_words(a.from_display)
    if mixed:
        a.add_signal("high", "display name mixes alphabets inside a word (%s): look-alike letters"
                     % ", ".join(_script_note(word) for word in mixed[:2]), ("T1036",))
    mixed = _mixed_script_words(a.subject)
    if mixed:
        a.add_signal("medium", "subject mixes alphabets inside a word (%s): look-alike letters"
                     % ", ".join(_script_note(word) for word in mixed[:2]), ("T1036",))
    _subject_tricks(a)
    shown = EMAIL_RE.search(a.from_display or "")
    if shown and shown.group(0).lower() != a.from_address:
        a.add_signal("medium", "display name shows a different address (%s)"
                     % defang_host(shown.group(0).lower()), ("T1656",))

    base = registrable_domain(a.from_domain)
    display_tokens = set(re.split(r"[^a-z0-9]+", (a.from_display or "").lower()))
    if base in FREEMAIL and (display_tokens & ORG_WORDS or display_tokens & set(BRANDS)):
        a.add_signal("medium", "display name '%s' reads as an organisation but the address is free-mail (%s)"
                     % (a.from_display[:40], base), ("T1656", "T1585.002"))

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
    # At most parse.MAX_URLS links reach here; a flood past that is its own signal (_structure).
    targets += [(host, "url") for host in dict.fromkeys(ioc.host for ioc in a.urls if ioc.host)]
    seen: set[tuple[str, str]] = set()
    protected = set(a.protected_domains)
    allowed = set(a.allowed_domains)
    for domain, where in targets:
        if allowed and registrable_domain(domain) in allowed:
            continue  # a partner you told PhishHawk about
        for hit in find_lookalikes(domain, where, a.protected_domains):
            key = (registrable_domain(hit.domain), hit.target)
            if key in seen:
                continue
            seen.add(key)
            a.lookalikes.append(hit)
            own = hit.target in protected
            if hit.method == "tld-swap":  # organisations often own several TLDs of their name
                # "slack.net" or "zoom.org" is usually just another organisation
                # with an ordinary word for a name (55 legitimate emails, no phish).
                word = domain_label(hit.target) in TOKEN_ONLY_BRANDS and not own \
                    and hit.domain.rsplit(".", 1)[-1] not in SUSPICIOUS_TLDS
                severity = "low" if word else "medium"
            elif hit.method == "subdomain":
                severity = "high" if strong_subdomain(hit.domain, hit.target) else "low"
            elif hit.method in HIGH_METHODS or own:
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
    # An address in the link text ("sent to you@example.com") names a mailbox,
    # not the website the link claims to open.
    match = DOMAINISH_RE.search(EMAIL_RE.sub(" ", anchor_text))
    return match.group(0).lower() if match else ""


# Links straight to a file that runs when opened, and to archives and app
# packages that usually carry one.
RUNNABLE_DOWNLOADS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".msi", ".bat", ".cmd",
                      ".ps1", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".jar", ".one", ".appx", ".msix", ".cpl"}
PACKED_DOWNLOADS = {".zip", ".rar", ".7z", ".apk", ".dmg", ".gz", ".tgz", ".cab", ".ace", ".arj"}


def _download(url: str) -> str:
    """The extension of the file a link downloads, when it is one to worry about."""
    try:
        path = urlsplit(url).path.lower().rstrip("/")
    except ValueError:
        return ""
    extension = os.path.splitext(path)[1]
    return extension if extension in RUNNABLE_DOWNLOADS | PACKED_DOWNLOADS else ""


def _urls(a: Analysis) -> None:
    tracked: set[str] = set()  # destinations already reported for a plain mismatch
    for ioc in a.urls:
        host, base = ioc.host, ioc.domain
        trusted = a.is_trusted_domain(host)
        extension = _download(ioc.url)
        clicked = [s for s in ioc.sources if "resource" not in s and not s.startswith("header:")]
        if extension and not trusted and clicked:  # a <script src> is not a download
            runnable = extension in RUNNABLE_DOWNLOADS
            ioc.notes.append("downloads a %s file" % extension)
            ioc.flagged = ioc.flagged or runnable
            a.add_signal("high" if runnable else "medium", "link downloads a %s file: %s"
                         % (extension, defang_url(ioc.url)), ("T1204.001", "T1566.002"))
        if is_ip(host):
            ioc.notes.append("raw IP address instead of a hostname")
            ioc.flagged = True
            a.add_signal("high", "URL points at a raw IP: %s" % defang_url(ioc.url), ("T1608.005",))
            written = raw_host(ioc.url)
            if written and written != host and ":" not in host:
                ioc.notes.append("the address is written as %s to hide it" % written[:40])
                a.add_signal("high", "URL disguises the IP address %s as %s" % (defang_host(host), written[:40]),
                             ("T1027", "T1608.005"))
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
                # Newsletters show their site and link through a click tracker,
                # so a mismatch alone is only medium. It is high when the text
                # borrows a name worth stealing or the destination is suspect.
                suspect = ioc.flagged or tld in SUSPICIOUS_TLDS or bool(hosting_kind(ioc.url))
                borrowed = a.is_trusted_domain(shown) or registrable_domain(shown) in FREEMAIL \
                    or bool(_GOVERNMENT_RE.search(shown))
                ioc.notes.append("link text shows %s but goes to %s" % (defang_host(shown), defang_host(host)))
                ioc.flagged = True
                if suspect or borrowed or base not in tracked:  # one click tracker counts once
                    a.add_signal("high" if suspect or borrowed else "medium",
                                 "link text/href mismatch: %s shown, %s real"
                                 % (defang_host(shown), defang_host(host)), ("T1036", "T1566.002"))
                    tracked.add(base)
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
            a.add_signal("high", "macro-enabled document: %s%s" % (f.filename, where), ("T1204.002", "T1059.005"))
        if f.archive:
            _archive(a, f)
        if f.html:
            _html_attachment(a, f)
        _documents(a, f, where)


def _archive(a: Analysis, f) -> None:
    summary = f.archive
    kind = summary.get("kind", "archive")
    f.notes.append("%s with %d file(s)" % (kind, summary["members"]))
    if "disk image" in kind:
        # Files inside a disk image lose the Mark of the Web, so neither
        # SmartScreen nor Office's block on internet macros applies to them.
        a.add_signal("high", "disk image %s delivers %d file(s) without the Mark of the Web"
                     % (f.filename, summary["members"]), ("T1553.005", "T1566.001"))
    elif kind != "gzip file":
        a.add_signal("low", "archive attachment: %s" % f.filename, ("T1566.001",))
    extracted = {m.filename for m in a.attachments if m.parent == f.filename}
    if summary.get("password_in_body"):
        f.flagged = True
        a.add_signal("high", "the message gives the password for its %s %s, so no gateway could look inside"
                     % ("archive" if "archive" in kind else "file", f.filename), ("T1027.013", "T1566.001"))
    if summary.get("names_hidden"):
        f.notes.append("even the file names are encrypted")
        f.flagged = True
        a.add_signal("high", "archive %s encrypts even its file names" % f.filename, ("T1027.013",))
    elif summary["encrypted"]:
        f.notes.append("password-protected: contents hidden from gateway scanning")
        f.flagged = True
        a.add_signal("high", "password-protected archive: %s" % f.filename, ("T1027.013",))
    for member in summary["listing"]:
        if member in extracted:
            continue  # extracted members are judged as attachments in their own right
        extension = os.path.splitext(member.lower())[1]
        if extension in RISKY_EXTENSIONS or _DOUBLE_EXT_RE.search(member.lower()):
            f.flagged = True
            hidden = "encrypted " if summary["encrypted"] else ""
            a.add_signal("high", "%s%s %s holds %s" % (hidden, kind, f.filename, member[:80]),
                         ("T1566.001", "T1204.002"))


def _documents(a: Analysis, f, where: str) -> None:
    """What a document, shortcut or container would do when opened."""
    name = f.filename + where
    shortcut = f.details.get("lnk")
    if shortcut:
        reasons = shortcut.get("reasons", [])
        command = " ".join(shortcut.get(key, "") for key in ("target", "relative_path", "arguments")).lower()
        techniques = ("T1204.002",) + (("T1059.001",) if "powershell" in command or "pwsh" in command else ()) \
            + (("T1218.005",) if "mshta" in command else ())
        if reasons:
            a.add_signal("high", "shortcut %s %s" % (name, "; ".join(reasons[:3])), techniques)
    office = f.details.get("office", {}).get("features", [])
    checks = (
        ("xlm-macro", "high", "Excel 4.0 (XLM) macros in %s", ("T1204.002",)),
        ("dde", "high", "a DDE field in %s runs a command on opening", ("T1559.002", "T1204.002")),
        ("protocol-handler", "high", "%s opens an external link through a Windows protocol handler "
                                     "(Follina family)", ("T1203", "T1221")),
        ("remote-attachedtemplate", "high", "%s loads a remote template when opened", ("T1221",)),
        ("remote-oleobject", "high", "%s loads a remote OLE object when opened", ("T1221",)),
        ("remote-frame", "high", "%s loads a remote frame when opened", ("T1221",)),
        ("remote-subdocument", "high", "%s loads a remote subdocument when opened", ("T1221",)),
        ("embedded-package", "high", "%s carries an embedded file (OLE Package)", ("T1204.002",)),
        ("activex", "medium", "ActiveX controls in %s", ("T1204.002",)),
        ("encrypted", "medium", "%s is password-protected, so no gateway could read it", ("T1027.013",)),
    )
    for feature, severity, label, techniques in checks:
        if feature in office:
            a.add_signal(severity, label % name, techniques)
    if "vba-macro" in office and "contains a VBA macro project" not in f.notes:
        a.add_signal("high", "macro-enabled document: %s" % name, ("T1204.002", "T1059.005"))
    pdf = set(f.details.get("pdf", {}).get("features", []))
    if "launch" in pdf:
        a.add_signal("high", "PDF %s has a launch action that starts a program" % name, ("T1204.002",))
    if "javascript" in pdf:
        automatic = pdf & {"open-action", "auto-action"}
        a.add_signal("high" if automatic else "medium", "PDF %s runs JavaScript%s"
                     % (name, " as soon as it opens" if automatic else ""), ("T1059.007", "T1204.002"))
    if "embedded-file" in pdf:
        a.add_signal("medium", "PDF %s carries an embedded file" % name, ("T1027", "T1204.002"))
    if "submit-form" in pdf:
        a.add_signal("medium", "PDF %s has a form that submits what is typed into it" % name, ("T1598.002",))
    rtf = set(f.details.get("rtf", {}).get("features", []))
    if rtf & {"class-equation.3", "class-equation"}:
        a.add_signal("high", "RTF %s carries an Equation Editor object, the CVE-2017-11882 exploit" % name,
                     ("T1203",))
    if rtf & {"class-htmlfile", "class-otkloadr.wrassembly"}:
        a.add_signal("high", "RTF %s carries an OLE object used by known exploits" % name, ("T1203",))
    if "remote-template" in rtf:
        a.add_signal("high", "RTF %s loads a remote template when opened" % name, ("T1221",))
    if "class-package" in rtf:
        a.add_signal("high", "RTF %s carries an embedded file (Package object)" % name, ("T1204.002",))
    elif "ole-object" in rtf:
        a.add_signal("medium", "RTF %s carries embedded OLE objects%s"
                     % (name, " that update on opening" if "auto-update" in rtf else ""), ("T1204.002",))
    if f.details.get("onenote", {}).get("features"):
        risky = [m.filename for m in a.attachments if m.parent == f.filename
                 and (m.true_type in ("pe", "lnk", "html") or os.path.splitext(m.filename.lower())[1]
                      in RISKY_EXTENSIONS)]
        a.add_signal("high" if risky else "medium", "OneNote file %s hides %s" % (
            name, "a runnable file (%s)" % risky[0] if risky else "embedded files"), ("T1204.002", "T1027"))


def _html_attachment(a: Analysis, f) -> None:
    html = f.html
    if (f.true_type == "svg" or f.filename.lower().endswith(".svg")) and html.get("scripts"):
        f.notes.append("SVG image that runs JavaScript")
        f.flagged = True
        a.add_signal("high", "SVG image %s runs JavaScript (SVG smuggling)" % f.filename,
                     ("T1027.006", "T1059.007"))
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

TAG_SPLIT_MIN = 8  # words broken by tags before it counts: a drop cap or a bold letter is one


def _calendar(a: Analysis) -> None:
    """An invitation lands in the calendar even when the message is filtered,
    with its links one tap away on a phone."""
    from_base = registrable_domain(a.from_domain)
    for invite in a.calendar:
        organizer = registrable_domain(invite.get("organizer", "").rsplit("@", 1)[-1])
        if invite.get("links"):
            a.add_signal("low", "calendar invitation (%s) carries %d link(s)" % (invite["where"], invite["links"]),
                         ("T1566.002",))
        if organizer and from_base and organizer != from_base and organizer not in a.list_domains:
            a.add_signal("medium", "calendar organiser %s is not the sender %s"
                         % (defang_host(invite.get("organizer", "")[:80]), defang_host(a.from_domain)), ("T1656",))


def _body(a: Analysis) -> None:
    if a.zero_width_chars >= 3:
        a.add_signal("medium", "%d zero-width characters hidden in the body (filter evasion)"
                     % a.zero_width_chars, ("T1027",))
    # A message with no link or attachment is as common in legitimate mail as
    # in phishing (7.4% and 6.0% of the tuning sets), so it is not scored.
    if a.hidden_splits >= 2:
        a.add_signal("high", "hidden text breaks up words in %d places, so filters read something else "
                             "than the reader" % a.hidden_splits, ("T1027",))
    elif a.hidden_splits:
        a.add_signal("medium", "hidden text sits inside a visible word (filter evasion)", ("T1027",))
    if a.tag_splits >= TAG_SPLIT_MIN:
        a.add_signal("medium", "%d words broken up with HTML tags, one piece at a time, so filters cannot read "
                               "them" % a.tag_splits, ("T1027",))
    if a.hidden_filler:
        a.add_signal("medium", "%d letters of hidden text the reader never sees, unrelated to the visible text "
                               "('%s...')" % (a.hidden_filler, a.hidden_sample[:50]), ("T1027",))
    for link in a.script_links[:3]:
        if link["kind"].startswith("javascript"):  # 2002 newsletters still opened pop-ups this way
            a.add_signal("medium", "a link runs JavaScript instead of opening a website (%s)" % link["where"],
                         ("T1027.006",))
        else:
            a.add_signal("high", "a link opens a page built into the link itself (%s, %s)"
                         % (link["kind"], link["where"]), ("T1027.006", "T1566.002"))


# ---------------------------------------------------------------------------
# Language: lure phrases, callback phishing, hash-busting
# ---------------------------------------------------------------------------

# Anchored so that a long run of letters is tried once, not from every position
# (quadratic: a 30,000-character To: header took 5 s).
_LOOSE_ADDRESS_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*")
_PHONE_RE = re.compile(r"(?<![\w.])\+?\(?\d{1,4}\)?(?:[\s.-]?\(?\d{2,4}\)?){2,4}(?![\w.])")
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9]{12,40}\b")
SEVERE_LURES = {"advance-fee", "extortion"}


def _case_flips(token: str) -> int:
    return sum(1 for x, y in zip(token, token[1:], strict=False) if x.islower() and y.isupper())


_SPACED_LETTERS_RE = re.compile(r"(?:\b[^\W\d_] ){10,}")
_EMAIL_GREETING_RE = re.compile(
    r"\b(?:dear|hello|hi|hey|ol[aá]|hola|hallo|bonjour|prezado|caro|estimado)\b[\s,]{0,3}"
    r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){0,4}", re.I)


_INVISIBLE_RE = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u034f\u180e]")


def reading_text(text: str) -> str:
    """Text as a reader reads it: styled Unicode letters (𝘾𝙊𝙉𝙂𝙍𝘼𝙏𝙎) folded
    to plain ones and invisible characters dropped, so neither hides a lure."""
    return unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text or ""))


def _lure_hits(a: Analysis) -> dict[str, list[str]]:
    cached = getattr(a, "_lure_cache", None)
    if cached is not None:
        return cached
    text = reading_text("%s\n%s" % (a.subject, a.body_text)).lower()
    squeezed = re.sub(r"\s+", "", text)
    hits: dict[str, list[str]] = {}
    for category, phrases in LURES.items():
        found = [p for p in phrases if p in text or (" " in p and p.replace(" ", "") in squeezed)]
        if found:
            hits[category] = found
    a.__dict__["_lure_cache"] = hits  # an analysis-scoped memo, not a dataclass field: never exported
    return hits


def _language(a: Analysis) -> None:
    hits = _lure_hits(a)

    for category, found in hits.items():
        if category in ("callback", "qr-code"):
            continue
        if category in SEVERE_LURES or category == "crypto":
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
                     % (hits["callback"][0], phones[0].strip()), ("T1566.004", "T1656"))
        for number in phones[:3]:
            number = " ".join(number.split())
            if number not in a.phones:
                a.phones.append(number)

    # Extortion, advance-fee and investment scams end in a wallet address.
    if a.wallets:
        currencies = sorted({w["currency"] for w in a.wallets})
        asks = [c for c in ("extortion", "advance-fee", "crypto", "payment", "prize") if hits.get(c)]
        if asks:
            a.add_signal("high", "asks for payment to a %s wallet (%s wording)" % ("/".join(currencies), asks[0]),
                         ("T1657",))
        else:
            a.add_signal("low", "%s wallet address in the message" % "/".join(currencies), ("T1657",))

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
                     % money[0], ("T1656", "T1657"))
    # BEC: a lookalike of your own domain asking for a payment or gift cards.
    own = next((hit for hit in a.lookalikes if hit.target in a.protected_domains
                and hit.where in ("sender", "reply-to")), None)
    if money and own:
        a.add_signal("high", "business email compromise: %s, a lookalike of your domain %s, asks for money (%s)"
                     % (defang_host(own.domain), defang_host(own.target), money[0]), ("T1656", "T1657"))

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
    recipients |= {m.lower() for m in _LOOSE_ADDRESS_RE.findall(a.to or "")}
    if any(address and address in (a.subject or "").lower() for address in recipients):
        a.add_signal("low", "recipient's address pasted into the subject (mail-merge lure)", ("T1566",))


# ---------------------------------------------------------------------------
# Enrichment-driven signals
# ---------------------------------------------------------------------------

MAX_NORMAL_MIME_DEPTH = 15  # 19,458 real messages, phishing and legitimate, never went past 4


def _structure(a: Analysis) -> None:
    """Shapes no mail client writes, built to wear out a scanner before it
    reaches the part that matters."""
    if a.mime_depth >= MIME_TOO_DEEP:
        a.add_signal("high", "MIME parts nested deeper than a mail parser can follow: the body was read as "
                             "plain text (filter evasion)", ("T1027",))
    elif a.mime_depth > MAX_NORMAL_MIME_DEPTH:
        a.add_signal("medium", "MIME parts nested %d levels deep; real mail stays under five (filter evasion)"
                     % a.mime_depth, ("T1027",))
    if a.urls_dropped:
        a.add_signal("medium", "%d more links than the %d checked: a flood of links can bury the one that "
                               "matters" % (a.urls_dropped, len(a.urls)), ("T1027",))


def _yara(a: Analysis) -> None:
    for match in a.yara:
        label = "YARA rule %s matched %s" % (match["rule"], match["where"])
        if match.get("description"):
            label += " (%s)" % match["description"][:80]
        a.add_signal(match.get("severity", "high"), label, tuple(match.get("techniques", ())))
        for f in a.attachments:
            if f.filename == match["where"]:
                f.flagged = True
                note = "YARA: %s" % match["rule"]
                if note not in f.notes:
                    f.notes.append(note)


def apply_enrichment(a: Analysis) -> Analysis:
    for ioc in a.urls:
        if vt_is_malicious(ioc.vt):
            ioc.flagged = True
            a.add_signal("high", "VirusTotal: %s flagged by %d engines"
                         % (defang_url(ioc.url), (ioc.vt or {})["malicious"]), ("T1566.002", "T1204.001"))
        elif vt_is_suspicious(ioc.vt):
            a.add_signal("medium", "VirusTotal: %s has minority detections" % defang_url(ioc.url),
                         ("T1566.002",))
        if ioc.urlscan and ioc.urlscan.get("malicious_hits"):
            a.add_signal("medium", "urlscan.io: malicious verdicts on %s" % defang_host(ioc.host),
                         ("T1608.005",))
    for f in a.attachments:
        if vt_is_malicious(f.vt):
            f.flagged = True
            a.add_signal("high", "VirusTotal: %s flagged by %d engines" % (f.filename, (f.vt or {})["malicious"]),
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


# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------

def _qr_codes(a: Analysis) -> None:
    """A QR code is scanned on a phone, away from the gateway and the desktop
    link checks. Tickets and payment codes are legitimate, so the code alone
    is medium; where it leads decides the rest."""
    hits = _lure_hits(a)
    lure = bool(hits.get("credential") or hits.get("qr-code")) or \
        any(word in a.body_text.lower() for word in ("mfa", "multi-factor", "2fa", "authenticat"))
    recipients = [address.lower() for address in EMAIL_RE.findall(a.to or "")]
    seen: set[str] = set()
    for code in a.qr_codes:
        url, where = code.get("url", ""), code["where"]
        if not url:
            if code["payload"].lower().startswith(("tel:", "sms:", "smsto:")):
                a.add_signal("medium", "QR code in %s calls or texts %s" % (where, code["payload"][:40]),
                             ("T1566",))
            continue
        host = host_of(url)
        if host in seen:
            continue
        seen.add(host)
        base = registrable_domain(host)
        reasons = []
        if is_ip(host):
            reasons.append("a raw IP")
        if hosting_kind(url):
            reasons.append(hosting_kind(url))
        if base in SHORTENERS:
            reasons.append("a link shortener")
        if base.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            reasons.append("a high-abuse TLD")
        if any(hit.domain == host for hit in a.lookalikes):
            reasons.append("a lookalike domain")
        parts = urlsplit(url)
        if any(word in ((parts.path or "") + "?" + (parts.query or "")).lower() for word in CREDENTIAL_WORDS):
            reasons.append("a login path")
        if any(r in url.lower() for r in recipients):
            reasons.append("your address in the link")
        own_site = base == registrable_domain(a.from_domain) and a.auth.get("dmarc") == "pass"
        if own_site and not reasons:
            severity = "low"
        elif reasons or lure:
            severity = "high"
        else:
            severity = "medium"
        label = "QR code in %s links to %s" % (where, defang_host(host))
        if reasons:
            label += " (%s)" % ", ".join(reasons)
        a.add_signal(severity, label, ("T1566.002",))

