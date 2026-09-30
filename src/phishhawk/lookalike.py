"""Lookalike-domain detection: homoglyph, typosquat, combosquat, TLD swap,
and brand-in-subdomain tricks, against well-known brands and against your
own (protected) domains.

The protected-domain check is the one that catches business email
compromise: `examp1e-corp.co.uk` writing to staff at `example-corp.co.uk`.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from .extract import domain_label, is_ip, registrable_domain
from .hosting import hosting_kind
from .knowledge import (
    BRANDS,
    COMBO_WORDS,
    CREDENTIAL_WORDS,
    GENERIC_CCTLDS,
    SUSPICIOUS_TLDS,
    TOKEN_ONLY_BRANDS,
    known_legit_domains,
)
from .models import Lookalike

# Characters attackers substitute for Latin letters. Digits and symbols first,
# then Cyrillic and Greek letters that render identically in most fonts.
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "|": "l", "!": "i",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ӏ": "l", "ԁ": "d", "ѕ": "s",
    "һ": "h", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ո": "n", "ս": "u",
    "ı": "i", "ł": "l", "ø": "o", "ð": "d",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i",
    "κ": "k",
})
# Multi-character tricks ("rn" reads as "m") are applied as extra variants
# only, never unconditionally: "cl" -> "d" would mangle every "cloud".
_MULTI_CHAR = (("rn", "m"), ("vv", "w"), ("cl", "d"))

HIGH_METHODS = {"homoglyph", "typosquat"}


def decode_idna(label: str) -> str:
    if "xn--" not in label:
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def skeletons(label: str) -> set[str]:
    """Every plausible 'what a human reads' form of a domain label."""
    text = unicodedata.normalize("NFKD", decode_idna(label).lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    bases = {text.translate(_CONFUSABLES), text.replace("1", "i").translate(_CONFUSABLES)}
    variants = set(bases)
    for base in bases:
        for pattern, replacement in _MULTI_CHAR:
            if pattern in base:
                variants.add(base.replace(pattern, replacement))
    return variants


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Optimal-string-alignment (Damerau) distance, with an early cut-off."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], previous2[j - 2] + 1)
        previous2, previous = previous, current
    return previous[-1]


def one_edit_apart(a: str, b: str) -> bool:
    """edit_distance(a, b) == 1, in one pass: a single substitution, insertion,
    deletion or swap of neighbours. The typosquat check asks this of every
    link host against every brand, so the full table is too slow there."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    if len(a) < len(b):
        return a[i:] == b[i + 1:]
    return a[i + 1:] == b[i + 1:] or (i + 1 < len(a) and a[i] == b[i + 1] and a[i + 1] == b[i]
                                      and a[i + 2:] == b[i + 2:])


@lru_cache(maxsize=65536)
def _tokens(text: str) -> frozenset[str]:
    return frozenset(token for token in re.split(r"[-_.]", text) if token)


@lru_cache(maxsize=4096)
def _made_of_words(part: str) -> bool:
    """Can `part` be split entirely into COMBO_WORDS ("securelogin")?"""
    reachable = [True] + [False] * len(part)
    for end in range(1, len(part) + 1):
        reachable[end] = any(reachable[start] and part[start:end] in COMBO_WORDS
                             for start in range(max(0, end - 16), end))
    return reachable[-1]


def _combo(raw: str, name: str) -> bool:
    """True when `raw` is `name` plus nothing but lure or business words,
    digits and short codes: "paypal-billing-update", "outlooksecure",
    "taxascorreios756". "linuxmafia" and "yahoogroups" are just other names."""
    index = raw.find(name)
    if index < 0:
        return False
    rest = raw[:index] + " " + raw[index + len(name):]
    return all(len(part) <= 2 or _made_of_words(part) for part in re.split(r"[^a-z]+", rest) if part)


def _country_site(suffix: str) -> bool:
    """"co.uk", "com.br", "de": a brand's own country site, not a TLD swap."""
    last = suffix.rsplit(".", 1)[-1]
    return len(last) == 2 and last not in GENERIC_CCTLDS


def strong_subdomain(domain: str, target: str) -> bool:
    """A brand in the subdomain ("outlook.4team.biz") is common on legitimate
    mail. It is damning when the brand's whole domain is spelled out
    ("microsoft.com.account-verify.top"), the site is on a high-abuse TLD or
    free hosting, or the real name is a credential word."""
    base = registrable_domain(domain)
    if target in domain[: -len(base)]:
        return True
    if base.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS or hosting_kind("https://%s/" % domain):
        return True
    label = domain_label(base)  # short words ("owa", "sso") only as a whole token: not "iowastate"
    return any(word in label if len(word) >= 5 else word in _tokens(label) for word in CREDENTIAL_WORDS)


@lru_cache(maxsize=256)
def _canonical(brand: str) -> str:
    domains = sorted(BRANDS[brand])
    if brand + ".com" in domains:
        return brand + ".com"
    for domain in domains:
        if domain_label(domain) == brand:
            return domain
    for domain in domains:
        if brand in domain:
            return domain
    return domains[0]


def _compare_protected(raw: str, variants: set[str], target: str) -> str:
    if raw == target:
        return "tld-swap"
    if raw.replace("-", "") == target.replace("-", ""):  # example-corp vs examplecorp, exam-ple-corp
        return "typosquat"
    if any(target in variant for variant in variants) and target not in raw:
        return "homoglyph"
    threshold = 1 if len(target) < 8 else 2
    if any(edit_distance(variant, target, threshold) <= threshold for variant in variants):
        return "typosquat"
    if len(target) >= 5 and target in raw:
        return "combosquat" if _combo(raw, target) else ""
    return ""


def _compare_brand(raw: str, variants: set[str], brand: str, suffix: str) -> str:
    if raw == brand:  # "yahoo.co.uk" is Yahoo's; "slack.net" is somebody else's
        return "" if _country_site(suffix) else "tld-swap"
    if brand in TOKEN_ONLY_BRANDS:
        if brand in _tokens(raw):
            return "combosquat" if _combo(raw, brand) else ""
        if any(brand in _tokens(variant) for variant in variants):
            return "homoglyph"
        return ""
    if brand in raw:
        return "combosquat" if _combo(raw, brand) else ""
    squashed = raw.replace("-", "")
    if squashed == brand:  # micros-oft: a hyphen dropped into the name
        return "typosquat"
    if brand in squashed and _combo(squashed, brand):
        return "combosquat"
    if any(brand in variant for variant in variants):
        return "homoglyph"
    if len(brand) >= 6:
        for variant in variants:
            for token in _tokens(variant):
                if len(token) >= 5 and one_edit_apart(token, brand):
                    return "typosquat"
    return ""


@lru_cache(maxsize=4096)
def _brand_hits(base: str) -> tuple[tuple[str, str], ...]:
    """Brand comparisons depend only on the registrable domain, and a digest
    newsletter can carry thousands of links to the same few sites."""
    label = domain_label(base)
    raw, suffix, variants = decode_idna(label).lower(), base[len(label) + 1:], skeletons(label)
    hits = ((_canonical(brand), _compare_brand(raw, variants, brand, suffix)) for brand in BRANDS)
    return tuple((target, method) for target, method in hits if method)


def find_lookalikes(domain: str, where: str, protected: list[str] | set[str] = ()) -> list[Lookalike]:
    domain = (domain or "").lower().strip(".")
    if not domain or is_ip(domain):
        return []
    base = registrable_domain(domain)
    protected_bases = {registrable_domain(p) for p in protected if p}
    if base in known_legit_domains() or base in protected_bases:
        return []

    raw = decode_idna(domain_label(base)).lower()
    variants = skeletons(domain_label(base))
    found: list[Lookalike] = []
    seen_targets: set[str] = set()

    def record(target: str, method: str) -> None:
        if method and target not in seen_targets:
            seen_targets.add(target)
            found.append(Lookalike(domain=domain, target=target, method=method, where=where))

    for protected_base in sorted(protected_bases):
        target_label = domain_label(protected_base)
        if len(target_label) >= 4:
            record(protected_base, _compare_protected(raw, variants, target_label))

    for target, method in _brand_hits(base):
        record(target, method)

    # "microsoft.com.account-verify.top": the brand sits in the subdomain,
    # where a hurried reader's eye stops.
    subdomain = domain[: -len(base)].rstrip(".") if domain != base else ""
    if subdomain:
        sub_tokens = _tokens(subdomain)
        sub_variants: set[str] = set()
        for token in sub_tokens:
            sub_variants |= skeletons(token)
        for brand in BRANDS:
            hit = brand in sub_tokens or any(brand == variant for variant in sub_variants) \
                or (brand not in TOKEN_ONLY_BRANDS
                    and any(brand in variant and _combo(variant, brand) for variant in sub_variants))
            if hit:
                record(_canonical(brand), "subdomain")
    return found
