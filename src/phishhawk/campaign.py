"""Campaign correlation: group reported messages that share infrastructure.

Offline, from the analyses alone. Two messages belong together when they
share a strong trait (an attachment, a phishing domain or link, a QR
payload, a sender or reply-to address that is not a well-known service, a
wallet or a phone number), or at least two weak ones (a subject that differs
only in numbers, a display name, an originating IP). Links are followed
transitively, so A-B and B-C make one campaign. A web address (link, domain
or host) links only messages at least half of which PhishHawk judged
suspicious or worse, and a mailing list's own links never do: ordinary sites
turn up in ordinary mail.

Shared services would glue unrelated mail together, so they never link at
domain level: known brands and your protected and allowed domains,
shorteners, free-mail providers, bulk-mail and click-tracking services and
mail-security gateways that rewrite links (a link through them links only
when the whole link matches), free hosting and other platforms whose
customers each get a host name (linked by that host, never the provider),
and file sharing (linked by the document or bucket). Embedded images never
link: copied brand templates load the same logos whoever sends them. A weak trait
seen in more than weak_cap messages is too common to mean anything.
"""

from __future__ import annotations

import datetime as dt
import email.utils
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from .extract import registrable_domain
from .hosting import hosting_kind
from .knowledge import FREEMAIL, RESERVED_DOMAINS, SHORTENERS
from .models import Analysis

# Mail and link-tracking services that carry countless unrelated senders' mail.
BULK_MAIL = {
    "sendgrid.net", "sendgrid.com", "list-manage.com", "mailchimp.com", "mcusercontent.com", "mailgun.org",
    "mailgun.net", "sparkpostmail.com", "amazonses.com", "exacttarget.com", "rs6.net", "constantcontact.com",
    "hubspotlinks.com", "hubspotemail.net", "hs-sites.com", "mandrillapp.com", "mailjet.com", "sendinblue.com",
    "brevo.com", "createsend.com", "cmail19.com", "cmail20.com", "klaviyo.com", "klclick.com", "mktomail.com",
    "mailerlite.com", "convertkit-mail.com", "ck.page", "substack.com", "beehiiv.com", "postmarkapp.com",
    "awstrack.me", "mjt.lu", "sendibt3.com", "sendibm1.com", "mailchi.mp", "eventbrite.com",
}
# Web plumbing: namespaces, fonts, script and style CDNs that any page or mail can load.
WEB_PLUMBING = {
    "w3.org", "schema.org", "googleapis.com", "gstatic.com", "jquery.com", "jsdelivr.net", "cdnjs.com",
    "bootstrapcdn.com", "fontawesome.com", "unpkg.com", "typekit.net", "googletagmanager.com",
    "google-analytics.com", "doubleclick.net", "gravatar.com", "wp.com", "xmlsoap.org", "openxmlformats.org",
    "purl.org", "ogp.me",
}
# Mail-security gateways that rewrite every link in a mailbox and are not
# unwrapped (Safe Links, Proofpoint and Barracuda are): every report from one
# organisation carries them, so only the very same rewritten link counts.
GATEWAYS = {
    "symantec.com", "mimecast.com", "mimecastprotect.com", "trendmicro.com", "sophos.com", "cisco.com",
    "checkpoint.com", "avanan.click", "inky.com", "menlosecurity.com", "ironscales.com", "forcepoint.net",
    "fortinet.com", "fortimail.com", "egress.com", "hornetsecurity.com", "cloudflare-email.com",
}
# Zones whose customers each get a name under them (registry second-level
# domains, cloud platforms, help desks): they link by host, never as a whole.
# Many more are found from the data (see PLATFORM_MIN_HOSTS); --psl knows the rest.
KNOWN_PLATFORMS = {
    "sa.com", "eu.com", "us.com", "uk.com", "gb.net", "za.com", "it.com", "br.com", "cn.com", "de.com",
    "jpn.com", "ru.com", "in.net", "us.org", "ae.org", "co.com", "co.ua", "com.ua", "run.app", "appspot.com",
    "cloudfunctions.net", "cloudfront.net", "azureedge.net", "zendesk.com", "freshdesk.com", "atlassian.net",
    "sharepoint.com", "myshopify.com", "wordpress.com", "secureserver.net", "my.salesforce.com", "notion.site",
}
STRONG_KINDS = ("attachment", "link", "domain", "host", "qr", "sender", "reply-to", "sender domain", "wallet",
                "phone")
WEAK_KINDS = ("subject", "display name", "originating IP")
# Web addresses also turn up in ordinary mail (a news site, a vendor's portal):
# they link only messages most of which PhishHawk judged suspicious or worse.
WEB_KINDS = ("link", "domain", "host")
VERDICT_ORDER = ("NO STRONG INDICATORS", "SUSPICIOUS", "LIKELY PHISHING", "MALICIOUS")
_PREFIX_RE = re.compile(r"^(?:\s*(?:re|fw|fwd|aw|wg|sv|vs|tr|rv|antw)\s*(?:\[\d+\])?\s*:\s*)+", re.I)
_DIGITS_RE = re.compile(r"\d+")
MIN_SUBJECT = 8
# A parent domain under which the messages use many different host names is a
# platform whose customers each get a host (Cloud Run, a CentralNic zone, ...):
# it links by host, never as a whole.
PLATFORM_MIN_HOSTS = 5
PLATFORM_HOST_SHARE = 0.6


def normalise_subject(subject: str) -> str:
    """Reply and forward prefixes dropped, numbers made alike, case and spacing folded."""
    text = _PREFIX_RE.sub("", subject or "")
    text = " ".join(_DIGITS_RE.sub("#", text).lower().split())
    return text if len(text) >= MIN_SUBJECT else ""


def _shared_service(a: Analysis, base: str) -> bool:
    return (not base or "." not in base or base in SHORTENERS or base in FREEMAIL or base in BULK_MAIL
            or base in RESERVED_DOMAINS or base in WEB_PLUMBING or a.is_trusted_domain(base))


def _link_key(url: str) -> str:
    """scheme://host/path, without the query or fragment that phishing kits
    fill with a per-recipient token."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    return "%s://%s%s" % (parts.scheme.lower(), host, parts.path or "/") if host else ""


_BUCKET_HOSTS = {"storage.googleapis.com": 1, "firebasestorage.googleapis.com": 3, "s3.amazonaws.com": 1}


def _bucket(url: str) -> str:
    """host/bucket for cloud storage where the tenant is in the path, not the host."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    depth = _BUCKET_HOSTS.get(host) or (1 if re.fullmatch(r"s3[.-][a-z0-9-]+\.amazonaws\.com", host) else 0)
    segments = [s for s in (parts.path or "").split("/") if s][:depth]
    return "%s/%s" % (host, "/".join(segments)) if depth and len(segments) == depth else ""


def _embedded(sources: list[str]) -> bool:
    """Only ever an image, stylesheet or other resource the message loads, never a link to follow."""
    return bool(sources) and all(source.endswith("resource") for source in sources)


def traits(a: Analysis) -> dict[str, set[str]]:
    """{kind: values} for one analysis; see the module docstring for what counts."""
    return _traits(a)[0]


def _traits(a: Analysis) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """The traits, and the host names seen under each domain-level one."""
    found: dict[str, set[str]] = defaultdict(set)
    under: dict[str, set[str]] = defaultdict(set)
    lists = {registrable_domain(domain) for domain in a.list_domains}  # a mailing list's own links
    for f in a.attachments:
        if not f.inline and f.sha256:
            found["attachment"].add(f.sha256)
    for ioc in a.urls:
        host = (ioc.host or "").lower()
        base = registrable_domain(host)
        kind = hosting_kind(ioc.url)
        if _embedded(ioc.sources) or base in lists:
            continue  # logos and pixels: copied brand templates load the same ones whoever sends them
        if kind == "file sharing" or _bucket(ioc.url):
            found["link"].add(_link_key(ioc.url))  # the tenant is in the path: one document, one link
            if _bucket(ioc.url):
                found["host"].add(_bucket(ioc.url))
        elif kind in ("free hosting", "tunnel or IPFS"):
            found["host"].add(host)  # the tenant is the host name, never the provider
            found["link"].add(_link_key(ioc.url))
        elif base in BULK_MAIL or base in GATEWAYS:
            found["link"].add(ioc.url)  # unique per recipient or per link: only an exact match counts
        elif not _shared_service(a, base):
            found["domain"].add(base)
            under[base].add(host)
            found["link"].add(_link_key(ioc.url))
    for code in a.qr_codes:
        if code.get("payload"):
            found["qr"].add(code["payload"])
    for kind, address in (("sender", a.from_address), ("reply-to", a.reply_to)):
        address = (address or "").lower()
        domain = registrable_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""
        # One free-mail account is one person (or one attacker), whatever the provider.
        if domain in FREEMAIL or not (_shared_service(a, domain) or domain in BULK_MAIL):
            found[kind].add(address)
    sender_base = registrable_domain(a.from_domain)
    sender_hosting = hosting_kind("https://%s/" % a.from_domain) if a.from_domain else ""
    if sender_hosting in ("free hosting", "tunnel or IPFS"):
        found["sender domain"].add(a.from_domain.lower())
    elif sender_base and not sender_hosting and not _shared_service(a, sender_base):
        found["sender domain"].add(sender_base)
        under[sender_base].add(a.from_domain.lower())
    for wallet in a.wallets:
        found["wallet"].add(wallet["address"])
    for number in a.phones:
        found["phone"].add(number)
    subject = normalise_subject(a.subject)
    if subject:
        found["subject"].add(subject)
    display = " ".join((a.from_display or "").lower().split())
    if len(display) >= 4:
        found["display name"].add(display)
    if a.originating_ip:
        found["originating IP"].add(a.originating_ip)
    found["link"].discard("")
    return {kind: values for kind, values in found.items() if values}, dict(under)


def _platforms(unders: list[dict[str, set[str]]]) -> list[dict[str, Any]]:
    holders: dict[str, int] = defaultdict(int)
    hosts: dict[str, set[str]] = defaultdict(set)
    for under in unders:
        for base, names in under.items():
            holders[base] += 1
            hosts[base] |= names
    found = [{"domain": base, "messages": holders[base], "hosts": len(hosts[base])} for base in holders
             if base in KNOWN_PLATFORMS
             or len(hosts[base]) >= max(PLATFORM_MIN_HOSTS, PLATFORM_HOST_SHARE * holders[base])]
    return sorted(found, key=lambda p: (-p["messages"], p["domain"]))


class _Groups:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def join(self, i: int, j: int) -> None:
        a, b = self.find(i), self.find(j)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def _when(date: str) -> dt.datetime | None:
    try:
        parsed = email.utils.parsedate_to_datetime(date)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    try:
        return parsed.astimezone(dt.timezone.utc)
    except (OverflowError, ValueError):
        return None


def _iso(moment: dt.datetime | None) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else ""


def _recipients(a: Analysis) -> set[str]:
    try:
        pairs = email.utils.getaddresses([a.to or ""])
    except Exception:  # a malformed To line names nobody
        return set()
    return {address.lower() for _, address in pairs if "@" in address}


def _summary(path: str, a: Analysis) -> dict[str, Any]:
    return {"path": path, "subject": a.subject, "from": a.from_address, "date": a.date, "verdict": a.verdict,
            "score": a.score, "sha256": a.evidence.get("sha256", "")}


def correlate(items: list[tuple[str, Analysis]], min_size: int = 2, weak_cap: int = 200) -> dict[str, Any]:
    """{"messages": n, "clusters": [...], "unclustered": [...]} for (path, analysis) pairs."""
    pairs = [_traits(a) for _, a in items]
    found = [traits for traits, _ in pairs]
    suspicious = [a.verdict != "NO STRONG INDICATORS" for _, a in items]
    platforms = _platforms([under for _, under in pairs])
    platform_names = {p["domain"] for p in platforms}
    for message_traits, (_, under) in zip(found, pairs, strict=True):
        for kind in ("domain", "sender domain"):
            for base in message_traits.get(kind, set()) & platform_names:
                message_traits[kind].discard(base)
                message_traits.setdefault("host", set()).update(under[base])
        for kind in [k for k, values in message_traits.items() if not values]:
            del message_traits[kind]
    groups = _Groups(len(items))
    holders: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, message_traits in enumerate(found):
        for kind, values in message_traits.items():
            for value in values:
                holders[(kind, value)].append(index)
    weak_pairs: dict[tuple[int, int], set[str]] = defaultdict(set)
    for (kind, _value), members in holders.items():
        if kind in WEAK_KINDS:
            if len(members) > weak_cap:
                continue
            for x, first in enumerate(members):
                for second in members[x + 1:]:
                    weak_pairs[(first, second)].add(kind)
        elif kind not in WEB_KINDS or 2 * sum(suspicious[i] for i in members) >= len(members):
            for other in members[1:]:
                groups.join(members[0], other)
    for (first, second), kinds in weak_pairs.items():
        if len(kinds) >= 2:
            groups.join(first, second)

    members_of: dict[int, list[int]] = defaultdict(list)
    for index in range(len(items)):
        members_of[groups.find(index)].append(index)
    clusters: list[dict[str, Any]] = []
    unclustered: list[dict[str, Any]] = []
    for members in members_of.values():
        if len(members) < max(2, min_size):
            unclustered += [_summary(*items[i]) for i in members]
            continue
        analyses = [items[i][1] for i in members]
        shared: list[dict[str, Any]] = []
        for kind in STRONG_KINDS + WEAK_KINDS:
            counts: dict[str, int] = defaultdict(int)
            for i in members:
                for value in found[i].get(kind, ()):
                    counts[value] += 1
            shared += [{"kind": kind, "value": value, "messages": n} for value, n in counts.items() if n >= 2]
        shared.sort(key=lambda item: (-item["messages"], (STRONG_KINDS + WEAK_KINDS).index(item["kind"]),
                                      item["value"]))
        moments = sorted(m for m in (_when(a.date) for a in analyses) if m is not None)
        verdicts: dict[str, int] = defaultdict(int)
        for a in analyses:
            verdicts[a.verdict] += 1
        clusters.append({
            "size": len(members),
            "messages": sorted((_summary(*items[i]) for i in members), key=lambda m: m["path"]),
            "shared": shared[:25],
            "recipients": sorted(set().union(*(_recipients(a) for a in analyses))),
            "senders": sorted({a.from_address.lower() for a in analyses if a.from_address}),
            "first_seen": _iso(moments[0]) if moments else "",
            "last_seen": _iso(moments[-1]) if moments else "",
            "verdicts": dict(sorted(verdicts.items(), key=lambda item: VERDICT_ORDER.index(item[0]))),
            "worst_verdict": max(verdicts, key=VERDICT_ORDER.index),
        })
    clusters.sort(key=lambda c: (-c["size"], c["first_seen"] or "~", c["messages"][0]["path"]))
    for number, cluster in enumerate(clusters, 1):
        cluster["id"] = "C%d" % number
    return {"messages": len(items), "clusters": [dict(id=c.pop("id"), **c) for c in clusters],
            "unclustered": sorted(unclustered, key=lambda m: m["path"]), "platforms": platforms}
