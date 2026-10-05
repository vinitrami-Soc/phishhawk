"""Data model shared by the parser, heuristics, enrichment and reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .extract import defang_url, registrable_domain
from .hosting import hosting_kind
from .knowledge import FREEMAIL, SHORTENERS, known_legit_domains

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}
LOW_CAP = 3  # low-severity signals add at most this many points between them
# One engine is noise; two independent engines is the usual SOC bar.
VT_MALICIOUS_MIN = 2


def vt_is_malicious(report: dict[str, Any] | None) -> bool:
    return bool(report and report.get("status") == "ok"
                and report.get("malicious", 0) >= VT_MALICIOUS_MIN)


def vt_is_suspicious(report: dict[str, Any] | None) -> bool:
    if not report or report.get("status") != "ok" or vt_is_malicious(report):
        return False
    return report.get("malicious", 0) > 0 or report.get("suspicious", 0) > 0


def _blank_parentheses(label: str) -> str:
    """What re.sub(r"\\([^)]*\\)", "()", label) gives, in linear time: that
    pattern rescans to the end from every "(" once no ")" is left."""
    out, start = [], 0
    while True:
        opening = label.find("(", start)
        closing = label.find(")", opening + 1) if opening >= 0 else -1
        if closing < 0:
            out.append(label[start:])
            return "".join(out)
        out.append(label[start:opening] + "()")
        start = closing + 1


def signal_kind(label: str) -> str:
    """A signal's label without the particulars: "credential-harvesting path
    on a[.]com" and "... on b[.]net" are one kind of finding. Labels quote
    the message, so every step here is linear in the label's length."""
    label = _blank_parentheses(label)
    label = re.sub(r"'[^']*'", "''", label)
    # A defanged domain or address ("a[.]com", "x@b[.]net"): "[.]" inside a word.
    label = re.sub(r"\S+", lambda word: "D" if "[.]" in word.group()[1:-1] else word.group(), label)
    label = re.sub(r"\d+", "N", label)
    return label.split(":", 1)[0] + ":" if ":" in label else label


# What part of a message a signal is about. Two signals from different
# families are independent evidence; two from the same family (DKIM fail and
# DMARC fail, say) are one finding seen twice.
FAMILIES = ("auth", "sender", "link", "attachment", "content", "evasion", "intel", "policy")


@dataclass
class Signal:
    severity: str  # high | medium | low
    label: str
    techniques: tuple[str, ...] = ()
    family: str = ""  # one of FAMILIES; "" for signals added outside the heuristics

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 1)


@dataclass
class UrlIoc:
    url: str
    host: str
    domain: str
    sources: list[str] = field(default_factory=list)
    anchor_texts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    flagged: bool = False  # true only for notes that would change triage
    redirect_to: str = ""  # target, when this is an open redirect on a trusted domain
    wrapped_by: str = ""   # the redirector or mail gateway that wrapped the link
    vt: dict[str, Any] | None = None
    urlscan: dict[str, Any] | None = None

    @property
    def defanged(self) -> str:
        return defang_url(self.url)


@dataclass
class FileIoc:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    true_type: str = ""
    parent: str = ""  # set when the file was pulled out of an archive
    inline: bool = False  # inline image (signature logo etc.): not an IOC
    notes: list[str] = field(default_factory=list)
    flagged: bool = False
    vt: dict[str, Any] | None = None
    archive: dict[str, Any] | None = None  # any container: ZIP, RAR, 7z, tar, ISO, disk image, winmail.dat
    html: dict[str, Any] | None = None
    details: dict[str, Any] = field(default_factory=dict)  # per-format findings: office, pdf, rtf, lnk ...


@dataclass
class Lookalike:
    domain: str
    target: str
    method: str  # homoglyph | typosquat | combosquat
    where: str   # sender, reply-to, return-path, url


MIME_TOO_DEEP = 1000  # Analysis.mime_depth when the parser could not follow the nesting


@dataclass
class Analysis:
    path: str
    evidence: dict[str, Any] = field(default_factory=dict)  # sha256, sha1, md5, size of the bytes analysed
    subject: str = ""
    date: str = ""
    message_id: str = ""
    to: str = ""
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    originating_ip: str = ""
    received_hops: int = 0
    hops: list[dict[str, Any]] = field(default_factory=list)  # Received chain, oldest first: from, by, ip, time
    mailing_list: bool = False  # List-Post, Mailing-List, X-BeenThere or Precedence: list
    list_domains: list[str] = field(default_factory=list)  # where those list headers point
    auth: dict[str, str] = field(default_factory=dict)
    forged_auth: list[dict[str, Any]] = field(default_factory=list)  # pass claims below the receiver's
    reported_by: dict[str, Any] | None = None
    forwarded_from: dict[str, str] | None = None  # original sender of an inline forward
    protected_domains: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)  # configured partners: trusted like known brands
    blocked_domains: list[str] = field(default_factory=list)  # configured: always flagged
    urls: list[UrlIoc] = field(default_factory=list)
    urls_dropped: int = 0  # distinct links past the per-message cap: counted, not checked
    mime_depth: int = 0  # deepest multipart nesting, MIME_TOO_DEEP if the parser gave up; real mail: under five
    attachments: list[FileIoc] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    body_emails: list[str] = field(default_factory=list)
    qr_codes: list[dict[str, str]] = field(default_factory=list)  # where, payload, url
    calendar: list[dict[str, Any]] = field(default_factory=list)  # invitations: organizer, summary, links
    wallets: list[dict[str, str]] = field(default_factory=list)  # cryptocurrency addresses: currency, address
    phones: list[str] = field(default_factory=list)  # numbers a callback phish asks the reader to ring
    yara: list[dict[str, Any]] = field(default_factory=list)  # matches of your YARA rules: rule, where, severity
    lookalikes: list[Lookalike] = field(default_factory=list)
    zero_width_chars: int = 0
    hidden_splits: int = 0  # hidden text inside visible words
    tag_splits: int = 0  # visible words broken up by HTML tags
    hidden_filler: int = 0  # letters of hidden text unrelated to the visible text
    hidden_sample: str = ""  # the start of that hidden text
    script_links: list[dict[str, Any]] = field(default_factory=list)  # javascript: and data:text/html links
    body_text: str = field(default="", repr=False)  # visible then hidden text, capped; not exported
    ip_intel: dict[str, Any] | None = None
    domain_intel: dict[str, dict[str, Any]] = field(default_factory=dict)
    enrichment_sources: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ----------------------------------------------------------- signals --
    def add_signal(self, severity: str, label: str, techniques: tuple[str, ...] = (), family: str = "") -> None:
        labels = self.__dict__.setdefault("_signal_labels", set())  # not a field: never exported
        if len(labels) != len(self.signals):  # the list was edited directly
            labels.clear()
            labels.update(existing.label for existing in self.signals)
        if label in labels:
            return
        labels.add(label)
        # The heuristics say which family they are checking; see heuristics.analyse.
        family = family or self.__dict__.get("_family", "")
        self.signals.append(Signal(severity, label, tuple(techniques), family))

    @property
    def score(self) -> int:
        """Weighted sum of the signals. Low-severity signals add at most 3
        points between them, and several of one kind count once: a
        newsletter's links to a dozen sign-in pages are one weak finding,
        not a dozen, and weak findings must not add up to a verdict alone."""
        return sum(s.weight for s in self.signals if s.severity != "low") + self.low_points

    @property
    def low_points(self) -> int:
        kinds = {signal_kind(s.label) for s in self.signals if s.severity == "low"}
        return min(len(kinds), LOW_CAP)

    @property
    def techniques(self) -> list[str]:
        seen: list[str] = []
        for signal in self.signals:
            for technique in signal.techniques:
                if technique not in seen:
                    seen.append(technique)
        return sorted(seen)

    @property
    def verdict(self) -> str:
        if any(vt_is_malicious(u.vt) for u in self.urls) or \
           any(vt_is_malicious(a.vt) for a in self.attachments):
            return "MALICIOUS"
        high = sum(1 for signal in self.signals if signal.severity == "high")
        if high >= 2 or (high and self.score >= 8) or (high and self.corroborated):
            return "LIKELY PHISHING"
        if len(self.families) >= 3 and self.score >= 8:  # three independent kinds of medium evidence
            return "LIKELY PHISHING"
        if high or self.score >= 4:
            return "SUSPICIOUS"
        return "NO STRONG INDICATORS"

    @property
    def families(self) -> set[str]:
        """The parts of the message that medium or high signals are about."""
        return {s.family for s in self.signals if s.severity != "low" and s.family}

    @property
    def corroborated(self) -> bool:
        """A high-severity signal backed by a medium or high one about another
        part of the message: a lookalike sender that also links to a raw IP,
        say, rather than two views of the same forged header."""
        families = self.families
        return any(s.severity == "high" and s.family and families - {s.family} for s in self.signals)

    # -------------------------------------------------------------- IOCs --
    def is_protected(self, domain: str) -> bool:
        base = registrable_domain(domain)
        return bool(base) and base in {registrable_domain(d) for d in self.protected_domains}

    def is_trusted_domain(self, domain: str) -> bool:
        base = registrable_domain(domain)
        return base in known_legit_domains() or self.is_protected(domain) or base in self.allowed_domains

    def iocs(self) -> list[dict[str, str]]:
        """Indicators worth blocking or sharing. Empty for a clean verdict.

        Known-legitimate brand domains (the decoy login.microsoftonline.com in
        a spoof), your own protected domains, shorteners and free-mail
        providers are never emitted at domain level: blocking bit.ly or
        gmail.com company-wide would do more harm than the phish.
        """
        if self.verdict == "NO STRONG INDICATORS":
            return []
        out: list[dict[str, str]] = []
        seen: dict[tuple[str, str], dict[str, str]] = {}

        def add(kind: str, value: str, context: str) -> None:
            if not value:
                return
            existing = seen.get((kind, value))
            if existing is None:
                seen[(kind, value)] = entry = {"type": kind, "value": value, "context": context}
                out.append(entry)
            elif context and context not in existing["context"].split(", "):
                existing["context"] += ", " + context  # an IP that is both a link host and the origin

        for ioc in self.urls:
            # A Google Drive or Forms link is blockable as a URL even though
            # google.com obviously is not.
            if not self.is_trusted_domain(ioc.host) or hosting_kind(ioc.url):
                add("url", ioc.url, ", ".join(ioc.sources))

        domain_roles = [(self.from_domain, "sender domain"),
                        (self.reply_to_domain, "reply-to domain"),
                        (self.return_path_domain, "return-path domain")]
        domain_roles += [(ioc.host, "url host") for ioc in self.urls]
        for domain, role in domain_roles:
            base = registrable_domain(domain)
            if (not base or base in SHORTENERS or base in FREEMAIL or self.is_trusted_domain(base)
                    or hosting_kind("https://%s/" % domain) in ("free hosting", "file sharing")):
                continue
            kind = "ipv6" if ":" in domain else "ipv4" if domain.replace(".", "").isdigit() else "domain"
            add(kind, domain, role)

        for address, role in ((self.from_address, "sender address"),
                              (self.reply_to, "reply-to address")):
            if address and not self.is_trusted_domain(address.rsplit("@", 1)[-1]):
                add("email", address, role)

        if self.originating_ip:
            add("ipv6" if ":" in self.originating_ip else "ipv4", self.originating_ip, "originating IP")
        for wallet in self.wallets:
            add("crypto-wallet", wallet["address"], "%s wallet in the message" % wallet["currency"])
        for number in self.phones:
            add("phone", number, "number the message asks the reader to call")
        for attachment in self.attachments:
            if attachment.inline or not attachment.sha256:
                continue
            origin = "inside %s" % attachment.parent if attachment.parent else "attachment"
            add("sha256", attachment.sha256, "%s (%s)" % (attachment.filename, origin))
        return out
