"""Data model shared by the parser, heuristics, enrichment and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .extract import defang_url, registrable_domain
from .knowledge import FREEMAIL, SHORTENERS, known_legit_domains

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}
# One engine is noise; two independent engines is the usual SOC bar.
VT_MALICIOUS_MIN = 2


def vt_is_malicious(report: dict[str, Any] | None) -> bool:
    return bool(report and report.get("status") == "ok"
                and report.get("malicious", 0) >= VT_MALICIOUS_MIN)


def vt_is_suspicious(report: dict[str, Any] | None) -> bool:
    if not report or report.get("status") != "ok" or vt_is_malicious(report):
        return False
    return report.get("malicious", 0) > 0 or report.get("suspicious", 0) > 0


@dataclass
class Signal:
    severity: str  # high | medium | low
    label: str
    techniques: tuple[str, ...] = ()

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
    archive: dict[str, Any] | None = None
    html: dict[str, Any] | None = None


@dataclass
class Lookalike:
    domain: str
    target: str
    method: str  # homoglyph | typosquat | combosquat
    where: str   # sender, reply-to, return-path, url


@dataclass
class Analysis:
    path: str
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
    auth: dict[str, str] = field(default_factory=dict)
    reported_by: dict[str, Any] | None = None
    protected_domains: list[str] = field(default_factory=list)
    urls: list[UrlIoc] = field(default_factory=list)
    attachments: list[FileIoc] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    body_emails: list[str] = field(default_factory=list)
    lookalikes: list[Lookalike] = field(default_factory=list)
    zero_width_chars: int = 0
    ip_intel: dict[str, Any] | None = None
    domain_intel: dict[str, dict[str, Any]] = field(default_factory=dict)
    enrichment_sources: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # ----------------------------------------------------------- signals --
    def add_signal(self, severity: str, label: str, techniques: tuple[str, ...] = ()) -> None:
        if any(existing.label == label for existing in self.signals):
            return
        self.signals.append(Signal(severity, label, tuple(techniques)))

    @property
    def score(self) -> int:
        return sum(signal.weight for signal in self.signals)

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
        if high >= 2 or self.score >= 6:
            return "LIKELY PHISHING"
        if high or self.score >= 3:
            return "SUSPICIOUS"
        return "NO STRONG INDICATORS"

    # -------------------------------------------------------------- IOCs --
    def is_protected(self, domain: str) -> bool:
        base = registrable_domain(domain)
        return bool(base) and base in {registrable_domain(d) for d in self.protected_domains}

    def is_trusted_domain(self, domain: str) -> bool:
        return registrable_domain(domain) in known_legit_domains() or self.is_protected(domain)

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
        seen: set[tuple[str, str]] = set()

        def add(kind: str, value: str, context: str) -> None:
            if value and (kind, value) not in seen:
                seen.add((kind, value))
                out.append({"type": kind, "value": value, "context": context})

        for ioc in self.urls:
            if not self.is_trusted_domain(ioc.host):
                add("url", ioc.url, ", ".join(ioc.sources))

        domain_roles = [(self.from_domain, "sender domain"),
                        (self.reply_to_domain, "reply-to domain"),
                        (self.return_path_domain, "return-path domain")]
        domain_roles += [(ioc.host, "url host") for ioc in self.urls]
        for domain, role in domain_roles:
            base = registrable_domain(domain)
            if not base or base in SHORTENERS or base in FREEMAIL or self.is_trusted_domain(base):
                continue
            add("ipv4" if domain.replace(".", "").isdigit() else "domain", domain, role)

        for address, role in ((self.from_address, "sender address"),
                              (self.reply_to, "reply-to address")):
            if address and not self.is_trusted_domain(address.rsplit("@", 1)[-1]):
                add("email", address, role)

        if self.originating_ip:
            add("ipv4", self.originating_ip, "originating IP")
        for attachment in self.attachments:
            if attachment.inline or not attachment.sha256:
                continue
            origin = "inside %s" % attachment.parent if attachment.parent else "attachment"
            add("sha256", attachment.sha256, "%s (%s)" % (attachment.filename, origin))
        return out
