"""Reputation enrichment: which indicator goes to which provider, and which
never leaves the machine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..extract import PRIVATE_IP_RE, is_ip, registrable_domain
from ..knowledge import FREEMAIL, SHORTENERS
from ..models import Analysis
from .abuseipdb import AbuseIPDB
from .base import Provider, RateLimiter
from .rdap import Rdap
from .urlscan import UrlScan
from .virustotal import VirusTotal

__all__ = ["AbuseIPDB", "Enricher", "Provider", "RateLimiter", "Rdap", "UrlScan", "VirusTotal"]

TRUSTED_SKIP = {"status": "skipped", "detail": "trusted domain, not sent to third parties"}
BUDGET_SKIP = {"status": "skipped", "detail": "per-message VirusTotal budget used"}


@dataclass
class Enricher:
    virustotal: VirusTotal | None = None
    urlscan: UrlScan | None = None
    rdap: Rdap | None = None
    abuseipdb: AbuseIPDB | None = None
    urlscan_submit: bool = False
    vt_budget: int = 20  # network lookups per message; cache hits are free

    @property
    def sources(self) -> list[str]:
        providers = (self.virustotal, self.urlscan, self.rdap, self.abuseipdb)
        return [provider.name for provider in providers if provider is not None]

    def enrich(self, analysis: Analysis, progress: Callable[[str], None] | None = None) -> Analysis:
        note = progress or (lambda message: None)
        analysis.enrichment_sources = self.sources
        if self.virustotal is not None:
            self._virustotal(analysis, note)
        if self.urlscan is not None:
            self._urlscan(analysis, note)
        if self.rdap is not None:
            self._rdap(analysis, note)
        ip = analysis.originating_ip
        if self.abuseipdb is not None and ip and not PRIVATE_IP_RE.match(ip):
            note("AbuseIPDB %s" % ip)
            analysis.ip_intel = self.abuseipdb.check_ip(ip)
        return analysis

    def _virustotal(self, a: Analysis, note: Callable[[str], None]) -> None:
        vt = self.virustotal
        start = vt.calls
        # Spend the budget where it matters: already-suspicious IOCs first.
        for ioc in sorted(a.urls, key=lambda u: not u.flagged):
            if a.is_trusted_domain(ioc.host):
                ioc.vt = dict(TRUSTED_SKIP)
            elif vt.calls - start >= self.vt_budget:
                ioc.vt = dict(BUDGET_SKIP)
            else:
                note("VirusTotal URL on %s" % ioc.host)
                ioc.vt = vt.lookup_url(ioc.url)
        files = [f for f in a.attachments if not f.inline and f.sha256]
        for f in sorted(files, key=lambda f: (bool(f.parent), not f.flagged)):
            if vt.calls - start >= self.vt_budget:
                f.vt = dict(BUDGET_SKIP)
            else:
                note("VirusTotal file %s" % f.filename)
                f.vt = vt.lookup_file(f.sha256)

    def _urlscan(self, a: Analysis, note: Callable[[str], None]) -> None:
        results: dict[str, dict] = {}
        for ioc in a.urls:
            if a.is_trusted_domain(ioc.host):
                continue
            if ioc.host not in results:
                note("urlscan.io %s" % ioc.host)
                results[ioc.host] = self.urlscan.search_host(ioc.host)
            ioc.urlscan = dict(results[ioc.host])
            if self.urlscan_submit:
                ioc.urlscan["submission"] = self.urlscan.submit(ioc.url)

    def _rdap(self, a: Analysis, note: Callable[[str], None]) -> None:
        candidates = [a.from_domain, a.reply_to_domain, a.return_path_domain]
        candidates += [ioc.host for ioc in a.urls]
        for host in candidates:
            base = registrable_domain(host)
            if (not base or is_ip(base) or base in a.domain_intel or base in SHORTENERS
                    or base in FREEMAIL or a.is_trusted_domain(base)):
                continue
            note("RDAP %s" % base)
            a.domain_intel[base] = self.rdap.domain_age(base)
