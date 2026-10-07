"""The engine as one call, for the web app and anything else that is not the
CLI: raw message bytes in; the analysis, every report format, the record that
is kept after the message is deleted, and what was sent to which provider out."""

from __future__ import annotations

import email.utils
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from . import __version__, campaign
from .cache import Cache
from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
from .enrich.base import new_session
from .models import Analysis
from .pipeline import Options, triage_bytes
from .report.bundle import RenderedFile, render_bundle
from .report.common import report_id, to_dict

PROVIDERS = ("virustotal", "urlscan", "rdap", "abuseipdb")


@dataclass
class AnalysisOptions:
    providers: frozenset[str] = frozenset()  # the enabled ones; empty means offline
    keys: dict[str, str] = field(default_factory=dict)  # provider name -> API key
    protected: list[str] = field(default_factory=list)
    allow_domains: list[str] = field(default_factory=list)
    block_domains: list[str] = field(default_factory=list)
    trusted_authserv: list[str] = field(default_factory=list)
    cache_path: str | None = None
    timeout: float = 20
    tlp: str = "amber"


@dataclass
class AnalysisResult:
    analysis: Analysis
    data: dict[str, Any]  # to_dict(): the full JSON report
    files: list[RenderedFile]  # six formats and the manifest
    summary: dict[str, Any]  # the record kept after the message is deleted
    traits: dict[str, Any]  # campaign.trait_record()
    lookups: list[dict[str, str]]  # every request sent to a provider


class _Recorder:
    """A provider's HTTP session that notes every request it sends: the
    provider, the method and the URL with its query. API keys travel in
    headers and are never noted."""

    def __init__(self, inner: Any, provider: str, log: list[dict[str, str]]) -> None:
        self._inner, self._provider, self._log = inner, provider, log

    def _note(self, method: str, url: str, params: Any) -> None:
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        self._log.append({"provider": self._provider, "method": method, "url": url})

    def get(self, url: str, **kwargs: Any) -> Any:
        self._note("GET", url, kwargs.get("params"))
        return self._inner.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        self._note("POST", url, kwargs.get("params"))
        return self._inner.post(url, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _enricher(options: AnalysisOptions, cache: Cache | None, log: list[dict[str, str]]) -> Enricher | None:
    enabled, keys = options.providers, options.keys
    if not enabled:
        return None
    common: dict[str, Any] = {"timeout": options.timeout, "cache": cache}

    def session(name: str) -> _Recorder:
        return _Recorder(new_session(), name, log)

    return Enricher(
        virustotal=VirusTotal(keys["virustotal"], session=session("virustotal"), **common)
        if "virustotal" in enabled and keys.get("virustotal") else None,
        urlscan=UrlScan(keys.get("urlscan", ""), session=session("urlscan"), **common)
        if "urlscan" in enabled else None,
        rdap=Rdap(session=session("rdap"), **common) if "rdap" in enabled else None,
        abuseipdb=AbuseIPDB(keys["abuseipdb"], session=session("abuseipdb"), **common)
        if "abuseipdb" in enabled and keys.get("abuseipdb") else None,
    )


def _summary(a: Analysis, data: dict[str, Any]) -> dict[str, Any]:
    try:
        recipients = {address.lower() for _, address in email.utils.getaddresses([a.to or ""]) if "@" in address}
    except Exception:  # a malformed To line names nobody
        recipients = set()
    return {
        "sha256": a.evidence.get("sha256", ""), "size": a.evidence.get("size", 0), "report_id": report_id(a),
        "verdict": a.verdict, "score": a.score, "engine_version": __version__,
        "sender": (a.from_address or "").lower(), "sender_domain": (a.from_domain or "").lower(),
        "recipient_count": len(recipients),
        "indicators": [{"type": ioc["type"], "value": ioc["value"]} for ioc in data["iocs"]],
        "techniques": [technique["id"] for technique in data["techniques"]],
    }


def analyze(raw: bytes, name: str = "<upload>", options: AnalysisOptions | None = None) -> AnalysisResult:
    options = options or AnalysisOptions()
    lookups: list[dict[str, str]] = []
    cache = Cache(options.cache_path) if options.cache_path and options.providers else None
    try:
        engine_options = Options(protected=list(options.protected), allow_domains=list(options.allow_domains),
                                 block_domains=list(options.block_domains),
                                 trusted_authserv=list(options.trusted_authserv))
        a = triage_bytes(raw, path=name, options=engine_options, enricher=_enricher(options, cache, lookups))
    finally:
        if cache is not None:
            cache.close()
    data = to_dict(a)
    return AnalysisResult(a, data, render_bundle([a], tlp=options.tlp), _summary(a, data),
                          campaign.trait_record(a), lookups)
