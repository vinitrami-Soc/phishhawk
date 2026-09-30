"""parse -> offline heuristics -> optional enrichment -> enrichment signals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import heuristics
from .enrich import Enricher
from .models import Analysis
from .parse import load_message, parse_message


@dataclass
class Options:
    unwrap: bool = True
    protected: list[str] = field(default_factory=list)
    auto_protect: bool = True
    qr: bool = True  # decode QR codes when the optional extra is installed
    trusted_authserv: list[str] = field(default_factory=list)  # your MX's authserv-id(s)


def _carriers(analysis: Analysis, options: Options) -> None:
    """An attacker can attach a harmless message to the phish, hoping the
    unwrapping step analyses the attachment instead. So every layer that was
    unwrapped is analysed too, and a suspicious one keeps its findings."""
    for carrier in getattr(analysis, "_carriers", []):
        wrapper = parse_message(carrier, path=analysis.path, unwrap=False, protected=analysis.protected_domains,
                                auto_protect=False, qr=options.qr,
                                trusted_authserv=tuple(options.trusted_authserv))
        heuristics.analyse(wrapper)
        if wrapper.verdict == "NO STRONG INDICATORS":
            continue
        for signal in wrapper.signals:
            analysis.add_signal(signal.severity, "carrier email: %s" % signal.label, signal.techniques)
        known = {ioc.url.rstrip("/").lower() for ioc in analysis.urls}
        for ioc in wrapper.urls:
            if ioc.url.rstrip("/").lower() not in known:
                ioc.sources = ["carrier email %s" % source for source in ioc.sources]
                analysis.urls.append(ioc)
        analysis.lookalikes.extend(wrapper.lookalikes)


def _finish(analysis: Analysis, options: Options, enricher: Enricher | None,
            progress: Callable[[str], None] | None) -> Analysis:
    heuristics.analyse(analysis)
    _carriers(analysis, options)
    if enricher is not None:
        enricher.enrich(analysis, progress)
        heuristics.apply_enrichment(analysis)
    return analysis


def triage_bytes(data: bytes, path: str = "<memory>", options: Options | None = None,
                 enricher: Enricher | None = None,
                 progress: Callable[[str], None] | None = None) -> Analysis:
    options = options or Options()
    analysis = parse_message(load_message(data), path=path, unwrap=options.unwrap,
                             protected=options.protected, auto_protect=options.auto_protect, qr=options.qr,
                             trusted_authserv=tuple(options.trusted_authserv))
    return _finish(analysis, options, enricher, progress)


def triage_file(path: str, options: Options | None = None, enricher: Enricher | None = None,
                progress: Callable[[str], None] | None = None) -> Analysis:
    with open(path, "rb") as handle:
        data = handle.read()
    return triage_bytes(data, path, options, enricher, progress)
