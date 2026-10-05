"""parse -> offline heuristics -> optional enrichment -> enrichment signals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import evidence, heuristics, yararules
from .enrich import Enricher
from .extract import registrable_domain
from .models import Analysis, FileIoc
from .parse import load_message, parse_message


@dataclass
class Options:
    unwrap: bool = True
    protected: list[str] = field(default_factory=list)
    auto_protect: bool = True
    qr: bool = True  # decode QR codes when the optional extra is installed
    trusted_authserv: list[str] = field(default_factory=list)  # your MX's authserv-id(s)
    allow_domains: list[str] = field(default_factory=list)  # partners never reported as lookalikes or IOCs
    block_domains: list[str] = field(default_factory=list)  # domains always flagged
    yara: yararules.Rules | None = None  # compiled rules from --yara
    keep_files: bool = False  # hold every file's bytes for a sandbox pack (see sandbox.py)


def _carriers(analysis: Analysis, options: Options) -> None:
    """An attacker can attach a harmless message to the phish, hoping the
    unwrapping step analyses the attachment instead. So every layer that was
    unwrapped is analysed too, and a suspicious one keeps its findings."""
    for carrier in getattr(analysis, "_carriers", []):
        wrapper = parse_message(carrier, path=analysis.path, unwrap=False, protected=analysis.protected_domains,
                                auto_protect=False, qr=options.qr,
                                trusted_authserv=tuple(options.trusted_authserv), open_attached=True)
        heuristics.analyse(wrapper)
        if wrapper.verdict == "NO STRONG INDICATORS":
            continue
        for signal in wrapper.signals:
            analysis.add_signal(signal.severity, "carrier email: %s" % signal.label, signal.techniques,
                                signal.family)
        known = {ioc.url.rstrip("/").lower() for ioc in analysis.urls}
        for ioc in wrapper.urls:
            if ioc.url.rstrip("/").lower() not in known:
                ioc.sources = ["carrier email %s" % source for source in ioc.sources]
                analysis.urls.append(ioc)
        analysis.lookalikes.extend(wrapper.lookalikes)


def _finish(analysis: Analysis, options: Options, enricher: Enricher | None,
            progress: Callable[[str], None] | None) -> Analysis:
    analysis.allowed_domains = sorted({registrable_domain(d) for d in options.allow_domains if d})
    analysis.blocked_domains = sorted({registrable_domain(d) for d in options.block_domains if d})
    heuristics.analyse(analysis)
    _carriers(analysis, options)
    if enricher is not None:
        enricher.enrich(analysis, progress)
        heuristics.apply_enrichment(analysis)
    return analysis


def _keep_file(analysis: Analysis, ioc: FileIoc, data: bytes) -> None:
    analysis.__dict__.setdefault("_files", []).append((ioc, data))  # not a field: never exported


def _file_hook(options: Options) -> Callable[[Analysis, FileIoc, bytes], None] | None:
    hooks = [yararules.hook(options.yara)] if options.yara is not None else []
    if options.keep_files:
        hooks.append(_keep_file)
    if not hooks:
        return None

    def run(analysis: Analysis, ioc: FileIoc, data: bytes) -> None:
        for hook in hooks:
            hook(analysis, ioc, data)
    return run


def triage_bytes(data: bytes, path: str = "<memory>", options: Options | None = None,
                 enricher: Enricher | None = None,
                 progress: Callable[[str], None] | None = None) -> Analysis:
    options = options or Options()
    rules = options.yara
    analysis = parse_message(load_message(data), path=path, unwrap=options.unwrap,
                             protected=options.protected, auto_protect=options.auto_protect, qr=options.qr,
                             trusted_authserv=tuple(options.trusted_authserv),
                             file_hook=_file_hook(options))
    analysis.evidence = evidence.fingerprint(data)
    if rules is not None:
        for match in rules.match(data):
            match["where"] = "the raw message"
            analysis.yara.append(match)
    return _finish(analysis, options, enricher, progress)


def triage_file(path: str, options: Options | None = None, enricher: Enricher | None = None,
                progress: Callable[[str], None] | None = None) -> Analysis:
    with open(path, "rb") as handle:
        data = handle.read()
    return triage_bytes(data, path, options, enricher, progress)
