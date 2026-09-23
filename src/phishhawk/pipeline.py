"""parse -> offline heuristics -> optional enrichment -> enrichment signals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import heuristics
from .enrich import Enricher
from .models import Analysis
from .parse import parse_bytes, parse_file


@dataclass
class Options:
    unwrap: bool = True
    protected: list[str] = field(default_factory=list)
    auto_protect: bool = True


def _finish(analysis: Analysis, enricher: Enricher | None,
            progress: Callable[[str], None] | None) -> Analysis:
    heuristics.analyse(analysis)
    if enricher is not None:
        enricher.enrich(analysis, progress)
        heuristics.apply_enrichment(analysis)
    return analysis


def triage_file(path: str, options: Options | None = None, enricher: Enricher | None = None,
                progress: Callable[[str], None] | None = None) -> Analysis:
    options = options or Options()
    analysis = parse_file(path, unwrap=options.unwrap, protected=options.protected,
                          auto_protect=options.auto_protect)
    return _finish(analysis, enricher, progress)


def triage_bytes(data: bytes, path: str = "<memory>", options: Options | None = None,
                 enricher: Enricher | None = None,
                 progress: Callable[[str], None] | None = None) -> Analysis:
    options = options or Options()
    analysis = parse_bytes(data, path=path, unwrap=options.unwrap, protected=options.protected,
                           auto_protect=options.auto_protect)
    return _finish(analysis, enricher, progress)
