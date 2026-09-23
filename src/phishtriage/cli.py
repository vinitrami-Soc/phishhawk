"""Command-line interface: `phish-triage mail.eml`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable

from . import __version__
from .cache import Cache, default_cache_path
from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
from .models import Analysis
from .pipeline import Options, triage_bytes, triage_file
from .report import console, csvout, html, markdown, stix
from .report.common import to_dict

EXIT_CODES = {"NO STRONG INDICATORS": 0, "SUSPICIOUS": 1, "LIKELY PHISHING": 1, "MALICIOUS": 2}
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-triage",
        description="Extract, enrich and triage phishing IOCs from .eml files.",
        epilog="Exit codes: 0 nothing notable, 1 suspicious/likely phishing, 2 malicious, 3 error.",
    )
    parser.add_argument("inputs", nargs="*", metavar="PATH",
                        help=".eml files, directories (searched recursively) or '-' for stdin")

    out = parser.add_argument_group("output")
    out.add_argument("--json", metavar="PATH", help="full structured report ('-' for stdout)")
    out.add_argument("--html", metavar="PATH", help="self-contained HTML report")
    out.add_argument("--stix", metavar="PATH", help="STIX 2.1 bundle for MISP / OpenCTI ('-' for stdout)")
    out.add_argument("--md", metavar="PATH", help="Markdown ticket note ('-' for stdout)")
    out.add_argument("--csv", metavar="PATH", help="CSV indicator list for blocklists ('-' for stdout)")
    out.add_argument("--quiet", action="store_true", help="summary block only")
    out.add_argument("--verbose", action="store_true", help="every signal, MD5s and all actions")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours")

    det = parser.add_argument_group("detection")
    det.add_argument("--protect", action="append", default=[], metavar="DOMAIN",
                     help="your organisation's domain (repeatable; also $PHISHTRIAGE_PROTECT). "
                          "Lookalikes of it are flagged as BEC and it is never sent to third parties")
    det.add_argument("--no-auto-protect", action="store_true",
                     help="do not treat recipient domains as protected")
    det.add_argument("--no-unwrap", action="store_true",
                     help="analyse the outer message even when it forwards another as an attachment")

    enr = parser.add_argument_group("enrichment")
    enr.add_argument("--offline", action="store_true", help="no network access at all")
    enr.add_argument("--vt-key", default="", help="VirusTotal key (default $VT_API_KEY)")
    enr.add_argument("--vt-rate", type=int, default=4, help="VirusTotal lookups/minute (default 4, free tier)")
    enr.add_argument("--vt-budget", type=int, default=20,
                     help="max VirusTotal network lookups per message (default 20; cache hits are free)")
    enr.add_argument("--no-virustotal", action="store_true")
    enr.add_argument("--urlscan-key", default="", help="urlscan.io key (default $URLSCAN_API_KEY)")
    enr.add_argument("--no-urlscan", action="store_true", help="skip urlscan.io searches")
    enr.add_argument("--urlscan-submit", action="store_true",
                     help="submit URLs as unlisted scans (needs a key; sends the URL to a third party)")
    enr.add_argument("--abuseipdb-key", default="", help="AbuseIPDB key (default $ABUSEIPDB_API_KEY)")
    enr.add_argument("--no-abuseipdb", action="store_true")
    enr.add_argument("--no-rdap", action="store_true", help="skip RDAP domain-age lookups")
    enr.add_argument("--timeout", type=float, default=20, help="HTTP timeout in seconds (default 20)")

    cache = parser.add_argument_group("cache")
    cache.add_argument("--no-cache", action="store_true", help="do not read or write the lookup cache")
    cache.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS",
                       help="how long a lookup stays fresh (default 24)")
    cache.add_argument("--cache-path", default=default_cache_path(), metavar="PATH")
    cache.add_argument("--clear-cache", action="store_true", help="empty the lookup cache and exit")

    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def expand_inputs(inputs: list[str]) -> list[str]:
    paths: list[str] = []
    for item in inputs:
        if item != "-" and os.path.isdir(item):
            for root, _, names in os.walk(item):
                paths += [os.path.join(root, n) for n in sorted(names) if n.lower().endswith(".eml")]
        else:
            paths.append(item)
    return paths


def build_enricher(args: argparse.Namespace, cache: Cache | None, notices: list[str]) -> Enricher | None:
    if args.offline:
        notices.append("offline mode: no reputation lookups performed")
        return None
    vt_key = args.vt_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY", "")
    urlscan_key = args.urlscan_key or os.environ.get("URLSCAN_API_KEY", "")
    abuse_key = args.abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    common = {"timeout": args.timeout, "cache": cache}
    try:
        enricher = Enricher(
            virustotal=VirusTotal(vt_key, rate_per_minute=args.vt_rate, **common)
            if vt_key and not args.no_virustotal else None,
            urlscan=None if args.no_urlscan else UrlScan(urlscan_key, **common),
            rdap=None if args.no_rdap else Rdap(**common),
            abuseipdb=AbuseIPDB(abuse_key, **common) if abuse_key and not args.no_abuseipdb else None,
            urlscan_submit=args.urlscan_submit and bool(urlscan_key),
            vt_budget=args.vt_budget,
        )
    except RuntimeError as exc:  # requests not installed
        notices.append(str(exc))
        return None
    if not vt_key and not args.no_virustotal:
        notices.append("no VirusTotal key (set VT_API_KEY): skipping VirusTotal")
    if args.urlscan_submit and not urlscan_key:
        notices.append("--urlscan-submit ignored: no urlscan.io API key")
    if enricher.sources:
        notices.append("enrichment: %s (trusted and protected domains are never sent)"
                       % ", ".join(enricher.sources))
    return enricher


def _write(path: str, content: str) -> None:
    if path == "-":
        sys.stdout.write(content)
        sys.stdout.flush()
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    wants_cache = args.clear_cache or not (args.no_cache or args.offline)
    cache = Cache(args.cache_path, args.cache_ttl) if wants_cache else None
    if args.clear_cache:
        removed = cache.purge() if cache else 0
        print("cleared %d cached lookup(s)" % removed, file=sys.stderr)
        return 0
    if not args.inputs:
        parser.error("no input: give one or more .eml files, directories or '-'")

    outputs = {"json": args.json, "html": args.html, "stix": args.stix, "md": args.md, "csv": args.csv}
    if list(outputs.values()).count("-") > 1:
        parser.error("only one output can go to stdout ('-')")
    if args.html == "-":
        parser.error("--html needs a file path")
    machine_mode = "-" in outputs.values()
    show_console = not machine_mode

    colour = console.Palette(enabled=not args.no_color and sys.stdout.isatty()
                             and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ)
    err_colour = console.Palette(enabled=colour.enabled and sys.stderr.isatty())
    protected = list(args.protect)
    protected += [d.strip() for d in os.environ.get("PHISHTRIAGE_PROTECT", "").split(",") if d.strip()]
    options = Options(unwrap=not args.no_unwrap, protected=protected, auto_protect=not args.no_auto_protect)

    notices: list[str] = []
    enricher = build_enricher(args, cache, notices)
    for notice in notices:
        print(err_colour("[i] " + notice, "dim"), file=sys.stderr)

    progress: Callable[[str], None] | None = None
    if sys.stderr.isatty() and not args.quiet:
        def progress(message: str) -> None:
            sys.stderr.write("\r  ... %-60s" % message[:60])
            sys.stderr.flush()

    analyses: list[Analysis] = []
    worst = 0
    for path in expand_inputs(args.inputs):
        try:
            if path == "-":
                analysis = triage_bytes(sys.stdin.buffer.read(), "<stdin>", options, enricher, progress)
            else:
                analysis = triage_file(path, options, enricher, progress)
        except FileNotFoundError:
            print(err_colour("[!] %s: file not found" % path, "red"), file=sys.stderr)
            worst = EXIT_ERROR
            continue
        except Exception as exc:  # one malformed mail must not kill a batch run
            print(err_colour("[!] %s: could not analyse (%s: %s)" % (path, type(exc).__name__, exc), "red"),
                  file=sys.stderr)
            worst = EXIT_ERROR
            continue
        finally:
            if progress:
                sys.stderr.write("\r%-66s\r" % "")
        analyses.append(analysis)
        if worst != EXIT_ERROR:
            worst = max(worst, EXIT_CODES.get(analysis.verdict, 0))
        if show_console:
            print(console.render_quiet(analysis, colour) if args.quiet
                  else console.render(analysis, colour, verbose=args.verbose))
            print("")

    if show_console and len(analyses) > 1:
        print(console.render_batch_table(analyses, colour))
        print("")

    renderers = {
        "json": lambda: json.dumps(to_dict(analyses[0]) if len(analyses) == 1
                                   else {"reports": [to_dict(a) for a in analyses]},
                                   indent=2, ensure_ascii=False) + "\n",
        "html": lambda: html.render(analyses),
        "stix": lambda: json.dumps(stix.build_bundle(analyses), indent=2) + "\n",
        "md": lambda: "\n---\n\n".join(markdown.render(a) for a in analyses),
        "csv": lambda: csvout.render(analyses),
    }
    for kind, path in outputs.items():
        if not path or not analyses:
            continue
        try:
            _write(path, renderers[kind]())
            if path != "-":
                print(err_colour("[i] %s report written to %s" % (kind.upper(), path), "dim"), file=sys.stderr)
        except OSError as exc:
            print(err_colour("[!] could not write %s: %s" % (path, exc), "red"), file=sys.stderr)
            worst = EXIT_ERROR

    if cache is not None:
        if cache.hits:
            print(err_colour("[i] %d lookup(s) served from cache" % cache.hits, "dim"), file=sys.stderr)
        cache.close()
    return worst


if __name__ == "__main__":
    sys.exit(main())
