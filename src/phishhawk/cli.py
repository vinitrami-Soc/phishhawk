"""PhishHawk command-line interface.

    phishhawk scan mail.eml        triage messages (the default command)
    phishhawk doctor               check dependencies, API keys, cache and network
    phishhawk cache stats|clear    inspect or empty the lookup cache
    phishhawk techniques           the MITRE ATT&CK techniques PhishHawk can evidence
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import textwrap
from collections.abc import Callable

from . import __version__, banner
from .attack import EVIDENCE, TECHNIQUES
from .cache import Cache, default_cache_path
from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
from .models import Analysis
from .pipeline import Options, triage_bytes, triage_file
from .report import console, csvout, html, markdown, stix
from .report.common import to_dict

COMMANDS = ("scan", "doctor", "cache", "techniques", "help")
EXIT_CODES = {"NO STRONG INDICATORS": 0, "SUSPICIOUS": 1, "LIKELY PHISHING": 1, "MALICIOUS": 2}
EXIT_ERROR = 3

OVERVIEW = """\
PhishHawk extracts every indicator from a reported phishing email, checks the
ones that matter against VirusTotal, urlscan.io, RDAP and AbuseIPDB, maps what
it finds to MITRE ATT&CK, and tells you what to do next."""

MAIN_EPILOG = """\
quick start:
  phishhawk suspicious.eml            triage one message (same as: phishhawk scan ...)
  phishhawk scan reported/ --quiet    every .eml in a folder, one summary each
  phishhawk doctor                    check keys and setup before the first real run

Run `phishhawk <command> -h` for everything a command can do."""

SCAN_EPILOG = """\
examples:
  phishhawk scan suspicious.eml                  full report in the terminal
  phishhawk suspicious.eml                       the same: scan is the default command
  phishhawk scan reported/ --quiet               every .eml in a folder, one summary each
  cat suspicious.eml | phishhawk scan -          read the message from stdin
  phishhawk scan suspicious.eml --offline        nothing leaves this machine
  phishhawk scan mail.eml --html r.html --stix iocs.json --md ticket.md
  phishhawk scan mail.eml --json - | jq .verdict pure JSON on stdout, notices on stderr
  phishhawk scan mail.eml --protect example.com  flag lookalikes of your own domain

environment:
  VT_API_KEY          VirusTotal key; the free tier works (VIRUSTOTAL_API_KEY also read)
  ABUSEIPDB_API_KEY   AbuseIPDB key for originating-IP reputation
  URLSCAN_API_KEY     urlscan.io key, only needed for --urlscan-submit
  PHISHHAWK_PROTECT   comma-separated domains to treat as your own
  NO_COLOR            disable colour, same as --no-color

exit codes:
  0  nothing notable              1  suspicious or likely phishing
  2  malicious                    3  an input could not be read or a report not written"""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _terminal_width() -> int:
    return max(60, min(100, shutil.get_terminal_size((90, 24)).columns))


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=30, width=_terminal_width())


def _colour_ok(stream, disabled: bool = False) -> bool:
    return (not disabled and hasattr(stream, "isatty") and stream.isatty()
            and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb")


def _banner_ok(stream) -> bool:
    return (hasattr(stream, "isatty") and stream.isatty() and "--no-banner" not in sys.argv
            and not os.environ.get("PHISHHAWK_NO_BANNER"))


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that shows the banner above help on a terminal."""

    def print_help(self, file=None) -> None:
        stream = file or sys.stdout
        if _banner_ok(stream):
            stream.write(banner.render(colour=_colour_ok(stream, "--no-color" in sys.argv)) + "\n")
        super().print_help(file)


def _display_options() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    group = common.add_argument_group("display")
    group.add_argument("--no-color", action="store_true", help="disable ANSI colours (or set NO_COLOR)")
    group.add_argument("--no-banner", action="store_true", help="do not print the PhishHawk banner")
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="phishhawk", description=OVERVIEW, epilog=MAIN_EPILOG, formatter_class=_Formatter)
    parser.add_argument("-V", "--version", action="version", version="PhishHawk %s" % __version__)
    parser.add_argument("--no-color", dest="top_no_color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-banner", dest="top_no_banner", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", title="commands", metavar="<command>")
    display = _display_options()

    scan = commands.add_parser(
        "scan", parents=[display], formatter_class=_Formatter, epilog=SCAN_EPILOG,
        help="triage .eml files, folders or stdin (the default command)",
        description="Triage one or more reported emails: extract indicators, detect, enrich, report.")
    scan.add_argument("inputs", nargs="*", metavar="PATH",
                      help=".eml files, directories (searched recursively) or '-' for stdin")

    out = scan.add_argument_group("reports")
    out.add_argument("--json", metavar="PATH", help="full structured report ('-' for stdout)")
    out.add_argument("--html", metavar="PATH", help="self-contained HTML report for tickets and L2")
    out.add_argument("--stix", metavar="PATH", help="STIX 2.1 bundle for MISP / OpenCTI ('-' for stdout)")
    out.add_argument("--md", metavar="PATH", help="Markdown ticket note ('-' for stdout)")
    out.add_argument("--csv", metavar="PATH", help="CSV indicator list for blocklists ('-' for stdout)")
    out.add_argument("-q", "--quiet", action="store_true", help="one summary block per message")
    out.add_argument("-v", "--verbose", action="store_true", help="every signal, MD5 hashes and all actions")

    det = scan.add_argument_group("detection")
    det.add_argument("-p", "--protect", action="append", default=[], metavar="DOMAIN",
                     help="your organisation's domain (repeatable); lookalikes of it are flagged "
                          "as BEC and it is never sent to third parties")
    det.add_argument("--no-auto-protect", action="store_true",
                     help="do not treat recipient domains as protected")
    det.add_argument("--no-unwrap", action="store_true",
                     help="analyse the covering note instead of the attached, reported original")

    enr = scan.add_argument_group("enrichment")
    enr.add_argument("-o", "--offline", action="store_true", help="no network access at all")
    enr.add_argument("--vt-key", default="", metavar="KEY", help="VirusTotal key (default: $VT_API_KEY)")
    enr.add_argument("--vt-rate", type=int, default=4, metavar="N",
                     help="VirusTotal lookups per minute (default 4, the free tier)")
    enr.add_argument("--vt-budget", type=int, default=20, metavar="N",
                     help="max VirusTotal network lookups per message (default 20)")
    enr.add_argument("--no-virustotal", action="store_true", help="skip VirusTotal")
    enr.add_argument("--urlscan-key", default="", metavar="KEY", help="urlscan.io key (default: $URLSCAN_API_KEY)")
    enr.add_argument("--no-urlscan", action="store_true", help="skip urlscan.io searches")
    enr.add_argument("--urlscan-submit", action="store_true",
                     help="submit URLs as unlisted scans (needs a key; sends the URL to urlscan.io)")
    enr.add_argument("--abuseipdb-key", default="", metavar="KEY",
                     help="AbuseIPDB key (default: $ABUSEIPDB_API_KEY)")
    enr.add_argument("--no-abuseipdb", action="store_true", help="skip AbuseIPDB")
    enr.add_argument("--no-rdap", action="store_true", help="skip RDAP domain-age lookups")
    enr.add_argument("--timeout", type=float, default=20, metavar="SECONDS",
                     help="HTTP timeout per request (default 20)")

    cache_opts = scan.add_argument_group("cache")
    cache_opts.add_argument("--no-cache", action="store_true", help="do not read or write the lookup cache")
    cache_opts.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS",
                            help="how long a lookup stays fresh (default 24)")
    cache_opts.add_argument("--cache-path", default=default_cache_path(), metavar="PATH",
                            help="SQLite cache file (default: %(default)s)")

    doctor = commands.add_parser(
        "doctor", parents=[display], formatter_class=_Formatter,
        help="check dependencies, API keys, cache and network",
        description="Check that PhishHawk is ready: Python, dependencies, API keys, cache, network.")
    doctor.add_argument("--network", action="store_true",
                        help="also check that each reputation API can be reached")

    cache = commands.add_parser(
        "cache", parents=[display], formatter_class=_Formatter,
        help="show or clear the lookup cache",
        description="Every definitive reputation answer is cached so a campaign that hit fifty "
                    "inboxes costs one lookup per indicator.")
    cache.add_argument("action", nargs="?", choices=("stats", "clear", "path"), default="stats",
                       help="stats (default), clear, or path")
    cache.add_argument("--provider", choices=("virustotal", "urlscan", "rdap", "abuseipdb"),
                       help="with clear: only this provider's entries")
    cache.add_argument("--cache-path", default=default_cache_path(), metavar="PATH")
    cache.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS")

    techniques = commands.add_parser(
        "techniques", parents=[display], formatter_class=_Formatter,
        help="list the MITRE ATT&CK techniques PhishHawk can evidence",
        description="The MITRE ATT&CK techniques PhishHawk can evidence, and what it looks for.")
    techniques.add_argument("--json", action="store_true", help="machine-readable output")

    helper = commands.add_parser("help", help="show help for a command")
    helper.add_argument("topic", nargs="?", choices=COMMANDS[:-1])
    return parser


def normalise_argv(argv: list[str]) -> list[str]:
    """`phishhawk mail.eml` means `phishhawk scan mail.eml`."""
    for token in argv:
        if token in ("-h", "--help", "-V", "--version"):
            return argv
        if token == "-" or not token.startswith("-"):
            return argv if token in COMMANDS else ["scan", *argv]
    return ["scan", *argv] if argv and not all(t in ("--no-color", "--no-banner") for t in argv) else argv


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

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
        notices.append("offline mode: no reputation lookups")
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
    except RuntimeError as exc:  # requests is not installed
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


def cmd_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    scan_parser = parser._subparsers._group_actions[0].choices["scan"]  # noqa: SLF001
    if not args.inputs:
        scan_parser.error("no input: give .eml files, directories or '-' for stdin")
    outputs = {"json": args.json, "html": args.html, "stix": args.stix, "md": args.md, "csv": args.csv}
    if list(outputs.values()).count("-") > 1:
        scan_parser.error("only one report can go to stdout ('-')")
    if args.html == "-":
        scan_parser.error("--html needs a file path")
    machine_mode = "-" in outputs.values()

    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    if not (args.no_banner or args.quiet or machine_mode) and _banner_ok(sys.stderr):
        sys.stderr.write(banner.render(colour=err.enabled) + "\n")

    cache = None if (args.no_cache or args.offline) else Cache(args.cache_path, args.cache_ttl)
    protected = list(args.protect)
    protected += [d.strip() for d in os.environ.get("PHISHHAWK_PROTECT", "").split(",") if d.strip()]
    options = Options(unwrap=not args.no_unwrap, protected=protected, auto_protect=not args.no_auto_protect)

    notices: list[str] = []
    enricher = build_enricher(args, cache, notices)
    for notice in notices:
        print(err("[i] " + notice, "dim"), file=sys.stderr)

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
            print(err("[!] %s: file not found" % path, "red"), file=sys.stderr)
            worst = EXIT_ERROR
            continue
        except IsADirectoryError:
            print(err("[!] %s: is a directory" % path, "red"), file=sys.stderr)
            worst = EXIT_ERROR
            continue
        except Exception as exc:  # one malformed mail must not kill a batch run
            print(err("[!] %s: could not analyse (%s: %s)" % (path, type(exc).__name__, exc), "red"),
                  file=sys.stderr)
            worst = EXIT_ERROR
            continue
        finally:
            if progress:
                sys.stderr.write("\r%-66s\r" % "")
        analyses.append(analysis)
        if worst != EXIT_ERROR:
            worst = max(worst, EXIT_CODES.get(analysis.verdict, 0))
        if not machine_mode:
            print(console.render_quiet(analysis, colour) if args.quiet
                  else console.render(analysis, colour, verbose=args.verbose))
            print("")

    if not machine_mode and len(analyses) > 1:
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
                print(err("[i] %s report written to %s" % (kind.upper(), path), "dim"), file=sys.stderr)
        except OSError as exc:
            print(err("[!] could not write %s: %s" % (path, exc), "red"), file=sys.stderr)
            worst = EXIT_ERROR

    if cache is not None:
        if cache.hits:
            print(err("[i] %d lookup(s) served from cache" % cache.hits, "dim"), file=sys.stderr)
        cache.close()
    return worst


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

ENDPOINTS = {
    "VirusTotal": "https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8",
    "urlscan.io": "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
    "RDAP": "https://rdap.org/domain/example.com",
    "AbuseIPDB": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
}


def _mask(value: str) -> str:
    return value[:4] + "…" + value[-2:] if len(value) > 8 else "set"


def cmd_doctor(args: argparse.Namespace) -> int:
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    if not args.no_banner and _banner_ok(sys.stderr):
        sys.stderr.write(banner.render(colour=_colour_ok(sys.stderr, args.no_color)) + "\n")
    tones = {"ok": ("OK", "green"), "warn": ("WARN", "amber"), "fail": ("FAIL", "red"), "info": ("--", "dim")}
    rows: list[tuple[str, str, str, str]] = []

    version = platform.python_version()
    rows.append(("Python", version, "ok" if sys.version_info >= (3, 10) else "fail",
                 "" if sys.version_info >= (3, 10) else "PhishHawk needs Python 3.10+"))
    try:
        import requests
        rows.append(("requests", requests.__version__, "ok", "used for enrichment"))
    except ImportError:
        requests = None
        rows.append(("requests", "not installed", "fail", "pip install requests  (or always use --offline)"))

    for name, envs, level, hint in (
        ("VirusTotal key", ("VT_API_KEY", "VIRUSTOTAL_API_KEY"), "warn",
         "free key: https://www.virustotal.com/gui/my-apikey"),
        ("AbuseIPDB key", ("ABUSEIPDB_API_KEY",), "warn", "free key: https://www.abuseipdb.com/account/api"),
        ("urlscan.io key", ("URLSCAN_API_KEY",), "info", "optional: search works without it"),
    ):
        found = next((e for e in envs if os.environ.get(e)), "")
        if found:
            rows.append((name, "%s (%s)" % (_mask(os.environ[found]), found), "ok", ""))
        else:
            rows.append((name, "not set", level, "export %s=...   %s" % (envs[0], hint)))

    protected = os.environ.get("PHISHHAWK_PROTECT", "")
    rows.append(("Protected domains", protected or "recipients only", "info",
                 "" if protected else "set PHISHHAWK_PROTECT=yourcompany.com to flag lookalikes of it"))

    cache = Cache(default_cache_path())
    stats = cache.stats()
    cache.close()
    if stats["enabled"]:
        rows.append(("Cache", "%s  (%d entries)" % (stats["path"], stats["entries"]), "ok", ""))
    else:
        rows.append(("Cache", default_cache_path(), "warn", "not writable: lookups will not be cached"))

    if args.network:
        if requests is None:
            rows.append(("Network", "skipped", "fail", "needs the requests package"))
        else:
            session = requests.Session()
            for name, url in ENDPOINTS.items():
                try:
                    code = session.get(url, timeout=8).status_code
                    rows.append((name + " API", "reachable (HTTP %d)" % code, "ok", ""))
                except requests.RequestException as exc:
                    rows.append((name + " API", "unreachable", "fail", type(exc).__name__))

    print(colour("PhishHawk %s doctor" % __version__, "bold"))
    print("")
    for check, value, status, hint in rows:
        label, tone = tones[status]
        print("  %s  %-18s %s" % (colour("%-4s" % label, tone), check, value))
        if hint:
            print("  %s  %-18s %s" % (" " * 4, "", colour(hint, "dim")))
    if not args.network:
        print("")
        print(colour("  Add --network to test that each reputation API is reachable.", "dim"))
    return 1 if any(status == "fail" for _, _, status, _ in rows) else 0


# ---------------------------------------------------------------------------
# cache, techniques
# ---------------------------------------------------------------------------

def cmd_cache(args: argparse.Namespace) -> int:
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    if args.action == "path":
        print(args.cache_path)
        return 0
    cache = Cache(args.cache_path, args.cache_ttl)
    if not cache.enabled:
        print(colour("cache unavailable at %s" % args.cache_path, "red"), file=sys.stderr)
        return EXIT_ERROR
    if args.action == "clear":
        removed = cache.purge(args.provider)
        cache.close()
        print("cleared %d cached lookup(s)%s" % (removed, " for " + args.provider if args.provider else ""))
        return 0
    stats = cache.stats()
    cache.close()
    print(colour("PhishHawk lookup cache", "bold"))
    print("  path      %s" % stats["path"])
    print("  size      %.1f KB" % (stats["bytes"] / 1024))
    print("  entries   %d  (%d fresh within %g h)" % (stats["entries"], stats["fresh"], args.cache_ttl))
    for provider, count in sorted(stats["providers"].items()):
        print("    %-12s %d" % (provider, count))
    return 0


def cmd_techniques(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps([{"id": t, "name": TECHNIQUES[t], "evidence": EVIDENCE[t]} for t in TECHNIQUES],
                         indent=2))
        return 0
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    width = _terminal_width()
    print(colour("%-10s %s" % ("ID", "TECHNIQUE  /  what PhishHawk looks for"), "bold"))
    for technique, name in sorted(TECHNIQUES.items()):
        print("%s %s" % (colour("%-10s" % technique, "cyan"), name))
        for line in textwrap.wrap(EVIDENCE[technique], width=width - 13):
            print("%s %s" % (" " * 12, colour(line, "dim")))
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalise_argv(list(sys.argv[1:] if argv is None else argv)))
    for flag in ("no_color", "no_banner"):
        setattr(args, flag, getattr(args, flag, False) or getattr(args, "top_" + flag, False))

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "help":
        target = parser._subparsers._group_actions[0].choices.get(args.topic) if args.topic else parser  # noqa: SLF001
        target.print_help()
        return 0
    if args.command == "scan":
        return cmd_scan(args, parser)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "cache":
        return cmd_cache(args)
    return cmd_techniques(args)


def run() -> None:
    """Console-script entry point: well-behaved in pipes and on Ctrl+C."""
    try:
        code = main()
        sys.stdout.flush()
    except BrokenPipeError:  # e.g. `phishhawk techniques | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 141
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    run()
