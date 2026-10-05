"""PhishHawk command-line interface.

    phishhawk scan mail.eml        triage messages: .eml, Outlook .msg or .mbox (the default command)
    phishhawk doctor               check dependencies, API keys, cache and network
    phishhawk cache stats|clear    inspect or empty the lookup cache
    phishhawk techniques           the MITRE ATT&CK techniques PhishHawk can evidence
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import getpass
import hashlib
import json
import mailbox
import os
import platform
import re
import shutil
import sys
import textwrap
import time
from collections.abc import Callable, Iterator

from . import __version__, banner, campaign, config, evidence, extract, imapfetch, mailapi, sweep, yararules
from . import qr as qrcodes
from .attack import EVIDENCE, TECHNIQUES
from .cache import Cache, default_cache_path
from .enrich import AbuseIPDB, Enricher, Rdap, UrlScan, VirusTotal
from .models import Analysis
from .pipeline import Options, triage_bytes
from .report import campaignout, console, csvout, html, markdown, misp, stix, sweepout
from .report.common import printable, to_dict

COMMANDS = ("scan", "imap", "graph", "gmail", "campaign", "sweep", "evidence", "doctor", "cache", "techniques",
            "help")
EXIT_CODES = {"NO STRONG INDICATORS": 0, "SUSPICIOUS": 1, "LIKELY PHISHING": 1, "MALICIOUS": 2}
EXIT_ERROR = 3

OVERVIEW = """\
PhishHawk extracts every indicator from a reported phishing email, checks the
ones that matter against VirusTotal, urlscan.io, RDAP and AbuseIPDB, maps what
it finds to MITRE ATT&CK, and tells you what to do next."""

MAIN_EPILOG = """\
quick start:
  phishhawk suspicious.eml            triage one message (same as: phishhawk scan ...)
  phishhawk scan reported/ --quiet    every .eml, .msg and .mbox in a folder, one summary each
  phishhawk doctor                    check keys and setup before the first real run

Run `phishhawk <command> -h` for everything a command can do."""

SCAN_EPILOG = """\
examples:
  phishhawk scan suspicious.eml                  full report in the terminal
  phishhawk suspicious.eml                       the same: scan is the default command
  phishhawk scan reported/ --quiet               every .eml, .msg and .mbox in a folder
  phishhawk scan "Invoice overdue.msg"           an Outlook message, as saved or reported
  cat suspicious.eml | phishhawk scan -          read the message from stdin
  phishhawk scan suspicious.eml --offline        nothing leaves this machine
  phishhawk scan mail.eml --html r.html --stix iocs.json --md ticket.md
  phishhawk scan mail.eml --json - | jq .verdict pure JSON on stdout, notices on stderr
  phishhawk scan mail.eml --protect example.com  flag lookalikes of your own domain
  phishhawk scan mail.eml --misp event.json      a MISP event with ATT&CK galaxy tags
  phishhawk scan reported/ --fail-on likely      exit 1 only for likely phishing or worse

environment:
  PHISHHAWK_CONFIG    settings file (protect, allow and block lists, brands, lures, YARA ...)
  VT_API_KEY          VirusTotal key; the free tier works (VIRUSTOTAL_API_KEY also read)
  ABUSEIPDB_API_KEY   AbuseIPDB key for originating-IP reputation
  URLSCAN_API_KEY     urlscan.io key, only needed for --urlscan-submit
  PHISHHAWK_PROTECT   comma-separated domains to treat as your own
  NO_COLOR            disable colour, same as --no-color

exit codes:
  0  nothing notable              1  suspicious or likely phishing
  2  malicious                    3  an input could not be read or a report not written"""

IMAP_EPILOG = """\
examples:
  export PHISHHAWK_IMAP_PASSWORD=...   (or PHISHHAWK_IMAP_TOKEN=... for OAuth / XOAUTH2)
  phishhawk imap --host outlook.office365.com --user soc@example.com --folder "Phish reports" --unseen
  phishhawk imap --host imap.gmail.com --user soc@example.com --since 2026-09-01 --out reports/
  phishhawk imap --host mail.example.com --user soc --watch 300 --quiet

The folder is opened read-only (EXAMINE) and fetched with BODY.PEEK, so nothing
changes on the server. The password is read from $PHISHHAWK_IMAP_PASSWORD or a
prompt, never from the command line."""

GRAPH_EPILOG = """\
examples:
  export PHISHHAWK_GRAPH_TOKEN=...     (an access token with Mail.Read)
  phishhawk graph --mailbox soc@example.com --folder "Phish reports" --unread
  phishhawk graph --since 2026-09-01 --out reports/       (the token's own mailbox)
  phishhawk graph --mailbox soc@example.com --watch 300 --quiet

Only GET requests are sent: each message is read as MIME ($value), and nothing
is marked read, moved or deleted. The token is read from $PHISHHAWK_GRAPH_TOKEN,
never the command line; `az account get-access-token --resource-type ms-graph`
prints one for a quick test."""

GMAIL_EPILOG = """\
examples:
  export PHISHHAWK_GMAIL_TOKEN=...     (an access token with gmail.readonly)
  phishhawk gmail --label "Phish reports" --unread
  phishhawk gmail --query "has:attachment" --since 2026-09-01
  phishhawk gmail --mailbox soc@example.com --watch 300 --out reports/

Only GET requests are sent: each message is read in raw form, and nothing is
marked read, moved or deleted. The token is read from $PHISHHAWK_GMAIL_TOKEN,
never the command line."""

CAMPAIGN_EPILOG = """\
examples:
  phishhawk campaign reported/                        which reports belong together
  phishhawk campaign reported/ --md campaigns.md      a ticket note per campaign
  phishhawk campaign a.mbox b.mbox --json - | jq '.clusters[0].recipients'

Messages are linked by one strong trait (an attachment, a phishing domain or
link, a QR payload, a sender or reply-to address, a wallet, a phone number)
or two weak ones (a subject differing only in numbers, a display name, an
originating IP), and links are followed: A-B and B-C make one campaign. Known
brands, your protected and allowed domains, shorteners, free-mail and bulk-mail
services never link at domain level. Nothing is looked up: correlation is
offline. Recipients come from each message's To line (the original's, for a
reported message)."""

SWEEP_EPILOG = """\
examples:
  export PHISHHAWK_GRAPH_TOKEN=...     (an app token with Mail.Read for every mailbox swept)
  phishhawk sweep graph --like reported.eml --mailboxes staff.txt
  phishhawk sweep graph --from billing@1nvoice-desk.top --mailbox alice@example.com --mailbox bob@example.com
  phishhawk sweep gmail --like reported.eml --since 2026-09-01 --csv copies.csv

--like reads the reported message (offline) and looks for its Message-ID, its
sender and reply-to addresses, its subject and the phishing domains it links
to; brands' own domains, free-mail providers and other shared services are
never searched for. Each copy found is listed with its folder, whether it
was read, and whether the mailbox's owner replied in its thread. Only GET
requests are sent. Gmail tokens are per mailbox: sweep each with its own.
Clicks and opened attachments are not in the mailbox: look in your proxy
and EDR logs for the domains and hashes in the scan report.

exit codes:
  0  no copies found     1  copies found     3  a mailbox could not be searched"""

EVIDENCE_EPILOG = """\
examples:
  phishhawk scan reported/ --evidence /cases/4711    keep each message and log its custody
  phishhawk evidence verify /cases/4711               check every record and kept message

With --evidence DIR, every message analysed is kept in DIR exactly as it was
read, read-only and named by its SHA-256, and a record is appended to
DIR/custody.jsonl: hashes, size, source, time, analyst ($PHISHHAWK_ANALYST, or
the login name), tool version and verdict. Each record includes the hash of
the one before it. verify recomputes that chain and every message's hash, and
prints the last link: put it in the ticket, and the log as it was then can be
proven unchanged later.

exit codes:
  0  every record and kept message checks out     1  something does not"""


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
    """ArgumentParser that shows the banner above help on a terminal, and
    knows its sub-commands by name."""

    commands: dict[str, argparse.ArgumentParser]

    def print_help(self, file=None) -> None:
        stream = file or sys.stdout
        if _banner_ok(stream):
            stream.write(banner.render(colour=_colour_ok(stream, "--no-color" in sys.argv)) + "\n")
        super().print_help(file)


def _display_options() -> _Parser:
    common = _Parser(add_help=False)
    group = common.add_argument_group("display")
    group.add_argument("--no-color", action="store_true", help="disable ANSI colours (or set NO_COLOR)")
    group.add_argument("--no-banner", action="store_true", help="do not print the PhishHawk banner")
    return common


def _detection_options(command: argparse.ArgumentParser) -> None:
    """How messages are read and judged; shared by the triage commands and campaign."""
    det = command.add_argument_group("detection")
    det.add_argument("-p", "--protect", action="append", default=[], metavar="DOMAIN",
                     help="your organisation's domain (repeatable); lookalikes of it are flagged "
                          "as BEC and it is never sent to third parties")
    det.add_argument("--allow", action="append", default=[], metavar="DOMAIN",
                     help="a partner's domain: never reported as a lookalike or an indicator (repeatable)")
    det.add_argument("--block", action="append", default=[], metavar="DOMAIN",
                     help="a domain always flagged when a message uses it (repeatable)")
    det.add_argument("--yara", metavar="PATH",
                     help="YARA rules (a file or folder) run on the message and every file in it "
                          "(needs: pip install 'phishhawk[yara]')")
    det.add_argument("--no-auto-protect", action="store_true",
                     help="do not treat recipient domains as protected")
    det.add_argument("--no-unwrap", action="store_true",
                     help="analyse the covering note instead of the attached, reported original")
    det.add_argument("--trusted-authserv", action="append", default=[], metavar="ID",
                     help="your mail server's authserv-id, e.g. mx.google.com (repeatable; default "
                          "$PHISHHAWK_TRUSTED_AUTHSERV): only its Authentication-Results are believed")
    det.add_argument("--max-size", type=int, default=None, metavar="MB",
                     help="skip messages larger than this (default 50 MB)")
    det.add_argument("--no-qr", action="store_true",
                     help="do not decode QR codes in images, PDFs and drawn tables "
                          "(decoding needs: pip install 'phishhawk[qr]')")
    det.add_argument("--psl", metavar="FILE",
                     help="a copy of the Public Suffix List (public_suffix_list.dat from publicsuffix.org), used "
                          "instead of the built-in approximation (default $PHISHHAWK_PSL)")


def _triage_options(command: argparse.ArgumentParser) -> None:
    """Report, detection, enrichment and cache options shared by scan and imap."""
    command.add_argument("--config", metavar="PATH",
                         help="settings file (default $PHISHHAWK_CONFIG, then ~/.config/phishhawk/config.toml)")
    out = command.add_argument_group("reports")
    out.add_argument("--json", metavar="PATH", help="full structured report ('-' for stdout)")
    out.add_argument("--html", metavar="PATH", help="self-contained HTML report for tickets and L2")
    out.add_argument("--stix", metavar="PATH", help="STIX 2.1 bundle for OpenCTI and Sentinel ('-' for stdout)")
    out.add_argument("--misp", metavar="PATH", help="MISP event JSON, one event per message ('-' for stdout)")
    out.add_argument("--md", metavar="PATH", help="Markdown ticket note ('-' for stdout)")
    out.add_argument("--csv", metavar="PATH", help="CSV indicator list for blocklists ('-' for stdout)")
    out.add_argument("--tlp", choices=("clear", "green", "amber", "amber+strict", "red"),
                     help="TLP tag for the MISP event (default amber)")
    out.add_argument("-q", "--quiet", action="store_true", help="one summary block per message")
    out.add_argument("-v", "--verbose", action="store_true", help="every signal, MD5 hashes and all actions")
    out.add_argument("--fail-on", choices=("never", "suspicious", "likely", "malicious"),
                     help="exit 0 unless a verdict reaches this level (for pipelines; default: exit codes below)")

    _detection_options(command)

    enr = command.add_argument_group("enrichment")
    enr.add_argument("-o", "--offline", action="store_true", help="no network access at all")
    enr.add_argument("--vt-key", default="", metavar="KEY", help="VirusTotal key (default: $VT_API_KEY)")
    enr.add_argument("--vt-rate", type=int, default=None, metavar="N",
                     help="VirusTotal lookups per minute (default 4, the free tier)")
    enr.add_argument("--vt-budget", type=int, default=None, metavar="N",
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

    kept = command.add_argument_group("evidence")
    kept.add_argument("--evidence", metavar="DIR",
                      help="keep each message here, read-only and named by its SHA-256, with a hash-chained "
                           "custody log (check it with: phishhawk evidence verify DIR)")

    cache_opts = command.add_argument_group("cache")
    cache_opts.add_argument("--no-cache", action="store_true", help="do not read or write the lookup cache")
    cache_opts.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS",
                            help="how long a lookup stays fresh (default 24)")
    cache_opts.add_argument("--cache-path", default=default_cache_path(), metavar="PATH",
                            help="SQLite cache file (default: %(default)s)")


def _seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number of seconds") from None
    if seconds < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return seconds


def build_parser() -> _Parser:
    parser = _Parser(prog="phishhawk", description=OVERVIEW, epilog=MAIN_EPILOG, formatter_class=_Formatter)
    parser.add_argument("-V", "--version", action="version", version="PhishHawk %s" % __version__)
    parser.add_argument("--no-color", dest="top_no_color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-banner", dest="top_no_banner", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", title="commands", metavar="<command>")
    display = _display_options()

    scan = commands.add_parser(
        "scan", parents=[display], formatter_class=_Formatter, epilog=SCAN_EPILOG,
        help="triage .eml, .msg or .mbox files, folders or stdin (the default command)",
        description="Triage one or more reported emails: extract indicators, detect, enrich, report.")
    scan.add_argument("inputs", nargs="*", metavar="PATH",
                      help=".eml, .msg or .mbox files, directories (searched recursively) or '-' for stdin")
    _triage_options(scan)

    imap = commands.add_parser(
        "imap", parents=[display], formatter_class=_Formatter, epilog=IMAP_EPILOG,
        help="triage messages straight from an IMAP folder, read-only",
        description="Triage the messages in an IMAP folder (a shared 'report phishing' mailbox, say). "
                    "The folder is opened read-only: nothing is marked read, moved or deleted.")
    box = imap.add_argument_group("mailbox")
    box.add_argument("--host", required=True, help="IMAP server, e.g. outlook.office365.com")
    box.add_argument("--user", default=os.environ.get("PHISHHAWK_IMAP_USER", ""),
                     help="login (default $PHISHHAWK_IMAP_USER)")
    box.add_argument("--folder", default="INBOX", help="folder to read (default INBOX)")
    box.add_argument("--port", type=int, default=0, help="port (default 993, or 143 with --starttls)")
    box.add_argument("--starttls", action="store_true", help="plain connection upgraded with STARTTLS")
    box.add_argument("--since", metavar="YYYY-MM-DD", help="only messages received on or after this date")
    box.add_argument("--unseen", action="store_true", help="only messages nobody has read yet")
    box.add_argument("--limit", type=int, default=50, metavar="N", help="the newest N messages (default 50)")
    box.add_argument("--out", metavar="DIR", help="also write a JSON and an HTML report per message here")
    box.add_argument("--watch", type=_seconds, default=0, metavar="SECONDS",
                     help="keep running and triage new messages every SECONDS (Ctrl+C stops)")
    _triage_options(imap)

    for name, epilog, what in (
            ("graph", GRAPH_EPILOG, "a Microsoft 365 mailbox through Microsoft Graph"),
            ("gmail", GMAIL_EPILOG, "a Gmail or Google Workspace mailbox through the Gmail API")):
        api = commands.add_parser(
            name, parents=[display], formatter_class=_Formatter, epilog=epilog,
            help="triage messages from %s, read-only" % what,
            description="Triage the messages in %s. Only GET requests are sent: nothing is marked read, "
                        "moved or deleted." % what)
        box = api.add_argument_group("mailbox")
        box.add_argument("--mailbox", default="me", help="a user id or address (default 'me': the token's own)")
        if name == "graph":
            box.add_argument("--folder", default="", help="folder name or id (default the Inbox)")
        else:
            box.add_argument("--label", dest="folder", default="", help="label (default the inbox)")
            box.add_argument("--query", default="", help="more Gmail search terms, e.g. 'has:attachment'")
        box.add_argument("--since", metavar="YYYY-MM-DD", help="only messages received on or after this date")
        box.add_argument("--unread", action="store_true", help="only messages nobody has read yet")
        box.add_argument("--limit", type=int, default=50, metavar="N", help="the newest N messages (default 50)")
        box.add_argument("--out", metavar="DIR", help="also write a JSON and an HTML report per message here")
        box.add_argument("--watch", type=_seconds, default=0, metavar="SECONDS",
                         help="keep running and triage new messages every SECONDS (Ctrl+C stops)")
        _triage_options(api)

    camp = commands.add_parser(
        "campaign", parents=[display], formatter_class=_Formatter, epilog=CAMPAIGN_EPILOG,
        help="group reported messages into campaigns by what they share, offline",
        description="Group reported messages that share attachments, phishing domains, links, QR payloads, "
                    "senders or other traits into campaigns, with who received them and when. Offline: "
                    "nothing is looked up.")
    camp.add_argument("inputs", nargs="+", metavar="PATH",
                      help=".eml, .msg or .mbox files, directories (searched recursively) or '-' for stdin")
    camp.add_argument("--config", metavar="PATH",
                      help="settings file (default $PHISHHAWK_CONFIG, then ~/.config/phishhawk/config.toml)")
    camp_out = camp.add_argument_group("reports")
    camp_out.add_argument("--json", metavar="PATH",
                          help="campaigns, what links them and their messages ('-' for stdout)")
    camp_out.add_argument("--csv", metavar="PATH", help="one row per message with its campaign ('-' for stdout)")
    camp_out.add_argument("--md", metavar="PATH", help="Markdown note per campaign ('-' for stdout)")
    camp_out.add_argument("--min-size", type=int, default=2, metavar="N",
                          help="smallest group reported as a campaign (default 2)")
    _detection_options(camp)
    camp.set_defaults(offline=True, vt_rate=None, vt_budget=None, fail_on=None, tlp=None)

    sw = commands.add_parser(
        "sweep", parents=[display], formatter_class=_Formatter, epilog=SWEEP_EPILOG,
        help="find the other copies of a reported message in mailboxes, read-only",
        description="Search mailboxes through Microsoft Graph or the Gmail API for copies of a reported "
                    "message, and report where each sits, whether it was read and whether anyone replied. "
                    "Only GET requests are sent.")
    sw.add_argument("service", choices=("graph", "gmail"), help="where the mailboxes are")
    sw.add_argument("--config", metavar="PATH",
                    help="settings file (default $PHISHHAWK_CONFIG, then ~/.config/phishhawk/config.toml)")
    look = sw.add_argument_group("what to look for (at least one)")
    look.add_argument("--like", metavar="FILE", help="the reported .eml or .msg: its Message-ID, senders, subject "
                                                     "and phishing domains")
    look.add_argument("--from", dest="senders", action="append", default=[], metavar="ADDRESS",
                      help="a sender or reply-to address (repeatable)")
    look.add_argument("--subject", dest="subjects", action="append", default=[], metavar="TEXT",
                      help="a subject; numbers may differ (repeatable)")
    look.add_argument("--domain", dest="domains", action="append", default=[], metavar="DOMAIN",
                      help="a domain the message links to (repeatable)")
    look.add_argument("--message-id", dest="message_ids", action="append", default=[], metavar="ID",
                      help="a Message-ID, with its angle brackets (repeatable)")
    where = sw.add_argument_group("where to look")
    where.add_argument("--mailbox", dest="mailboxes", action="append", default=[], metavar="ADDRESS",
                       help="a mailbox (repeatable; default 'me': the token's own)")
    where.add_argument("--mailboxes", dest="mailbox_file", metavar="FILE",
                       help="a file with one mailbox per line (# starts a comment)")
    where.add_argument("--since", metavar="YYYY-MM-DD", help="only messages received on or after this date")
    where.add_argument("--limit", type=int, default=100, metavar="N",
                       help="results per search and mailbox (default 100, at most 1000)")
    where.add_argument("--timeout", type=float, default=30, metavar="SECONDS", help="HTTP timeout (default 30)")
    sw_out = sw.add_argument_group("reports")
    sw_out.add_argument("--json", metavar="PATH", help="every copy found and what matched ('-' for stdout)")
    sw_out.add_argument("--csv", metavar="PATH", help="one row per copy ('-' for stdout)")
    _detection_options(sw)
    sw.set_defaults(offline=True, vt_rate=None, vt_budget=None, fail_on=None, tlp=None)

    kept = commands.add_parser(
        "evidence", parents=[display], formatter_class=_Formatter, epilog=EVIDENCE_EPILOG,
        help="verify the messages and custody log kept with --evidence",
        description="Check the messages kept with --evidence and their custody log: every record still "
                    "follows the one before it and every kept message still has its recorded SHA-256.")
    kept.add_argument("action", choices=("verify",), help="verify: check the log and every kept message")
    kept.add_argument("directory", metavar="DIR", help="the folder given to --evidence")

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
    parser.commands = dict(commands.choices)
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
    """Files to scan. Inside a directory only regular .eml, .msg and .mbox
    files count: a planted FIFO or a symlink to /dev/zero would otherwise
    hang the batch."""
    paths: list[str] = []
    for item in inputs:
        if item != "-" and os.path.isdir(item):
            for root, _, names in os.walk(item):  # symlinked directories are not followed
                paths += [os.path.join(root, n) for n in sorted(names)
                          if n.lower().endswith((".eml", ".msg", ".mbox"))
                          and os.path.isfile(os.path.join(root, n))]
        else:
            paths.append(item)
    return paths


class InputTooLarge(Exception):
    pass


def read_input(path: str, limit: int) -> bytes:
    """One message, refusing what is not a regular file or is over the limit."""
    if path == "-":
        data = sys.stdin.buffer.read(limit + 1)
    else:
        if os.path.exists(path) and not os.path.isdir(path) and not os.path.isfile(path):
            raise InputTooLarge("not a regular file")
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    if len(data) > limit:
        raise InputTooLarge("larger than %d MB" % (limit // (1024 * 1024)))
    return data


def iter_messages(paths: list[str], limit: int) -> Iterator[tuple[str, bytes | Exception]]:
    """(label, raw message or the reason it was skipped). An .mbox file (a
    Google Takeout or Thunderbird export) yields each message it holds."""
    for path in paths:
        if path != "-" and path.lower().endswith(".mbox") and os.path.isfile(path):
            try:
                box = mailbox.mbox(path, create=False)
                keys = list(box.iterkeys())
            except Exception as exc:
                yield path, exc
                continue
            for index, key in enumerate(keys, 1):
                label = "%s#%d" % (path, index)
                try:
                    data = box.get_bytes(key)
                except Exception as exc:
                    yield label, exc
                    continue
                too_big = InputTooLarge("larger than %d MB" % (limit // (1024 * 1024)))
                yield label, too_big if len(data) > limit else data
            continue
        try:
            yield path, read_input(path, limit)
        except Exception as exc:
            yield path, exc


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


FAIL_ORDER = {"never": 99, "suspicious": 1, "likely": 2, "malicious": 3}
VERDICT_RANK = {"NO STRONG INDICATORS": 0, "SUSPICIOUS": 1, "LIKELY PHISHING": 2, "MALICIOUS": 3}


def _settings(args: argparse.Namespace, error: Callable[[str], None]) -> tuple[Options, config.Config]:
    """Command line over config file over built-in defaults."""
    try:
        settings = config.load(args.config or "")
    except config.ConfigError as exc:
        error(str(exc))
        raise
    config.apply_knowledge(settings)
    args.offline = args.offline or settings.offline
    args.max_size = args.max_size or settings.max_size or 50
    args.vt_rate = args.vt_rate or settings.vt_rate or 4
    args.vt_budget = args.vt_budget or settings.vt_budget or 20
    args.fail_on = args.fail_on or settings.fail_on or ""
    args.tlp = args.tlp or settings.tlp
    protected = list(args.protect) + settings.protect
    protected += [d.strip() for d in os.environ.get("PHISHHAWK_PROTECT", "").split(",") if d.strip()]
    trusted = args.trusted_authserv or settings.trusted_authserv or [
        item.strip() for item in os.environ.get("PHISHHAWK_TRUSTED_AUTHSERV", "").split(",") if item.strip()]
    psl = args.psl or settings.public_suffix_list or os.environ.get("PHISHHAWK_PSL", "")
    if psl:
        try:
            extract.load_public_suffixes(os.path.expanduser(psl))
        except ValueError as exc:
            error(str(exc))
            raise config.ConfigError(str(exc)) from exc
    rules = None
    yara_path = args.yara or settings.yara
    if yara_path:
        try:
            rules = yararules.Rules(os.path.expanduser(yara_path))
        except yararules.YaraError as exc:
            error(str(exc))
            raise
    options = Options(unwrap=not args.no_unwrap, protected=protected, auto_protect=not args.no_auto_protect,
                      qr=not args.no_qr, trusted_authserv=trusted,
                      allow_domains=[d.strip().lower() for d in args.allow] + settings.allow_domains,
                      block_domains=[d.strip().lower() for d in args.block] + settings.block_domains,
                      yara=rules)
    return options, settings


def _exit_code(analyses: list[Analysis], failed: bool, fail_on: str) -> int:
    if failed:
        return EXIT_ERROR
    worst = max((VERDICT_RANK.get(a.verdict, 0) for a in analyses), default=0)
    if fail_on:
        return 1 if worst >= FAIL_ORDER[fail_on] else 0
    return {0: 0, 1: 1, 2: 1, 3: 2}[worst]


def cmd_scan(args: argparse.Namespace, parser: _Parser) -> int:
    scan_parser = parser.commands["scan"]
    if not args.inputs:
        scan_parser.error("no input: give .eml, .msg or .mbox files, directories or '-' for stdin")
    return _triage(args, scan_parser, lambda limit: iter_messages(expand_inputs(args.inputs), limit))


def _triage(args: argparse.Namespace, command: argparse.ArgumentParser,
            source: Callable[[int], Iterator[tuple[str, bytes | Exception]]],
            per_message: Callable[[str, Analysis], None] | None = None) -> int:
    outputs = {"json": args.json, "html": args.html, "stix": args.stix, "misp": args.misp, "md": args.md,
               "csv": args.csv}
    if list(outputs.values()).count("-") > 1:
        command.error("only one report can go to stdout ('-')")
    if args.html == "-":
        command.error("--html needs a file path")
    machine_mode = "-" in outputs.values()

    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    try:
        options, _ = _settings(args, lambda message: print(err("[!] %s" % printable(message), "red"),
                                                           file=sys.stderr))
    except (config.ConfigError, yararules.YaraError):
        return EXIT_ERROR
    if not (args.no_banner or args.quiet or machine_mode) and _banner_ok(sys.stderr):
        sys.stderr.write(banner.render(colour=err.enabled) + "\n")

    cache = None if (args.no_cache or args.offline) else Cache(args.cache_path, args.cache_ttl)
    notices: list[str] = []
    enricher = build_enricher(args, cache, notices)
    if options.yara is not None:
        notices.append("YARA: %d rule file(s) from %s" % (options.yara.count, options.yara.path))
    for notice in notices:
        print(err("[i] " + notice, "dim"), file=sys.stderr)

    progress: Callable[[str], None] | None = None
    if sys.stderr.isatty() and not args.quiet:
        def progress(message: str) -> None:
            sys.stderr.write("\r  ... %-60s" % printable(message)[:60])
            sys.stderr.flush()

    analyses: list[Analysis] = []
    failed = False
    for path, data in source(args.max_size * 1024 * 1024):
        try:
            if isinstance(data, Exception):
                raise data
            analysis = triage_bytes(data, "<stdin>" if path == "-" else path, options, enricher, progress)
        except FileNotFoundError:
            print(err("[!] %s: file not found" % printable(path), "red"), file=sys.stderr)
            failed = True
            continue
        except IsADirectoryError:
            print(err("[!] %s: is a directory" % printable(path), "red"), file=sys.stderr)
            failed = True
            continue
        except InputTooLarge as exc:
            print(err("[!] %s: skipped, %s" % (printable(path), exc), "red"), file=sys.stderr)
            failed = True
            continue
        except Exception as exc:  # one malformed mail must not kill a batch run
            print(err("[!] %s: could not analyse (%s: %s)" % (printable(path), type(exc).__name__,
                                                              printable(str(exc))), "red"), file=sys.stderr)
            failed = True
            continue
        finally:
            if progress:
                sys.stderr.write("\r%-66s\r" % "")
        if args.evidence and isinstance(data, bytes):
            try:
                evidence.keep(args.evidence, data, "<stdin>" if path == "-" else path, analysis)
            except (evidence.EvidenceError, OSError) as exc:
                print(err("[!] %s: not kept as evidence (%s)" % (printable(path), printable(str(exc))), "red"),
                      file=sys.stderr)
                failed = True
        analyses.append(analysis)
        if per_message is not None:
            per_message(path, analysis)
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
        "misp": lambda: json.dumps(misp.build(analyses, args.tlp), indent=2, ensure_ascii=False) + "\n",
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
            failed = True

    if cache is not None:
        if cache.hits:
            print(err("[i] %d lookup(s) served from cache" % cache.hits, "dim"), file=sys.stderr)
        cache.close()
    return _exit_code(analyses, failed, args.fail_on)


# ---------------------------------------------------------------------------
# imap
# ---------------------------------------------------------------------------

def cmd_imap(args: argparse.Namespace, parser: _Parser) -> int:
    imap_parser = parser.commands["imap"]
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    if not args.user:
        imap_parser.error("--user (or $PHISHHAWK_IMAP_USER) is required")
    since = None
    if args.since:
        try:
            since = datetime.date.fromisoformat(args.since)
        except ValueError:
            imap_parser.error("--since must be a date like 2026-09-01")
    token = os.environ.get("PHISHHAWK_IMAP_TOKEN", "")
    password = os.environ.get("PHISHHAWK_IMAP_PASSWORD", "")
    if not token and not password:
        if not sys.stdin.isatty():
            imap_parser.error("set PHISHHAWK_IMAP_PASSWORD or PHISHHAWK_IMAP_TOKEN (no terminal to ask on)")
        password = getpass.getpass("IMAP password for %s@%s: " % (args.user, args.host))
    source = imapfetch.ImapSource(host=args.host, user=args.user, password=password, token=token,
                                  folder=args.folder, port=args.port or (143 if args.starttls else 993),
                                  starttls=args.starttls, since=since, unseen=args.unseen,
                                  limit=max(0, args.limit), timeout=args.timeout)
    if args.out:
        os.makedirs(args.out, exist_ok=True)

    def save(label: str, analysis: Analysis) -> None:
        if not args.out:
            return
        uid = label.rsplit("=", 1)[-1]
        name = os.path.join(args.out, "imap-%s" % re.sub(r"[^0-9A-Za-z_-]", "_", uid))
        try:
            _write(name + ".json", json.dumps(to_dict(analysis), indent=2, ensure_ascii=False) + "\n")
            _write(name + ".html", html.render([analysis]))
        except OSError as exc:
            print(err("[!] could not write %s: %s" % (name, exc), "red"), file=sys.stderr)

    last_uid = 0
    code = 0
    while True:
        seen: list[int] = []

        def messages(limit: int, seen: list[int] = seen, after: int = last_uid,
                     ) -> Iterator[tuple[str, bytes | Exception]]:
            try:
                for label, uid, data in imapfetch.fetch(source, limit, after_uid=after):
                    seen.append(uid)
                    yield label, data
            except imapfetch.ImapError as exc:
                yield "imap://%s/%s" % (args.host, args.folder), exc

        code = max(code, _triage(args, imap_parser, messages, save))
        if not args.watch:
            return code
        last_uid = max(seen + [last_uid])
        print(err("[i] waiting %d s for new messages (Ctrl+C stops)" % args.watch, "dim"), file=sys.stderr)
        time.sleep(args.watch)


# ---------------------------------------------------------------------------
# graph and gmail
# ---------------------------------------------------------------------------

def cmd_mail_api(args: argparse.Namespace, parser: _Parser) -> int:
    command = parser.commands[args.command]
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    variable = "PHISHHAWK_%s_TOKEN" % args.command.upper()
    token = os.environ.get(variable, "").strip()
    if not token:
        command.error("set %s to an access token (it is never taken on the command line)" % variable)
    since = None
    if args.since:
        try:
            since = datetime.date.fromisoformat(args.since)
        except ValueError:
            command.error("--since must be a date like 2026-09-01")
    source = mailapi.ApiSource(token=token, mailbox=args.mailbox or "me", folder=args.folder,
                               query=getattr(args, "query", ""), since=since, unread=args.unread,
                               limit=max(0, args.limit), timeout=args.timeout)
    fetch = mailapi.fetch_graph if args.command == "graph" else mailapi.fetch_gmail
    if args.out:
        os.makedirs(args.out, exist_ok=True)
    ids: dict[str, str] = {}  # label -> message id, for the report file names

    def save(label: str, analysis: Analysis) -> None:
        if not args.out:
            return
        message_id = ids.get(label, label)
        tail = message_id
        if not re.fullmatch(r"[0-9a-z_-]{1,64}", message_id):
            # Made file-safe, or on a disk that ignores case, two ids could share a name.
            digest = hashlib.sha256(message_id.encode("utf-8", "replace")).hexdigest()[:12]
            tail = "%s-%s" % (re.sub(r"[^0-9A-Za-z_-]", "_", message_id)[-40:], digest)
        name = os.path.join(args.out, "%s-%s" % (args.command, tail))
        try:
            _write(name + ".json", json.dumps(to_dict(analysis), indent=2, ensure_ascii=False) + "\n")
            _write(name + ".html", html.render([analysis]))
        except OSError as exc:
            print(err("[!] could not write %s: %s" % (name, exc), "red"), file=sys.stderr)

    done: set[str] = set()
    code = 0
    while True:
        def messages(limit: int) -> Iterator[tuple[str, bytes | Exception]]:
            try:
                for label, message_id, data in fetch(source, limit, seen=frozenset(done)):
                    if not isinstance(data, mailapi.MailApiError):  # throttled or offline: ask again next round
                        done.add(message_id)
                    ids[label] = message_id
                    yield label, data
            except mailapi.MailApiError as exc:
                yield "%s://%s" % (args.command, source.mailbox), exc

        code = max(code, _triage(args, command, messages, save))
        if not args.watch:
            return code
        print(err("[i] waiting %d s for new messages (Ctrl+C stops)" % args.watch, "dim"), file=sys.stderr)
        time.sleep(args.watch)


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
        import requests as http
        rows.append(("requests", http.__version__, "ok", "used for enrichment"))
    except ImportError:
        http = None  # type: ignore[assignment]
        rows.append(("requests", "not installed", "fail", "pip install requests  (or always use --offline)"))
    qr_versions = qrcodes.versions()
    if qr_versions:
        rows.append(("QR decoding", ", ".join("%s %s" % item for item in qr_versions.items()), "ok",
                     "codes in images, PDFs and drawn tables are decoded"))
    else:
        rows.append(("QR decoding", "not installed", "info",
                     "optional: pip install 'phishhawk[qr]'  (QR lure wording is still flagged)"))
    if yararules.available():
        rows.append(("YARA", "yara-python %s" % yararules.version(), "ok", "run your rules with --yara PATH"))
    else:
        rows.append(("YARA", "not installed", "info", "optional: pip install 'phishhawk[yara]'"))
    psl = ""
    try:
        settings = config.load()
        psl = settings.public_suffix_list
        if settings.path:
            rows.append(("Config", settings.path, "ok", "%d protected, %d allowed, %d blocked domain(s)"
                         % (len(settings.protect), len(settings.allow_domains), len(settings.block_domains))))
        else:
            rows.append(("Config", "none", "info",
                         "optional: ~/.config/phishhawk/config.toml (see docs/USAGE.md)"))
    except config.ConfigError as exc:
        rows.append(("Config", "invalid", "fail", str(exc)[:200]))
    psl = os.path.expanduser(psl or os.environ.get("PHISHHAWK_PSL", ""))  # as scan reads it, bar --psl
    if psl:
        try:
            rows.append(("Public suffixes", "%s  (%d rules)" % (psl, extract.load_public_suffixes(psl)), "ok", ""))
        except ValueError as exc:
            rows.append(("Public suffixes", psl, "fail", str(exc)[:200]))
        extract.use_public_suffixes(None)
    else:
        rows.append(("Public suffixes", "built-in approximation", "info",
                     "optional: --psl FILE or PHISHHAWK_PSL, a copy of publicsuffix.org's list"))

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
        if http is None:
            rows.append(("Network", "skipped", "fail", "needs the requests package"))
        else:
            session = http.Session()
            for name, url in ENDPOINTS.items():
                try:
                    code = session.get(url, timeout=8).status_code
                    rows.append((name + " API", "reachable (HTTP %d)" % code, "ok", ""))
                except http.RequestException as exc:
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


def cmd_campaign(args: argparse.Namespace, parser: _Parser) -> int:
    command = parser.commands["campaign"]
    outputs = {"json": args.json, "csv": args.csv, "md": args.md}
    if list(outputs.values()).count("-") > 1:
        command.error("only one report can go to stdout ('-')")
    if args.min_size < 2:
        command.error("--min-size must be 2 or more")
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    try:
        options, _ = _settings(args, lambda message: print(err("[!] %s" % printable(message), "red"),
                                                           file=sys.stderr))
    except (config.ConfigError, yararules.YaraError):
        return EXIT_ERROR
    items: list[tuple[str, Analysis]] = []
    failed = False
    for path, data in iter_messages(expand_inputs(args.inputs), args.max_size * 1024 * 1024):
        label = "<stdin>" if path == "-" else path
        try:
            if isinstance(data, Exception):
                raise data
            items.append((label, triage_bytes(data, label, options, None)))
        except FileNotFoundError:
            print(err("[!] %s: file not found" % printable(path), "red"), file=sys.stderr)
            failed = True
        except Exception as exc:  # one malformed mail must not stop the correlation
            print(err("[!] %s: could not analyse (%s: %s)" % (printable(path), type(exc).__name__,
                                                              printable(str(exc))), "red"), file=sys.stderr)
            failed = True
    result = campaign.correlate(items, args.min_size)
    if "-" not in outputs.values():
        print(campaignout.render_console(result, colour))
    renderers = {"json": lambda: json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                 "csv": lambda: campaignout.render_csv(result), "md": lambda: campaignout.render_markdown(result)}
    for kind, path in outputs.items():
        if not path:
            continue
        try:
            _write(path, renderers[kind]())
            if path != "-":
                print(err("[i] %s written to %s" % (kind.upper(), path), "dim"), file=sys.stderr)
        except OSError as exc:
            print(err("[!] could not write %s: %s" % (path, exc), "red"), file=sys.stderr)
            failed = True
    return EXIT_ERROR if failed else 0


def _mailbox_list(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = [line.strip() for line in handle.read().splitlines()[:sweep.MAX_MAILBOXES * 2]]
    return [line for line in lines if line and not line.startswith("#")]


def cmd_sweep(args: argparse.Namespace, parser: _Parser) -> int:
    command = parser.commands["sweep"]
    if [args.json, args.csv].count("-") > 1:
        command.error("only one report can go to stdout ('-')")
    if not 1 <= args.limit <= 1000:
        command.error("--limit must be between 1 and 1000")
    variable = "PHISHHAWK_%s_TOKEN" % args.service.upper()
    token = os.environ.get(variable, "").strip()
    if not token:
        command.error("set %s to an access token (it is never taken on the command line)" % variable)
    since = None
    if args.since:
        try:
            since = datetime.date.fromisoformat(args.since)
        except ValueError:
            command.error("--since must be a date like 2026-09-01")
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    err = console.Palette(_colour_ok(sys.stderr, args.no_color))
    criteria = sweep.Criteria(senders=[s.strip().lower() for s in args.senders if s.strip()],
                              subjects=[s.strip() for s in args.subjects if s.strip()],
                              domains=[d.strip().lower() for d in args.domains if d.strip()],
                              message_ids=[m.strip() for m in args.message_ids if m.strip()])
    if args.like:
        try:
            options, _ = _settings(args, lambda message: print(err("[!] %s" % printable(message), "red"),
                                                               file=sys.stderr))
            reported = triage_bytes(read_input(args.like, args.max_size * 1024 * 1024), args.like, options, None)
        except (config.ConfigError, yararules.YaraError):
            return EXIT_ERROR
        except Exception as exc:  # unreadable or too large
            print(err("[!] %s: could not read (%s)" % (printable(args.like), printable(str(exc))), "red"),
                  file=sys.stderr)
            return EXIT_ERROR
        derived = sweep.criteria_from(reported)
        for name in ("senders", "subjects", "domains", "message_ids"):
            merged = getattr(criteria, name) + getattr(derived, name)
            setattr(criteria, name, list(dict.fromkeys(merged)))
    if not criteria:
        command.error("nothing to look for: give --like, --from, --subject, --domain or --message-id")
    mailboxes = list(args.mailboxes)
    if args.mailbox_file:
        try:
            mailboxes += _mailbox_list(args.mailbox_file)
        except OSError as exc:
            command.error("--mailboxes: %s" % exc)
    mailboxes = list(dict.fromkeys(mailboxes or ["me"]))
    search = sweep.sweep_graph if args.service == "graph" else sweep.sweep_gmail
    try:
        boxes = search(token, mailboxes, criteria, since=since, limit=args.limit, timeout=args.timeout)
    except mailapi.MailApiError as exc:  # a malformed token, refused before any request
        print(err("[!] %s" % printable(str(exc)), "red"), file=sys.stderr)
        return EXIT_ERROR
    result = {"service": args.service, "criteria": dataclasses.asdict(criteria), "since": args.since or "",
              "mailboxes": boxes}
    count = sweepout.totals(result)
    result["found"] = count["copies"]
    outputs = {"json": args.json, "csv": args.csv}
    if "-" not in outputs.values():
        print(sweepout.render_console(result, colour))
    renderers = {"json": lambda: json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                 "csv": lambda: sweepout.render_csv(result)}
    failed = bool(count["errors"])
    for kind, path in outputs.items():
        if not path:
            continue
        try:
            _write(path, renderers[kind]())
            if path != "-":
                print(err("[i] %s written to %s" % (kind.upper(), path), "dim"), file=sys.stderr)
        except OSError as exc:
            print(err("[!] could not write %s: %s" % (path, exc), "red"), file=sys.stderr)
            failed = True
    if failed:
        return EXIT_ERROR
    return 1 if count["copies"] else 0


def cmd_evidence(args: argparse.Namespace) -> int:
    colour = console.Palette(_colour_ok(sys.stdout, args.no_color))
    result = evidence.verify(args.directory)
    for problem in result.problems:
        print(colour("[!] " + printable(problem), "red"))
    if result.problems:
        print("%s checked, %s" % (_count(result.records, "record"), _count(len(result.problems), "problem")))
        return 1
    print(colour("[ok] %s checked: every record follows the one before it and every kept message "
                 "matches its SHA-256" % _count(result.records, "record"), "green"))
    print("head %s" % result.head)
    return 0


def _count(number: int, noun: str) -> str:
    return "%d %s%s" % (number, noun, "" if number == 1 else "s")


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
        target = parser.commands.get(args.topic, parser) if args.topic else parser
        target.print_help()
        return 0
    if args.command == "scan":
        return cmd_scan(args, parser)
    if args.command == "imap":
        return cmd_imap(args, parser)
    if args.command in ("graph", "gmail"):
        return cmd_mail_api(args, parser)
    if args.command == "campaign":
        return cmd_campaign(args, parser)
    if args.command == "sweep":
        return cmd_sweep(args, parser)
    if args.command == "evidence":
        return cmd_evidence(args)
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
