"""Terminal report."""

from __future__ import annotations

from ..extract import defang_host
from ..models import Analysis, vt_is_malicious
from .common import (
    children_of,
    human_size,
    recommendations,
    sorted_signals,
    summary_sentences,
    technique_rows,
    top_level_files,
    urlscan_text,
    vt_text,
)

WIDTH = 74


class Palette:
    CODES = {"red": "31;1", "amber": "33;1", "green": "32;1", "cyan": "36;1", "dim": "2", "bold": "1"}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, tone: str) -> str:
        if not self.enabled or tone not in self.CODES:
            return text
        return "\033[%sm%s\033[0m" % (self.CODES[tone], text)


def _section(title: str) -> str:
    head = "-- %s " % title
    return head + "-" * max(3, WIDTH - len(head))


def _verdict_tone(verdict: str) -> str:
    return {"MALICIOUS": "red", "LIKELY PHISHING": "red", "SUSPICIOUS": "amber"}.get(verdict, "green")


def render(a: Analysis, colour: Palette, verbose: bool = False) -> str:
    out: list[str] = []
    rule = "=" * WIDTH
    out += [colour(rule, "cyan"), colour("  PHISHING TRIAGE REPORT", "cyan"), colour(rule, "cyan")]
    out.append("File       : %s" % a.path)
    out.append("Subject    : %s" % (a.subject or "(none)"))
    out.append("Date       : %s" % (a.date or "(none)"))
    out.append("Message-ID : %s" % (a.message_id or "(none)"))
    if a.to:
        out.append("To         : %s" % a.to)

    if a.reported_by:
        rb = a.reported_by
        out += ["", colour(_section("REPORTED BY"), "bold")]
        out.append("Reporter     : %s%s" % (rb.get("display") + " " if rb.get("display") else "",
                                           "<%s>" % rb.get("from") if rb.get("from") else ""))
        out.append("Covering note: %s" % (rb.get("subject") or "(none)"))
        out.append(colour("The attached original was unwrapped and is analysed below.", "dim"))

    out += ["", colour(_section("SENDER"), "bold")]
    out.append("Display name : %s" % (a.from_display or "(none)"))
    out.append("From         : %s" % (defang_host(a.from_address) or "(none)"))
    if a.reply_to:
        out.append("Reply-To     : %s" % defang_host(a.reply_to))
    if a.return_path:
        out.append("Return-Path  : %s" % defang_host(a.return_path))
    if a.originating_ip:
        out.append("Originating  : %s  (%d Received hop(s))" % (defang_host(a.originating_ip), a.received_hops))
    if a.auth:
        bits = []
        for mechanism in ("spf", "dkim", "dmarc", "compauth"):
            if mechanism in a.auth:
                value = a.auth[mechanism]
                tone = "green" if value == "pass" else ("red" if value in ("fail", "softfail") else "")
                bits.append(colour("%s=%s" % (mechanism, value), tone))
        out.append("Auth         : %s" % "  ".join(bits))
    else:
        out.append("Auth         : %s" % colour("no Authentication-Results header", "dim"))
    if a.protected_domains:
        out.append("Protected    : %s" % colour(", ".join(a.protected_domains), "dim"))

    if a.lookalikes:
        out += ["", colour(_section("LOOKALIKE DOMAINS (%d)" % len(a.lookalikes)), "bold")]
        for hit in a.lookalikes:
            own = "  <- YOUR DOMAIN" if hit.target in a.protected_domains else ""
            out.append("  %s  %-10s  %s  (%s)%s" % (colour("%-30s" % defang_host(hit.domain), "red"), hit.method,
                                                   defang_host(hit.target), hit.where, own))

    out += ["", colour(_section("URLS (%d)" % len(a.urls)), "bold")]
    if not a.urls:
        out.append("  (none)")
    for index, ioc in enumerate(a.urls, 1):
        marker = "!" if (ioc.flagged or vt_is_malicious(ioc.vt)) else " "
        out.append(" %s[%d] %s" % (marker, index, ioc.defanged))
        out.append("      seen in: %s" % ", ".join(ioc.sources))
        for note in ioc.notes:
            out.append("      %s" % colour("! " + note, "amber"))
        if ioc.vt:
            text, tone = vt_text(ioc.vt)
            out.append("      %s" % colour("VT: " + text, tone))
        if ioc.urlscan:
            text, tone = urlscan_text(ioc.urlscan)
            out.append("      %s" % colour("urlscan: " + text, tone))

    files = [f for f in a.attachments if not f.inline]
    nested = len([f for f in files if f.parent])
    title = "ATTACHMENTS (%d%s)" % (len(files) - nested, " + %d in archives" % nested if nested else "")
    out += ["", colour(_section(title), "bold")]
    if not files:
        out.append("  (none)")

    def file_lines(f, depth: int) -> None:
        pad = "  " + "    " * depth + ("`-- " if depth else "")
        body = "  " + "    " * depth + ("    " if depth else "") + "    "
        real = " (really %s)" % f.true_type if any(n.startswith("claims ") for n in f.notes) else ""
        out.append("%s%s   %s%s   %s" % (pad, f.filename, f.content_type, real, human_size(f.size)))
        out.append("%sSHA256 : %s" % (body, f.sha256))
        if verbose:
            out.append("%sMD5    : %s" % (body, f.md5))
        for note in f.notes:
            out.append("%s%s" % (body, colour("! " + note, "amber")))
        if f.vt:
            text, tone = vt_text(f.vt)
            out.append("%s%s" % (body, colour("VT: " + text, tone)))
        for child in children_of(a, f):
            file_lines(child, depth + 1)

    for f in top_level_files(a):
        if not f.inline:
            file_lines(f, 0)

    if a.domain_intel or a.ip_intel:
        out += ["", colour(_section("INFRASTRUCTURE"), "bold")]
        for domain, info in a.domain_intel.items():
            if info.get("status") == "ok":
                age = info["age_days"]
                tone = "red" if age < 30 else ("amber" if age < 90 else "dim")
                out.append("  %-34s registered %s  %s  %s" % (
                    defang_host(domain), info["registered"], colour("(%d days old)" % age, tone),
                    info.get("registrar", "")))
            else:
                out.append("  %-34s %s" % (defang_host(domain), colour("RDAP: %s" % info.get("status"), "dim")))
        ip = a.ip_intel
        if ip:
            if ip.get("status") == "ok":
                tone = "red" if ip["score"] >= 75 else ("amber" if ip["score"] >= 25 else "green")
                out.append("  %-34s %s  %d reports  %s %s" % (
                    defang_host(a.originating_ip), colour("AbuseIPDB %d%%" % ip["score"], tone),
                    ip.get("reports", 0), ip.get("country", ""), ip.get("isp", "")))
            else:
                out.append("  %-34s %s" % (defang_host(a.originating_ip),
                                          colour("AbuseIPDB: %s" % ip.get("status"), "dim")))

    if a.signals:
        signals = sorted_signals(a)
        out += ["", colour(_section("SIGNALS (%d)" % len(signals)), "bold")]
        shown = signals if verbose else signals[:18]
        for signal in shown:
            tone = {"high": "red", "medium": "amber"}.get(signal.severity, "dim")
            out.append("  [%s] %s" % (colour("%-6s" % signal.severity, tone), signal.label))
        if len(shown) < len(signals):
            out.append(colour("  ... %d more (use --verbose)" % (len(signals) - len(shown)), "dim"))

    rows = technique_rows(a)
    if rows:
        out += ["", colour(_section("MITRE ATT&CK (%d)" % len(rows)), "bold")]
        for row in rows:
            out.append("  %s %s" % (colour("%-10s" % row["id"], "cyan"), row["name"]))

    if a.errors:
        out += ["", colour(_section("ERRORS"), "bold")]
        out += ["  %s" % colour(error, "red") for error in a.errors]

    out += ["", colour(_section("SUMMARY"), "bold")]
    out += ["  " + line for line in summary_sentences(a)]
    out.append("  Verdict: %s  (risk score %d)" % (colour(a.verdict, _verdict_tone(a.verdict)), a.score))
    actions = recommendations(a)
    out.append("  Next step: %s" % actions[0])
    if verbose:
        out += ["             %s" % action for action in actions[1:]]
    out.append(colour(rule, "cyan"))
    return "\n".join(out)


def render_quiet(a: Analysis, colour: Palette) -> str:
    lines = [colour("== %s" % a.path, "cyan")]
    lines += ["  " + line for line in summary_sentences(a)]
    lines.append("  Verdict: %s (risk score %d)" % (colour(a.verdict, _verdict_tone(a.verdict)), a.score))
    return "\n".join(lines)


def render_batch_table(analyses: list[Analysis], colour: Palette) -> str:
    lines = [colour(_section("BATCH SUMMARY (%d messages)" % len(analyses)), "bold")]
    lines.append("  %-38s %-21s %5s %5s %5s" % ("file", "verdict", "score", "urls", "files"))
    for a in analyses:
        name = a.path if len(a.path) <= 38 else "..." + a.path[-35:]
        lines.append("  %-38s %s %5d %5d %5d" % (
            name, colour("%-21s" % a.verdict, _verdict_tone(a.verdict)), a.score, len(a.urls),
            len([f for f in a.attachments if not f.inline])))
    return "\n".join(lines)
