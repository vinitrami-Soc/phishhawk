"""Markdown ticket note: paste straight into Jira, ServiceNow or TheHive."""

from __future__ import annotations

import re

from .. import __version__
from ..alignment import assess
from ..extract import defang_host
from ..models import Analysis
from .common import (
    analysis_status,
    defang_ioc,
    display_copy,
    limitations,
    recommendations,
    sorted_signals,
    summary_sentences,
    technique_rows,
    utc_now,
)

_MARKDOWN_RE = re.compile(r"([\\`*_{}\[\]()#+!|~])")
_AUTOLINK_RE = re.compile(r"(?i)\b(https?)(?=://)|\bwww\.")  # GitHub and GitLab link these bare


def _cell(text: str) -> str:
    """Attacker text as inert Markdown: "[Pay now](https://...)" in a subject
    must not become a live link, nor "![](https://...)" an image that tells
    the attacker when the ticket was opened."""
    text = _AUTOLINK_RE.sub(lambda m: "hxxp" + m.group(1)[4:] if m.group(1) else "www[.]", str(text))
    escaped = _MARKDOWN_RE.sub(r"\\\1", text.replace("\n", " "))
    return escaped.replace("<", "&lt;").replace(">", "&gt;")


def _code(text: str) -> str:
    """A code span that attacker text cannot close."""
    return "`%s`" % str(text).replace("`", "'").replace("|", "\\|").replace("\n", " ")


def _defang_ioc(ioc: dict) -> str:
    return defang_ioc(ioc["type"], ioc["value"])


def render(a: Analysis) -> str:
    a = display_copy(a)
    out = ["## Phishing triage: %s (risk score %d)" % (a.verdict, a.score), ""]
    out.append("| | |")
    out.append("|---|---|")
    out.append("| **Subject** | %s |" % _cell(a.subject or "(none)"))
    out.append("| **From** | %s %s |" % (_cell(a.from_display), _code(defang_host(a.from_address))))
    if a.reply_to:
        out.append("| **Reply-To** | %s |" % _code(defang_host(a.reply_to)))
    if a.originating_ip:
        out.append("| **Originating IP** | %s |" % _code(defang_host(a.originating_ip)))
    if a.hops:
        first = a.hops[0]
        out.append("| **First hop** | %s |" % _code("%s -> %s" % (defang_host(first.get("from", "?")),
                                                                defang_host(first.get("by", "?")))))
    if a.auth:
        out.append("| **Authentication** | %s |" % " · ".join(
            "%s %s" % (k.upper(), v) for k, v in a.auth.items()))
    out.append("| **Message-ID** | %s |" % _code(a.message_id or "(none)"))
    if a.evidence.get("sha256"):
        out.append("| **Message SHA-256** | %s |" % _code(a.evidence["sha256"]))
    if a.evidence.get("custody"):
        out.append("| **Custody record** | %s |" % _code(a.evidence["custody"]))
    if a.reported_by:
        out.append("| **Reported by** | %s |" % _cell(a.reported_by.get("from", "")))
    status = analysis_status(a)
    reasons = ": " + " ".join(status["reasons"]) if status["reasons"] else ""
    out.append("| **Analysis** | %s |" % _cell(status["status"].capitalize() + reasons))
    out.append("| **Reputation** | %s (%s) |" % (_cell(status["reputation"].capitalize()),
                                                 _cell(status["reputation_detail"])))
    out += ["", "**Summary:** " + " ".join(summary_sentences(a)), ""]

    block = assess(a, defang_host)
    out += ["### Authentication: %s" % block["status"].upper(), ""]
    if block["checks"]:
        out += ["| Check | Result | Domain | Aligned with From |", "|---|---|---|---|"]
        out += ["| %s | %s | %s | %s |" % (row["check"], _cell(row["result"]),
                                           _code(defang_host(row["domain"])) if row["domain"] else "",
                                           {True: "yes", False: "no"}.get(row["aligned"], ""))
                for row in block["checks"]]
        out.append("")
    out += ["- %s" % _cell(line) for line in block["explanation"]]
    out.append("")

    signals = sorted_signals(a)
    if signals:
        out += ["### Key findings", ""]
        for signal in signals[:15]:
            tags = " (%s)" % ", ".join(signal.techniques) if signal.techniques else ""
            out.append("- **%s**: %s%s" % (signal.severity.upper(), _cell(signal.label), tags))
        if len(signals) > 15:
            out.append("- ... %d lower-priority findings in the full report" % (len(signals) - 15))
        out.append("")

    if a.qr_codes:
        out += ["### QR codes", ""]
        for code in a.qr_codes:
            target = defang_ioc("url", code["url"]) if code.get("url") else code.get("payload", "")[:200]
            out.append("- in %s: %s" % (_cell(code["where"]), _code(target)))
        out.append("")

    if a.yara:
        out += ["### YARA matches", ""]
        out += ["- **%s** %s in %s" % (m.get("severity", "high").upper(), _code(m["rule"]), _cell(m["where"]))
                for m in a.yara]
        out.append("")

    iocs = a.iocs()
    if iocs:
        out += ["### Indicators (defanged)", "", "| Type | Value | Context |", "|---|---|---|"]
        out += ["| %s | %s | %s |" % (i["type"], _code(_defang_ioc(i)), _cell(i["context"])) for i in iocs]
        out.append("")

    rows = technique_rows(a)
    if rows:
        out += ["### MITRE ATT&CK", ""]
        out += ["- [%s](%s) %s" % (row["id"], row["url"], row["name"]) for row in rows]
        out.append("")

    out += ["### Recommended actions", ""]
    out += ["- [ ] %s" % _cell(action) for action in recommendations(a)]
    out += ["", "### Limitations", ""]
    out += ["- %s" % _cell(note) for note in limitations(a)]
    out += ["", "_Generated by phishhawk %s at %s_" % (__version__, utc_now()), ""]
    return "\n".join(out)
