"""Wording and data shared by every report format."""

from __future__ import annotations

import dataclasses
import re
import time
from dataclasses import asdict
from typing import Any

from .. import __version__
from ..alignment import assess
from ..attack import technique_name, technique_url
from ..extract import defang_host, defang_url
from ..models import MIME_TOO_DEEP, Analysis, FileIoc, vt_is_malicious

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
VERDICT_TONE = {"MALICIOUS": "red", "LIKELY PHISHING": "red", "SUSPICIOUS": "amber",
                "NO STRONG INDICATORS": "green"}


_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")
_BIDI_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def printable(text: str) -> str:
    """Attacker text made safe to show. Control characters (ESC opens the
    terminal sequences that clear the screen, write the clipboard or hide
    output; a newline could forge a report line) are shown escaped, and
    bidirectional overrides are named, so "invoice<U+202E>fdp.exe" reads as
    what it is instead of rendering as "invoiceexe.pdf"."""
    text = _CONTROL_RE.sub(lambda m: "\\x%02x" % ord(m.group()), str(text).replace("\t", " "))
    return _BIDI_RE.sub(lambda m: "<U+%04X>" % ord(m.group()), text)


def display_copy(value: Any, _copies: dict[int, Any] | None = None) -> Any:
    """A copy of an analysis (or any part of one) with every string printable.
    Each object is copied once, and the links that are not fields (a file's
    parent, see children_of) point at the copies, as in the original."""
    copies = {} if _copies is None else _copies
    if isinstance(value, str):
        return printable(value)
    if isinstance(value, list):
        return [display_copy(item, copies) for item in value]
    if isinstance(value, tuple):
        return tuple(display_copy(item, copies) for item in value)
    if isinstance(value, dict):
        return {display_copy(key, copies): display_copy(item, copies) for key, item in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if id(value) in copies:
            return copies[id(value)]
        fields = [f.name for f in dataclasses.fields(value) if f.init]
        copy = dataclasses.replace(value, **{name: display_copy(getattr(value, name), copies) for name in fields})
        copies[id(value)] = copy
        for name, extra in value.__dict__.items():
            if name.startswith("_") and name not in fields:
                copy.__dict__[name] = display_copy(extra, copies)
        return copy
    return value


RAW_IOC_TYPES = {"sha256", "crypto-wallet", "phone"}  # nothing in them can be clicked
REPORT_VERSION = "2.0"  # the JSON layout; docs/report.schema.json describes it


def defang_ioc(kind: str, value: str) -> str:
    """An indicator made safe to paste: URLs and hosts defanged, hashes,
    wallet addresses and phone numbers as they are."""
    if kind == "url":
        return defang_url(value)
    if kind in RAW_IOC_TYPES:
        return value
    return defang_host(value)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sorted_signals(analysis: Analysis) -> list:
    return sorted(analysis.signals, key=lambda s: SEVERITY_ORDER.get(s.severity, 3))


def plural(count: int, word: str) -> str:
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return ("%d %s" % (value, unit)) if unit == "B" else ("%.1f %s" % (value, unit))
        value /= 1024
    return "%.1f GB" % value


def vt_queried(report: dict[str, Any] | None) -> bool:
    return bool(report) and (report or {}).get("status") != "skipped"


def vt_text(report: dict[str, Any] | None) -> tuple[str, str]:
    """(text, tone) for a VirusTotal result; tone is red/amber/green/dim."""
    if not report:
        return "not queried", "dim"
    status = report.get("status")
    cached = " (cached)" if report.get("cached") else ""
    if status == "ok":
        text = "%d/%d malicious" % (report.get("malicious", 0), report.get("engines", 0))
        if report.get("suspicious"):
            text += ", %d suspicious" % report["suspicious"]
        if report.get("threat_label"):
            text += " [%s]" % report["threat_label"]
        text += cached
        if vt_is_malicious(report):
            return text, "red"
        if report.get("malicious") or report.get("suspicious"):
            return text, "amber"
        return text, "green"
    messages = {
        "not_found": "no record: never submitted to VirusTotal",
        "rate_limited": "rate limited (free tier: 4 lookups/min)",
        "auth_error": "API key rejected",
        "skipped": str(report.get("detail", "skipped")),
    }
    return messages.get(str(status), str(report.get("detail") or status)) + cached, "dim"


def urlscan_text(report: dict[str, Any] | None) -> tuple[str, str]:
    if not report:
        return "", "dim"
    if report.get("status") != "ok":
        return str(report.get("detail") or report.get("status")), "dim"
    text = "%s" % plural(report.get("total", 0), "prior scan")
    if report.get("malicious_hits"):
        return text + ", %d with malicious verdicts" % report["malicious_hits"], "amber"
    latest = (report.get("latest_scan") or {}).get("time", "")
    return text + ("  (latest %s)" % latest[:10] if latest else ""), "dim"


def top_level_files(analysis: Analysis) -> list[FileIoc]:
    return [f for f in analysis.attachments if not f.parent]


def children_of(analysis: Analysis, parent: FileIoc) -> list[FileIoc]:
    """The files opened out of `parent`. Names repeat (every message attached
    to a message is "attached-message.eml"), so a file the inspector opened
    names its parent object; for others, the name decides. A child always
    comes after its parent, so no file can be its own descendant."""
    files = analysis.attachments
    start = next((index for index, f in enumerate(files) if f is parent), len(files)) + 1
    return [f for f in files[start:]
            if f.parent == parent.filename and f.__dict__.get("_parent_file", parent) is parent]


def unopened_members(analysis: Analysis, parent: FileIoc) -> list[str]:
    """Names listed in a container that were not opened (RAR and 7-Zip
    members, encrypted or oversized ones), so the report still shows them."""
    if not parent.archive:
        return []
    opened = {f.filename for f in children_of(analysis, parent)}
    return [name for name in parent.archive.get("listing", []) if name not in opened]


def summary_sentences(analysis: Analysis) -> list[str]:
    lines: list[str] = []
    urls = analysis.urls
    if urls:
        sentence = "%s found" % plural(len(urls), "URL")
        if any(vt_queried(u.vt) for u in urls):
            sentence += ", %d flagged as malicious by VirusTotal" % sum(vt_is_malicious(u.vt) for u in urls)
        lines.append(sentence + ".")
    else:
        lines.append("No URLs found.")
    files = [f for f in analysis.attachments if not f.inline]
    if files:
        top = [f for f in files if not f.parent]
        sentence = "%s found" % plural(len(top), "attachment")
        nested = len(files) - len(top)
        if nested:
            sentence += " (+%d inside archives)" % nested
        if any(vt_queried(f.vt) for f in files):
            sentence += ", %d flagged as malicious by VirusTotal" % sum(vt_is_malicious(f.vt) for f in files)
        lines.append(sentence + ".")
    if analysis.lookalikes:
        lines.append("%s detected." % plural(len(analysis.lookalikes), "lookalike domain"))
    high = sum(1 for s in analysis.signals if s.severity == "high")
    if high:
        lines.append("%s raised." % plural(high, "high-severity signal"))
    if analysis.techniques:
        lines.append("Maps to %s." % plural(len(analysis.techniques), "MITRE ATT&CK technique"))
    return lines


def recommendations(analysis: Analysis) -> list[str]:
    verdict = analysis.verdict
    if verdict == "NO STRONG INDICATORS":
        return ["Close as benign unless the reporter describes harm; thank them for reporting."]
    if verdict == "SUSPICIOUS":
        return ["Detonate the URLs and attachments in a sandbox before deciding.",
                "Confirm with the recipient whether they expected this message.",
                "Keep the message away from users through your quarantine process until the sandbox "
                "result is back."]
    iocs = analysis.iocs()
    actions = ["Search every mailbox for copies by sender and Message-ID (phishhawk sweep does this "
               "read-only), then remove confirmed copies through your approved workflow.",
               "After confirming them, block %s at your approved control points, such as the mail gateway "
               "and web proxy." % plural(len([i for i in iocs if i["type"] in ("url", "domain", "email", "ipv4")]),
                                         "network indicator")]
    techniques = set(analysis.techniques)
    if techniques & {"T1598.002", "T1598.003", "T1566.002"}:
        actions.append("Find who clicked (proxy logs for the URL hosts); for each, reset the password "
                       "and revoke active sessions and MFA tokens.")
    if any(f.flagged for f in analysis.attachments):
        actions.append("Hunt the attachment SHA-256 values in EDR; isolate any host that executed them.")
    if any(hit.target in analysis.protected_domains for hit in analysis.lookalikes):
        actions.append("Your own domain is being impersonated: alert finance/HR about possible "
                       "payment-diversion (BEC) and consider takedown of the lookalike.")
    actions.append("Escalate to L2 with this report attached.")
    return actions


FAILED_LOOKUPS = ("error", "rate_limited", "auth_error")
PROVIDER_NAMES = {"virustotal": "VirusTotal", "urlscan": "urlscan.io", "rdap": "RDAP", "abuseipdb": "AbuseIPDB"}


def _lookups(analysis: Analysis):
    """Every reputation answer in the analysis, with the service that gave it."""
    for url in analysis.urls:
        yield "VirusTotal", url.vt
        yield "urlscan.io", url.urlscan
    for attachment in analysis.attachments:
        yield "VirusTotal", attachment.vt
    for info in analysis.domain_intel.values():
        yield "RDAP", info
    yield "AbuseIPDB", analysis.ip_intel


def analysis_status(analysis: Analysis) -> dict[str, Any]:
    """Whether every part of the message was read, and whether the reputation
    services were asked and answered. No answer is never reported as clean."""
    reasons = list(analysis.errors)
    if analysis.urls_dropped:
        reasons.append("%s past the per-message cap were counted but not checked."
                       % plural(analysis.urls_dropped, "link"))
    if analysis.mime_depth >= MIME_TOO_DEEP:
        reasons.append("The MIME structure was nested too deep to follow; the body was read as plain text.")
    unopened = sum(len(unopened_members(analysis, f)) for f in analysis.attachments)
    if unopened:
        reasons.append("%s inside archives or disk images were listed but not opened." % plural(unopened, "file"))
    answers = [(name, report) for name, report in _lookups(analysis) if report]
    failed = sorted({name for name, report in answers if report.get("status") in FAILED_LOOKUPS})
    n_failed = sum(1 for _, report in answers if report.get("status") in FAILED_LOOKUPS)
    n_budget = sum(1 for _, report in answers
                   if report.get("status") == "skipped" and "budget" in str(report.get("detail", "")))
    if not analysis.enrichment_sources:
        reputation, detail = "not checked", "offline: no reputation service was asked"
    elif n_failed or n_budget:
        parts = []
        if n_failed:
            parts.append("%s failed (%s)" % (plural(n_failed, "lookup"), ", ".join(failed)))
        if n_budget:
            parts.append("%s skipped by the per-message VirusTotal budget" % plural(n_budget, "lookup"))
        reputation, detail = "partially checked", "; ".join(parts)
    else:
        reputation, detail = "checked", ", ".join(PROVIDER_NAMES.get(n, n) for n in analysis.enrichment_sources)
    return {"status": "incomplete" if reasons else "complete", "reasons": reasons,
            "reputation": reputation, "reputation_detail": detail}


def limitations(analysis: Analysis) -> list[str]:
    """What this report cannot tell, for this message."""
    notes = ["This report is an investigation aid: confirm indicators and follow your approved response process "
             "before blocking or removing anything."]
    server = " (written by %s)" % defang_host(analysis.auth_receiver) if analysis.auth_receiver else ""
    if analysis.auth_pinned and analysis.auth_header:
        notes.append("Authentication results were read only from the servers named with --trusted-authserv%s."
                     % server)
    elif analysis.auth_header == "Authentication-Results":
        notes.append("Authentication results were read from the topmost Authentication-Results headers%s. If "
                     "your receiving server did not write them, a sender could have; --trusted-authserv names "
                     "the server to trust." % server)
    elif analysis.auth_header:
        notes.append("Only a Received-SPF header was found: DKIM and DMARC could not be judged, and no "
                     "Authentication-Results header vouches for the SPF result.")
    else:
        notes.append("No Authentication-Results header was found, so SPF, DKIM and DMARC could not be judged.")
    if analysis.enrichment_sources:
        notes.append("A clean or empty reputation result does not prove an indicator is safe.")
    else:
        notes.append("No reputation service was asked. The absence of reputation data does not mean an "
                     "indicator is safe.")
    if analysis.urls or analysis.qr_codes or any(not f.inline for f in analysis.attachments):
        notes.append("Whether anyone clicked a link or opened a file is not visible in the message: check "
                     "proxy and EDR telemetry.")
    if any(info.get("status") == "ok" for info in analysis.domain_intel.values()):
        notes.append("A newly registered domain is not malicious by itself, and an old one is not safe by itself.")
    if analysis.evidence.get("sha256"):
        notes.append("The SHA-256 identifies the exact bytes analysed; it does not prove who wrote the message.")
    return notes


def technique_rows(analysis: Analysis) -> list[dict[str, Any]]:
    rows = []
    for technique in analysis.techniques:
        evidence = [s.label for s in analysis.signals if technique in s.techniques]
        rows.append({"id": technique, "name": technique_name(technique),
                     "url": technique_url(technique), "evidence": evidence})
    return rows


def to_dict(analysis: Analysis) -> dict[str, Any]:
    payload = asdict(analysis)
    payload.pop("body_text", None)  # message content stays out of exported reports
    payload["score"] = analysis.score
    payload["verdict"] = analysis.verdict
    payload["techniques"] = [{k: v for k, v in row.items()} for row in technique_rows(analysis)]
    payload["iocs"] = analysis.iocs()
    payload["authentication"] = assess(analysis)
    payload["recommendations"] = recommendations(analysis)
    payload["summary"] = summary_sentences(analysis)
    payload["analysis_status"] = analysis_status(analysis)
    payload["limitations"] = limitations(analysis)
    payload["generated_at"] = utc_now()
    payload["tool_version"] = __version__
    payload["report_version"] = REPORT_VERSION
    for item, ioc in zip(payload["urls"], analysis.urls, strict=True):
        item["defanged"] = ioc.defanged
    return payload
