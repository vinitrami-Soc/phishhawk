"""Wording and data shared by every report format."""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

from .. import __version__
from ..attack import technique_name, technique_url
from ..models import Analysis, FileIoc, vt_is_malicious

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
VERDICT_TONE = {"MALICIOUS": "red", "LIKELY PHISHING": "red", "SUSPICIOUS": "amber",
                "NO STRONG INDICATORS": "green"}


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
    return bool(report) and report.get("status") not in ("skipped",)


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
        "skipped": report.get("detail", "skipped"),
    }
    return messages.get(status, report.get("detail") or str(status)) + cached, "dim"


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
    return [f for f in analysis.attachments if f.parent == parent.filename and f is not parent]


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
                "Hold the message in quarantine until the sandbox result is back."]
    iocs = analysis.iocs()
    actions = ["Purge the message from every mailbox (search by sender and Message-ID).",
               "Block %s at the mail gateway and web proxy."
               % plural(len([i for i in iocs if i["type"] in ("url", "domain", "email", "ipv4")]),
                        "network indicator")]
    techniques = set(analysis.techniques)
    if techniques & {"T1598.002", "T1598.003", "T1566.002"}:
        actions.append("Find who clicked (proxy logs for the URL hosts); for each, reset the password "
                       "and revoke active sessions and MFA tokens.")
    if any(f.flagged for f in analysis.attachments):
        actions.append("Hunt the attachment SHA256 values in EDR; isolate any host that executed them.")
    if any(hit.target in analysis.protected_domains for hit in analysis.lookalikes):
        actions.append("Your own domain is being impersonated: alert finance/HR about possible "
                       "payment-diversion (BEC) and consider takedown of the lookalike.")
    actions.append("Escalate to L2 with this report attached.")
    return actions


def technique_rows(analysis: Analysis) -> list[dict[str, Any]]:
    rows = []
    for technique in analysis.techniques:
        evidence = [s.label for s in analysis.signals if technique in s.techniques]
        rows.append({"id": technique, "name": technique_name(technique),
                     "url": technique_url(technique), "evidence": evidence})
    return rows


def to_dict(analysis: Analysis) -> dict[str, Any]:
    payload = asdict(analysis)
    payload["score"] = analysis.score
    payload["verdict"] = analysis.verdict
    payload["techniques"] = [{k: v for k, v in row.items()} for row in technique_rows(analysis)]
    payload["iocs"] = analysis.iocs()
    payload["recommendations"] = recommendations(analysis)
    payload["summary"] = summary_sentences(analysis)
    payload["generated_at"] = utc_now()
    payload["tool_version"] = __version__
    for item, ioc in zip(payload["urls"], analysis.urls, strict=True):
        item["defanged"] = ioc.defanged
    return payload
