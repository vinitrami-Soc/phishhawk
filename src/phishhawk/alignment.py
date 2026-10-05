"""Authentication and alignment, explained for a ticket.

SPF, DKIM and DMARC each vouch for a domain, and only DMARC is about the
domain the reader sees in From. A bulk mailer's SPF pass for its own bounce
domain says nothing about the sender; a DKIM signature counts for the sender
only when it is by the sender's own organisation ("aligned", in the relaxed
sense DMARC uses by default: news.shop.example aligns with shop.example).
This module only explains; the detection signals are in heuristics.py.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .extract import registrable_domain
from .models import Analysis

UNVERIFIED = ("No authentication results: the receiving server recorded none, or they were lost when the "
              "message was exported. Treat the From address as unverified.")


def _organisation(domain: str) -> str:
    return registrable_domain(domain) if domain else ""


def _aligned(domain: str, sender: str) -> bool:
    return bool(domain and sender) and _organisation(domain) == _organisation(sender)


def _row(check: str, result: str, domain: str, sender: str) -> dict[str, Any]:
    return {"check": check, "result": result or "none", "domain": domain,
            "aligned": _aligned(domain, sender) if domain else None}


def _dkim(a: Analysis) -> dict[str, Any]:
    """The signature that counts most: an aligned pass, then any pass, then the first."""
    signatures = [c for c in a.auth_checks if c["method"] == "dkim"]
    sender = a.from_domain
    for wanted in (lambda c: c["result"] == "pass" and _aligned(c["domain"], sender),
                   lambda c: c["result"] == "pass", lambda c: True):
        for signature in signatures:
            if wanted(signature):
                return _row("DKIM", signature["result"], signature["domain"], sender)
    return _row("DKIM", a.auth.get("dkim", ""), "", sender)


def _first(a: Analysis, method: str) -> dict[str, str]:
    return next((c for c in a.auth_checks if c["method"] == method), {})


def _explain_spf(row: dict[str, Any], sender: str) -> str:
    result, domain = row["result"], row["shown"] or "the envelope sender"
    if result == "pass":
        if row["aligned"]:
            return "SPF passed for %s, the sender's own organisation." % domain
        return ("SPF passed for %s, a different organisation from %s: it vouches for the bounce address, "
                "not the sender the reader sees." % (domain, sender or "the sender"))
    if result in ("fail", "softfail"):
        return "SPF %s: the sending server is not authorised to send for %s." % (result, domain)
    return "SPF %s for %s." % (result, domain)


def _explain_dkim(row: dict[str, Any], sender: str) -> str:
    result, domain = row["result"], row["shown"]
    if result == "pass":
        if row["aligned"]:
            return "DKIM signature by %s verified: it is the sender's own organisation." % domain
        return "DKIM signature verified, but it is by %s, not %s." % (domain or "another domain",
                                                                     sender or "the sender")
    if result == "none":
        return "No DKIM signature."
    return ("DKIM signature%s did not verify (%s): the message changed in transit or the signature is forged."
            % (" by " + domain if domain else "", result))


def assess(a: Analysis, show: Callable[[str], str] = str) -> dict[str, Any]:
    """{status: pass | fail | unknown, checks, identities, explanation}. show
    formats each domain inside the explanation (reports pass defang_host)."""
    sender = a.from_domain
    identities: list[dict[str, Any]] = [{"role": "From", "address": a.from_address, "domain": sender,
                                         "same_organisation": True}]
    for role, address, domain in (("Reply-To", a.reply_to, a.reply_to_domain),
                                  ("Return-Path", a.return_path, a.return_path_domain)):
        if address:
            identities.append({"role": role, "address": address, "domain": domain,
                               "same_organisation": _aligned(domain, sender)})
    if not a.auth:
        return {"status": "unknown", "checks": [], "identities": identities, "explanation": [UNVERIFIED]}

    spf = _row("SPF", a.auth.get("spf", ""), _first(a, "spf").get("domain") or a.return_path_domain, sender)
    dkim = _dkim(a)
    dmarc_result = a.auth.get("dmarc", "")
    dmarc = {"check": "DMARC", "result": dmarc_result or "none",
             "domain": _first(a, "dmarc").get("domain") or sender, "aligned": None}
    aligned_pass = any(row["result"] == "pass" and row["aligned"] for row in (spf, dkim))
    if dmarc_result == "pass":
        status = "pass"
    elif dmarc_result == "fail":
        status = "fail"
    else:
        status = "pass" if aligned_pass else "fail"

    shown = show(sender) if sender else "the From domain"
    for row in (spf, dkim):
        row["shown"] = show(row["domain"]) if row["domain"] else ""
    if dmarc_result == "pass":
        explanation = ["DMARC passed: %s, the domain the reader sees, is authenticated." % shown]
    elif dmarc_result == "fail":
        explanation = ["DMARC failed: neither SPF nor DKIM authenticated %s, the domain the reader sees." % shown]
    elif status == "pass":
        explanation = ["No DMARC result, but an aligned check authenticated %s." % shown]
    else:
        explanation = ["No check authenticated %s, the domain the reader sees." % shown]
    explanation += [_explain_spf(spf, shown), _explain_dkim(dkim, shown)]
    for row in (spf, dkim):
        del row["shown"]
    for row in identities[1:]:
        if row["same_organisation"] or not row["domain"]:
            continue
        if row["role"] == "Reply-To":
            explanation.append("Replies go to %s, a different organisation from the sender %s."
                               % (show(row["domain"]), shown))
        else:
            explanation.append("Bounces go to %s, a different organisation (usual for bulk-mail services)."
                               % show(row["domain"]))
    if a.forged_auth:
        explanation.append("%d authentication claim(s) below the receiving server's were written by the sender "
                           "and ignored." % len(a.forged_auth))
    return {"status": status, "checks": [spf, dkim, dmarc], "identities": identities, "explanation": explanation}
