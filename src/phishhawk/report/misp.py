"""MISP event JSON: one event per message, ready for "Add Event > Populate
from JSON" or the /events/add API, with ATT&CK galaxy tags and an email
object describing the message."""

from __future__ import annotations

import time
import uuid
from typing import Any

from .. import __version__
from ..attack import technique_name
from ..models import Analysis

NAMESPACE = uuid.UUID("2f0b5c1e-4a6d-4f8a-9d3e-7c21a8e4b610")
THREAT_LEVEL = {"MALICIOUS": "1", "LIKELY PHISHING": "2", "SUSPICIOUS": "3"}  # 1 high .. 4 undefined
# (MISP type, category) for each PhishHawk indicator type and role
ATTRIBUTE_TYPES = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "phone": ("phone-number", "Other"),
}
WALLET_TYPES = {"bitcoin": "btc", "monero": "xmr"}


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts)))


def _attribute(kind: str, category: str, value: str, comment: str, to_ids: bool = True) -> dict[str, Any]:
    return {"uuid": _uuid(kind, value), "type": kind, "category": category, "value": value,
            "comment": comment[:250], "to_ids": to_ids, "distribution": "5"}


def _attributes(a: Analysis) -> list[dict[str, Any]]:
    out = []
    for ioc in a.iocs():
        kind, value, context = ioc["type"], ioc["value"], ioc["context"]
        if kind == "crypto-wallet":
            currency = context.split(" ", 1)[0]
            misp_type = WALLET_TYPES.get(currency, "text")
            out.append(_attribute(misp_type, "Financial fraud", value, context, misp_type != "text"))
            continue
        if kind in ("ipv4", "ipv6") and "originating IP" in context:
            out.append(_attribute("ip-src", "Network activity", value, context))
            if context == "originating IP":
                continue
        if kind == "email" and context == "reply-to address":
            out.append(_attribute("email-reply-to", "Payload delivery", value, context))
            continue
        misp_type, category = ATTRIBUTE_TYPES.get(kind, ("text", "Other"))
        out.append(_attribute(misp_type, category, value, context))
        if kind == "sha256":
            name = context.split(" (", 1)[0]
            out.append(_attribute("filename|sha256", "Payload delivery", "%s|%s" % (name, value), context))
    return out


def _email_object(a: Analysis) -> dict[str, Any]:
    fields = [("subject", "email-subject", a.subject), ("from", "email-src", a.from_address),
              ("from-display-name", "email-src-display-name", a.from_display),
              ("reply-to", "email-reply-to", a.reply_to), ("message-id", "email-message-id", a.message_id),
              ("send-date", "datetime", "")]
    attributes = [{"object_relation": relation, "type": kind, "value": value, "to_ids": False}
                  for relation, kind, value in fields if value]
    return {"name": "email", "meta-category": "network", "template_uuid": "a0c666e0-fc65-4be8-b48f-3423d788b552",
            "uuid": _uuid("email", a.message_id or a.path, a.subject), "Attribute": attributes}


def _tags(a: Analysis, tlp: str) -> list[dict[str, str]]:
    tags = [{"name": "tlp:%s" % tlp}, {"name": 'phishhawk:verdict="%s"' % a.verdict.lower().replace(" ", "-")},
            {"name": 'rsit:fraud="phishing"'}]
    for technique in a.techniques:
        name = technique_name(technique).split(": ", 1)[-1]
        tags.append({"name": 'misp-galaxy:mitre-attack-pattern="%s - %s"' % (name, technique)})
    return tags


def build_event(a: Analysis, tlp: str = "amber") -> dict[str, Any]:
    return {"Event": {
        "uuid": _uuid("event", a.message_id or a.path, a.subject),
        "info": ("Phishing: %s" % (a.subject or a.path))[:250],
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "threat_level_id": THREAT_LEVEL.get(a.verdict, "4"),
        "analysis": "1",  # ongoing: a triage, not a closed investigation
        "distribution": "0",  # your organisation only, until someone decides otherwise
        "Tag": _tags(a, tlp),
        "Attribute": _attributes(a),
        "Object": [_email_object(a)],
        "comment": "PhishHawk %s: %s, risk score %d" % (__version__, a.verdict, a.score),
    }}


def build(analyses: list[Analysis], tlp: str = "amber") -> dict[str, Any] | list[dict[str, Any]]:
    """One event for one message; a list of events for a batch."""
    events = [build_event(a, tlp) for a in analyses]
    return events[0] if len(events) == 1 else events
