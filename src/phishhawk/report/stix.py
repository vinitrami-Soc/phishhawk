"""STIX 2.1 bundle for threat-intel platforms (MISP, OpenCTI, Sentinel TI).

Object ids are UUIDv5 over the indicator value, so the same URL reported
by fifty users becomes one indicator in the platform, not fifty.
"""

from __future__ import annotations

import uuid
from typing import Any

from .. import __version__
from ..attack import technique_name, technique_url
from ..extract import defang_url
from ..models import Analysis

NAMESPACE = uuid.UUID("5d0c1a3e-7c1b-4e36-9a52-6a1f0e0b8f11")
PATTERNS = {
    "url": "[url:value = '%s']",
    "domain": "[domain-name:value = '%s']",
    "ipv4": "[ipv4-addr:value = '%s']",
    "email": "[email-addr:value = '%s']",
    "sha256": "[file:hashes.'SHA-256' = '%s']",
}
CONFIDENCE = {"MALICIOUS": 85, "LIKELY PHISHING": 70, "SUSPICIOUS": 40}


def _stix_id(kind: str, *parts: str) -> str:
    return "%s--%s" % (kind, uuid.uuid5(NAMESPACE, "|".join((kind,) + parts)))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _timestamp() -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)


def build_bundle(analyses: list[Analysis]) -> dict[str, Any]:
    now = _timestamp()
    identity = {
        "type": "identity", "spec_version": "2.1", "id": _stix_id("identity", "phishhawk"),
        "created": now, "modified": now, "name": "phishhawk %s" % __version__,
        "identity_class": "system",
    }
    objects: dict[str, dict[str, Any]] = {identity["id"]: identity}

    for analysis in analyses:
        verdict = analysis.verdict
        refs: list[str] = []
        for ioc in analysis.iocs():
            pattern = PATTERNS[ioc["type"]] % _escape(ioc["value"])
            indicator_id = _stix_id("indicator", ioc["type"], ioc["value"])
            shown = ioc["value"] if ioc["type"] == "sha256" else defang_url(ioc["value"])
            objects.setdefault(indicator_id, {
                "type": "indicator", "spec_version": "2.1", "id": indicator_id,
                "created": now, "modified": now, "created_by_ref": identity["id"],
                "name": "Phishing %s: %s" % (ioc["type"], shown),
                "description": "%s in phishing email '%s'" % (ioc["context"], analysis.subject),
                "indicator_types": ["malicious-activity"] if verdict in ("MALICIOUS", "LIKELY PHISHING")
                else ["anomalous-activity"],
                "pattern": pattern, "pattern_type": "stix", "valid_from": now,
                "confidence": CONFIDENCE.get(verdict, 20),
                "labels": ["phishing"],
            })
            refs.append(indicator_id)
        for technique in analysis.techniques:
            pattern_id = _stix_id("attack-pattern", technique)
            objects.setdefault(pattern_id, {
                "type": "attack-pattern", "spec_version": "2.1", "id": pattern_id,
                "created": now, "modified": now, "created_by_ref": identity["id"],
                "name": technique_name(technique),
                "external_references": [{"source_name": "mitre-attack", "external_id": technique,
                                         "url": technique_url(technique)}],
            })
            refs.append(pattern_id)
        report_id = _stix_id("report", analysis.message_id or analysis.path, analysis.subject)
        objects[report_id] = {
            "type": "report", "spec_version": "2.1", "id": report_id,
            "created": now, "modified": now, "created_by_ref": identity["id"],
            "name": "Phishing triage: %s" % (analysis.subject or analysis.path),
            "description": "Verdict %s, risk score %d. Sender %s." % (
                verdict, analysis.score, analysis.from_address or "unknown"),
            "published": now, "report_types": ["threat-report"],
            "object_refs": refs or [identity["id"]],
            "labels": ["phishing", verdict.lower().replace(" ", "-")],
        }
    return {"type": "bundle", "id": "bundle--%s" % uuid.uuid4(), "objects": list(objects.values())}
