"""MITRE ATT&CK techniques the heuristics can evidence.

Every signal carries the technique IDs it supports, so each report can list
the techniques observed in that message rather than a static table.
"""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.002": "Phishing for Information: Spearphishing Attachment",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
    "T1036": "Masquerading",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1608.005": "Stage Capabilities: Link Target",
    "T1027": "Obfuscated Files or Information",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/%s/" % technique_id.replace(".", "/")
