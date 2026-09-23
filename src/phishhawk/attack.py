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
    "T1583.006": "Acquire Infrastructure: Web Services",
    "T1608.005": "Stage Capabilities: Link Target",
    "T1027": "Obfuscated Files or Information",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
}


# What PhishHawk looks for as evidence of each technique (`phishhawk techniques`).
EVIDENCE: dict[str, str] = {
    "T1566": "urgency and pressure wording in the subject",
    "T1566.001": "risky, archived, macro-enabled or VirusTotal-flagged attachments",
    "T1566.002": "link text that shows one domain but points at another; QR-code lures; VirusTotal-flagged URLs",
    "T1598.002": "credential forms inside HTML attachments",
    "T1598.003": "credential-harvesting URL paths (/login, /verify, /owa ...) on untrusted hosts",
    "T1656": "brand display names, Reply-To diversion, lookalikes of brands or your domain, free-mail BEC",
    "T1036": "homoglyph hosts, '@' userinfo tricks in URLs",
    "T1036.002": "right-to-left override characters in attachment names",
    "T1036.007": "double extensions such as invoice.pdf.js",
    "T1036.008": "files whose magic bytes contradict their extension",
    "T1204.001": "links the recipient is lured to click (VirusTotal-confirmed)",
    "T1204.002": "risky or macro-enabled files the recipient is lured to open",
    "T1583.001": "lookalike, punycode, high-abuse-TLD and newly registered domains",
    "T1583.006": "links to free hosting, tunnels, IPFS, cloud storage and form builders",
    "T1608.005": "URL shorteners, raw-IP hosts and HTML redirects",
    "T1027": "zero-width characters in the body; URLs hidden in base64",
    "T1027.006": "HTML smuggling code (atob, Blob, createObjectURL) in attachments",
    "T1027.013": "password-protected archives the gateway cannot scan",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/%s/" % technique_id.replace(".", "/")
