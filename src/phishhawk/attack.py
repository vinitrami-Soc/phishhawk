"""MITRE ATT&CK techniques the heuristics can evidence.

Every signal carries the technique IDs it supports, so each report can list
the techniques observed in that message rather than a static table.
"""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1566.004": "Phishing: Spearphishing Voice",
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
    "T1657": "Financial Theft",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1221": "Template Injection",
    "T1559.002": "Inter-Process Communication: Dynamic Data Exchange",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
    "T1203": "Exploitation for Client Execution",
}


# What PhishHawk looks for as evidence of each technique (`phishhawk techniques`).
EVIDENCE: dict[str, str] = {
    "T1566": "urgency and pressure wording in the subject",
    "T1566.001": "risky, archived, macro-enabled or VirusTotal-flagged attachments",
    "T1566.002": "link text that shows one domain but points at another; QR codes; links to runnable files; "
                 "VirusTotal-flagged URLs",
    "T1566.004": "callback phishing: a fake renewal or order and a phone number to ring",
    "T1598.002": "credential forms inside HTML attachments",
    "T1598.003": "credential-harvesting URL paths (/login, /verify, /owa ...) on untrusted hosts",
    "T1656": "brand display names, Reply-To diversion, lookalikes of brands or your domain, free-mail BEC",
    "T1036": "homoglyph hosts, '@' userinfo tricks in URLs, look-alike letters in names, forged brand senders",
    "T1036.002": "right-to-left override characters in attachment names",
    "T1036.007": "double extensions such as invoice.pdf.js",
    "T1036.008": "files whose magic bytes contradict their extension",
    "T1204.001": "links the recipient is lured to click (VirusTotal-confirmed)",
    "T1204.002": "risky or macro-enabled files the recipient is lured to open",
    "T1583.001": "lookalike, punycode, high-abuse-TLD and newly registered domains",
    "T1583.006": "links to free hosting, tunnels, IPFS, cloud storage and form builders",
    "T1608.005": "URL shorteners, raw-IP hosts and HTML redirects",
    "T1027": "zero-width characters, hidden text, words broken up by tags, styled Unicode, IPs written as "
             "numbers; URLs hidden in base64",
    "T1027.006": "HTML smuggling code (atob, Blob, createObjectURL) in attachments",
    "T1027.013": "password-protected archives the gateway cannot scan",
    "T1657": "requests for payments, gift cards or bank-detail changes from lookalike or free-mail senders",
    "T1585.002": "organisation names on free-mail sender addresses",
    "T1059.001": "shortcuts (.lnk) and scripts that start PowerShell",
    "T1059.005": "VBA macros in Office documents",
    "T1059.007": "JavaScript files and links that run script",
    "T1218.005": "shortcuts and scripts that start mshta.exe; .hta files",
    "T1221": "Word documents that load a remote template",
    "T1559.002": "DDE fields in Office documents",
    "T1553.005": "ISO, IMG and VHD containers that strip the Mark of the Web",
    "T1203": "RTF documents carrying OLE objects of the kind used in exploits",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/%s/" % technique_id.replace(".", "/")


# The ATT&CK tactic each technique belongs to (Enterprise matrix), in the order
# the matrix lists them, so a report can show where in an intrusion the
# evidence sits.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Defense Evasion", "Impact",
)

# Every tactic of the Enterprise matrix. The ones outside TACTIC_ORDER happen
# after delivery (persistence, lateral movement, ...): a message cannot show
# them, so a report marks them "not assessed" rather than "not observed".
ENTERPRISE_TACTICS: tuple[str, ...] = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
)
TACTICS: dict[str, str] = {
    "T1598": "Reconnaissance",
    "T1583": "Resource Development",
    "T1608": "Resource Development",
    "T1566": "Initial Access",
    "T1204": "Execution",
    "T1036": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1656": "Defense Evasion",
    "T1657": "Impact",
    "T1585": "Resource Development",
    "T1059": "Execution",
    "T1203": "Execution",
    "T1559": "Execution",
    "T1218": "Defense Evasion",
    "T1221": "Defense Evasion",
    "T1553": "Defense Evasion",
}


def technique_tactic(technique_id: str) -> str:
    return TACTICS.get(technique_id.split(".", 1)[0], "")
