"""Text, URL and HTML extraction primitives. Pure functions, no I/O."""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlsplit

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Bounded quantifiers (RFC 5321: local part <= 64, labels <= 63) keep every match
# attempt short. Unbounded, a 100 KB base64 image in an HTML body made this
# regex quadratic: one real phishing sample took 60 seconds to parse.
EMAIL_RE = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}")
URL_RE = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>\"'`\\\u00a0]+", re.I)
DOMAINISH_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}\b", re.I)
ZERO_WIDTH_RE = re.compile("[\u200b\u2060]|(?<=[A-Za-z])[\u200c\u200d](?=[A-Za-z])")
PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|255\.)"
)

# Two-label public suffixes worth knowing when guessing a registrable domain.
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "nhs.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "co.za", "com.br", "gov.br", "org.br", "net.br", "com.mx", "com.sg", "com.hk", "co.jp",
    "com.tr", "com.cn", "com.tw", "co.kr", "com.my", "co.id", "com.ph",
}

_REFANG_RULES = [
    (re.compile(r"h(?:xx|XX|\*\*)p(s?)\s*(?::|\[:\])//", re.I), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\\\."), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]


def refang(text: str) -> str:
    """Turn analyst-defanged text (hxxp://evil[.]com) back into real URLs."""
    out = text or ""
    for pattern, replacement in _REFANG_RULES:
        out = pattern.sub(replacement, out)
    return out


def defang_host(host: str) -> str:
    return (host or "").replace(".", "[.]")


def defang_url(url: str) -> str:
    """Make a URL safe to paste into a ticket or a chat window."""
    if not url:
        return ""
    out = re.sub(r"^http(s?)://", lambda m: "hxxp%s://" % m.group(1), url, flags=re.I)
    match = re.match(r"^(hxxps?://|ftp://)([^/?#]+)(.*)$", out, re.I)
    if match:
        return match.group(1) + defang_host(match.group(2)) + match.group(3)
    return defang_host(out)


def host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def is_ip(value: str) -> bool:
    return bool(IPV4_RE.fullmatch(value or ""))


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without pulling in a public-suffix dependency."""
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) < 3:
        return host
    if ".".join(labels[-2:]) in MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_label(domain: str) -> str:
    """'mail.example-corp.co.uk' -> 'example-corp' (the part people recognise)."""
    registrable = registrable_domain(domain)
    if not registrable or is_ip(registrable):
        return registrable
    return registrable.split(".", 1)[0]


def domain_of_address(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower().rstrip(".")


def clean_url(raw: str) -> str:
    url = (raw or "").strip().strip("\u200b\u200c\ufeff")
    url = url.rstrip(".,;:!?\"'*_")
    while url and url[-1] in ")]}":
        opener = {")": "(", "]": "[", "}": "{"}[url[-1]]
        if url.count(opener) >= url.count(url[-1]):
            break
        url = url[:-1]
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def usable_url(url: str) -> bool:
    if not url or "://" not in url:
        return False
    if url.split("://", 1)[0].lower() not in ("http", "https", "ftp"):
        return False
    host = host_of(url)
    return bool(host) and ("." in host or host == "localhost")


def urls_from_text(text: str) -> list[str]:
    found = []
    for match in URL_RE.finditer(refang(text or "")):
        url = clean_url(match.group(0))
        if usable_url(url):
            found.append(url)
    return found


# ---------------------------------------------------------------------------
# Link wrappers and redirectors
# ---------------------------------------------------------------------------

_URLDEFENSE_V3 = re.compile(r"urldefense\.com/v3/__(.+?)__;", re.I)
_GOOGLE_HOST = re.compile(r"(^|\.)google\.[a-z]{2,3}(\.[a-z]{2})?$")


def unwrap_link(url: str) -> tuple[str, str, str] | None:
    """(inner URL, who wrapped it, kind) for a wrapped link, else None.

    kind "gateway": a mail-security product rewrote the link (Microsoft Safe
    Links, Proofpoint, Barracuda). The inner URL is what the sender sent.
    kind "redirect": an open redirector on a trusted domain (Google AMP,
    Bing, Facebook, YouTube, LinkedIn), a favourite way to borrow a
    reputable domain for a malicious link.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parse_qs(parts.query)

    def first(key: str) -> str:
        values = query.get(key) or []
        return values[0] if values else ""

    inner, who, kind = "", "", ""
    if host.endswith("safelinks.protection.outlook.com"):
        inner, who, kind = first("url"), "Microsoft Safe Links", "gateway"
    elif host == "urldefense.proofpoint.com" and path.startswith("/v2/url"):
        encoded = first("u").replace("-", "%").replace("_", "/")
        inner, who, kind = unquote(encoded), "Proofpoint URL Defense", "gateway"
    elif host == "urldefense.com":
        match = _URLDEFENSE_V3.search(url)
        inner, who, kind = (match.group(1) if match else ""), "Proofpoint URL Defense", "gateway"
    elif host == "linkprotect.cudasvc.com":
        inner, who, kind = first("a"), "Barracuda Link Protection", "gateway"
    elif _GOOGLE_HOST.search(host) and path == "/url":
        inner, who, kind = first("q") or first("url"), "Google redirect", "redirect"
    elif _GOOGLE_HOST.search(host) and path.startswith("/amp/"):
        rest = path[len("/amp/s/"):] if path.startswith("/amp/s/") else path[len("/amp/"):]
        scheme = "https://" if path.startswith("/amp/s/") else "http://"
        inner, who, kind = scheme + rest + ("?" + parts.query if parts.query else ""), "Google AMP", "redirect"
    elif host.endswith("bing.com") and path == "/ck/a":
        token = first("u")
        if token.startswith("a1"):
            try:
                padded = token[2:] + "=" * (-len(token[2:]) % 4)
                inner = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                inner = ""
        who, kind = "Bing redirect", "redirect"
    elif host in ("l.facebook.com", "lm.facebook.com") or (host.endswith("facebook.com") and path == "/l.php"):
        inner, who, kind = first("u"), "Facebook redirect", "redirect"
    elif host.endswith("youtube.com") and path == "/redirect":
        inner, who, kind = first("q"), "YouTube redirect", "redirect"
    elif host.endswith("linkedin.com") and path.startswith("/redir/redirect"):
        inner, who, kind = first("url"), "LinkedIn redirect", "redirect"
    inner = clean_url(inner)
    if inner and usable_url(inner) and inner != url:
        return inner, who, kind
    return None


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_JS_REDIRECT_RES = [
    re.compile(r"""(?:window|document|top|self|parent)?\.?location(?:\.href)?\s*=\s*['"]([^'"]{4,2048})['"]"""),
    re.compile(r"""location\.(?:replace|assign)\(\s*['"]([^'"]{4,2048})['"]"""),
]

# Markers of HTML smuggling: the file assembles and "downloads" a payload
# client-side, so no URL ever crosses the mail gateway.
SMUGGLING_MARKERS = {
    "atob(": "base64 decoding (atob)",
    "new blob(": "Blob construction",
    "createobjecturl": "URL.createObjectURL",
    "mssaveoropenblob": "msSaveOrOpenBlob",
    "uint8array": "Uint8Array byte assembly",
    "unescape(": "unescape() obfuscation",
    "eval(": "eval()",
    "document.write(": "document.write()",
    "fromcharcode": "String.fromCharCode",
}
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{800,}={0,2}")


@dataclass
class HtmlFindings:
    anchors: list[tuple[str, str]] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    password_inputs: int = 0
    redirects: list[str] = field(default_factory=list)
    script_text: str = ""
    text: str = ""  # visible text (outside script/style)

    @property
    def smuggling_markers(self) -> list[str]:
        lowered = self.script_text.lower()
        markers = [label for token, label in SMUGGLING_MARKERS.items() if token in lowered]
        if _LONG_BASE64_RE.search(self.script_text):
            markers.append("large embedded base64 blob")
        return markers


class _HtmlParser(HTMLParser):
    RESOURCE_ATTRS = ("src", "background", "data-href", "poster")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings = HtmlFindings()
        self._anchor_depth = 0
        self._in_script = False
        self._in_style = False
        self._text: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {k.lower(): (v or "") for k, v in attrs}
        found = self.findings
        if tag == "a":
            found.anchors.append((values.get("href", "").strip(), ""))
            self._anchor_depth += 1
        elif tag == "form":
            self._form = {"action": values.get("action", "").strip(),
                          "method": (values.get("method") or "get").lower(),
                          "has_password": False}
            found.forms.append(self._form)
        elif tag == "input" and values.get("type", "").lower() == "password":
            found.password_inputs += 1
            if self._form is not None:
                self._form["has_password"] = True
        elif tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True
        elif tag == "meta" and "refresh" in values.get("http-equiv", "").lower():
            match = re.search(r"url\s*=\s*([^;\s]+)", values.get("content", ""), re.I)
            if match:
                found.redirects.append(match.group(1).strip("'\" "))
        for key in self.RESOURCE_ATTRS:
            if values.get(key):
                found.resources.append(values[key].strip())

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() == "a" and self._anchor_depth:
            self._anchor_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a" and self._anchor_depth:
            self._anchor_depth -= 1
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.findings.script_text += data + "\n"
            return
        if self._in_style:
            return
        self._text.append(data)
        if self._anchor_depth and self.findings.anchors:
            href, text = self.findings.anchors[-1]
            if len(text) < 500:  # anchor text only needs to show a domain
                self.findings.anchors[-1] = (href, text + data)


def parse_html(html: str) -> HtmlFindings:
    parser = _HtmlParser()
    try:
        parser.feed(refang(html or ""))
        parser.close()
    except Exception:  # malformed HTML is the norm in phishing mail
        pass
    found = parser.findings
    found.text = " ".join(parser._text)  # noqa: SLF001
    found.anchors = [(href, " ".join(text.split())) for href, text in found.anchors if href]
    for pattern in _JS_REDIRECT_RES:
        found.redirects.extend(match.group(1) for match in pattern.finditer(found.script_text))
    return found


# ---------------------------------------------------------------------------
# PDF (best effort: uncompressed link annotations only)
# ---------------------------------------------------------------------------

_PDF_URI_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){4,2048})\)")
_PDF_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{8,4096})>")
_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
PDF_MAX_STREAMS = 300
PDF_MAX_INFLATED = 20 * 1024 * 1024  # total, across all streams


def _pdf_uris(blob: bytes, found: list[str]) -> None:
    for match in _PDF_URI_RE.finditer(blob):
        raw = re.sub(r"\\([()\\])", r"\1", match.group(1).decode("latin-1"))
        _keep(clean_url(raw), found)
    for match in _PDF_URI_HEX_RE.finditer(blob):
        try:
            raw = bytes.fromhex(match.group(1).decode("ascii").replace(" ", "").replace("\n", ""))
        except ValueError:
            continue
        _keep(clean_url(raw.decode("latin-1")), found)


def _keep(url: str, found: list[str]) -> None:
    if usable_url(url) and url not in found:
        found.append(url)


def urls_from_pdf(data: bytes) -> list[str]:
    """Link annotations, including those inside Flate-compressed object
    streams. Decompression output is capped, so a PDF bomb stays harmless."""
    found: list[str] = []
    data = data or b""
    _pdf_uris(data, found)
    budget = PDF_MAX_INFLATED
    for index, match in enumerate(_PDF_STREAM_RE.finditer(data)):
        if index >= PDF_MAX_STREAMS or budget <= 0:
            break
        try:
            inflated = zlib.decompressobj().decompress(match.group(1), budget)
        except zlib.error:
            continue
        budget -= len(inflated)
        if b"/URI" in inflated:
            _pdf_uris(inflated, found)
    return found


# ---------------------------------------------------------------------------
# File type sniffing
# ---------------------------------------------------------------------------

def sniff_type(data: bytes) -> str:
    """Identify what a file really is from its first bytes."""
    head = (data or b"")[:1024]
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF8"):
        return "gif"
    if len(data or b"") > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    lowered = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if lowered.startswith((b"<!doctype html", b"<html", b"<script", b"<head", b"<body")) \
            or b"<form" in lowered or b"<script" in lowered:
        return "html"
    if lowered.startswith(b"<svg") or (lowered.startswith(b"<?xml") and b"<svg" in lowered):
        return "svg"
    return ""


TYPE_DESCRIPTIONS = {
    "pe": "a Windows executable", "elf": "a Linux executable", "zip": "a ZIP archive",
    "pdf": "a PDF", "rar": "a RAR archive", "7z": "a 7-Zip archive", "ole": "an OLE/legacy Office file",
    "png": "a PNG image", "jpeg": "a JPEG image", "gif": "a GIF image", "iso": "an ISO disk image",
    "html": "an HTML document", "svg": "an SVG image",
}

# What each extension is allowed to be. Only a mismatch towards a dangerous
# real type is reported, so a .jpg that is really a .png stays quiet.
EXPECTED_TYPES = {
    ".pdf": {"pdf"}, ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msg": {"ole"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"}, ".docm": {"zip"}, ".xlsm": {"zip"},
    ".odt": {"zip"}, ".zip": {"zip"}, ".jar": {"zip"}, ".rar": {"rar"}, ".7z": {"7z"},
    ".exe": {"pe"}, ".dll": {"pe"}, ".scr": {"pe"}, ".png": {"png"}, ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"}, ".gif": {"gif"}, ".html": {"html"}, ".htm": {"html"}, ".svg": {"svg", "html"},
    ".iso": {"iso"}, ".txt": set(), ".csv": set(), ".eml": set(),
}
DANGEROUS_TYPES = {"pe", "elf", "html", "iso", "zip", "rar", "7z", "svg"}
