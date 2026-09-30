"""Text, URL and HTML extraction primitives. Pure functions, no I/O."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlsplit

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Bounded quantifiers (RFC 5321: local part <= 64, labels <= 63) keep every match
# attempt short. Unbounded, a 100 KB base64 image in an HTML body made this
# regex quadratic: one real phishing sample took 60 seconds to parse. The
# lookbehind starts a match only where a run of address characters starts, so
# a 2 MB base64 body is tried once per run, not 64 times per character (1.3 s).
EMAIL_RE = re.compile(r"(?<![\w.!#$%&'*+/=?^`{|}~-])[\w.!#$%&'*+/=?^`{|}~-]{1,64}"
                      r"@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}")
MAX_URL_LENGTH = 8192  # a 1.4 MB "link" of NUL bytes once took seconds to show in each report
URL_RE = re.compile(r"(?:(?:https?|ftp)://|www\.)[^\s<>\"'`\\\u00a0\x00-\x1f\x7f]{1,%d}" % MAX_URL_LENGTH, re.I)
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


_ASCII_DIGITS_RE = re.compile(r"[0-9]+")
_HEX_RE = re.compile(r"0[xX][0-9a-fA-F]*")


def _ipv4_part(part: str) -> int | None:
    if _HEX_RE.fullmatch(part):
        return int(part[2:] or "0", 16)
    if not _ASCII_DIGITS_RE.fullmatch(part):
        return None
    if len(part) > 1 and part[0] == "0":
        return int(part, 8) if re.fullmatch(r"[0-7]+", part) else None
    return int(part)


def parse_ipv4(host: str) -> str:
    """The dotted-quad address for every IPv4 spelling a browser opens:
    3232235777, 0xC0A80101, 0300.0250.1.1 and 192.168.257 all reach
    192.168.1.1. Attackers write the number to get past checks that only
    look for four dotted decimals. Empty when the host is not an address."""
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if not 1 <= len(parts) <= 4 or len(host) > 64:
        return ""
    numbers = [_ipv4_part(part) for part in parts]
    if any(n is None for n in numbers):
        return ""
    values = [n for n in numbers if n is not None]
    if any(n > 255 for n in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return ""
    total = values[-1] + sum(n << (8 * (3 - i)) for i, n in enumerate(values[:-1]))
    return ".".join(str((total >> shift) & 255) for shift in (24, 16, 8, 0))


def canonical_host(host: str) -> str:
    """Lower case, no trailing dot, and an IP address in its standard form."""
    host = (host or "").lower().rstrip(".")
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host.split("%", 1)[0]))
        except ValueError:
            return host
    return parse_ipv4(host) or host


def raw_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def host_of(url: str) -> str:
    return canonical_host(raw_host(url))


_ANY_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]{1,2000}", re.I)


def defang_text(text: str) -> str:
    """Free text (a shortcut's command line, a QR payload, a note) with
    every URL in it defanged, so no report shows a live link."""
    return _ANY_URL_RE.sub(lambda m: defang_url(m.group(0)), text or "")


def is_ip(value: str) -> bool:
    if IPV4_RE.fullmatch(value or ""):
        return True
    if ":" not in (value or ""):
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


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
    # '"service@adac.de"' written without angle brackets keeps its quotes
    return address.rsplit("@", 1)[1].strip().strip("<>\"' ").lower().rstrip(".")


_URL_TAB_NEWLINE_RE = re.compile(r"[\t\n\r]")
_URL_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_C0_AND_SPACE = "".join(map(chr, range(0x21)))


def clean_url(raw: str) -> str:
    # As a browser reads an href: tabs and line breaks anywhere are dropped
    # ("https://ev&#10;il.top" opens evil.top), other control characters are
    # percent-encoded.
    url = _URL_TAB_NEWLINE_RE.sub("", (raw or "")[:MAX_URL_LENGTH * 2])
    url = _URL_CONTROL_RE.sub(lambda m: "%%%02X" % ord(m.group()), url.strip(_C0_AND_SPACE))[:MAX_URL_LENGTH]
    url = url.strip().strip("\u200b\u200c\ufeff")
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
    return bool(host) and ("." in host or host == "localhost" or is_ip(host))


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


def _on(host: str, domain: str) -> bool:
    """True for the domain itself or a subdomain of it.

    A bare suffix check would also accept evilbing.com as Bing, and the report
    would then call an attacker's own domain a trusted redirector.
    """
    return host == domain or host.endswith("." + domain)


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
    if _on(host, "safelinks.protection.outlook.com"):
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
    elif _on(host, "bing.com") and path == "/ck/a":
        token = first("u")
        if token.startswith("a1"):
            try:
                padded = token[2:] + "=" * (-len(token[2:]) % 4)
                inner = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                inner = ""
        who, kind = "Bing redirect", "redirect"
    elif host in ("l.facebook.com", "lm.facebook.com") or (_on(host, "facebook.com") and path == "/l.php"):
        inner, who, kind = first("u"), "Facebook redirect", "redirect"
    elif _on(host, "youtube.com") and path == "/redirect":
        inner, who, kind = first("q"), "YouTube redirect", "redirect"
    elif _on(host, "linkedin.com") and path.startswith("/redir/redirect"):
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
    text: str = ""  # all text outside script/style, hidden or not
    cell_grids: list[list[list[int]]] = field(default_factory=list)  # tables of dark/light cells
    hidden_text: str = ""  # text styled invisible (display:none, font-size:0 ...), capped
    visible_text: str = ""  # text a reader actually sees
    hidden_splits: int = 0  # times hidden text sat inside a visible word: "Micro<span hidden>x</span>soft"
    tag_splits: int = 0  # times a tag broke a visible word: "T<span></span>h<span></span>e"

    @property
    def smuggling_markers(self) -> list[str]:
        lowered = self.script_text.lower()
        markers = [label for token, label in SMUGGLING_MARKERS.items() if token in lowered]
        if _LONG_BASE64_RE.search(self.script_text):
            markers.append("large embedded base64 blob")
        return markers


# Inline styles that make text invisible. Newsletters hide a short preview
# line this way too, so the heuristics weigh how much is hidden and whether
# it repeats the visible text, not the trick itself.
_HIDING_STYLE_RE = re.compile(
    r"display:none|visibility:hidden|mso-hide:all|opacity:0(?![.0-9]*[1-9])"
    r"|font-size:0(?:\.0+)?(?:px|pt|em|rem|%)?(?![.0-9]*[1-9])|font-size:[01]px"
    r"|(?:max-)?(?:height|width):0(?:px)?(?![.0-9]*[1-9]).{0,200}overflow:hidden"
    r"|overflow:hidden.{0,200}(?:max-)?(?:height|width):0(?:px)?(?![.0-9]*[1-9])")
_STYLE_CLASS_RULE_RE = re.compile(r"\.([A-Za-z0-9_-]{1,64})\s*\{([^{}]{0,1000})\}")
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
              "source", "track", "wbr", "keygen", "frame", "basefont", "isindex"}
# Elements that start a new line: text on either side of one is not one word.
_BLOCK_TAGS = {"address", "article", "aside", "blockquote", "br", "center", "dd", "div", "dl", "dt",
               "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
               "header", "hr", "li", "main", "nav", "ol", "option", "p", "pre", "section", "table", "tbody",
               "td", "tfoot", "th", "thead", "title", "tr", "ul", "body", "html", "head"}
MAX_OPEN_ELEMENTS = 2000
MAX_HIDDEN_TEXT = 20_000


def hides_text(style: str) -> bool:
    return bool(_HIDING_STYLE_RE.search(re.sub(r"\s+|!important", "", (style or "").lower())))


_COLOR_RE = re.compile(r"background(?:-color)?\s*:\s*([^;\"']{1,40})", re.I)
_NAMED_DARK = {"black", "#000", "#000000", "rgb(0,0,0)", "#111", "#111111", "#222", "#222222"}
MAX_TABLE_CELLS = 40_000  # a QR code drawn in cells is at most a few thousand


def _dark_cell(values: dict[str, str]) -> int:
    """1 when a table cell is painted dark: how QR codes are drawn without an image."""
    match = _COLOR_RE.search(values.get("style", ""))
    color = (match.group(1) if match else values.get("bgcolor", "")).strip().lower().replace(" ", "")
    if not color:
        return 0
    if color in _NAMED_DARK:
        return 1
    hex_match = re.fullmatch(r"#?([0-9a-f]{3}|[0-9a-f]{6})", color)
    if hex_match:
        digits = hex_match.group(1)
        if len(digits) == 3:
            digits = "".join(ch * 2 for ch in digits)
        red, green, blue = (int(digits[i:i + 2], 16) for i in (0, 2, 4))
        return int(0.299 * red + 0.587 * green + 0.114 * blue < 96)
    rgb = re.fullmatch(r"rgba?\((\d+),(\d+),(\d+)[^)]*\)", color)
    if rgb:
        red, green, blue = (int(v) for v in rgb.groups())
        return int(0.299 * red + 0.587 * green + 0.114 * blue < 96)
    return 0


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
        self._tables: list[dict] = []
        self._open: list[tuple[str, bool]] = []  # (tag, hidden) of open elements
        self._open_count: dict[str, int] = {}
        self._hidden_classes: set[str] = set()
        self._hidden: list[str] = []
        self._hidden_size = 0
        self._visible: list[str] = []
        self._last_visible_alnum = False
        self._hidden_since_visible = False
        self._tag_since_visible = False

    @property
    def _in_hidden(self) -> bool:
        return bool(self._open) and self._open[-1][1]

    def _push(self, tag: str, values: dict[str, str]) -> None:
        if tag in _VOID_TAGS or len(self._open) >= MAX_OPEN_ELEMENTS:
            return
        classes = set(values.get("class", "").lower().split())
        hidden = self._in_hidden or "hidden" in values or hides_text(values.get("style", "")) \
            or bool(classes & self._hidden_classes)
        self._open.append((tag, hidden))
        self._open_count[tag] = self._open_count.get(tag, 0) + 1

    def _pop(self, tag: str) -> None:
        if not self._open_count.get(tag):
            return  # a stray end tag closes nothing
        while self._open:
            name, _ = self._open.pop()
            self._open_count[name] -= 1
            if name == tag:
                break

    def _line_break(self) -> None:
        """A visible block boundary: what follows is a new word."""
        if not self._in_hidden:
            self._visible.append(" ")
            self._last_visible_alnum = False
            self._hidden_since_visible = False

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
        elif tag == "table":
            self._tables.append({"rows": [], "cells": 0})
        elif tag == "tr" and self._tables:
            self._tables[-1]["rows"].append([])
        elif tag in ("td", "th") and self._tables and self._tables[-1]["rows"]:
            table = self._tables[-1]
            colspan = values.get("colspan", "1")
            span = min(int(colspan), 200) if colspan.isdigit() and int(colspan) > 0 else 1
            if table["cells"] + span <= MAX_TABLE_CELLS:
                table["rows"][-1].extend([_dark_cell(values)] * span)
                table["cells"] += span
        elif tag == "meta" and "refresh" in values.get("http-equiv", "").lower():
            match = re.search(r"url\s*=\s*([^;\s]+)", values.get("content", ""), re.I)
            if match:
                found.redirects.append(match.group(1).strip("'\" "))
        for key in self.RESOURCE_ATTRS:
            if values.get(key):
                found.resources.append(values[key].strip())
        if tag not in ("script", "style"):
            self._push(tag, values)
        self._tag_since_visible = True
        if tag in _BLOCK_TAGS:
            self._line_break()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        tag = tag.lower()
        if tag == "a" and self._anchor_depth:
            self._anchor_depth -= 1
        if tag not in _VOID_TAGS:
            self._pop(tag)  # <span/> opens and closes at once

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        closing_visible_block = tag in _BLOCK_TAGS and not self._in_hidden
        self._pop(tag)
        self._tag_since_visible = True
        if closing_visible_block:
            self._line_break()
        if tag == "a" and self._anchor_depth:
            self._anchor_depth -= 1
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False
        elif tag == "form":
            self._form = None
        elif tag == "table" and self._tables:
            self._close_table()

    def _close_table(self) -> None:
        rows = [row for row in self._tables.pop()["rows"] if row]
        if len(rows) >= 21 and min(len(row) for row in rows) >= 21 and any(any(row) for row in rows):
            self.findings.cell_grids.append(rows)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.findings.script_text += data + "\n"
            return
        if self._in_style:
            if len(self._hidden_classes) < 500:
                for name, body in _STYLE_CLASS_RULE_RE.findall(data[:200_000]):
                    if hides_text(body):
                        self._hidden_classes.add(name.lower())
            return
        self._text.append(data)
        if self._in_hidden:
            if self._hidden_size < MAX_HIDDEN_TEXT:
                self._hidden.append(data[:MAX_HIDDEN_TEXT - self._hidden_size])
                self._hidden_size += len(data)
            if any(ch.isalnum() for ch in data):
                self._hidden_since_visible = True
        elif data.strip() or not self._hidden_since_visible:
            if self._last_visible_alnum and data[:1].isalnum():
                if self._hidden_since_visible:
                    self.findings.hidden_splits += 1
                elif self._tag_since_visible:
                    self.findings.tag_splits += 1
            self._hidden_since_visible = self._tag_since_visible = False
            self._visible.append(data)
            self._last_visible_alnum = data[-1:].isalnum()
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
    while parser._tables:  # noqa: SLF001 - a table left open is still drawn
        parser._close_table()  # noqa: SLF001
    found = parser.findings
    found.text = " ".join(parser._text)  # noqa: SLF001
    found.hidden_text = " ".join(" ".join(parser._hidden).split())  # noqa: SLF001
    found.visible_text = " ".join("".join(parser._visible).split())  # noqa: SLF001
    found.anchors = [(href, " ".join(text.split())) for href, text in found.anchors if href]
    for pattern in _JS_REDIRECT_RES:
        found.redirects.extend(match.group(1) for match in pattern.finditer(found.script_text))
    return found


# ---------------------------------------------------------------------------
# PDF (best effort: uncompressed link annotations only)
# ---------------------------------------------------------------------------

_PDF_URI_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){4,2048})\)")
_PDF_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{8,4096})>")
PDF_MAX_STREAMS = 300


def pdf_streams(data: bytes, limit: int = PDF_MAX_STREAMS):
    """(offset, raw bytes) of each stream, found with plain searches: a
    regular expression that looks for 'endstream' after every 'stream' goes
    quadratic on a file full of the one and missing the other."""
    position = 0
    for _ in range(limit):
        start = data.find(b"stream", position)
        if start < 0:
            return
        body = start + 6
        if data[body:body + 2] == b"\r\n":
            body += 2
        elif data[body:body + 1] in (b"\n", b"\r"):
            body += 1
        else:  # "endstream", or "stream" inside a word
            position = body
            continue
        end = data.find(b"endstream", body)
        if end < 0:
            return
        content = data[body:end]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        elif content.endswith((b"\n", b"\r")):
            content = content[:-1]
        yield start, content
        position = end + 9
PDF_MAX_INFLATED = 20 * 1024 * 1024  # total, across all streams


def _pdf_uris(blob: bytes, found: list[str]) -> None:
    for match in _PDF_URI_RE.finditer(blob):
        raw = re.sub(r"\\([()\\])", r"\1", match.group(1).decode("latin-1"))
        _keep(clean_url(raw), found)
    for match in _PDF_URI_HEX_RE.finditer(blob):
        try:
            decoded = bytes.fromhex(match.group(1).decode("ascii").replace(" ", "").replace("\n", ""))
        except ValueError:
            continue
        _keep(clean_url(decoded.decode("latin-1")), found)


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
    for _, stream in pdf_streams(data):
        if budget <= 0:
            break
        try:
            inflated = zlib.decompressobj().decompress(stream, budget)
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
    if head.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")):
        return "onenote"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"\x78\x9f\x3e\x22"):
        return "tnef"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF\x00\x00\x00\x00"):
        return "cab"
    if head.startswith(b"vhdxfile") or head.startswith(b"conectix") or (data or b"")[-512:-504] == b"conectix":
        return "vhd"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"BM") and len(data) >= 26 and int.from_bytes(head[2:6], "little") == len(data):
        return "bmp"
    if len(data or b"") > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and (head[54:59] in (b"FAT12", b"FAT16")
                                                               or head[82:87] == b"FAT32"):
        return "fatimg"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    lowered = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if lowered.startswith((b"<!doctype html", b"<html", b"<script", b"<head", b"<body")) \
            or b"<form" in lowered or b"<script" in lowered:
        return "html"
    if lowered.startswith(b"<svg") or (lowered.startswith(b"<?xml") and b"<svg" in lowered):
        return "svg"
    if lowered.startswith(b"begin:vcalendar"):
        return "calendar"
    return ""


TYPE_DESCRIPTIONS = {
    "pe": "a Windows executable", "elf": "a Linux executable", "zip": "a ZIP archive",
    "pdf": "a PDF", "rar": "a RAR archive", "7z": "a 7-Zip archive", "ole": "an OLE/legacy Office file",
    "png": "a PNG image", "jpeg": "a JPEG image", "gif": "a GIF image", "iso": "an ISO disk image",
    "html": "an HTML document", "svg": "an SVG image", "webp": "a WebP image", "bmp": "a BMP image",
    "lnk": "a Windows shortcut", "onenote": "a OneNote section", "rtf": "an RTF document",
    "tnef": "an Outlook winmail.dat", "gzip": "a gzip file", "cab": "a Windows cabinet archive",
    "vhd": "a virtual hard disk", "fatimg": "a FAT disk image", "tar": "a tar archive",
    "calendar": "a calendar invitation",
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
    ".one": {"onenote"}, ".lnk": {"lnk"}, ".img": {"fatimg", "iso"}, ".vhd": {"vhd"}, ".vhdx": {"vhd"},
    ".rtf": {"rtf"}, ".gz": {"gzip"}, ".tgz": {"gzip"}, ".tar": {"tar"}, ".cab": {"cab"}, ".dat": {"tnef"},
    ".ics": {"calendar"}, ".msi": {"ole"}, ".xlsb": {"zip"}, ".pptm": {"zip"}, ".dotm": {"zip"},
}
DANGEROUS_TYPES = {"pe", "elf", "html", "iso", "zip", "rar", "7z", "svg", "lnk", "onenote", "fatimg", "vhd", "ole",
                   "cab"}
