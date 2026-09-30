"""Outlook .msg files as ordinary email messages.

Outlook saves and forwards mail as .msg (a compound file of MAPI
properties), and users report phish that way. The message is rebuilt as
the .eml it was sent as: the original transport headers when Outlook kept
them (so SPF, DKIM and DMARC results survive), the plain, HTML or RTF
body, and every attachment, including attached messages, which are
rebuilt the same way.
"""

from __future__ import annotations

import email
import email.header
import email.parser
import email.policy
import email.utils
import re
import struct
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage, Message

from ..mailpolicy import POLICY
from .cfb import SIGNATURE, CfbError, CompoundFile, Entry

MAX_DEPTH = 3
MAX_ATTACHMENTS = 200
_CONTENT_HEADERS = {"content-type", "content-transfer-encoding", "mime-version", "content-disposition"}

# Property IDs (MS-OXPROPS)
TRANSPORT_HEADERS, SUBJECT, BODY, HTML, RTF = 0x007D, 0x0037, 0x1000, 0x1013, 0x1009
SENDER_NAME, SENDER_EMAIL, SENDER_SMTP, SENDER_TYPE = 0x0C1A, 0x0C1F, 0x5D01, 0x0C1E
REPRESENTING_NAME, REPRESENTING_EMAIL, REPRESENTING_SMTP = 0x0042, 0x0065, 0x5D02
MESSAGE_ID, SUBMIT_TIME, CODEPAGE, INTERNET_CODEPAGE = 0x1035, 0x0039, 0x3FFD, 0x3FDE
RECIPIENT_NAME, RECIPIENT_EMAIL, RECIPIENT_SMTP, RECIPIENT_TYPE = 0x3001, 0x3003, 0x39FE, 0x0C15
ATTACH_DATA, ATTACH_NAME, ATTACH_LONG_NAME, ATTACH_MIME, ATTACH_METHOD = 0x3701, 0x3704, 0x3707, 0x370E, 0x3705
ATTACH_CONTENT_ID, DISPLAY_NAME = 0x3712, 0x3001
DELIVERY_TIME, CREATION_TIME = 0x0E06, 0x3007


class MsgError(ValueError):
    pass


def is_msg(data: bytes) -> bool:
    return data[:8] == SIGNATURE


class _Properties:
    """The MAPI properties of one message, recipient or attachment storage."""

    def __init__(self, cfb: CompoundFile, prefix: tuple[str, ...], header_size: int) -> None:
        self.cfb, self.prefix = cfb, prefix
        self.fixed: dict[int, bytes] = {}
        raw = cfb.read_path(*prefix, "__properties_version1.0") or b""
        for offset in range(header_size, len(raw) - 15, 16):
            tag = struct.unpack_from("<I", raw, offset)[0]
            self.fixed[tag >> 16] = raw[offset + 8:offset + 16]
        self.streams: dict[int, tuple[str, Entry]] = {}
        for entry in cfb.children(*prefix):
            if entry.name.startswith("__substg1.0_"):
                code = entry.name[12:20]
                try:
                    self.streams.setdefault(int(code[:4], 16), (code[4:].upper(), entry))
                except ValueError:
                    continue

    def long(self, prop: int) -> int | None:
        value = self.fixed.get(prop)
        return struct.unpack_from("<i", value)[0] if value else None

    def time(self, prop: int) -> datetime | None:
        value = self.fixed.get(prop)
        if not value:
            return None
        ticks = struct.unpack_from("<Q", value)[0]
        try:
            return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
        except OverflowError:
            return None

    def raw(self, prop: int) -> bytes | None:
        found = self.streams.get(prop)
        if not found or not found[1].is_stream:
            return None
        return self.cfb.read(found[1])

    def text(self, prop: int, codepage: str = "cp1252") -> str:
        found = self.streams.get(prop)
        if not found or not found[1].is_stream:
            return ""
        kind, entry = found
        data = self.cfb.read(entry)
        if kind == "001F":
            return data.decode("utf-16-le", errors="replace").rstrip("\x00")
        return _decode(data, codepage).rstrip("\x00")

    def storage(self, prop: int) -> tuple[str, ...] | None:
        found = self.streams.get(prop)
        if found and found[1].is_storage:
            return found[1].path
        name = "__substg1.0_%04X000D" % prop
        for entry in self.cfb.children(*self.prefix):
            if entry.is_storage and entry.name.upper() == name:
                return entry.path
        return None


def _decode(data: bytes, codepage: str) -> str:
    try:
        return data.decode(codepage, errors="replace")
    except (LookupError, ValueError):
        return data.decode("cp1252", errors="replace")


def _codepage(number: int | None, default: str) -> str:
    if not number:
        return default
    return {65001: "utf-8", 1200: "utf-16-le", 20127: "ascii", 28591: "latin-1"}.get(number, "cp%d" % number)


# ---------------------------------------------------------------- RTF body --

_LZFU_DICTIONARY = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript "
    b"\\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par "
    b"\\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)
MAX_RTF = 20 * 1024 * 1024


def decompress_rtf(data: bytes) -> bytes:
    """PR_RTF_COMPRESSED (MS-OXRTFCP): LZFu, or MELA for stored RTF."""
    if len(data) < 16:
        raise MsgError("RTF header too short")
    raw_size, kind = struct.unpack_from("<I4s", data, 4)
    body = data[16:]
    if kind == b"MELA":
        return body[: min(raw_size, MAX_RTF)]
    if kind != b"LZFu":
        raise MsgError("unknown RTF compression")
    window = bytearray(4096)
    window[: len(_LZFU_DICTIONARY)] = _LZFU_DICTIONARY
    write = len(_LZFU_DICTIONARY)
    out = bytearray()
    limit = min(raw_size, MAX_RTF)
    i = 0
    while i < len(body) and len(out) < limit:
        control = body[i]
        i += 1
        for bit in range(8):
            if i >= len(body) or len(out) >= limit:
                break
            if control & (1 << bit):
                if i + 1 >= len(body):
                    return bytes(out)
                word = (body[i] << 8) | body[i + 1]
                i += 2
                offset, length = word >> 4, (word & 0xF) + 2
                if offset == write:
                    return bytes(out)
                for step in range(length):
                    byte = window[(offset + step) % 4096]
                    out.append(byte)
                    window[write] = byte
                    write = (write + 1) % 4096
            else:
                byte = body[i]
                i += 1
                out.append(byte)
                window[write] = byte
                write = (write + 1) % 4096
    return bytes(out)


_RTF_TOKEN_RE = re.compile(rb"\\'([0-9a-fA-F]{2})|\\u(-?\d{1,6})\??|\\([a-zA-Z]{1,32})(-?\d{1,10})? ?"
                           rb"|\\([^a-zA-Z])|([{}])|([^\\{}]+)")
_SKIP_DESTINATIONS = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"object", b"themedata",
                      b"datastore", b"latentstyles", b"listtable", b"listoverridetable", b"rsidtbl",
                      b"generator", b"xmlnstbl", b"mmathPr", b"filetbl", b"revtbl"}


_KEEP_DESTINATIONS = {b"htmltag", b"mhtmltag", b"fldinst"}


def rtf_to_text(rtf: bytes, limit: int = 2_000_000) -> tuple[str, bool]:
    """(text, is_html) from RTF. Outlook wraps HTML mail in RTF (\\fromhtml1);
    the HTML is recovered from the \\htmltag groups, else the plain text."""
    is_html = b"\\fromhtml" in rtf[:2000]
    out: list[str] = []
    size = 0
    stack: list[tuple[bool, bool]] = []
    skip, html_only = False, False  # inside an ignored group; inside \htmlrtf (RTF-only text)
    pending_star = False
    for match in _RTF_TOKEN_RE.finditer(rtf[: MAX_RTF]):
        hex_byte, unicode_value, word, number, symbol, brace, text = match.groups()
        if brace == b"{":
            stack.append((skip, html_only))
            pending_star = False
            continue
        if brace == b"}":
            if stack:
                skip, html_only = stack.pop()
            continue
        if word is not None:
            name = word
            if pending_star and name not in _KEEP_DESTINATIONS:
                skip = True  # {\*\generator ...} and the like; links and HTML are kept
            pending_star = False
            if name in _SKIP_DESTINATIONS:
                skip = True
            elif name == b"htmlrtf":
                html_only = number != b"0"
            elif name in (b"par", b"line", b"row") and not skip and not html_only:
                out.append("\n")
            elif name == b"tab" and not skip and not html_only:
                out.append("\t")
            continue
        if symbol is not None:
            if symbol == b"*":
                pending_star = True
            elif not skip and not html_only and symbol in (b"\\", b"{", b"}"):
                out.append(symbol.decode())
            continue
        if skip or html_only:
            continue
        if hex_byte is not None:
            out.append(bytes([int(hex_byte, 16)]).decode("cp1252", errors="replace"))
        elif unicode_value is not None:
            value = int(unicode_value)
            out.append(chr(value % 65536) if 0 < value % 65536 < 0xD800 or value % 65536 > 0xDFFF else "")
        elif text is not None:
            out.append(text.replace(b"\r", b"").replace(b"\n", b"").decode("cp1252", errors="replace"))
        size += len(out[-1]) if out else 0
        if size > limit:
            break
    return "".join(out), is_html


# ----------------------------------------------------------------- builder --

def _smtp(*candidates: str) -> str:
    for value in candidates:
        if value and "@" in value and not value.upper().startswith("/O="):
            return value.strip()
    return ""


def _filetime_header(when: datetime | None) -> str:
    return email.utils.format_datetime(when) if when else ""


def _unfold(headers: str) -> str:
    return headers.replace("\r\n", "\n").strip("\n\x00")


def _build(cfb: CompoundFile, prefix: tuple[str, ...], depth: int, embedded: bool) -> bytes:
    props = _Properties(cfb, prefix, 24 if embedded else 32)
    codepage = _codepage(props.long(CODEPAGE), "cp1252")
    internet_codepage = _codepage(props.long(INTERNET_CODEPAGE), "utf-8")

    body = EmailMessage(policy=email.policy.SMTP)
    plain = props.text(BODY, codepage)
    html_raw = props.raw(HTML)
    if html_raw is not None and HTML in props.streams and props.streams[HTML][0] == "001F":
        html = html_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    elif html_raw is not None:
        html = _decode(html_raw, internet_codepage).rstrip("\x00")
    else:
        html = ""
    if not html and not plain:
        compressed = props.raw(RTF)
        if compressed:
            try:
                text, is_html = rtf_to_text(decompress_rtf(compressed))
            except (MsgError, struct.error):
                text, is_html = "", False
            if is_html:
                html = text
            else:
                plain = text
    body.set_content(plain or "")
    if html:
        body.add_alternative(html, subtype="html")

    attachments = sorted((e for e in cfb.children(*prefix) if e.kind == 1
                          and e.name.lower().startswith("__attach_version1.0_")), key=lambda e: e.name)
    for entry in attachments[:MAX_ATTACHMENTS]:
        try:
            attach = _Properties(cfb, entry.path, 8)
            name = attach.text(ATTACH_LONG_NAME, codepage) or attach.text(ATTACH_NAME, codepage) \
                or attach.text(DISPLAY_NAME, codepage) or "attachment"
        except CfbError:  # past the reader's budget: the rest of the message still counts
            continue
        name = " ".join(name.replace("\x00", "").split())[:255] or "attachment"
        inner = attach.storage(ATTACH_DATA)
        if inner is not None and depth < MAX_DEPTH:
            try:
                data = _build(cfb, inner, depth + 1, embedded=True)
            except (CfbError, MsgError, struct.error, ValueError):
                continue
            part = email.message_from_bytes(data, policy=POLICY)
            body.add_attachment(part, filename=name if name.lower().endswith((".msg", ".eml")) else name + ".msg")
            continue
        try:
            blob = attach.raw(ATTACH_DATA)
        except CfbError:
            blob = b""  # unreadable, but its name is still evidence
        if blob is None:
            continue
        mime = attach.text(ATTACH_MIME, codepage).strip().lower()
        maintype, _, subtype = mime.partition("/")
        token = r"[a-z0-9.+-]{1,64}"
        if not re.fullmatch(token, maintype or "") or not re.fullmatch(token, subtype):
            maintype, subtype = "application", "octet-stream"
        if maintype == "text":  # set_content wants str for text/*; keep the bytes as they are
            maintype, subtype = "application", "octet-stream"
        cid = attach.text(ATTACH_CONTENT_ID, codepage).strip("<> \x00")
        body.add_attachment(blob, maintype=maintype, subtype=subtype, filename=name,
                            disposition="inline" if cid and maintype == "image" else "attachment")

    headers = _unfold(props.text(TRANSPORT_HEADERS, codepage))
    if headers:
        kept = email.parser.Parser(policy=email.policy.compat32).parsestr(headers + "\n\n", headersonly=True)
        lines = ["%s: %s" % (name, " ".join(str(value).split())) for name, value in kept.items()
                 if name.lower() not in _CONTENT_HEADERS]
    else:
        lines = _synthetic_headers(cfb, prefix, props, codepage)
    content = body.as_bytes()
    head_end = content.find(b"\r\n\r\n")
    body_head = content[:head_end].decode("ascii", errors="replace").split("\r\n") if head_end >= 0 else []
    body_head = [line for line in body_head if line]
    return ("\r\n".join(lines + body_head) + "\r\n\r\n").encode("utf-8", errors="replace") + content[head_end + 4:]


def _synthetic_headers(cfb: CompoundFile, prefix: tuple[str, ...], props: _Properties, codepage: str) -> list[str]:
    """Headers from MAPI properties when Outlook did not keep the originals
    (drafts, and messages Outlook composed itself)."""
    lines = []
    sender = _smtp(props.text(SENDER_SMTP, codepage), props.text(SENDER_EMAIL, codepage),
                   props.text(REPRESENTING_SMTP, codepage), props.text(REPRESENTING_EMAIL, codepage))
    name = props.text(SENDER_NAME, codepage) or props.text(REPRESENTING_NAME, codepage)
    if sender or name:
        lines.append("From: %s" % email.utils.formataddr((" ".join(name.split()), sender)))
    groups: dict[int, list[str]] = {1: [], 2: []}
    recipients = sorted((e for e in cfb.children(*prefix) if e.kind == 1
                         and e.name.lower().startswith("__recip_version1.0_")), key=lambda e: e.name)
    for entry in recipients[:500]:
        recipient = _Properties(cfb, entry.path, 8)
        address = _smtp(recipient.text(RECIPIENT_SMTP, codepage), recipient.text(RECIPIENT_EMAIL, codepage))
        display = " ".join(recipient.text(RECIPIENT_NAME, codepage).split())
        kind = recipient.long(RECIPIENT_TYPE) or 1
        if kind in groups and (address or display):
            groups[kind].append(email.utils.formataddr((display, address)))
    if groups[1]:
        lines.append("To: %s" % ", ".join(groups[1]))
    if groups[2]:
        lines.append("Cc: %s" % ", ".join(groups[2]))
    subject = " ".join(props.text(SUBJECT, codepage).split())
    if subject:
        lines.append("Subject: %s" % email.header.Header(subject, "utf-8").encode()
                     if not subject.isascii() else "Subject: %s" % subject)
    when = _filetime_header(props.time(SUBMIT_TIME) or props.time(DELIVERY_TIME) or props.time(CREATION_TIME))
    if when:
        lines.append("Date: %s" % when)
    message_id = props.text(MESSAGE_ID, codepage).strip()
    if message_id:
        lines.append("Message-ID: %s" % " ".join(message_id.split()))
    return [line.replace("\r", " ").replace("\n", " ") for line in lines]


def msg_to_bytes(data: bytes) -> bytes:
    """The .msg as the bytes of an equivalent .eml."""
    try:
        cfb = CompoundFile(data)
        if cfb.find("__properties_version1.0") is None:
            raise MsgError("a compound file, but not an Outlook message")
        return _build(cfb, (), 0, embedded=False)
    except (CfbError, struct.error) as exc:
        raise MsgError(str(exc)) from exc


def msg_to_message(data: bytes) -> Message:
    return email.message_from_bytes(msg_to_bytes(data), policy=POLICY)
