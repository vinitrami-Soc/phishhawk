"""Two containers mail clients make: Outlook's winmail.dat (TNEF), which
hides the real attachments and body from anything that does not decode it,
and calendar invitations (iCalendar), whose links reach the calendar even
when the message itself is filtered."""

from __future__ import annotations

import contextlib
import re
import struct
from dataclasses import dataclass, field

from .msg import MsgError, decompress_rtf, rtf_to_text

TNEF_SIGNATURE = b"\x78\x9f\x3e\x22"
MAX_TNEF_ATTACHMENTS = 100
MAX_TNEF_BYTES = 50 * 1024 * 1024


@dataclass
class Tnef:
    attachments: list[tuple[str, bytes]] = field(default_factory=list)
    body: str = ""


def is_tnef(data: bytes) -> bool:
    return data[:4] == TNEF_SIGNATURE


def parse_tnef(data: bytes) -> Tnef:
    """Attachments (title and data) and the body of a winmail.dat."""
    if not is_tnef(data):
        raise ValueError("not a TNEF stream")
    out = Tnef()
    offset = 6
    current: dict[str, object] | None = None
    while offset + 9 <= len(data) and len(out.attachments) < MAX_TNEF_ATTACHMENTS:
        level, attribute, length = struct.unpack_from("<BII", data, offset)
        offset += 9
        if length > len(data) - offset:
            break
        value = data[offset:offset + length]
        offset += length + 2  # the checksum
        if level not in (1, 2):
            break
        if attribute == 0x00069002:  # attAttachRendData: a new attachment starts
            if current and current.get("data") is not None:
                out.attachments.append((str(current.get("name") or "attachment"), current["data"]))  # type: ignore[arg-type]
            current = {}
        elif attribute == 0x00018010 and current is not None:  # attAttachTitle
            current["name"] = value.split(b"\x00", 1)[0].decode("cp1252", errors="replace").strip()
        elif attribute == 0x0006800F and current is not None:  # attAttachData
            current["data"] = value[:MAX_TNEF_BYTES]
        elif attribute == 0x0001800C and not out.body:  # attBody
            out.body = value.split(b"\x00", 1)[0].decode("cp1252", errors="replace")
        elif attribute == 0x00069003 and not out.body:  # attMsgProps: the RTF body lives here
            start = value.find(b"LZFu")
            if start >= 8:
                with contextlib.suppress(MsgError, struct.error):
                    out.body = rtf_to_text(decompress_rtf(value[start - 8:]))[0]
    if current and current.get("data") is not None:
        out.attachments.append((str(current.get("name") or "attachment"), current["data"]))  # type: ignore[arg-type]
    return out


# --------------------------------------------------------------- iCalendar --

_ESCAPES = {"\\n": "\n", "\\N": "\n", "\\,": ",", "\\;": ";", "\\\\": "\\"}
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]{4,2000}", re.I)
MAX_CALENDAR = 2 * 1024 * 1024


@dataclass
class Invite:
    organizer: str = ""
    summary: str = ""
    method: str = ""
    urls: list[str] = field(default_factory=list)
    attendees: int = 0


def is_calendar(data: bytes) -> bool:
    return data.lstrip(b"\xef\xbb\xbf \r\n\t")[:15].upper() == b"BEGIN:VCALENDAR"


def parse_calendar(text: str) -> Invite:
    """The organiser, summary and every link in an invitation."""
    text = re.sub(r"\r?\n[ \t]", "", text[:MAX_CALENDAR])  # unfold continuation lines
    invite = Invite()
    for line in text.splitlines():
        name, _, value = line.partition(":")
        if not _:
            continue
        key = name.split(";", 1)[0].strip().upper()
        value = re.sub(r"\\[nN,;\\]", lambda m: _ESCAPES[m.group(0)], value)
        if key == "ORGANIZER":
            invite.organizer = value.split("mailto:", 1)[-1].split("MAILTO:", 1)[-1].strip()[:200]
        elif key == "ATTENDEE":
            invite.attendees += 1
        elif key == "SUMMARY" and not invite.summary:
            invite.summary = " ".join(value.split())[:200]
        elif key == "METHOD":
            invite.method = value.strip().upper()[:20]
        if key in ("DESCRIPTION", "X-ALT-DESC", "LOCATION", "URL", "ATTACH", "SUMMARY", "COMMENT", "CONFERENCE",
                   "X-MICROSOFT-SKYPETEAMSMEETINGURL", "X-GOOGLE-CONFERENCE"):
            for url in _URL_RE.findall(value):
                if url not in invite.urls and len(invite.urls) < 200:
                    invite.urls.append(url.rstrip(".,;)>"))
    return invite
