"""Windows shortcut (.lnk) files: what they run and with which arguments.

Since Office stopped running macros from the internet, a shortcut inside a
ZIP or ISO that starts PowerShell or mshta has been the usual first stage.
The target and command line are read from the Shell Link structure
(MS-SHLLINK); nothing is resolved or executed.
"""

from __future__ import annotations

import re
import struct
from typing import Any

HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
MAX_STRING = 32_768

# Programs a shortcut in an email has no business starting.
LAUNCHERS = ("powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
             "certutil", "bitsadmin", "msiexec", "curl", "wget", "wmic", "forfiles", "conhost", "schtasks",
             "hh.exe", "explorer.exe", "msbuild", "installutil", "cmstp", "odbcconf", "pcalua", "scriptrunner",
             "finger", "ftp.exe", "expand", "extrac32", "bash.exe", "python")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'`<>|^)]{4,500}", re.I)


def is_lnk(data: bytes) -> bool:
    return data[:20] == HEADER


def _string(data: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    size = count * (2 if unicode else 1)
    raw = data[offset:offset + min(size, MAX_STRING)]
    text = raw.decode("utf-16-le" if unicode else "cp1252", errors="replace")
    return text, offset + size


def _cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset, offset + 1024)
    return data[offset:end if end >= 0 else offset + 1024].decode("cp1252", errors="replace")


def _wstring(data: bytes, start: int, end: int) -> str:
    """A NUL-terminated UTF-16 string, read two bytes at a time."""
    chars = bytearray()
    for position in range(start, min(end, start + 2048) - 1, 2):
        pair = data[position:position + 2]
        if pair == b"\x00\x00":
            break
        chars += pair
    return chars.decode("utf-16-le", errors="replace")


def parse_lnk(data: bytes) -> dict[str, Any]:
    """target, arguments, working_dir, icon, name, relative_path, minimized.
    Raises ValueError for anything that is not a readable shortcut."""
    if not is_lnk(data) or len(data) < 0x4C:
        raise ValueError("not a shortcut")
    try:
        return _parse(data)
    except struct.error as exc:
        raise ValueError("truncated shortcut") from exc


def _parse(data: bytes) -> dict[str, Any]:
    flags = struct.unpack_from("<I", data, 0x14)[0]
    show = struct.unpack_from("<I", data, 0x3C)[0]
    unicode = bool(flags & 0x80)
    out: dict[str, Any] = {"minimized": show in (2, 7), "target": ""}
    offset = 0x4C
    if flags & 0x01:  # LinkTargetIDList
        offset += 2 + struct.unpack_from("<H", data, offset)[0]
    if flags & 0x02:  # LinkInfo: the local base path of the target
        size, header_size, info_flags, _, base_offset = struct.unpack_from("<IIIII", data, offset)
        if info_flags & 0x01 and 0 < base_offset < size:
            out["target"] = _cstring(data, offset + base_offset)
        if header_size >= 0x24 and info_flags & 0x01:
            unicode_offset = struct.unpack_from("<I", data, offset + 0x1C)[0]
            if 0 < unicode_offset < size:
                out["target"] = _wstring(data, offset + unicode_offset, offset + size) or out["target"]
        offset += size
    for bit, key in ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"),
                     (0x40, "icon")):
        if flags & bit:
            out[key], offset = _string(data, offset, unicode)
    # ExtraData: the environment-variable form of the target ("%windir%\system32\cmd.exe")
    for _ in range(64):
        if offset + 8 > len(data):
            break
        block_size, signature = struct.unpack_from("<II", data, offset)
        if block_size < 8:
            break
        if signature == 0xA0000001 and block_size >= 0x314:
            target = data[offset + 8 + 260:offset + 8 + 260 + 520].decode("utf-16-le", errors="replace")
            target = target.split("\x00", 1)[0] or _cstring(data, offset + 8)
            out.setdefault("environment_target", target)
            if not out["target"]:
                out["target"] = target
        offset += block_size
    arguments = out.get("arguments", "").replace("\x00", "")
    # Whitespace in front of the command pushes it out of the Properties box.
    out["padding"] = len(arguments) - len(arguments.lstrip())
    for key in list(out):
        if isinstance(out[key], str):
            out[key] = out[key].replace("\x00", "").strip()[:MAX_STRING]
    return out


def suspicious(details: dict[str, Any]) -> list[str]:
    """Reasons this shortcut is dangerous, most telling first."""
    command = " ".join(str(details.get(k, "")) for k in ("target", "environment_target", "relative_path",
                                                       "arguments")).lower()
    reasons = []
    launchers = [name for name in LAUNCHERS if name in command]
    if launchers:
        reasons.append("starts %s" % ", ".join(launchers[:3]))
    arguments = details.get("arguments", "")
    if re.search(r"(?:^|\s)-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", arguments, re.I):
        reasons.append("runs an encoded PowerShell command")
    if _URL_RE.search(arguments):
        reasons.append("downloads from the internet")
    if len(arguments) > 400 or details.get("padding", 0) >= 40 or re.search(r"\s{40,}", arguments):
        reasons.append("hides a long command line")
    if details.get("minimized") and arguments:
        reasons.append("opens minimised")
    return reasons


def urls(details: dict[str, Any]) -> list[str]:
    return _URL_RE.findall(" ".join(str(details.get(k, "")) for k in ("arguments", "icon", "working_dir")))
