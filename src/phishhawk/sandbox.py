"""Sandbox handoff: everything a sandbox needs to detonate a reported message,
in one password-protected ZIP.

PhishHawk never runs anything. With --sandbox DIR it writes, per message,
DIR/<message SHA-256>.zip holding the message as it was read, every file
pulled out of it (archive members included, so a payload behind a password
PhishHawk guessed arrives unpacked), the links worth detonating and a
manifest. Every member is encrypted with the password "infected", the
convention sandboxes, malware repositories and mail filters share, so the
pack is not quarantined or opened by accident on the way. ZipCrypto is weak
encryption, and that is not its job here: the pack holds the message, so
keep it where your evidence goes.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
import struct
import zlib
from typing import TYPE_CHECKING, Any

from . import __version__
from .evidence import OLE_MAGIC

if TYPE_CHECKING:
    from .models import Analysis, FileIoc

PASSWORD = b"infected"
MAX_PACK = 50 * 1024 * 1024  # file bytes per pack; encryption here is pure Python
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


class SandboxError(Exception):
    pass


def _crc_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_TABLE = _crc_table()


def _encrypt(data: bytes, check: int) -> bytes:
    """Traditional PKWARE encryption (APPNOTE 6.1): a 12-byte header whose
    last byte is the CRC's high byte, then the data."""
    t = _TABLE
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in PASSWORD:
        k0 = t[(k0 ^ c) & 0xFF] ^ (k0 >> 8)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = t[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
    plain = os.urandom(11) + bytes([check]) + data
    out = bytearray(len(plain))
    for i, p in enumerate(plain):
        key = (k2 | 2) & 0xFFFF
        out[i] = p ^ (((key * (key ^ 1)) >> 8) & 0xFF)
        k0 = t[(k0 ^ p) & 0xFF] ^ (k0 >> 8)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = t[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
    return bytes(out)


def _dos_time(moment: dt.datetime) -> tuple[int, int]:
    return ((moment.hour << 11) | (moment.minute << 5) | (moment.second // 2),
            ((moment.year - 1980) << 9) | (moment.month << 5) | moment.day)


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    """An encrypted, deflated ZIP of (name, data) pairs; names are ASCII and safe."""
    when, day = _dos_time(dt.datetime.now())
    body, directory = bytearray(), bytearray()
    for name, data in members:
        raw = name.encode("ascii")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        squeezer = zlib.compressobj(6, zlib.DEFLATED, -15)
        sealed = _encrypt(squeezer.compress(data) + squeezer.flush(), crc >> 24)
        fields = (20, 0x0001, 8, when, day, crc, len(sealed), len(data), len(raw))
        directory += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, *fields, 0, 0, 0, 0, 0, len(body)) + raw
        body += struct.pack("<IHHHHHIIIHH", 0x04034B50, *fields, 0) + raw + sealed
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(directory), len(body), 0)
    return bytes(body + directory + end)


def _safe_name(name: str) -> str:
    base = re.split(r"[\\/]", name or "")[-1]
    base = _UNSAFE_RE.sub("_", base).strip("._") or "file"
    return base[-80:]


def _files(analysis: Analysis) -> list[tuple[FileIoc, bytes]]:
    kept = analysis.__dict__.get("_files")
    return list(kept) if isinstance(kept, list) else []


def _urls(analysis: Analysis) -> list[str]:
    return [ioc.url for ioc in analysis.urls if not analysis.is_trusted_domain(ioc.host)][:500]


def pack(directory: str, data: bytes, analysis: Analysis) -> str:
    """Write DIR/<sha256>.zip for one analysed message; returns its path."""
    from .evidence import fingerprint  # noqa: PLC0415 - shared with the evidence log

    prints = fingerprint(data)
    members: list[tuple[str, bytes]] = [("message.msg" if data.startswith(OLE_MAGIC) else "message.eml", data)]
    entries, not_packed, seen, total = [], [], set(), 0
    for ioc, content in _files(analysis):
        if ioc.inline or not ioc.sha256 or ioc.sha256 in seen:
            continue
        seen.add(ioc.sha256)
        entry: dict[str, Any] = {"filename": ioc.filename, "sha256": ioc.sha256, "md5": ioc.md5, "size": ioc.size,
                                 "true_type": ioc.true_type, "parent": ioc.parent, "flagged": ioc.flagged,
                                 "notes": ioc.notes[:10]}
        if total + len(content) > MAX_PACK:
            not_packed.append(dict(entry, reason="past the pack's size cap of %d MB" % (MAX_PACK // 2 ** 20)))
            continue
        total += len(content)
        entry["packed_as"] = "files/%s-%s" % (ioc.sha256[:16], _safe_name(ioc.filename))
        members.append((entry["packed_as"], content))
        entries.append(entry)
    urls = _urls(analysis)
    members.append(("urls.txt", ("# Links to detonate. NOT defanged: for sandbox submission only.\n"
                                 + "".join(url + "\n" for url in urls)).encode("utf-8")))
    manifest = {"tool": "PhishHawk %s" % __version__, "password": PASSWORD.decode(),
                "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "message": dict(prints, file=members[0][0], subject=analysis.subject, sender=analysis.from_address,
                                verdict=analysis.verdict, score=analysis.score),
                "files": entries, "not_packed": not_packed, "urls": len(urls)}
    members.append(("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, prints["sha256"] + ".zip")
    try:
        # Non-blocking: a FIFO planted under this name fails at once instead of hanging the run.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | _NOFOLLOW | _BINARY | getattr(os, "O_NONBLOCK", 0), 0o600)
    except OSError as exc:
        raise SandboxError("%s cannot be written safely (%s)" % (path, exc.strerror or exc)) from exc
    with os.fdopen(fd, "wb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise SandboxError("%s is not a regular file" % path)
        if hasattr(os, "fchmod"):
            os.fchmod(handle.fileno(), 0o600)  # also when an older pack was there
        handle.truncate(0)
        handle.write(_zip(members))
    return path
