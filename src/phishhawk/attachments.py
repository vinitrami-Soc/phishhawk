"""Attachment inspection: every file is typed by its bytes, opened in memory
by the reader for its format, and whatever it carries (archive members,
disk-image files, embedded documents, the attachments inside winmail.dat)
is inspected in turn, a few levels deep.

Nothing is written to disk or executed. Each reader is capped, and the
whole message has a budget of files and bytes, so a zip bomb, a million
tiny members or a self-including archive ends the walk, not the analysis.
"""

from __future__ import annotations

import hashlib
import io
import mimetypes
import os
import re
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from typing import Any

from .extract import defang_text, sniff_type, urls_from_pdf, urls_from_text
from .formats import archives, disk, documents, lnk, mailparts
from .formats.cfb import SIGNATURE as OLE_SIGNATURE
from .models import Analysis, FileIoc

MAX_NEST = 3  # levels below an attachment: zip -> iso -> lnk
MAX_FILES = 400  # files per message, all levels together
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 200
MAX_MEMBER_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 100 * 1024 * 1024
MAX_GUNZIP = 50 * 1024 * 1024
OOXML_EXTENSIONS = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam", ".pptx",
                    ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".sldx"}
HTML_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml"}
IMAGE_TYPES = {"png", "jpeg", "gif", "bmp", "webp"}

# "Password: 1234", "the archive password is Inv2291", "Senha: 7788"
_PASSWORD_RE = re.compile(
    r"(?i)\b(?:password|passcode|passwd|pwd|pw|pin|senha|contrase(?:ñ|n)a|clave|passwort|kennwort|"
    r"mot de passe|wachtwoord|parola|has(?:ł|l)o|пароль)\b"
    r"(?:\s+(?:for|to open|of)\s+(?:the\s+)?(?:file|archive|attachment|document|zip|pdf|it))?"
    r"(?:\s+(?:is|es|ist|est|é|è|:))?\s*[:=\-–—]?\s*[\"'“«]?([^\s\"'”»<>]{3,32})")


def password_candidates(text: str) -> list[str]:
    """Passwords a message hands out for its own attachment."""
    found: list[str] = []
    for match in _PASSWORD_RE.finditer(text[:50_000]):
        candidate = match.group(1).strip(".,;:!?)]}")
        if len(candidate) >= 3 and candidate.lower() not in ("the", "for", "and", "reset", "expired", "expires",
                                                                "below", "above", "protected", "required") \
                and candidate not in found:
            found.append(candidate)
        if len(found) >= 6:
            break
    return found


def file_ioc(filename: str, content_type: str, data: bytes, parent: str = "") -> FileIoc:
    return FileIoc(
        filename=" ".join(str(filename).split()) or "(unnamed)",
        content_type=content_type or "application/octet-stream",
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        true_type=sniff_type(data),
        parent=parent,
    )


class Inspector:
    """Walks one message's attachments. `add_url(url, source)` records a
    link; `scan` decodes QR codes; `inspect_html(ioc, data)` handles HTML."""

    def __init__(self, analysis: Analysis, add_url: Callable[[str, str], None], scan: Any,
                 inspect_html: Callable[[FileIoc, bytes], None], passwords: list[str],
                 file_hook: Callable[[Analysis, FileIoc, bytes], None] | None = None) -> None:
        self.analysis, self.add_url, self.scan = analysis, add_url, scan
        self.file_hook = file_hook
        self.inspect_html = inspect_html
        self.passwords = passwords
        self.files = 0
        self.bytes = 0
        self.extra_text: list[str] = []  # body text found inside winmail.dat

    # ------------------------------------------------------------ plumbing --
    def attach(self, name: str, content_type: str, data: bytes, parent: FileIoc | None = None,
               depth: int = 0, inline: bool = False) -> FileIoc | None:
        if self.files >= MAX_FILES or self.bytes + len(data) > MAX_TOTAL_BYTES:
            if parent is not None and "file budget for this message reached" not in parent.notes:
                parent.notes.append("file budget for this message reached: the rest was not opened")
            return None
        ioc = file_ioc(name, content_type, data, parent=parent.filename if parent else "")
        ioc.inline = inline
        self.analysis.attachments.append(ioc)
        self.files += 1
        self.bytes += len(data)
        try:
            if self.file_hook is not None:
                self.file_hook(self.analysis, ioc, data)
            self.inspect(ioc, data, depth)
        except Exception as exc:  # one hostile file must not end the analysis
            ioc.notes.append("could not be fully inspected (%s)" % type(exc).__name__)
        return ioc

    def child(self, parent: FileIoc, name: str, data: bytes, depth: int) -> FileIoc | None:
        if depth >= MAX_NEST:
            if "nested too deep to open further" not in parent.notes:
                parent.notes.append("nested too deep to open further")
            return None
        guessed = mimetypes.guess_type(name)[0] or "application/octet-stream"
        return self.attach(name, guessed, data, parent=parent, depth=depth + 1)

    def _url(self, url: str, ioc: FileIoc, what: str = "") -> None:
        self.add_url(url, "attachment:%s%s" % (ioc.filename, " " + what if what else ""))

    # ------------------------------------------------------------ dispatch --
    def inspect(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        extension = os.path.splitext(ioc.filename.lower())[1]
        kind = ioc.true_type
        if kind == "zip" and extension in OOXML_EXTENSIONS:
            self._office(ioc, documents.inspect_ooxml(data), depth)
        elif kind == "zip":
            self._zip(ioc, data, depth)
        elif kind == "ole":
            self._ole(ioc, data, depth)
        elif kind == "rtf":
            self._office(ioc, documents.inspect_rtf(data), depth)
        elif kind == "pdf":
            for url in urls_from_pdf(data):
                self._url(url, ioc)
            self.scan.pdf(data, ioc.filename, ioc)
            self._office(ioc, documents.inspect_pdf(data), depth)
        elif kind == "onenote":
            self._office(ioc, documents.inspect_onenote(data), depth)
        elif kind == "lnk":
            self._lnk(ioc, data)
        elif kind == "iso":
            self._disk(ioc, "ISO disk image", lambda: disk.list_iso(data), depth)
        elif kind == "fatimg":
            self._disk(ioc, "FAT disk image", lambda: disk.list_fat(data), depth)
        elif kind == "vhd":
            ioc.details["container"] = {"kind": "virtual hard disk"}
            ioc.notes.append("virtual hard disk: mounts with a double-click, contents not listed")
            ioc.flagged = True
        elif kind in ("rar", "7z"):
            self._listing(ioc, data, kind)
        elif kind == "gzip":
            self._gzip(ioc, data, depth)
        elif kind == "tar":
            self._tar(ioc, data, depth)
        elif kind == "tnef":
            self._tnef(ioc, data, depth)
        elif kind == "calendar" or extension == ".ics":
            self.calendar(data.decode("utf-8", errors="replace"), ioc.filename)
        if kind in ("html", "svg") or extension in HTML_EXTENSIONS:
            self.inspect_html(ioc, data)
        if kind in IMAGE_TYPES:
            self.scan.image(data, ioc.filename, ioc)
        if ioc.content_type == "message/rfc822" or extension in (".eml", ".msg"):
            ioc.notes.append("attached email message")

    # -------------------------------------------------------------- readers --
    def _office(self, ioc: FileIoc, found: documents.DocFindings, depth: int) -> None:
        ioc.details[found.kind] = {"features": found.features, "remote": found.remote[:20]}
        for note in found.notes:
            note = defang_text(note)
            if note not in ioc.notes:
                ioc.notes.append(note)
        if found.features and set(found.features) - {"corrupt", "encrypted", "xfa", "rich-media"}:
            ioc.flagged = True
        for url in found.urls:
            self._url(url, ioc, found.kind)
        for target in found.remote:
            if target.lower().startswith(("http://", "https://", "ftp://")):
                self._url(target, ioc, "remote template")
        for name, blob in found.embedded:
            self.child(ioc, name, blob, depth)

    def _ole(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        try:
            from .formats.cfb import CompoundFile  # noqa: PLC0415

            is_message = CompoundFile(data).find("__properties_version1.0") is not None
        except Exception:
            is_message = False
        if is_message:
            ioc.notes.append("Outlook message (.msg)")
            return
        self._office(ioc, documents.inspect_ole(data), depth)

    def _lnk(self, ioc: FileIoc, data: bytes) -> None:
        try:
            details = lnk.parse_lnk(data)
        except ValueError:
            ioc.notes.append("corrupt shortcut")
            return
        reasons = lnk.suspicious(details)
        shown = {key: str(details.get(key, ""))[:300]
                 for key in ("target", "relative_path", "arguments", "working_dir", "icon")}
        ioc.details["lnk"] = dict(shown, reasons=reasons, minimized=details.get("minimized", False))
        command = ((shown["target"] or shown["relative_path"]) + " " + shown["arguments"]).strip()
        if command:
            ioc.notes.append("runs: %s" % defang_text(command[:200]))
        for reason in reasons:
            ioc.notes.append("shortcut %s" % reason)
        ioc.flagged = True
        for url in lnk.urls(details):
            self._url(url, ioc, "shortcut")

    def _summary(self, ioc: FileIoc, kind: str, names: list[str], encrypted: bool = False,
                 truncated: bool = False, names_hidden: bool = False) -> dict[str, Any]:
        summary: dict[str, Any] = {"kind": kind, "members": len(names), "encrypted": encrypted,
                                   "listing": names[:MAX_ARCHIVE_MEMBERS], "truncated": truncated,
                                   "names_hidden": names_hidden, "skipped": 0}
        ioc.archive = summary
        return summary

    def _disk(self, ioc: FileIoc, kind: str, lister: Callable[[], list[disk.DiskFile]], depth: int) -> None:
        try:
            files = lister()
        except (ValueError, struct.error, IndexError) as exc:
            ioc.notes.append("unreadable %s (%s)" % (kind, str(exc)[:60]))
            return
        summary = self._summary(ioc, kind, [f.name for f in files], truncated=len(files) >= disk.MAX_FILES)
        ioc.details["container"] = {"kind": kind, "files": len(files)}
        ioc.flagged = True
        for item in files:
            if item.data is None:
                summary["skipped"] += 1
                continue
            self.child(ioc, item.name, item.data, depth)

    def _listing(self, ioc: FileIoc, data: bytes, kind: str) -> None:
        try:
            listing = archives.list_rar(data) if kind == "rar" else archives.list_7z(data)
        except (ValueError, struct.error, IndexError) as exc:
            ioc.notes.append("unreadable %s archive (%s)" % (kind.upper(), str(exc)[:60]))
            return
        summary = self._summary(ioc, "%s archive" % kind.upper(), listing.names, listing.encrypted,
                                listing.truncated, listing.names_hidden)
        summary["skipped"] = len(listing.names)  # listed from the headers, not extracted
        if listing.encrypted and self.passwords:
            summary["password_in_body"] = self.passwords[0]

    def _zip(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            infos = [info for info in archive.infolist() if not info.is_dir()]
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
            ioc.notes.append("corrupt or unreadable archive")
            return
        encrypted = any(info.flag_bits & 0x1 for info in infos)
        summary = self._summary(ioc, "ZIP archive", [info.filename for info in infos], encrypted,
                                len(infos) > MAX_ARCHIVE_MEMBERS)
        password = self._zip_password(archive, infos) if encrypted else None
        if password is not None:
            summary["password_in_body"] = password
            summary["opened_with_password"] = True
            ioc.notes.append("opened with the password given in the message ('%s')" % password[:32])
        elif encrypted and self.passwords:
            summary["password_in_body"] = self.passwords[0]
        total = 0
        for info in infos[:MAX_ARCHIVE_MEMBERS]:
            locked = bool(info.flag_bits & 0x1)
            if (locked and password is None) or info.file_size > MAX_MEMBER_BYTES \
                    or total + info.file_size > MAX_ARCHIVE_TOTAL:
                summary["skipped"] += 1
                continue
            try:
                # ZipExtFile stops at the declared size, so a lying header
                # cannot inflate this beyond MAX_MEMBER_BYTES.
                content = archive.read(info, pwd=password.encode() if locked and password else None)
            except Exception:
                summary["skipped"] += 1
                continue
            total += len(content)
            self.child(ioc, info.filename, content, depth)

    def _zip_password(self, archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo]) -> str | None:
        locked = next((info for info in infos if info.flag_bits & 0x1 and info.compress_type != 99
                       and info.file_size <= MAX_MEMBER_BYTES), None)
        if locked is None:
            return None
        for candidate in self.passwords:
            try:
                archive.read(locked, pwd=candidate.encode())
                return candidate
            except Exception:  # wrong password: RuntimeError, bad CRC or zlib error
                continue
        return None

    def _gzip(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        try:
            content = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_GUNZIP)
        except zlib.error:
            ioc.notes.append("corrupt gzip file")
            return
        name = ioc.filename[:-3] if ioc.filename.lower().endswith(".gz") else ioc.filename + ".out"
        if ioc.filename.lower().endswith(".tgz"):
            name = ioc.filename[:-4] + ".tar"
        self._summary(ioc, "gzip file", [name])
        self.child(ioc, name, content, depth)

    def _tar(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        members: list[tuple[str, bytes | None]] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                total = 0
                for member in archive:
                    if not member.isfile():
                        continue
                    content = None
                    if member.size <= MAX_MEMBER_BYTES and total + member.size <= MAX_ARCHIVE_TOTAL:
                        handle = archive.extractfile(member)
                        content = handle.read(MAX_MEMBER_BYTES) if handle else b""
                        total += len(content)
                    members.append((member.name, content))
                    if len(members) > MAX_ARCHIVE_MEMBERS:
                        break
        except (tarfile.TarError, OSError, ValueError, EOFError):
            if not members:
                ioc.notes.append("corrupt tar archive")
                return
        summary = self._summary(ioc, "tar archive", [name for name, _ in members],
                                truncated=len(members) > MAX_ARCHIVE_MEMBERS)
        for name, content in members[:MAX_ARCHIVE_MEMBERS]:
            if content is None:
                summary["skipped"] += 1
                continue
            self.child(ioc, name, content, depth)

    def _tnef(self, ioc: FileIoc, data: bytes, depth: int) -> None:
        try:
            parsed = mailparts.parse_tnef(data)
        except (ValueError, struct.error):
            ioc.notes.append("corrupt winmail.dat")
            return
        self._summary(ioc, "Outlook winmail.dat", [name for name, _ in parsed.attachments])
        ioc.notes.append("Outlook rich-text wrapper (TNEF): %d hidden attachment(s)" % len(parsed.attachments))
        if parsed.body:
            self.extra_text.append(parsed.body)
            for url in urls_from_text(parsed.body):
                self._url(url, ioc, "body")
        for name, blob in parsed.attachments:
            self.child(ioc, name, blob, depth)

    def calendar(self, text: str, where: str) -> None:
        invite = mailparts.parse_calendar(text)
        entry = {"where": where, "organizer": invite.organizer, "summary": invite.summary,
                 "method": invite.method, "links": len(invite.urls)}
        if len(self.analysis.calendar) < 10:
            self.analysis.calendar.append(entry)
        for url in invite.urls:
            self.add_url(url, "calendar invite (%s)" % where)


def is_ole(data: bytes) -> bool:
    return data[:8] == OLE_SIGNATURE
