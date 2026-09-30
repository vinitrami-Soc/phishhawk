"""What an attached document would do when opened: Office macros, remote
templates, DDE and embedded objects; PDF scripts, launch actions and
embedded files; RTF exploit objects; files embedded in OneNote pages.

Each reader returns findings and any embedded files it could recover. XML
is searched with bounded regular expressions, never handed to an XML
parser, so entity-expansion and external-entity tricks have nothing to
work with.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Any

from ..extract import pdf_streams
from .cfb import CfbError, CompoundFile

MAX_PART = 8 * 1024 * 1024
MAX_OOXML_READ = 64 * 1024 * 1024  # inflated bytes read from one document, all parts together
MAX_EMBEDDED = 20
MAX_EMBEDDED_BYTES = 25 * 1024 * 1024


@dataclass
class DocFindings:
    kind: str
    features: list[str] = field(default_factory=list)  # short machine-readable tags
    urls: list[str] = field(default_factory=list)
    remote: list[str] = field(default_factory=list)  # remote templates, OLE links, frames
    embedded: list[tuple[str, bytes]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def add(self, feature: str, note: str = "") -> None:
        if feature not in self.features:
            self.features.append(feature)
            if note:
                self.notes.append(note)


# -------------------------------------------------------------------- OOXML --

_REL_RE = re.compile(r"<Relationship\b([^>]{0,4000})>", re.I)
_ATTR_RE = re.compile(r'(?<![A-Za-z:])([A-Za-z:]+)\s*=\s*"([^"]{0,4000})"')  # anchored: linear, not quadratic
_DDE_RE = re.compile(r"\b(DDEAUTO|DDE)\b\s", re.I)
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]{4,2000}", re.I)


class _Parts:
    """Reads the parts of one document against a shared budget: a zip can
    list thousands of names that all point at the same compressed bomb."""

    def __init__(self, archive: zipfile.ZipFile) -> None:
        self.archive, self.left = archive, MAX_OOXML_READ

    def read(self, name: str) -> bytes:
        info = self.archive.getinfo(name)
        if info.file_size > MAX_PART or info.flag_bits & 0x1 or self.left <= 0:
            return b""
        with self.archive.open(info) as handle:
            data = handle.read(min(MAX_PART, self.left))
        self.left -= max(len(data), 4096)  # every open costs something, however small the part
        return data


def inspect_ooxml(data: bytes) -> DocFindings:
    """Word, Excel and PowerPoint files (.docx .docm .xlsx .xlsm .pptx ...)."""
    found = DocFindings("office")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        names = archive.namelist()
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        found.add("corrupt", "corrupt Office container")
        return found
    parts = _Parts(archive)
    lowered = [n.lower() for n in names]
    if "encryptioninfo" in lowered or "encryptedpackage" in lowered:
        found.add("encrypted", "password-protected Office document")
    if any(n.endswith("vbaproject.bin") for n in lowered):
        found.add("vba-macro", "contains a VBA macro project")
    if any(n.startswith("xl/macrosheets/") for n in lowered):
        found.add("xlm-macro", "contains Excel 4.0 (XLM) macro sheets")
    if any("/activex/" in n for n in lowered):
        found.add("activex", "contains ActiveX controls")
    for name, low in zip(names, lowered, strict=True):
        if low.endswith(".rels"):
            try:
                text = parts.read(name).decode("utf-8", errors="replace")
            except (KeyError, zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError, zlib.error):
                continue
            for match in _REL_RE.finditer(text):
                attrs = {k.lower(): v for k, v in _ATTR_RE.findall(match.group(1))}
                if attrs.get("targetmode", "").lower() != "external":
                    continue
                target = attrs.get("target", "").strip()
                kind = attrs.get("type", "").rsplit("/", 1)[-1].lower()
                if not target:
                    continue
                scheme = target.split(":", 1)[0].lower()
                if scheme in ("mhtml", "ms-msdt", "search-ms", "ms-officecmd", "ms-word", "ms-excel", "file") \
                        or "!x-usc:" in target.lower():
                    found.add("protocol-handler", "external link through the %s: handler (the Follina "
                                                  "family of exploits)" % scheme)
                    found.remote.append(target)
                elif kind in ("attachedtemplate", "oleobject", "frame", "subdocument"):
                    found.add("remote-" + kind, "loads a remote %s when opened: %s" % (kind, target[:120]))
                    found.remote.append(target)
                if target.lower().startswith(("http://", "https://", "ftp://")):
                    found.urls.append(target)
        elif low.endswith((".xml", ".vml")) and ("document" in low or "sheet" in low or "slide" in low
                                                  or "header" in low or "footer" in low):
            try:
                text = parts.read(name).decode("utf-8", errors="replace")
            except (KeyError, zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError, zlib.error):
                continue
            instructions = " ".join(re.findall(r"<w:instrText[^>]{0,200}>([^<]{0,2000})<", text)) + " " + \
                " ".join(re.findall(r'w:instr="([^"]{0,2000})"', text))
            if _DDE_RE.search(instructions):
                found.add("dde", "a DDE field runs a command when the document opens")
        elif "/embeddings/" in low and len(found.embedded) < MAX_EMBEDDED:
            try:
                blob = parts.read(name)
            except (KeyError, zipfile.BadZipFile, OSError, RuntimeError, ValueError, EOFError, zlib.error):
                continue
            if blob:
                found.add("embedded-object", "carries embedded objects")
                found.embedded.append((name.rsplit("/", 1)[-1], blob))
    found.urls = list(dict.fromkeys(found.urls))[:200]
    return found


# ------------------------------------------------------------ legacy Office --

def inspect_ole(data: bytes) -> DocFindings:
    """.doc, .xls, .ppt: VBA and Excel 4.0 macros, embedded packages, encryption."""
    found = DocFindings("office")
    try:
        cfb = CompoundFile(data)
    except (CfbError, struct.error, ValueError):
        found.add("corrupt", "corrupt OLE container")
        return found
    paths = [(e, "/".join(e.path).lower()) for e in cfb.streams()]
    if any(p.endswith("vba/dir") or p.endswith("_vba_project") or "/vba/" in p for _, p in paths):
        found.add("vba-macro", "contains a VBA macro project")
    if any(p in ("encryptedpackage", "encryptioninfo") for _, p in paths):
        found.add("encrypted", "password-protected Office document")
    for entry, path in paths:
        try:
            if path.endswith("\x01ole10native") and len(found.embedded) < MAX_EMBEDDED:
                name, blob = _ole10native(cfb.read(entry))
                if blob:
                    found.add("embedded-package", "carries an embedded file (%s)" % name)
                    found.embedded.append((name, blob))
            if path in ("workbook", "book") and _xlm_macro_sheets(cfb.read(entry)):
                found.add("xlm-macro", "contains Excel 4.0 (XLM) macro sheets")
        except CfbError:  # a stream running off the file, or past the read budget
            found.add("corrupt", "damaged OLE stream")
    return found


def _ole10native(blob: bytes) -> tuple[str, bytes]:
    """The file inside an OLE Package object: size, flags, label, path,
    then the data."""
    try:
        position = 6
        label_end = blob.index(b"\x00", position)
        label = blob[position:label_end].decode("cp1252", errors="replace")
        path_end = blob.index(b"\x00", label_end + 1)
        position = path_end + 1 + 4  # reserved
        temp_len = struct.unpack_from("<I", blob, position)[0]
        position += 4 + temp_len
        size = struct.unpack_from("<I", blob, position)[0]
        position += 4
        return label or "package", blob[position:position + min(size, MAX_EMBEDDED_BYTES)]
    except (ValueError, struct.error):
        return "package", b""


def _xlm_macro_sheets(workbook: bytes) -> bool:
    """A BIFF8 BOUNDSHEET record whose sheet type is 'macro'."""
    offset = 0
    for _ in range(500_000):
        if offset + 4 > len(workbook):
            return False
        record, length = struct.unpack_from("<HH", workbook, offset)
        if record == 0x0085 and length >= 6 and workbook[offset + 4 + 5] == 0x01:
            return True
        offset += 4 + length
    return False


# --------------------------------------------------------------------- PDF --

_PDF_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
PDF_KEYS = {
    b"/JavaScript": "javascript", b"/JS": "javascript", b"/OpenAction": "open-action", b"/AA": "auto-action",
    b"/Launch": "launch", b"/EmbeddedFile": "embedded-file", b"/SubmitForm": "submit-form", b"/XFA": "xfa",
    b"/RichMedia": "rich-media", b"/Encrypt": "encrypted", b"/GoToR": "remote-goto", b"/ImportData": "import-data",
}
_PDF_KEY_RE = re.compile(rb"/(?:JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|SubmitForm|XFA|RichMedia|Encrypt|"
                         rb"GoToR|ImportData)(?![A-Za-z])")
PDF_MAX_INFLATED = 20 * 1024 * 1024


def inspect_pdf(data: bytes) -> DocFindings:
    """Actions and scripts in a PDF, in the file and inside compressed object
    streams; embedded files are recovered for the attachment checks."""
    found = DocFindings("pdf")
    budget = PDF_MAX_INFLATED
    blobs = [data]
    for start, stream in pdf_streams(data, 500):
        if budget <= 0:
            break
        head = data[max(0, start - 400):start]
        try:
            inflated = zlib.decompressobj().decompress(stream, budget)
        except zlib.error:
            inflated = b""
        budget -= len(inflated)
        if b"/EmbeddedFile" in _PDF_NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), head) \
                and len(found.embedded) < MAX_EMBEDDED:
            content = inflated or stream
            if content:
                found.embedded.append(("embedded-%d" % (len(found.embedded) + 1), content[:MAX_EMBEDDED_BYTES]))
        if inflated:
            blobs.append(inflated)
    names = re.compile(rb"/(?:F|UF)\s*\(([^)]{1,200})\)")
    embedded_names = []
    for blob in blobs:
        plain = _PDF_NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), blob)
        for key in set(_PDF_KEY_RE.findall(plain)):
            feature = PDF_KEYS.get(key)
            if feature:
                found.add(feature)
        if b"/EmbeddedFile" in plain or b"/Filespec" in plain:
            embedded_names += [n.decode("latin-1", errors="replace") for n in names.findall(plain)[:20]]
        for match in re.finditer(rb"/Launch.{0,300}?/F\s*\(([^)]{1,300})\)", plain, re.S):
            found.remote.append(match.group(1).decode("latin-1", errors="replace"))
    for index, name in enumerate(dict.fromkeys(embedded_names)):
        if index < len(found.embedded):
            found.embedded[index] = (name.strip() or found.embedded[index][0], found.embedded[index][1])
    return found


# --------------------------------------------------------------------- RTF --

# OLE classes exploited through RTF: the Equation Editor (CVE-2017-11882,
# CVE-2018-0802), Package objects that carry a file, and HTML/OLE links.
_RTF_EXPLOIT_CLASSES = {"equation.3": "Equation Editor object (CVE-2017-11882 family)",
                        "equation": "Equation Editor object (CVE-2017-11882 family)",
                        "package": "embedded Package object (carries a file)",
                        "htmlfile": "HTML file object (CVE-2017-0199 family)",
                        "word.document.8": "embedded Word document", "forms.": "ActiveX form control",
                        "otkloadr.wrassembly": "OTKLoadr object (ASLR bypass)"}


def inspect_rtf(data: bytes) -> DocFindings:
    found = DocFindings("rtf")
    text = data[:MAX_PART * 2]
    if re.search(rb"\\objdata", text):
        found.add("ole-object", "carries embedded OLE objects")
    if re.search(rb"\\objupdate", text):
        found.add("auto-update", "OLE object set to update itself on opening (\\objupdate)")
    for match in re.finditer(rb"\\objclass\s*([^\\}{]{1,80})", text):
        name = match.group(1).decode("latin-1", errors="replace").strip().lower()
        for key, note in _RTF_EXPLOIT_CLASSES.items():
            if name.startswith(key):
                found.add("class-" + key.rstrip("."), note)
    hexed = b"".join(re.findall(rb"\\objdata\s*([0-9A-Fa-f\s]{0,200000})", text))
    decoded = b""
    if hexed:
        digits = re.sub(rb"\s", b"", hexed)
        try:
            decoded = bytes.fromhex(digits[: len(digits) // 2 * 2].decode("ascii"))
        except ValueError:
            decoded = b""
    lowered = decoded.lower()
    if b"equation.3" in lowered or b"\x02\xce\x02\x00" in decoded:
        found.add("class-equation.3", _RTF_EXPLOIT_CLASSES["equation.3"])
    if b"package" in lowered and b"\x00" in decoded:
        found.add("class-package", _RTF_EXPLOIT_CLASSES["package"])
    for match in re.finditer(rb"\\\*\\template\s*([^}]{4,1000})", text):
        target = match.group(1).decode("latin-1", errors="replace").strip()
        found.add("remote-template", "loads a remote template: %s" % target[:120])
        found.remote.append(target)
    for match in re.finditer(rb'HYPERLINK\s+"([^"]{4,2000})"', text):
        found.urls.append(match.group(1).decode("latin-1", errors="replace"))
    for url in _URL_RE.findall(text.decode("latin-1", errors="replace")):
        found.urls.append(url.rstrip("\\}"))
    found.urls = list(dict.fromkeys(found.urls))[:200]
    return found


# ---------------------------------------------------------------- OneNote --

ONENOTE_SIGNATURE = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
_FILE_DATA_GUID = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")


def is_onenote(data: bytes) -> bool:
    return data[:16] == ONENOTE_SIGNATURE


def inspect_onenote(data: bytes) -> DocFindings:
    """Files embedded in a OneNote section (FileDataStoreObject blocks):
    the 2023 wave hid .hta, .cmd and .js files under a fake 'double-click
    to view' button."""
    found = DocFindings("onenote")
    offset = 0
    while len(found.embedded) < MAX_EMBEDDED:
        offset = data.find(_FILE_DATA_GUID, offset)
        if offset < 0 or offset + 36 > len(data):
            break
        size = struct.unpack_from("<Q", data, offset + 16)[0]
        start = offset + 36
        if 0 < size <= min(MAX_EMBEDDED_BYTES, len(data) - start):
            found.embedded.append(("embedded-%d" % (len(found.embedded) + 1), data[start:start + size]))
            found.add("embedded-file", "carries embedded files")
            offset = start + size
        else:
            offset += 16
    return found
