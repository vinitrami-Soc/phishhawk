"""Builders for the file formats phish deliver, so every reader is tested on
files made here rather than on real malware."""

from __future__ import annotations

import binascii
import io
import struct
import zipfile
import zlib

# ------------------------------------------------------------ Windows shortcut --

ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def lnk(target: str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        arguments: str = "-w hidden -enc " + ENCODED,
        icon: str = "C:\\Windows\\System32\\shell32.dll", minimized: bool = True) -> bytes:
    flags = 0x08 | 0x20 | 0x40 | 0x80  # relative path, arguments, icon, unicode
    header = struct.pack("<I16sII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20)
    header += b"\0" * 24 + struct.pack("<IiIH", 0, 0, 7 if minimized else 1, 0) + b"\0" * 10

    def string(value: str) -> bytes:
        return struct.pack("<H", len(value)) + value.encode("utf-16-le")

    return header + string(target) + string(arguments) + string(icon) + struct.pack("<I", 0)


# ------------------------------------------------------------------ ISO 9660 --

def iso(files: dict[str, bytes]) -> bytes:
    """An ISO 9660 image with one root directory holding `files`."""
    block = 2048

    def record(name: bytes, extent: int, size: int, directory: bool) -> bytes:
        body = struct.pack("<BI", 0, extent) + struct.pack(">I", extent) + struct.pack("<I", size) \
            + struct.pack(">I", size) + b"\0" * 7 + bytes([2 if directory else 0, 0, 0]) \
            + struct.pack("<H", 1) + struct.pack(">H", 1) + bytes([len(name)]) + name
        if (len(body) + 1) % 2:  # records have an even length
            body += b"\0"
        return bytes([len(body) + 1]) + body

    root_extent = 18
    data_extent = 19
    entries = [record(b"\0", root_extent, block, True), record(b"\1", root_extent, block, True)]
    contents = b""
    for name, data in files.items():
        extent = data_extent + len(contents) // block
        entries.append(record(name.upper().encode() + b";1", extent, len(data), False))
        contents += data.ljust(-(-len(data) // block) * block or block, b"\0")
    directory = b"".join(entries).ljust(block, b"\0")
    pvd = bytearray(block)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[156:156 + 34] = record(b"\0", root_extent, block, True)[:34]
    terminator = bytearray(block)
    terminator[0], terminator[1:6], terminator[6] = 255, b"CD001", 1
    return b"\0" * (16 * block) + bytes(pvd) + bytes(terminator) + directory + contents


# ------------------------------------------------------------------ FAT12 image --

def fat12(files: dict[str, bytes]) -> bytes:
    """A 1.44 MB floppy image with `files` (8.3 names) in the root directory."""
    sector, total = 512, 2880
    boot = bytearray(sector)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHI", boot, 11, sector, 1, 1, 2, 224, total, 0xF0, 9, 18, 2, 0)
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    fat = bytearray(9 * sector)
    fat[0:3] = b"\xf0\xff\xff"
    root = bytearray(224 * 32)
    data_area = bytearray()
    cluster = 2

    def set_fat(index: int, value: int) -> None:
        offset = index + index // 2
        current = struct.unpack_from("<H", fat, offset)[0]
        if index & 1:
            current = (current & 0x000F) | (value << 4)
        else:
            current = (current & 0xF000) | value
        struct.pack_into("<H", fat, offset, current)

    for slot, (name, data) in enumerate(files.items()):
        stem, _, ext = name.upper().partition(".")
        count = max(1, -(-len(data) // sector))
        for k in range(count):
            set_fat(cluster + k, cluster + k + 1 if k < count - 1 else 0xFFF)
        entry = stem[:8].ljust(8).encode() + ext[:3].ljust(3).encode() + b"\x20" + b"\0" * 14
        entry += struct.pack("<HI", cluster, len(data))
        root[slot * 32:slot * 32 + 32] = entry
        data_area += data.ljust(count * sector, b"\0")
        cluster += count
    image = bytes(boot) + bytes(fat) + bytes(fat) + bytes(root) + bytes(data_area)
    return image.ljust(total * sector, b"\0")


# ----------------------------------------------------------------------- RAR5 --

def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def rar5(names: list[str], encrypted_headers: bool = False) -> bytes:
    """A RAR5 archive's headers: stored empty files named `names`."""
    def block(kind: int, body: bytes, flags: int = 0) -> bytes:
        header = _vint(kind) + _vint(flags) + body
        size = _vint(len(header))
        return struct.pack("<I", binascii.crc32(size + header)) + size + header

    out = b"Rar!\x1a\x07\x01\x00" + block(1, _vint(0))
    if encrypted_headers:
        return out + block(4, _vint(0) + _vint(0) + _vint(15) + b"\0" * 16 + b"\0" * 16)
    for name in names:
        encoded = name.encode()
        body = _vint(0) + _vint(0) + _vint(0x20) + _vint(0) + _vint(0) + _vint(len(encoded)) + encoded
        out += block(2, body)
    return out + block(5, _vint(0))


# ----------------------------------------------------------------------- 7-Zip --

def seven_zip(names: list[str]) -> bytes:
    """A 7z archive with a plain (unencoded) header listing empty files."""
    def number(value: int) -> bytes:
        assert value < 0x80
        return bytes([value])

    names_blob = b"\0" + b"".join(n.encode("utf-16-le") + b"\0\0" for n in names)
    empty = bytes([0xFF]) * (-(-len(names) // 8))
    header = b"\x01" + b"\x05" + number(len(names))
    header += b"\x0e" + number(len(empty)) + empty  # every file is an empty stream
    header += b"\x11" + number(len(names_blob)) if len(names_blob) < 0x80 else b""
    if len(names_blob) >= 0x80:
        size = len(names_blob)
        header += b"\x11" + bytes([0x80 | (size >> 8), size & 0xFF])
    header += names_blob + b"\x00" + b"\x00"
    start = struct.pack("<QQI", 0, len(header), binascii.crc32(header))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", binascii.crc32(start)) + start + header


# ------------------------------------------------------------- encrypted ZIP --

class _ZipCrypto:
    def __init__(self, password: bytes) -> None:
        self.keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            self._update(byte)

    def _crc(self, crc: int, byte: int) -> int:
        return (binascii.crc32(bytes([byte]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF

    def _update(self, byte: int) -> None:
        self.keys[0] = self._crc(self.keys[0], byte)
        self.keys[1] = (self.keys[1] + (self.keys[0] & 0xFF)) & 0xFFFFFFFF
        self.keys[1] = (self.keys[1] * 134775813 + 1) & 0xFFFFFFFF
        self.keys[2] = self._crc(self.keys[2], self.keys[1] >> 24)

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            temp = (self.keys[2] | 2) & 0xFFFF
            out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            self._update(byte)
        return bytes(out)


def encrypted_zip(files: dict[str, bytes], password: str) -> bytes:
    """A traditional (ZipCrypto) password-protected ZIP, stored."""
    out, central = io.BytesIO(), b""
    for name, data in files.items():
        crc = binascii.crc32(data) & 0xFFFFFFFF
        cipher = _ZipCrypto(password.encode())
        body = cipher.encrypt(b"\0" * 11 + bytes([crc >> 24])) + cipher.encrypt(data)
        offset = out.tell()
        encoded = name.encode()
        local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0, crc, len(body), len(data), len(encoded), 0)
        out.write(local + encoded + body)
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0, crc, len(body), len(data),
                               len(encoded), 0, 0, 0, 0, 0, offset) + encoded
    start = out.tell()
    out.write(central + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), start, 0))
    return out.getvalue()


def plain_zip(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


# ----------------------------------------------------------- TNEF, RTF, PDF --

def tnef(attachments: dict[str, bytes], body: str = "") -> bytes:
    def attribute(level: int, attr: int, data: bytes) -> bytes:
        return struct.pack("<BII", level, attr, len(data)) + data + struct.pack("<H", sum(data) & 0xFFFF)

    out = b"\x78\x9f\x3e\x22" + b"\x01\x00"
    if body:
        out += attribute(1, 0x0001800C, body.encode("cp1252") + b"\0")
    for name, data in attachments.items():
        out += attribute(2, 0x00069002, b"\0" * 14)
        out += attribute(2, 0x00018010, name.encode("cp1252") + b"\0")
        out += attribute(2, 0x0006800F, data)
    return out


def lzfu(rtf: bytes) -> bytes:
    """PR_RTF_COMPRESSED holding `rtf` as literals only (valid LZFu)."""
    body = bytearray()
    for start in range(0, len(rtf), 8):
        chunk = rtf[start:start + 8]
        body.append(0)
        body += chunk
    body += bytes([0x01]) + struct.pack(">H", (207 + len(rtf)) % 4096 << 4)  # end marker: offset == write position
    return struct.pack("<II4sI", len(body) + 12, len(rtf), b"LZFu", 0) + bytes(body)


def pdf(objects: list[bytes]) -> bytes:
    out = b"%PDF-1.7\n"
    for number, body in enumerate(objects, 1):
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    return out + b"trailer << /Root 1 0 R >>\n%%EOF\n"


def pdf_stream(dictionary: bytes, data: bytes, compress: bool = True) -> bytes:
    payload = zlib.compress(data) if compress else data
    filters = b" /Filter /FlateDecode" if compress else b""
    return b"<< " + dictionary + filters + b" /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream"
