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


# ------------------------------------------------------ virtual hard disks --

def mbr_disk(volumes: list[tuple[int, bytes]], start: int = 2048) -> bytes:
    """A raw disk with an MBR: (partition type, volume bytes) from sector `start`."""
    table, body, lba = bytearray(), bytearray(start * 512), start
    for kind, volume in volumes:
        sectors = -(-len(volume) // 512)
        table += bytes([0, 0, 0, 0, kind, 0, 0, 0]) + struct.pack("<II", lba, sectors)
        body += volume.ljust(sectors * 512, b"\0")
        lba += sectors
    body[446:446 + len(table)] = table
    body[510:512] = b"\x55\xaa"
    return bytes(body)


def _vhd_footer(size: int, kind: int, data_offset: int) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">IIQ", footer, 8, 2, 0x10000, data_offset)
    footer[28:32] = b"qem2"
    struct.pack_into(">QQ", footer, 40, size, size)
    struct.pack_into(">I", footer, 60, kind)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


def vhd_fixed(disk: bytes) -> bytes:
    """A fixed VHD: the disk, then a 512-byte footer."""
    return disk + _vhd_footer(len(disk), 2, 0xFFFFFFFFFFFFFFFF)


def vhd_dynamic(disk: bytes, block_size: int = 2 * 1024 * 1024) -> bytes:
    """A dynamic VHD: footer copy, sparse header, block table, then only the
    blocks that hold something, each after its sector bitmap."""
    size = -(-len(disk) // block_size) * block_size
    entries = size // block_size
    table_at = 512 + 1024
    table_size = -(-entries * 4 // 512) * 512
    header = bytearray(1024)
    header[0:8] = b"cxsparse"
    struct.pack_into(">QQIII", header, 8, 0xFFFFFFFFFFFFFFFF, table_at, 0x10000, entries, block_size)
    bitmap = -(-block_size // 512 // 8 // 512) * 512
    table, blocks = bytearray(b"\xff" * table_size), bytearray()
    at = table_at + table_size
    for index in range(entries):
        block = disk[index * block_size:(index + 1) * block_size]
        if block.strip(b"\0"):
            struct.pack_into(">I", table, 4 * index, (at + len(blocks)) // 512)
            blocks += b"\xff" * bitmap + block.ljust(block_size, b"\0")
    footer = _vhd_footer(size, 3, 512)
    return footer + bytes(header) + bytes(table) + bytes(blocks) + footer


def vhdx(disk: bytes, block_size: int = 1024 * 1024) -> bytes:
    """A VHDX: file identifier, region table, metadata, block table and the
    payload blocks that hold something, each at a 1 MB boundary."""
    import uuid

    guid = lambda text: uuid.UUID(text).bytes_le  # noqa: E731
    mb = 1024 * 1024
    size = len(disk)
    payload = -(-size // block_size)
    chunk = (1 << 23) * 512 // block_size
    out = bytearray(3 * mb)
    out[0:8] = b"vhdxfile"
    regions = b"regi" + struct.pack("<III", 0, 2, 0)
    regions += guid("2DC27766-F623-4200-9D64-115E9BFD4A08") + struct.pack("<QII", mb, mb, 1)
    regions += guid("8B7CA206-4790-4B9A-B8FE-575F050F886E") + struct.pack("<QII", 2 * mb, mb, 1)
    out[0x30000:0x30000 + len(regions)] = regions
    items = [(guid("CAA16737-FA36-4D43-B3B6-33F0AA44E76B"), struct.pack("<II", block_size, 0)),
             (guid("2FA54224-CD1B-4876-B211-5DBED83BF4B8"), struct.pack("<Q", size)),
             (guid("8141BF1D-A96F-4709-BA47-F233A8FAAB5F"), struct.pack("<I", 512))]
    meta = bytearray(b"metadata" + struct.pack("<HH", 0, len(items)) + bytes(20))
    offset = 0x10000
    for item, value in items:
        meta += item + struct.pack("<IIII", offset, len(value), 0, 0)
        offset += len(value)
    meta = meta.ljust(0x10000, b"\0") + b"".join(value for _, value in items)
    out[2 * mb:2 * mb + len(meta)] = meta
    blocks = bytearray()
    for index in range(payload):
        block = disk[index * block_size:(index + 1) * block_size]
        if not block.strip(b"\0"):
            continue
        at = len(out) + len(blocks)
        entry = 6 | ((at // mb) << 20)
        struct.pack_into("<Q", out, mb + 8 * (index + index // chunk), entry)
        blocks += block.ljust(block_size, b"\0")
    return bytes(out + blocks)


def ntfs(files: dict[str, bytes], directories: tuple[str, ...] = ()) -> bytes:
    """A small NTFS volume: its master file table holds `directories` and
    `files` (paths with "/"), small files resident, larger ones in clusters."""
    sector, cluster, record_size, mft_lcn, mft_records = 512, 4096, 1024, 4, 64
    data_lcn = mft_lcn + mft_records * record_size // cluster
    clusters: list[bytes] = []

    def attribute(kind: int, body: bytes, resident: bool = True, runs: bytes = b"", size: int = 0) -> bytes:
        if resident:
            header = struct.pack("<IIBBHHHIHBB", kind, 0, 0, 0, 0, 0, 0, len(body), 24, 0, 0)
            whole = header + body
        else:
            allocated = -(-size // cluster) * cluster
            last_vcn = max(0, allocated // cluster - 1)
            header = struct.pack("<IIBBHHHQQHHIQQQ", kind, 0, 1, 0, 0, 0, 0, 0, last_vcn, 64, 0, 0,
                                 allocated, size, size)
            whole = header + runs
        whole = whole.ljust(-(-len(whole) // 8) * 8, b"\0")
        return whole[:4] + struct.pack("<I", len(whole)) + whole[8:]

    def file_name(parent: int, name: str) -> bytes:
        encoded = name.encode("utf-16-le")
        body = struct.pack("<Q", parent | (1 << 48)) + bytes(32) + struct.pack("<QQII", 0, 0, 0x20, 0)
        return attribute(0x30, body + bytes([len(name), 1]) + encoded)

    def record(flags: int, attributes: bytes) -> bytes:
        body = bytearray(record_size)
        body[0:4] = b"FILE"
        struct.pack_into("<HHQHHHHII", body, 4, 48, 3, 0, 1, 1, 56, flags, 56 + len(attributes) + 8, record_size)
        body[56:56 + len(attributes)] = attributes
        body[56 + len(attributes):60 + len(attributes)] = b"\xff\xff\xff\xff"
        body[48:54] = b"\x01\x00" + bytes(body[510:512]) + bytes(body[1022:1024])
        body[510:512] = body[1022:1024] = b"\x01\x00"
        return bytes(body)

    def runs_for(lcn: int, count: int) -> bytes:
        return bytes([0x42]) + struct.pack("<HI", count, lcn) + b"\0"

    table = bytearray(mft_records * record_size)
    mft_data = attribute(0x80, b"", resident=False, runs=runs_for(mft_lcn, mft_records * record_size // cluster),
                         size=mft_records * record_size)
    table[0:record_size] = record(0x01, file_name(5, "$MFT") + mft_data)
    table[5 * record_size:6 * record_size] = record(0x03, file_name(5, "."))
    numbers = {"": 5}
    next_record = 24
    for path in directories:
        parent, _, name = path.rpartition("/")
        table[next_record * record_size:(next_record + 1) * record_size] = \
            record(0x03, file_name(numbers[parent], name))
        numbers[path] = next_record
        next_record += 1
    for path, content in files.items():
        parent, _, name = path.rpartition("/")
        if len(content) <= 600:
            data = attribute(0x80, content)
        else:
            count = -(-len(content) // cluster)
            data = attribute(0x80, b"", resident=False, runs=runs_for(data_lcn + len(clusters), count),
                             size=len(content))
            clusters += [content[i * cluster:(i + 1) * cluster].ljust(cluster, b"\0") for i in range(count)]
        table[next_record * record_size:(next_record + 1) * record_size] = \
            record(0x01, file_name(numbers[parent], name) + data)
        next_record += 1
    total = data_lcn + len(clusters) + 8
    boot = bytearray(sector)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 11, sector, cluster // sector)
    struct.pack_into("<QQQb", boot, 40, total * cluster // sector, mft_lcn, mft_lcn, -10)
    boot[510:512] = b"\x55\xaa"
    volume = bytearray(total * cluster)
    volume[0:sector] = boot
    volume[mft_lcn * cluster:mft_lcn * cluster + len(table)] = table
    for index, chunk in enumerate(clusters):
        volume[(data_lcn + index) * cluster:(data_lcn + index + 1) * cluster] = chunk
    return bytes(volume)


# ----------------------------------------------------------------------- RAR5 --

def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def rar5(names: list[str], encrypted_headers: bool = False, contents: dict[str, bytes] | None = None,
         compressed: bool = False) -> bytes:
    """A RAR5 archive: files named `names`, stored with `contents` (empty by
    default), or marked as compressed (method 3) with those bytes as data."""
    def block(kind: int, body: bytes, flags: int = 0, data: bytes = b"") -> bytes:
        header = _vint(kind) + _vint(flags | (0x02 if data else 0)) + (_vint(len(data)) if data else b"") + body
        size = _vint(len(header))
        return struct.pack("<I", binascii.crc32(size + header)) + size + header + data

    out = b"Rar!\x1a\x07\x01\x00" + block(1, _vint(0))
    if encrypted_headers:
        return out + block(4, _vint(0) + _vint(0) + _vint(15) + b"\0" * 16 + b"\0" * 16)
    for name in names:
        encoded = name.encode()
        data = (contents or {}).get(name, b"")
        compression = (3 << 7) if compressed else 0
        body = _vint(0) + _vint(len(data)) + _vint(0x20) + _vint(compression) + _vint(0) + _vint(len(encoded)) \
            + encoded
        out += block(2, body, data=data)
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


# ------------------------------------------------- deeper variants for coverage --

def _7z_number(value: int) -> bytes:
    """7-Zip's variable-length UINT64."""
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value < 0x200000:
        return bytes([0xC0 | (value >> 16), value & 0xFF, (value >> 8) & 0xFF])
    return bytes([0xE0 | (value >> 24)]) + (value & 0xFFFFFF).to_bytes(3, "little")


def seven_zip_packed(files: dict[str, bytes], bcj: bool = False, header_coder: str = "",
                     unbacked: tuple[str, ...] = ()) -> bytes:
    """A 7z archive whose files are really compressed: one solid LZMA2 folder,
    optionally behind the x86 branch filter, as 7-Zip packs executables.
    `unbacked` names more files with a data stream the archive does not have."""
    import lzma

    data = b"".join(files.values())
    filters = ([{"id": lzma.FILTER_X86}] if bcj else []) + [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}]
    packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    lzma2 = bytes([0x21]) + b"\x21" + _7z_number(1) + bytes([16])  # 1 MB dictionary
    if bcj:  # coder 0 (BCJ) reads coder 1's (LZMA2) output; the packed stream feeds LZMA2
        coders = _7z_number(2) + bytes([0x04]) + b"\x03\x03\x01\x03" + lzma2 + _7z_number(0) + _7z_number(1)
        unpack = _7z_number(len(data)) * 2
    else:
        coders = _7z_number(1) + lzma2
        unpack = _7z_number(len(data))
    sizes = list(files.values())
    header = b"\x01\x04"
    header += b"\x06" + _7z_number(0) + _7z_number(1) + b"\x09" + _7z_number(len(packed)) + b"\x00"
    header += b"\x07\x0b" + _7z_number(1) + b"\x00" + coders + b"\x0c" + unpack + b"\x00"
    header += b"\x08\x0d" + _7z_number(len(files)) + b"\x09" \
        + b"".join(_7z_number(len(item)) for item in sizes[:-1]) + b"\x00"
    header += b"\x00"
    names = list(files) + list(unbacked)
    names_blob = b"\0" + b"".join(n.encode("utf-16-le") + b"\0\0" for n in names)
    header += b"\x05" + _7z_number(len(names)) + b"\x11" + _7z_number(len(names_blob)) + names_blob + b"\x00"
    header += b"\x00"
    start = struct.pack("<QQI", len(packed), len(header), binascii.crc32(header))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", binascii.crc32(start)) + start + packed + header


def seven_zip_encoded(names: list[str], coder: str = "lzma", encrypted_content: bool = False,
                      directories: tuple[str, ...] = ()) -> bytes:
    """A 7z archive whose header is itself packed (LZMA, LZMA2) or encrypted
    (AES), as 7-Zip writes by default; optionally with encrypted content."""
    import lzma

    everything = list(names) + list(directories)
    names_blob = b"\0" + b"".join(n.encode("utf-16-le") + b"\0\0" for n in everything)
    header = b"\x01"
    if encrypted_content:  # MainStreamsInfo whose one folder is AES then LZMA
        header += b"\x04" + b"\x06" + _7z_number(0) + _7z_number(1) + b"\x09" + _7z_number(16) + b"\x00"
        header += b"\x07\x0b" + _7z_number(1) + b"\x00" + _7z_number(1)
        header += bytes([0x24]) + b"\x06\xf1\x07\x01" + _7z_number(2) + b"\x00\x00"
        header += b"\x0c" + _7z_number(16) + b"\x00" + b"\x00"
    header += b"\x05" + _7z_number(len(everything))
    header += b"\x11" + _7z_number(len(names_blob)) + names_blob
    if directories:
        attributes = b"\x01\x00" + b"".join(struct.pack("<I", 0x10 if name in directories else 0x20)
                                            for name in everything)
        header += b"\x15" + _7z_number(len(attributes)) + attributes
    header += b"\x00\x00"
    if coder == "lzma":
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]
        packed = lzma.compress(header, format=lzma.FORMAT_RAW, filters=filters)
        coder_bytes = bytes([0x23]) + b"\x03\x01\x01" + _7z_number(5) + bytes([3 + 0 * 9 + 2 * 45]) \
            + struct.pack("<I", 1 << 16)
    elif coder == "lzma2":
        packed = lzma.compress(header, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2,
                                                                          "dict_size": 1 << 16}])
        coder_bytes = bytes([0x21]) + b"\x21" + _7z_number(1) + bytes([10])
    else:  # AES: the header cannot be read without the password
        packed = b"\x5a" * 64
        coder_bytes = bytes([0x24]) + b"\x06\xf1\x07\x01" + _7z_number(2) + b"\x00\x00"
    encoded = b"\x17" + b"\x06" + _7z_number(0) + _7z_number(1) + b"\x09" + _7z_number(len(packed)) + b"\x00"
    encoded += b"\x07\x0b" + _7z_number(1) + b"\x00" + _7z_number(1) + coder_bytes
    encoded += b"\x0c" + _7z_number(len(header)) + b"\x00" + b"\x00"
    start = struct.pack("<QQI", len(packed), len(encoded), binascii.crc32(encoded))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", binascii.crc32(start)) + start + packed + encoded


def rar4(entries: list[tuple[str, int]], encrypted_headers: bool = False) -> bytes:
    """RAR 2.9-4 headers. entries: (name, flags); flag 0x04 encrypted,
    0x200 a Unicode name (written in RAR's encoded form), 0xE0 a directory."""
    def block(kind: int, flags: int, body: bytes, add: bytes = b"") -> bytes:
        size = 7 + len(body)
        return struct.pack("<HBHH", 0, kind, flags | (0x8000 if add else 0), size) + body + add

    out = b"Rar!\x1a\x07\x00" + block(0x73, 0x0080 if encrypted_headers else 0, b"\0" * 6)
    for name, flags in entries:
        if flags & 0x200:
            encoded = bytearray([0])  # high byte 0; then four characters per flag byte, all 16-bit
            chars = name.encode("utf-16-le")
            for start in range(0, len(chars), 8):
                group = chars[start:start + 8]
                encoded.append(0xAA)
                encoded += group
            raw = name.encode("ascii", errors="replace") + b"\0" + bytes(encoded)
        else:
            raw = name.encode("cp437", errors="replace")
        body = struct.pack("<IIBIIBBHI", 0, 0, 2, 0, 0, 29, 0x30, len(raw), 0x20) + raw
        out += block(0x74, flags, body)
    return out + block(0x7B, 0, b"")


def lnk_full(target: str, arguments: str = "", environment_target: str = "") -> bytes:
    """A shortcut with an ID list, a LinkInfo local base path (ANSI and
    Unicode) and an environment-variable block, as Explorer writes them."""
    flags = 0x01 | 0x02 | 0x20 | 0x80
    header = struct.pack("<I16sII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20)
    header += b"\0" * 24 + struct.pack("<IiIH", 0, 0, 1, 0) + b"\0" * 10
    idlist = struct.pack("<H", 4) + b"\x02\x00\x00\x00"
    ansi = target.encode("cp1252", errors="replace") + b"\0"
    wide = target.encode("utf-16-le") + b"\0\0"
    info_header = 0x24
    base = info_header
    base_unicode = base + len(ansi)
    info = struct.pack("<IIIIIIIII", info_header + len(ansi) + len(wide), info_header, 1, 0, base, 0, 0,
                       base_unicode, 0) + ansi + wide
    strings = struct.pack("<H", len(arguments)) + arguments.encode("utf-16-le")
    extra = b""
    if environment_target:
        block = environment_target.encode("cp1252")[:259].ljust(260, b"\0") \
            + environment_target.encode("utf-16-le")[:518].ljust(520, b"\0")
        extra = struct.pack("<II", 8 + len(block), 0xA0000001) + block
    return header + idlist + info + strings + extra + struct.pack("<I", 0)


def iso_tree(files: dict[str, bytes], joliet: bool = True) -> bytes:
    """An ISO 9660 image with subdirectories ("dir/name") and, optionally,
    a Joliet volume holding the long, mixed-case names."""
    block = 2048

    def record(name: bytes, extent: int, size: int, directory: bool) -> bytes:
        body = struct.pack("<BI", 0, extent) + struct.pack(">I", extent) + struct.pack("<I", size) \
            + struct.pack(">I", size) + b"\0" * 7 + bytes([2 if directory else 0, 0, 0]) \
            + struct.pack("<H", 1) + struct.pack(">H", 1) + bytes([len(name)]) + name
        if (len(body) + 1) % 2:
            body += b"\0"
        return bytes([len(body) + 1]) + body

    tree: dict[str, dict[str, bytes]] = {"": {}}
    for path, data in files.items():
        folder, _, name = path.rpartition("/")
        tree.setdefault(folder, {})[name] = data
    blocks: list[bytes] = []

    def encode(name: str, is_joliet: bool) -> bytes:
        return name.encode("utf-16-be") if is_joliet else name.upper().encode() + b";1"

    def build(is_joliet: bool, first_extent: int) -> tuple[int, list[bytes]]:
        order = sorted(tree)
        extents = {folder: first_extent + index for index, folder in enumerate(order)}
        data_extent = first_extent + len(order)
        payload, contents = [], []
        for folder in order:
            entries = [record(b"\0", extents[folder], block, True), record(b"\1", extents[folder], block, True)]
            for sub in order:
                if sub and sub.rpartition("/")[0] == folder:
                    entries.append(record(encode(sub.rpartition("/")[2], is_joliet)
                                          if is_joliet else sub.rpartition("/")[2].upper().encode(),
                                          extents[sub], block, True))
            for name, data in tree[folder].items():
                count = max(1, -(-len(data) // block))
                entries.append(record(encode(name, is_joliet), data_extent, len(data), False))
                contents.append(data.ljust(count * block, b"\0"))
                data_extent += count
            payload.append(b"".join(entries).ljust(block, b"\0"))
        return extents[""], payload + contents

    descriptors = 2 + (1 if joliet else 0)
    root_plain, plain = build(False, 16 + descriptors)
    blocks += plain
    root_joliet = 0
    if joliet:
        root_joliet, joliet_blocks = build(True, 16 + descriptors + len(plain))
        blocks += joliet_blocks
    pvd = bytearray(block)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[156:190] = record(b"\0", root_plain, block, True)[:34]
    out = [bytes(pvd)]
    if joliet:
        svd = bytearray(block)
        svd[0], svd[1:6], svd[6] = 2, b"CD001", 1
        svd[88:91] = b"%/E"
        svd[156:190] = record(b"\0", root_joliet, block, True)[:34]
        out.append(bytes(svd))
    terminator = bytearray(block)
    terminator[0], terminator[1:6], terminator[6] = 255, b"CD001", 1
    out.append(bytes(terminator))
    return b"\0" * (16 * block) + b"".join(out) + b"".join(blocks)
