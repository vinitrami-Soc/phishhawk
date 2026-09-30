"""File listings of RAR and 7-Zip archives, read from their headers.

Decompressing RAR needs the proprietary algorithm and 7-Zip needs LZMA
streams of any size, so members are not extracted; the names alone show
the .lnk, .js or .exe a phish hides, and whether a password hides even
the names.
"""

from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass, field

MAX_MEMBERS = 1000
MAX_HEADER = 4 * 1024 * 1024


@dataclass
class Listing:
    kind: str
    names: list[str] = field(default_factory=list)
    sizes: list[int] = field(default_factory=list)
    encrypted: bool = False  # member data needs a password
    names_hidden: bool = False  # the listing itself is encrypted
    truncated: bool = False


RAR4 = b"Rar!\x1a\x07\x00"
RAR5 = b"Rar!\x1a\x07\x01\x00"
SEVEN_ZIP = b"7z\xbc\xaf\x27\x1c"


# --------------------------------------------------------------------- RAR --

def _vint(data: bytes, offset: int) -> tuple[int, int]:
    value, shift = 0, 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise ValueError("truncated number")


def _rar5(data: bytes, listing: Listing) -> Listing:
    offset = len(RAR5)
    for _ in range(MAX_MEMBERS * 4):
        if offset + 7 > len(data):
            break
        size, start = _vint(data, offset + 4)
        end = start + size
        kind, position = _vint(data, start)
        flags, position = _vint(data, position)
        extra = data_size = 0
        if flags & 0x01:
            extra, position = _vint(data, position)
        if flags & 0x02:
            data_size, position = _vint(data, position)
        if kind == 4:  # archive encryption header: everything after it is encrypted
            listing.names_hidden = listing.encrypted = True
            break
        if kind == 5:
            break
        if kind == 2:
            file_flags, position = _vint(data, position)
            unpacked, position = _vint(data, position)
            _, position = _vint(data, position)  # attributes
            if file_flags & 0x02:
                position += 4
            if file_flags & 0x04:
                position += 4
            _, position = _vint(data, position)  # compression
            _, position = _vint(data, position)  # host OS
            name_length, position = _vint(data, position)
            name = data[position:position + min(name_length, 2048)].decode("utf-8", errors="replace")
            position += name_length
            extra_area = data[end - extra:end] if extra else b""
            record = 0
            while record < len(extra_area):
                record_size, after = _vint(extra_area, record)
                record_type, _ = _vint(extra_area, after)
                if record_type == 1:
                    listing.encrypted = True
                record = after + record_size
                if record_size == 0:
                    break
            if not file_flags & 0x01 and name not in listing.names:  # not a directory, nor a second version
                listing.names.append(name)
                listing.sizes.append(unpacked)
                if len(listing.names) >= MAX_MEMBERS:
                    listing.truncated = True
                    break
        offset = end + data_size
    return listing


def _rar_unicode(standard: bytes, encoded: bytes) -> str:
    """RAR 2.9-4 names: an ANSI form, then the Unicode form compressed
    against it (the scheme unrar's EncodeFileName uses)."""
    out = bytearray()
    position = 0
    stream = iter(encoded)

    def put(low: int, high: int) -> None:
        nonlocal position
        out.extend((low, high))
        position += 1

    def std() -> int:
        return standard[position] if position < len(standard) else 0x3F

    try:
        high = next(stream)
        flags, bits = 0, 0
        while len(out) < 4096:
            if bits == 0:
                flags, bits = next(stream), 8
            bits -= 2
            kind = (flags >> bits) & 3
            if kind == 0:
                put(next(stream), 0)
            elif kind == 1:
                put(next(stream), high)
            elif kind == 2:
                low = next(stream)
                put(low, next(stream))
            else:
                count = next(stream)
                if count & 0x80:
                    correction = next(stream)
                    for _ in range((count & 0x7F) + 2):
                        put((std() + correction) & 0xFF, high)
                else:
                    for _ in range(count + 2):
                        put(std(), 0)
    except StopIteration:
        pass
    return out.decode("utf-16-le", errors="replace")


def _rar4(data: bytes, listing: Listing) -> Listing:
    offset = len(RAR4)
    for _ in range(MAX_MEMBERS * 4):
        if offset + 7 > len(data):
            break
        _, kind, flags, size = struct.unpack_from("<HBHH", data, offset)
        if size < 7:
            break
        add = struct.unpack_from("<I", data, offset + 7)[0] if flags & 0x8000 and offset + 11 <= len(data) else 0
        if kind == 0x73 and flags & 0x0080:  # main header: block headers encrypted
            listing.names_hidden = listing.encrypted = True
            break
        if kind == 0x74:
            packed, unpacked = struct.unpack_from("<II", data, offset + 7)
            name_size = struct.unpack_from("<H", data, offset + 26)[0]
            name_start = offset + 32 + (8 if flags & 0x100 else 0)
            raw = data[name_start:name_start + min(name_size, 2048)]
            if flags & 0x200 and b"\x00" in raw:
                standard, encoded = raw.split(b"\x00", 1)
                name = _rar_unicode(standard, encoded) or standard.decode("cp437", errors="replace")
            else:
                try:
                    name = raw.decode("utf-8")
                except UnicodeDecodeError:
                    name = raw.decode("cp437", errors="replace")
            if flags & 0x04:
                listing.encrypted = True
            name = name.replace("\\", "/")
            if flags & 0xE0 != 0xE0 and name not in listing.names:  # 0xE0: a directory entry
                listing.names.append(name)
                listing.sizes.append(unpacked)
                if len(listing.names) >= MAX_MEMBERS:
                    listing.truncated = True
                    break
            add = packed
        if kind == 0x7B:
            break
        offset += size + add
    return listing


def list_rar(data: bytes) -> Listing:
    """The members of a RAR archive; a truncated archive gives what it has."""
    if data.startswith(RAR5):
        reader = _rar5
    elif data.startswith(RAR4):
        reader = _rar4
    else:
        raise ValueError("not a RAR archive")
    listing = Listing("rar")
    try:
        reader(data, listing)
    except (struct.error, ValueError, IndexError):
        listing.truncated = True
    return listing


# ------------------------------------------------------------------- 7-Zip --

class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated 7z header")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated 7z header")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def number(self) -> int:
        first = self.byte()
        mask, value = 0x80, 0
        for index in range(8):
            if not first & mask:
                high = first & (mask - 1)
                return value | (high << (8 * index))
            value |= self.byte() << (8 * index)
            mask >>= 1
        return value

    def bits(self, count: int) -> list[bool]:
        out, byte, mask = [], 0, 0
        for _ in range(count):
            if mask == 0:
                byte, mask = self.byte(), 0x80
            out.append(bool(byte & mask))
            mask >>= 1
        return out

    def defined(self, count: int) -> list[bool]:
        all_defined = self.byte()
        return [True] * count if all_defined else self.bits(count)


_AES = b"\x06\xf1\x07\x01"


def _folders(reader: _Reader) -> tuple[list[list[tuple[bytes, bytes]]], list[list[int]]]:
    """UnPackInfo: the coders of each folder and their unpack sizes."""
    if reader.byte() != 0x0B:
        raise ValueError("unexpected 7z structure")
    count = reader.number()
    if count > 10_000 or reader.byte() != 0:  # external folders are not supported
        raise ValueError("unsupported 7z folders")
    folders, outputs = [], []
    for _ in range(count):
        coders = []
        total_in = total_out = 0
        coder_count = reader.number()
        if coder_count > 64:
            raise ValueError("too many 7z coders")
        for _ in range(coder_count):
            flags = reader.byte()
            coder_id = reader.take(flags & 0x0F)
            ins = outs = 1
            if flags & 0x10:
                ins, outs = reader.number(), reader.number()
            props = reader.take(reader.number()) if flags & 0x20 else b""
            coders.append((coder_id, props))
            total_in, total_out = total_in + ins, total_out + outs
        if total_in > 64 or total_out > 64:
            raise ValueError("too many 7z streams")
        for _ in range(total_out - 1):  # bind pairs
            reader.number()
            reader.number()
        packed = total_in - (total_out - 1)
        if packed > 1:
            for _ in range(packed):
                reader.number()
        folders.append(coders)
        outputs.append(total_out)
    if reader.byte() != 0x0C:
        raise ValueError("unexpected 7z structure")
    sizes = [[reader.number() for _ in range(max(1, total))] for total in outputs]
    while True:
        marker = reader.byte()
        if marker == 0x00:
            break
        if marker == 0x0A:
            reader.take(4 * sum(reader.defined(len(folders))))
        else:
            raise ValueError("unexpected 7z structure")
    return folders, sizes


def _streams_info(reader: _Reader) -> tuple[int, list[int], list[list[tuple[bytes, bytes]]], list[list[int]]]:
    pack_pos, pack_sizes, folders, sizes = 0, [], [], []
    while True:
        marker = reader.byte()
        if marker == 0x00:
            return pack_pos, pack_sizes, folders, sizes
        if marker == 0x06:
            pack_pos = reader.number()
            count = reader.number()
            while True:
                sub = reader.byte()
                if sub == 0x00:
                    break
                if sub == 0x09:
                    pack_sizes = [reader.number() for _ in range(min(count, 10_000))]
                elif sub == 0x0A:
                    reader.take(4 * sum(reader.defined(count)))
                else:
                    raise ValueError("unexpected 7z structure")
        elif marker == 0x07:
            folders, sizes = _folders(reader)
        elif marker == 0x08:
            _skip_substreams(reader, len(folders))
        else:
            raise ValueError("unexpected 7z structure")


def _skip_substreams(reader: _Reader, folder_count: int) -> None:
    counts = [1] * folder_count
    while True:
        marker = reader.byte()
        if marker == 0x00:
            return
        if marker == 0x0D:
            counts = [reader.number() for _ in range(folder_count)]
        elif marker == 0x09:
            for count in counts:
                for _ in range(max(0, count - 1)):
                    reader.number()
        elif marker == 0x0A:
            reader.take(4 * sum(reader.defined(sum(counts))))
        else:
            raise ValueError("unexpected 7z structure")


def _decode_header(data: bytes, pack_pos: int, pack_sizes: list[int], coders: list[tuple[bytes, bytes]],
                   unpack_size: int) -> bytes:
    if any(coder_id == _AES for coder_id, _ in coders):
        raise PermissionError("encrypted header")
    if len(coders) != 1 or unpack_size > MAX_HEADER:
        raise ValueError("unsupported 7z header coding")
    coder_id, props = coders[0]
    start = 32 + pack_pos
    packed = data[start:start + (pack_sizes[0] if pack_sizes else len(data))]
    if coder_id == b"\x03\x01\x01" and len(props) == 5:
        lc_lp_pb = props[0]
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": struct.unpack_from("<I", props, 1)[0],
                    "lc": lc_lp_pb % 9, "lp": (lc_lp_pb // 9) % 5, "pb": lc_lp_pb // 45}]
    elif coder_id == b"\x21" and len(props) == 1:
        exponent = props[0]
        dict_size = 0xFFFFFFFF if exponent == 40 else (2 | (exponent & 1)) << (exponent // 2 + 11)
        filters = [{"id": lzma.FILTER_LZMA2, "dict_size": min(dict_size, 1 << 30)}]
    elif coder_id == b"\x00":
        return packed[:unpack_size]
    else:
        raise ValueError("unsupported 7z header coder")
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        return decoder.decompress(packed, max_length=unpack_size)
    except lzma.LZMAError as exc:
        raise ValueError("corrupt 7z header") from exc


def _files(reader: _Reader, listing: Listing) -> None:
    count = reader.number()
    if count > 1_000_000:
        raise ValueError("implausible 7z file count")
    names: list[str] = []
    directories = [False] * count
    while True:
        kind = reader.byte()
        if kind == 0x00:
            break
        size = reader.number()
        body = _Reader(reader.take(size))
        if kind == 0x11:
            if body.byte() != 0:
                continue
            text = body.data[body.pos:].decode("utf-16-le", errors="replace")
            names = text.split("\x00")[:count]
        elif kind == 0x15:  # attributes: the directory bit
            defined = body.defined(count)
            if body.byte() != 0:
                continue
            for index, has in enumerate(defined):
                if has and body.pos + 4 <= len(body.data):
                    directories[index] = bool(struct.unpack_from("<I", body.data, body.pos)[0] & 0x10)
                    body.pos += 4
    for index, name in enumerate(names):
        if name and not directories[index]:
            listing.names.append(name.replace("\\", "/"))
            listing.sizes.append(0)
            if len(listing.names) >= MAX_MEMBERS:
                listing.truncated = True
                break


def list_7z(data: bytes) -> Listing:
    listing = Listing("7z")
    if not data.startswith(SEVEN_ZIP) or len(data) < 32:
        raise ValueError("not a 7-Zip archive")
    offset, size = struct.unpack_from("<QQ", data, 12)
    if size > MAX_HEADER or 32 + offset + size > len(data):
        raise ValueError("7z header outside the file")
    header = data[32 + offset:32 + offset + size]
    try:
        for _ in range(4):  # an encoded header can itself be encoded
            reader = _Reader(header)
            marker = reader.byte()
            if marker == 0x17:
                pack_pos, pack_sizes, folders, sizes = _streams_info(reader)
                if not folders:
                    raise ValueError("empty 7z header stream")
                header = _decode_header(data, pack_pos, pack_sizes, folders[0], sizes[0][0])
                continue
            if marker != 0x01:
                raise ValueError("unexpected 7z header")
            while True:
                section = reader.byte()
                if section == 0x00:
                    return listing
                if section == 0x02:  # archive properties
                    while reader.byte() != 0:
                        reader.take(reader.number())
                elif section == 0x03:
                    _streams_info(reader)
                elif section == 0x04:
                    _, _, folders, _ = _streams_info(reader)
                    listing.encrypted = any(coder_id == _AES for coders in folders for coder_id, _ in coders)
                elif section == 0x05:
                    _files(reader, listing)
                else:
                    raise ValueError("unexpected 7z header section")
    except PermissionError:
        listing.names_hidden = listing.encrypted = True
    return listing
