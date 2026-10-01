"""RAR and 7-Zip archives, read in memory.

7-Zip members are decompressed within a byte budget (LZMA, LZMA2, Deflate,
BZip2, stored, with branch and delta filters). RAR's compression is
proprietary, so only its stored members are read; the rest are listed from
the headers, which still show the .lnk, .js or .exe a phish hides, and
whether a password hides even the names.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import zlib
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
    contents: list[bytes | None] | None = None  # when extracted: each member's bytes, None if unreadable
    budget: int = 0  # bytes left to extract
    unpacked: int = 0  # bytes decompressed or copied, headers included: what reading it cost


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
        if extra > end - position:  # the extra area ends the header: it cannot reach back before it
            raise ValueError("RAR extra area outside its header")
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
            compression, position = _vint(data, position)
            _, position = _vint(data, position)  # host OS
            name_length, position = _vint(data, position)
            name = data[position:position + min(name_length, 2048)].decode("utf-8", errors="replace")
            position += name_length
            extra_area = data[end - extra:end] if extra else b""
            record = 0
            locked = False
            while record < len(extra_area):
                record_size, after = _vint(extra_area, record)
                record_type, _ = _vint(extra_area, after)
                if record_type == 1:
                    listing.encrypted = locked = True
                record = after + record_size
                if record_size == 0:
                    break
            if not file_flags & 0x01 and name not in listing.names:  # not a directory, nor a second version
                listing.names.append(name)
                listing.sizes.append(unpacked)
                # Method 0 is stored: the bytes follow the header as they are.
                stored = (compression >> 7) & 7 == 0 and not locked and not flags & 0x18 \
                    and data_size == unpacked
                _keep(listing, data[end:end + data_size] if stored else None, unpacked)
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
            method = data[offset + 25]
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
                # Method 0x30 is stored; 0x03 split, 0x04 encrypted, 0x10 solid, 0x100 sizes over 4 GB.
                stored = method == 0x30 and not flags & 0x117 and packed == unpacked
                _keep(listing, data[offset + size:offset + size + packed] if stored else None, unpacked)
                if len(listing.names) >= MAX_MEMBERS:
                    listing.truncated = True
                    break
            add = packed
        if kind == 0x7B:
            break
        offset += size + add
    return listing


def _keep(listing: Listing, content: bytes | None, size: int) -> None:
    """Record a member's content if it is readable, complete and in budget."""
    if listing.contents is None:
        return
    if content is not None and (len(content) != size or size > listing.budget):
        content = None
    if content is not None:
        listing.budget -= size
        listing.unpacked += size
    listing.contents.append(content)


def list_rar(data: bytes, budget: int = 0) -> Listing:
    """The members of a RAR archive; a truncated archive gives what it has.
    With a byte budget, the contents of stored (uncompressed) members too:
    RAR's own compression is proprietary, so compressed members are listed
    only."""
    if data.startswith(RAR5):
        reader = _rar5
    elif data.startswith(RAR4):
        reader = _rar4
    else:
        raise ValueError("not a RAR archive")
    listing = Listing("rar", contents=[] if budget > 0 else None, budget=budget)
    try:
        reader(data, listing)
    except (struct.error, ValueError, IndexError):
        listing.truncated = True
    if listing.contents is not None:
        listing.contents.extend([None] * (len(listing.names) - len(listing.contents)))
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
_COPY, _LZMA, _LZMA2, _DELTA = b"\x00", b"\x03\x01\x01", b"\x21", b"\x03"
_DEFLATE, _BZIP2 = b"\x04\x01\x08", b"\x04\x02\x02"
# Branch converters that make executable code compress better (7-Zip's BCJ).
_BRANCH = {b"\x03\x03\x01\x03": lzma.FILTER_X86, b"\x03\x03\x02\x05": lzma.FILTER_POWERPC,
           b"\x03\x03\x04\x01": lzma.FILTER_IA64, b"\x03\x03\x05\x01": lzma.FILTER_ARM,
           b"\x03\x03\x07\x01": lzma.FILTER_ARMTHUMB, b"\x03\x03\x08\x05": lzma.FILTER_SPARC}


@dataclass
class _Folder:
    """One compressed block: its coders, how their streams connect, and the
    size of every stream they produce."""
    coders: list[tuple[bytes, bytes, int, int]]  # (id, properties, inputs, outputs)
    binds: list[tuple[int, int]]  # (input index, output index): that input reads that output
    packed: list[int]  # the inputs fed by packed streams
    sizes: list[int] = field(default_factory=list)
    crc: bool = False

    @property
    def unpack_size(self) -> int:
        bound = {output for _, output in self.binds}
        final = [index for index in range(len(self.sizes)) if index not in bound]
        return self.sizes[final[0]] if final else 0


@dataclass
class _Streams:
    pack_pos: int = 0
    pack_sizes: list[int] = field(default_factory=list)
    folders: list[_Folder] = field(default_factory=list)
    files: list[list[int]] = field(default_factory=list)  # per folder: the sizes of the files in it


def _folders(reader: _Reader) -> list[_Folder]:
    """UnPackInfo: the coders of each folder and their unpack sizes."""
    if reader.byte() != 0x0B:
        raise ValueError("unexpected 7z structure")
    count = reader.number()
    if count > 10_000 or reader.byte() != 0:  # external folders are not supported
        raise ValueError("unsupported 7z folders")
    folders = []
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
            coders.append((coder_id, props, ins, outs))
            total_in, total_out = total_in + ins, total_out + outs
        if total_in > 64 or total_out > 64 or total_out < 1:
            raise ValueError("too many 7z streams")
        binds = [(reader.number(), reader.number()) for _ in range(total_out - 1)]
        packed_count = total_in - (total_out - 1)
        if packed_count < 1:
            raise ValueError("unexpected 7z structure")
        if packed_count == 1:
            bound_inputs = {index for index, _ in binds}
            packed = [index for index in range(total_in) if index not in bound_inputs][:1]
        else:
            packed = [reader.number() for _ in range(packed_count)]
        folders.append(_Folder(coders, binds, packed))
    if reader.byte() != 0x0C:
        raise ValueError("unexpected 7z structure")
    for folder in folders:
        folder.sizes = [reader.number() for _ in range(sum(outs for _, _, _, outs in folder.coders))]
    while True:
        marker = reader.byte()
        if marker == 0x00:
            break
        if marker == 0x0A:
            defined = reader.defined(len(folders))
            reader.take(4 * sum(defined))
            for folder, has in zip(folders, defined, strict=True):
                folder.crc = has
        else:
            raise ValueError("unexpected 7z structure")
    return folders


def _streams_info(reader: _Reader) -> _Streams:
    streams = _Streams()
    while True:
        marker = reader.byte()
        if marker == 0x00:
            if not streams.files:
                streams.files = [[folder.unpack_size] for folder in streams.folders]
            return streams
        if marker == 0x06:
            streams.pack_pos = reader.number()
            count = reader.number()
            if count > 10_000:
                raise ValueError("implausible 7z stream count")
            while True:
                sub = reader.byte()
                if sub == 0x00:
                    break
                if sub == 0x09:
                    streams.pack_sizes = [reader.number() for _ in range(count)]
                elif sub == 0x0A:
                    reader.take(4 * sum(reader.defined(count)))
                else:
                    raise ValueError("unexpected 7z structure")
        elif marker == 0x07:
            streams.folders = _folders(reader)
        elif marker == 0x08:
            streams.files = _substreams(reader, streams.folders)
        else:
            raise ValueError("unexpected 7z structure")


def _substreams(reader: _Reader, folders: list[_Folder]) -> list[list[int]]:
    """SubStreamsInfo: how each folder's output splits into files."""
    counts = [1] * len(folders)
    files: list[list[int]] | None = None
    while True:
        marker = reader.byte()
        if marker == 0x00:
            break
        if marker == 0x0D:
            counts = [reader.number() for _ in folders]
            if sum(counts) > 1_000_000:
                raise ValueError("implausible 7z file count")
        elif marker == 0x09:
            files = []
            for folder, count in zip(folders, counts, strict=True):
                sizes = [reader.number() for _ in range(max(0, count - 1))]
                if count:
                    sizes.append(folder.unpack_size - sum(sizes))
                files.append(sizes)
        elif marker == 0x0A:
            digests = sum(count for folder, count in zip(folders, counts, strict=True)
                          if not (count == 1 and folder.crc))
            reader.take(4 * sum(reader.defined(digests)))
        else:
            raise ValueError("unexpected 7z structure")
    if files is None:
        if any(count > 1 for count in counts):
            raise ValueError("7z file sizes missing")
        files = [[folder.unpack_size] * count for folder, count in zip(folders, counts, strict=True)]
    if any(size < 0 for sizes in files for size in sizes):
        raise ValueError("7z file sizes exceed their folder")
    return files


def _chain(folder: _Folder) -> list[tuple[bytes, bytes]]:
    """The coders of a folder in decoding order, from its packed stream to
    its output. Only chains of one-in, one-out coders (all 7-Zip writes but
    BCJ2) are followed."""
    if len(folder.packed) != 1 or any(ins != 1 or outs != 1 for _, _, ins, outs in folder.coders):
        raise ValueError("unsupported 7z coder layout")
    order: list[tuple[bytes, bytes]] = []
    coder = folder.packed[0]
    for _ in folder.coders:
        if not 0 <= coder < len(folder.coders):
            raise ValueError("unexpected 7z structure")
        coder_id, props, _, _ = folder.coders[coder]
        order.append((coder_id, props))
        coder = next((index for index, output in folder.binds if output == coder), -1)
        if coder < 0:
            break
    if len(order) != len(folder.coders):
        raise ValueError("unexpected 7z structure")
    return order


def _lzma_filter(coder_id: bytes, props: bytes, dict_limit: int) -> dict[str, int]:
    # No match distance can reach past the output, so a dictionary larger than
    # the output only costs memory (a 4 GB one fails to allocate).
    if coder_id == _LZMA and len(props) == 5:
        lc_lp_pb = props[0]
        if lc_lp_pb >= 9 * 5 * 5:
            raise ValueError("corrupt 7z coder properties")
        return {"id": lzma.FILTER_LZMA1, "dict_size": max(4096, min(struct.unpack_from("<I", props, 1)[0],
                                                                    dict_limit)),
                "lc": lc_lp_pb % 9, "lp": (lc_lp_pb // 9) % 5, "pb": lc_lp_pb // 45}
    if coder_id == _LZMA2 and len(props) == 1 and props[0] <= 40:
        exponent = props[0]
        dict_size = 0xFFFFFFFF if exponent == 40 else (2 | (exponent & 1)) << (exponent // 2 + 11)
        return {"id": lzma.FILTER_LZMA2, "dict_size": max(4096, min(dict_size, dict_limit))}
    if coder_id == _DELTA and len(props) == 1:
        return {"id": lzma.FILTER_DELTA, "dist": props[0] + 1}
    if coder_id in _BRANCH and len(props) in (0, 4):
        spec = {"id": _BRANCH[coder_id]}
        if props:
            spec["start_offset"] = struct.unpack("<I", props)[0]
        return spec
    raise ValueError("unsupported 7z coder")


def _decode(packed: bytes, chain: list[tuple[bytes, bytes]], size: int) -> bytes:
    """A folder's output, at most `size` bytes."""
    if any(coder_id == _AES for coder_id, _ in chain):
        raise PermissionError("encrypted")
    if size <= 0:  # zlib reads a max_length of 0 as "no limit"
        return b""
    first = chain[0][0]
    try:
        if len(chain) == 1 and first == _COPY:
            return packed[:size]
        if len(chain) == 1 and first == _DEFLATE:
            return zlib.decompressobj(-15).decompress(packed, size)
        if len(chain) == 1 and first == _BZIP2:
            return bz2.BZ2Decompressor().decompress(packed, max_length=size)
        if first in (_LZMA, _LZMA2):
            filters = [_lzma_filter(coder_id, props, size) for coder_id, props in reversed(chain)]
            if any(spec["id"] in (lzma.FILTER_LZMA1, lzma.FILTER_LZMA2) for spec in filters[:-1]):
                raise ValueError("unsupported 7z coder chain")
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            return decoder.decompress(packed, max_length=size)
    except (lzma.LZMAError, zlib.error, OSError, EOFError) as exc:
        raise ValueError("corrupt 7z data") from exc
    raise ValueError("unsupported 7z coder")


def _decode_header(data: bytes, streams: _Streams) -> bytes:
    if not streams.folders:
        raise ValueError("empty 7z header stream")
    folder = streams.folders[0]
    if any(coder_id == _AES for coder_id, _, _, _ in folder.coders):
        raise PermissionError("encrypted header")
    if folder.unpack_size > MAX_HEADER:
        raise ValueError("unsupported 7z header coding")
    start = 32 + streams.pack_pos
    packed = data[start:start + (streams.pack_sizes[0] if streams.pack_sizes else len(data))]
    return _decode(packed, _chain(folder), folder.unpack_size)


def _extract(data: bytes, streams: _Streams, listing: Listing) -> list[bytes | None]:
    """Every file's content in stream order; None where it cannot be read:
    an encrypted or unsupported folder, or one past the listing's budget. A
    folder is paid for before it is decoded, whether or not it decodes."""
    out: list[bytes | None] = []
    position = 32 + streams.pack_pos
    packed_index = 0
    for folder, sizes in zip(streams.folders, streams.files, strict=True):
        lengths = streams.pack_sizes[packed_index:packed_index + len(folder.packed)]
        packed_index += len(folder.packed)
        content: bytes | None = None
        if len(lengths) == 1 and folder.unpack_size <= listing.budget and position + lengths[0] <= len(data):
            listing.budget -= folder.unpack_size
            listing.unpacked += folder.unpack_size
            try:
                content = _decode(data[position:position + lengths[0]], _chain(folder), folder.unpack_size)
            except (ValueError, PermissionError):
                content = None
        position += sum(lengths)
        offset = 0
        for size in sizes:
            piece = content[offset:offset + size] if content is not None else None
            out.append(piece if piece is not None and len(piece) == size else None)
            offset += size
    return out


def _files(reader: _Reader, listing: Listing, streams: _Streams, contents: list[bytes | None]) -> None:
    count = reader.number()
    if count > 1_000_000:
        raise ValueError("implausible 7z file count")
    names: list[str] = []
    directories = [False] * count
    empty = [False] * count
    while True:
        kind = reader.byte()
        if kind == 0x00:
            break
        size = reader.number()
        body = _Reader(reader.take(size))
        if kind == 0x0E:  # which files have no data stream (directories, empty files)
            empty = body.bits(count)
        elif kind == 0x11:
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
    sizes = [size for folder_sizes in streams.files for size in folder_sizes]
    stream = 0
    for index, name in enumerate(names):
        has_stream = not empty[index]
        if has_stream:
            stream += 1
        if not name or directories[index]:
            continue
        listing.names.append(name.replace("\\", "/"))
        listing.sizes.append(sizes[stream - 1] if has_stream and stream <= len(sizes) else 0)
        if listing.contents is not None:  # an empty file is b""; one whose data is missing, unknown
            content = (contents[stream - 1] if stream <= len(contents) else None) if has_stream else b""
            listing.contents.append(content)
        if len(listing.names) >= MAX_MEMBERS:
            listing.truncated = True
            break


def list_7z(data: bytes, budget: int = 0) -> Listing:
    """The members of a 7-Zip archive. With a byte budget, their contents
    too, decompressed in memory: LZMA and LZMA2 folders behind any branch or
    delta filter, and Deflate, BZip2 and stored ones. Encrypted and other
    folders are listed only. A damaged archive raises ValueError, unless
    something was already decompressed: then it is a truncated listing, so
    that `unpacked` still says what reading it cost."""
    listing = Listing("7z", contents=[] if budget > 0 else None, budget=budget)
    if not data.startswith(SEVEN_ZIP) or len(data) < 32:
        raise ValueError("not a 7-Zip archive")
    offset, size = struct.unpack_from("<QQ", data, 12)
    if size > MAX_HEADER or 32 + offset + size > len(data):
        raise ValueError("7z header outside the file")
    try:
        _read_7z(data, data[32 + offset:32 + offset + size], listing)
    except PermissionError:
        listing.names_hidden = listing.encrypted = True
    except ValueError:
        if not listing.unpacked:
            raise
        listing.truncated = True
    return listing


def _read_7z(data: bytes, header: bytes, listing: Listing) -> None:
    for _ in range(4):  # an encoded header can itself be encoded
        reader = _Reader(header)
        marker = reader.byte()
        if marker == 0x17:
            header = _decode_header(data, _streams_info(reader))
            listing.unpacked += len(header)
            continue
        if marker != 0x01:
            raise ValueError("unexpected 7z header")
        streams = _Streams()
        contents: list[bytes | None] = []
        last = 0
        while True:
            section = reader.byte()
            if section == 0x00:
                return
            # 7-Zip reads each section once, in this order, and refuses anything else.
            if section not in (0x02, 0x03, 0x04, 0x05) or section <= last:
                raise ValueError("unexpected 7z header section")
            last = section
            if section == 0x02:  # archive properties
                while reader.byte() != 0:
                    reader.take(reader.number())
            elif section == 0x03:
                _streams_info(reader)
            elif section == 0x04:
                streams = _streams_info(reader)
                listing.encrypted = any(coder_id == _AES for folder in streams.folders
                                        for coder_id, _, _, _ in folder.coders)
                if listing.contents is not None:
                    contents = _extract(data, streams, listing)
            else:
                _files(reader, listing, streams, contents)
    raise ValueError("7z header encoded too many times")
