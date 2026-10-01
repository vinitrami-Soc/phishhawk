"""Virtual hard disks (VHD and VHDX) mailed as attachments.

Windows mounts them with a double-click and, like ISO images, the files
inside carry no Mark of the Web. This reads them in memory: the fixed,
dynamic and differencing VHD layouts and VHDX, the partition table (MBR or
GPT), and the files on each FAT or NTFS volume. Nothing is mounted, and the
disk is never assembled: a 2 TB virtual disk costs what its file costs.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from .disk import MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, DiskFile, list_fat

SECTOR = 512
# Every read from the disk counts against this, so no layout (a block table
# pointing every entry at one block, say) can make a small file expensive.
MAX_READ = 256 * 1024 * 1024
MAX_BAT_BYTES = 16 * 1024 * 1024
MAX_PARTITIONS = 16
MAX_MFT_RECORDS = 16384
MAX_PATH_DEPTH = 32


class DiskView:
    """Bytes of a virtual disk by offset, read from the file on demand."""

    def __init__(self, size: int, sector: int = SECTOR) -> None:
        self.size, self.sector = size, sector
        self.budget = MAX_READ

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative disk offset")
        length = max(0, min(length, self.size - offset))
        self.charge(length)
        return self._read(offset, length) if length else b""

    def charge(self, length: int) -> None:
        """Count bytes produced from this disk, read or not (a hole in a file)."""
        self.budget -= length
        if self.budget < 0:
            raise ValueError("virtual disk read budget exhausted")

    def _read(self, offset: int, length: int) -> bytes:
        raise NotImplementedError


class _Raw(DiskView):
    def __init__(self, data: bytes, size: int) -> None:
        super().__init__(min(size, len(data)))
        self.data = data

    def _read(self, offset: int, length: int) -> bytes:
        return self.data[offset:offset + length]


class _Blocks(DiskView):
    """A disk stored as a table of fixed-size blocks, some never written. The
    table is read entry by entry as blocks are needed, never all at once."""

    def __init__(self, data: bytes, size: int, block_size: int, locate: Callable[[int], int | None],
                 sector: int = SECTOR) -> None:
        super().__init__(size, sector)
        self.data, self.block_size, self.locate = data, block_size, locate

    def _read(self, offset: int, length: int) -> bytes:
        out = bytearray()
        while length > 0:
            index, within = divmod(offset, self.block_size)
            take = min(length, self.block_size - within)
            start = self.locate(index)
            if start is None:
                out += bytes(take)  # never written: reads as zeros
            else:
                piece = self.data[start + within:start + within + take]
                out += piece + bytes(take - len(piece))
            offset += take
            length -= take
        return bytes(out)


class Volume:
    """One partition of a disk, sliceable like bytes (what disk.list_fat reads)."""

    def __init__(self, view: DiskView, start: int, length: int) -> None:
        self.view, self.start, self.length = view, start, max(0, min(length, view.size - start))

    def __len__(self) -> int:
        return self.length

    def __getitem__(self, item: slice) -> bytes:
        if not isinstance(item, slice) or item.step not in (None, 1):
            raise TypeError("volumes are read by slice")
        begin, end, _ = item.indices(self.length)
        return self.view.read(self.start + begin, max(0, end - begin))


# --------------------------------------------------------------------- VHD --

def _vhd(data: bytes) -> DiskView:
    if data[-512:-504] == b"conectix":
        footer = data[-512:]
    elif data[:8] == b"conectix":
        footer = data[:512]
    else:
        raise ValueError("no VHD footer")
    size = struct.unpack_from(">Q", footer, 48)[0]
    kind = struct.unpack_from(">I", footer, 60)[0]
    if kind == 2:  # fixed: the disk, then the footer
        return _Raw(data, min(size, len(data) - 512))
    if kind not in (3, 4):  # 3 dynamic, 4 differencing (its parent is not in the mail)
        raise ValueError("unsupported VHD type %d" % kind)
    header_at = struct.unpack_from(">Q", footer, 16)[0]
    header = data[header_at:header_at + 1024]
    if len(header) < 1024 or header[:8] != b"cxsparse":
        raise ValueError("no VHD dynamic header")
    table_at, = struct.unpack_from(">Q", header, 16)
    entries, block_size = struct.unpack_from(">II", header, 28)
    if not 4096 <= block_size <= 256 * 1024 * 1024 or block_size & (block_size - 1) or \
            entries * 4 > MAX_BAT_BYTES:
        raise ValueError("implausible VHD block table")
    bitmap = -(-block_size // SECTOR // 8 // SECTOR) * SECTOR  # each block starts with a sector bitmap

    def locate(index: int) -> int | None:
        at = table_at + 4 * index
        if index >= entries or at + 4 > len(data):
            return None
        sector = struct.unpack_from(">I", data, at)[0]
        return None if sector == 0xFFFFFFFF else sector * SECTOR + bitmap

    return _Blocks(data, min(size, entries * block_size), block_size, locate)


# -------------------------------------------------------------------- VHDX --

_BAT = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08").bytes_le
_METADATA = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
_FILE_PARAMETERS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
_DISK_SIZE = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8").bytes_le
_LOGICAL_SECTOR = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F").bytes_le


def _vhdx(data: bytes) -> DiskView:
    regions: dict[bytes, tuple[int, int]] = {}
    for table_at in (0x30000, 0x40000):  # two copies of the region table
        table = data[table_at:table_at + 0x10000]
        if table[:4] != b"regi":
            continue
        count = min(struct.unpack_from("<I", table, 8)[0], 2047)
        for index in range(count):
            entry = table[16 + 32 * index:48 + 32 * index]
            if len(entry) == 32:
                regions.setdefault(entry[:16], struct.unpack_from("<QI", entry, 16))
        break
    if _BAT not in regions or _METADATA not in regions:
        raise ValueError("no VHDX region table")
    meta_at, meta_length = regions[_METADATA]
    meta = data[meta_at:meta_at + min(meta_length, 1024 * 1024)]
    if meta[:8] != b"metadata":
        raise ValueError("no VHDX metadata")
    items: dict[bytes, bytes] = {}
    for index in range(min(struct.unpack_from("<H", meta, 10)[0], 2047)):
        entry = meta[32 + 32 * index:64 + 32 * index]
        if len(entry) == 32:
            offset, length = struct.unpack_from("<II", entry, 16)
            items[entry[:16]] = meta[offset:offset + min(length, 64)]
    try:
        block_size = struct.unpack_from("<I", items[_FILE_PARAMETERS])[0]
        size = struct.unpack_from("<Q", items[_DISK_SIZE])[0]
        sector = struct.unpack_from("<I", items[_LOGICAL_SECTOR])[0]
    except (KeyError, struct.error) as exc:
        raise ValueError("incomplete VHDX metadata") from exc
    if not 1024 * 1024 <= block_size <= 256 * 1024 * 1024 or block_size & (block_size - 1) \
            or sector not in (512, 4096):
        raise ValueError("implausible VHDX parameters")
    chunk = (1 << 23) * sector // block_size  # payload blocks per sector-bitmap block
    payload = -(-size // block_size)
    bat_at, bat_length = regions[_BAT]
    entries = payload + (payload - 1) // chunk if payload else 0
    if entries * 8 > min(bat_length, MAX_BAT_BYTES):
        raise ValueError("implausible VHDX block table")

    def locate(index: int) -> int | None:
        at = bat_at + 8 * (index + index // chunk)  # a sector-bitmap entry follows every `chunk` blocks
        if index >= payload or at + 8 > len(data):
            return None
        value = struct.unpack_from("<Q", data, at)[0]
        return (value >> 20) * 1024 * 1024 if value & 7 in (6, 7) else None  # fully or partly present

    return _Blocks(data, size, block_size, locate, sector)


def open_disk(data: bytes) -> DiskView:
    """A VHD or VHDX file as the disk it holds."""
    if data[:8] == b"vhdxfile":
        return _vhdx(data)
    return _vhd(data)


# -------------------------------------------------------------- partitions --

_BASIC_DATA_TYPES = {0x01, 0x04, 0x06, 0x07, 0x0B, 0x0C, 0x0E, 0x17, 0x1B, 0x1C, 0x1E, 0x27}


def _is_volume(boot: bytes) -> bool:
    return boot[3:11] == b"NTFS    " or boot[54:59] in (b"FAT12", b"FAT16") or boot[82:87] == b"FAT32"


def partitions(view: DiskView) -> list[Volume]:
    """The data partitions of a disk: MBR or GPT, or one volume filling a disk
    with no partition table (a "superfloppy")."""
    first = view.read(0, SECTOR)
    if _is_volume(first):
        return [Volume(view, 0, view.size)]
    if first[510:512] != b"\x55\xaa":
        return []
    entries = [first[446 + 16 * i:462 + 16 * i] for i in range(4)]
    if any(entry[4] == 0xEE for entry in entries):
        return _gpt(view)
    out = []
    for entry in entries:
        kind = entry[4]
        start, count = struct.unpack_from("<II", entry, 8)
        if kind in _BASIC_DATA_TYPES and count:  # counted in the disk's own sectors (4096 bytes on 4K disks)
            out.append(Volume(view, start * view.sector, count * view.sector))
    return out


def _gpt(view: DiskView) -> list[Volume]:
    header = view.read(view.sector, 92)
    if header[:8] != b"EFI PART":
        return []
    table_lba, count, size = struct.unpack_from("<QII", header, 72)
    if not 128 <= size <= 1024 or count > 1024:
        return []
    table = view.read(table_lba * view.sector, min(count, 256) * size)
    out = []
    for index in range(len(table) // size):
        entry = table[index * size:index * size + size]
        if entry[:16] == bytes(16):
            continue
        first, last = struct.unpack_from("<QQ", entry, 32)
        if last >= first:
            out.append(Volume(view, first * view.sector, (last - first + 1) * view.sector))
        if len(out) >= MAX_PARTITIONS:
            break
    return out


# -------------------------------------------------------------------- NTFS --

@dataclass
class _Record:
    name: str = ""
    namespace: int = 99
    parent: int = -1
    directory: bool = False
    size: int = 0
    resident: bytes | None = None
    runs: list[tuple[int | None, int]] = field(default_factory=list)
    unreadable: bool = False  # compressed, encrypted or split across records


def _runs(data: bytes, offset: int) -> list[tuple[int | None, int]]:
    """An attribute's data runs: (first cluster or None for a hole, clusters)."""
    out: list[tuple[int | None, int]] = []
    lcn = 0
    while offset < len(data) and data[offset] and len(out) < 4096:
        header = data[offset]
        length_size, offset_size = header & 0x0F, header >> 4
        if not 1 <= length_size <= 8 or offset_size > 8:
            raise ValueError("corrupt NTFS data runs")
        length = int.from_bytes(data[offset + 1:offset + 1 + length_size], "little")
        offset += 1 + length_size
        if offset_size:
            lcn += int.from_bytes(data[offset:offset + offset_size], "little", signed=True)
            out.append((lcn, length))
        else:
            out.append((None, length))
        offset += offset_size
    return out


FIXUP_STRIDE = 512  # update sequences step in 512 bytes, whatever the sector size


def _fixup(record: bytes) -> bytes | None:
    """Undo the update sequence: the last two bytes of each 512-byte stride
    were swapped for a check value when the record was written."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 2 or usa_offset + 2 * usa_count > len(record):
        return None
    fixed = bytearray(record)
    check = record[usa_offset:usa_offset + 2]
    for index in range(1, usa_count):
        end = index * FIXUP_STRIDE
        if end > len(fixed) or fixed[end - 2:end] != check:
            return None
        fixed[end - 2:end] = record[usa_offset + 2 * index:usa_offset + 2 * index + 2]
    return bytes(fixed)


def _parse_record(raw: bytes) -> _Record | None:
    """A file record, or None when it is unused or damaged: one torn record
    must not hide the rest of the volume."""
    if raw[:4] != b"FILE" or len(raw) < 48:
        return None
    record = _fixup(raw)
    if record is None:
        return None
    try:
        return _read_attributes(record)
    except (struct.error, IndexError):
        return None


def _read_attributes(record: bytes) -> _Record | None:
    flags = struct.unpack_from("<H", record, 22)[0]
    if not flags & 0x01:  # not in use
        return None
    out = _Record(directory=bool(flags & 0x02))
    position = struct.unpack_from("<H", record, 20)[0]
    for _ in range(64):
        if position + 16 > len(record):
            break
        kind, length = struct.unpack_from("<II", record, position)
        if kind == 0xFFFFFFFF or length < 16 or position + length > len(record):
            break
        attribute = record[position:position + length]
        resident = attribute[8] == 0
        name_length = attribute[9]
        if kind == 0x20:  # an attribute list: the data may live in other records
            out.unreadable = True
        elif kind == 0x30 and resident:
            content_length, content_at = struct.unpack_from("<IH", attribute, 16)
            content = attribute[content_at:content_at + content_length]
            if len(content) >= 66:
                namespace = content[65]
                name = content[66:66 + 2 * content[64]].decode("utf-16-le", errors="replace")
                if namespace != 2 and (out.namespace == 2 or out.namespace == 99 or not out.name):
                    out.name, out.namespace = name, namespace  # prefer the long name to the 8.3 one
                elif not out.name:
                    out.name, out.namespace = name, namespace
                out.parent = struct.unpack_from("<Q", content, 0)[0] & 0xFFFFFFFFFFFF
        elif kind == 0x80 and name_length == 0:  # the unnamed data stream: the file's content
            attribute_flags = struct.unpack_from("<H", attribute, 12)[0]
            if resident:
                content_length, content_at = struct.unpack_from("<IH", attribute, 16)
                out.resident = attribute[content_at:content_at + content_length]
                out.size = len(out.resident)
            else:
                start_vcn = struct.unpack_from("<Q", attribute, 16)[0]
                runs_at = struct.unpack_from("<H", attribute, 32)[0]
                if start_vcn == 0:
                    out.size = struct.unpack_from("<Q", attribute, 48)[0]
                    try:
                        out.runs = _runs(attribute, runs_at)
                    except ValueError:
                        out.unreadable = True
                else:
                    out.unreadable = True
                if attribute_flags & 0x4001:  # encrypted or compressed; a sparse file reads, holes as zeros
                    out.unreadable = True
        position += length
    return out


def _read_runs(volume: Volume, runs: list[tuple[int | None, int]], cluster: int, size: int) -> bytes:
    out = bytearray()
    for lcn, length in runs:
        if len(out) >= size:
            break
        take = min(length * cluster, size - len(out))
        if lcn is None:  # a hole: zeros, which cost what reading them would
            volume.view.charge(take)
            out += bytes(take)
        else:
            out += volume[lcn * cluster:lcn * cluster + take].ljust(take, b"\0")
    return bytes(out[:size])


def list_ntfs(volume: Volume, budget: int | None = None) -> list[DiskFile]:
    """Files on an NTFS volume, found through the master file table.
    `budget` caps the bytes of file content read (MAX_TOTAL_BYTES by default)."""
    boot = volume[0:512]
    if boot[3:11] != b"NTFS    ":
        raise ValueError("not an NTFS volume")
    sector = struct.unpack_from("<H", boot, 11)[0]
    per_cluster = boot[13] if boot[13] <= 128 else 1 << (256 - boot[13])
    cluster = sector * per_cluster
    mft_lcn = struct.unpack_from("<Q", boot, 48)[0]
    per_record = struct.unpack_from("<b", boot, 64)[0]
    record_size = cluster * per_record if per_record > 0 else 1 << -per_record
    if sector not in (512, 1024, 2048, 4096) or not 0 < cluster <= 2 * 1024 * 1024 or \
            record_size not in (1024, 2048, 4096):
        raise ValueError("implausible NTFS boot sector")
    first = _parse_record(volume[mft_lcn * cluster:mft_lcn * cluster + record_size])
    if first is None or not first.runs:
        raise ValueError("unreadable NTFS master file table")
    records: dict[int, _Record] = {}
    number = 0
    for lcn, length in first.runs:
        count = length * cluster // record_size
        if lcn is None:  # a hole in the table
            number += count
            continue
        for index in range(min(count, MAX_MFT_RECORDS - number)):
            at = lcn * cluster + index * record_size
            parsed = _parse_record(volume[at:at + record_size])
            if parsed is not None and parsed.name:
                records[number + index] = parsed
        number += count
        if number >= MAX_MFT_RECORDS:
            break

    def path(number: int) -> str | None:
        parts: list[str] = []
        seen: set[int] = set()
        while number != 5:  # record 5 is the root directory
            record = records.get(number)
            if record is None or number in seen or len(parts) > MAX_PATH_DEPTH:
                return None
            seen.add(number)
            parts.append(record.name)
            number = record.parent
        return "/".join(reversed(parts))

    files: list[DiskFile] = []
    budget = MAX_TOTAL_BYTES if budget is None else budget
    for number in sorted(records):
        record = records[number]
        if record.directory or number < 24:  # the file system's own files
            continue
        where = path(number)
        if not where or where.startswith("$"):
            continue
        content: bytes | None = None
        if not record.unreadable and record.size <= min(MAX_FILE_BYTES, budget):
            content = record.resident if record.resident is not None else \
                _read_runs(volume, record.runs, cluster, record.size)
            budget -= len(content)
        files.append(DiskFile(where, record.size, content))
        if len(files) >= MAX_FILES:
            break
    return files


# ----------------------------------------------------------------- listing --

@dataclass
class VirtualDisk:
    files: list[DiskFile]
    read: int  # bytes read from the disk (or made up for its holes)
    damaged: list[str] = field(default_factory=list)  # "partition 2: why", for each volume not read


def list_vhd(data: bytes) -> list[DiskFile]:
    """The files on every FAT or NTFS volume of a VHD or VHDX disk. A
    damaged disk raises ValueError."""
    return read_vhd(data).files


def read_vhd(data: bytes, budget: int = MAX_READ) -> VirtualDisk:
    """The files on every FAT or NTFS volume of a VHD or VHDX disk, what
    reading them cost (at most `budget` bytes), and the volumes that could
    not be read. A disk none of whose volumes can be read raises ValueError."""
    try:
        return _read_vhd(data, min(budget, MAX_READ))
    except (struct.error, IndexError, OverflowError) as exc:
        raise ValueError("damaged virtual disk (%s)" % type(exc).__name__) from exc


def _read_vhd(data: bytes, budget: int) -> VirtualDisk:
    view = open_disk(data)
    view.budget = budget
    volumes = partitions(view)
    disk = VirtualDisk([], 0)
    # One budget for the whole disk: every partition entry could name the same
    # volume, and a file's holes read as zeros without touching the disk.
    content = min(MAX_TOTAL_BYTES, budget)
    failure: Exception | None = None
    read_one = False
    for number, volume in enumerate(volumes, 1):
        try:
            boot = volume[0:512]
            if boot[3:11] == b"NTFS    ":
                found = list_ntfs(volume, content)
            elif boot[54:59] in (b"FAT12", b"FAT16") or boot[82:87] == b"FAT32":
                found = list_fat(volume, content)  # type: ignore[arg-type]  # a Volume slices like bytes
            else:
                continue
        except (ValueError, struct.error, IndexError, OverflowError) as exc:
            failure = exc  # a damaged volume does not hide the others
            disk.damaged.append("partition %d: %s" % (number, str(exc)[:80] or type(exc).__name__))
            continue
        read_one = True
        content -= sum(len(item.data) for item in found if item.data is not None)
        prefix = "partition %d/" % number if len(volumes) > 1 else ""
        disk.files += [DiskFile(prefix + item.name, item.size, item.data) for item in found]
        if len(disk.files) >= MAX_FILES:
            break
    disk.read = budget - view.budget
    if failure is not None and not read_one:
        raise failure
    disk.files = disk.files[:MAX_FILES]
    return disk
