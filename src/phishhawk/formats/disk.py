"""Disk images mailed as attachments: ISO 9660 (with Joliet names) and
FAT12, FAT16 and FAT32 disk images (.img). Virtual hard disks are in vdisk.

Windows opens them with a double-click, and files inside do not carry the
Mark of the Web, so SmartScreen and Office's macro block never see them.
The directory tree is listed and small files are handed back for the
normal attachment checks; nothing is mounted or written to disk.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

BLOCK = 2048
MAX_FILES = 500
MAX_DEPTH = 8
MAX_FILE_BYTES = 25 * 1024 * 1024
# Directory entries can all point at the same extent, so a 20 MB image could
# otherwise hand back 500 copies of it (10 GB). Past this many bytes in all,
# files are listed without their content.
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_DIRECTORY_BYTES = 16 * 1024 * 1024  # directory records read, all directories together
MAX_FAT_BYTES = 16 * 1024 * 1024  # of the file allocation table: a 32 GB FAT32 volume's


@dataclass
class DiskFile:
    name: str
    size: int
    data: bytes | None  # None when too large to read or out of the image


def is_iso(data: bytes) -> bool:
    return len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001"


def is_fat_image(data: bytes) -> bool:
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return False
    return data[54:59] in (b"FAT12", b"FAT16") or data[82:87] == b"FAT32"


def is_vhd(data: bytes) -> bool:
    return data[:8] == b"vhdxfile" or data[-512:-504] == b"conectix" or data[:8] == b"conectix"


# ---------------------------------------------------------------- ISO 9660 --

def _iso_records(data: bytes, extent: int, size: int):
    start = extent * BLOCK
    end = min(start + size, len(data))
    offset = start
    while offset < end:
        length = data[offset]
        if length == 0:  # records never cross a block: skip to the next one
            offset = (offset // BLOCK + 1) * BLOCK
            continue
        record = data[offset:offset + length]
        if len(record) < 34:
            break
        yield record
        offset += length


def list_iso(data: bytes) -> list[DiskFile]:
    """Files in an ISO 9660 image, by their Joliet names when present."""
    root, joliet = None, False
    for index in range(16, 64):
        descriptor = data[index * BLOCK:(index + 1) * BLOCK]
        if len(descriptor) < 190 or descriptor[1:6] != b"CD001":
            break
        kind = descriptor[0]
        if kind == 255:
            break
        if kind == 1 and root is None:
            root = descriptor[156:190]
        if kind == 2 and descriptor[88:90] == b"%/" and descriptor[90:91] in (b"@", b"C", b"E"):
            root, joliet = descriptor[156:190], True
    if root is None:
        raise ValueError("no ISO 9660 volume descriptor")
    files: list[DiskFile] = []
    seen: set[int] = set()
    budget, directory_budget = MAX_TOTAL_BYTES, MAX_DIRECTORY_BYTES
    stack = [(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "", 0)]
    while stack and len(files) < MAX_FILES and directory_budget > 0:
        extent, size, prefix, depth = stack.pop()
        if extent in seen or depth > MAX_DEPTH:
            continue
        seen.add(extent)
        size = min(size, directory_budget)
        directory_budget -= max(size, BLOCK)
        for record in _iso_records(data, extent, size):
            name_length = record[32]
            raw = record[33:33 + name_length]
            if raw in (b"\x00", b"\x01"):
                continue
            name = raw.decode("utf-16-be" if joliet else "latin-1", errors="replace").split(";", 1)[0]
            name = name.rstrip(".") or "(unnamed)"
            child_extent = struct.unpack_from("<I", record, 2)[0]
            child_size = struct.unpack_from("<I", record, 10)[0]
            path = prefix + name
            if record[25] & 0x02:
                stack.append((child_extent, child_size, path + "/", depth + 1))
                continue
            begin = child_extent * BLOCK
            readable = child_size <= min(MAX_FILE_BYTES, budget) and begin + child_size <= len(data)
            if readable:
                budget -= child_size
            files.append(DiskFile(path, child_size, data[begin:begin + child_size] if readable else None))
            if len(files) >= MAX_FILES:
                break
    return files


# --------------------------------------------------------------------- FAT --

def list_fat(data: bytes) -> list[DiskFile]:
    """Files in a FAT12, FAT16 or FAT32 image: the root directory and its
    subdirectories. `data` is anything that slices like bytes (a partition
    of a virtual disk is read on demand)."""
    head = bytes(data[:512])
    if len(head) < 512:
        raise ValueError("not a FAT image")
    sector_size, cluster_sectors, reserved, fats, root_entries, total16, _, fat_sectors = \
        struct.unpack_from("<HBHBHHBH", head, 11)
    total = total16 or struct.unpack_from("<I", head, 32)[0]
    fat32 = fat_sectors == 0  # FAT32 keeps a 32-bit FAT size, and its root directory in clusters
    root_cluster = 0
    if fat32:
        fat_sectors, = struct.unpack_from("<I", head, 36)
        root_cluster, = struct.unpack_from("<I", head, 44)
    if sector_size not in (512, 1024, 2048, 4096) or not cluster_sectors or not fats or not fat_sectors:
        raise ValueError("not a FAT image")
    fat_start = reserved * sector_size
    fat = bytes(data[fat_start:fat_start + min(fat_sectors * sector_size, MAX_FAT_BYTES)])
    root_start = (reserved + fats * fat_sectors) * sector_size
    root_size = 0 if fat32 else root_entries * 32
    data_start = root_start + ((root_size + sector_size - 1) // sector_size) * sector_size
    cluster_size = cluster_sectors * sector_size
    clusters = max(0, (total * sector_size - data_start) // cluster_size)
    fat12 = not fat32 and clusters < 4085

    def next_cluster(cluster: int) -> int:
        if fat12:
            offset = cluster + cluster // 2
            if offset + 1 >= len(fat):
                return 0xFFF
            value = struct.unpack_from("<H", fat, offset)[0]
            return (value >> 4) if cluster & 1 else (value & 0xFFF)
        if fat32:
            if 4 * cluster + 3 >= len(fat):
                return 0x0FFFFFFF
            return struct.unpack_from("<I", fat, 4 * cluster)[0] & 0x0FFFFFFF
        if 2 * cluster + 1 >= len(fat):
            return 0xFFFF
        return struct.unpack_from("<H", fat, 2 * cluster)[0]

    end_marker = 0xFF8 if fat12 else 0x0FFFFFF8 if fat32 else 0xFFF8

    def read_chain(first: int, size: int) -> bytes | None:
        out, cluster, seen = bytearray(), first, set()
        while 2 <= cluster < end_marker and len(out) < size and cluster not in seen:
            seen.add(cluster)
            offset = data_start + (cluster - 2) * cluster_size
            if offset >= len(data):
                return None
            out += data[offset:offset + cluster_size]
            cluster = next_cluster(cluster)
        return bytes(out[:size])

    def entries(raw: bytes):
        long_name: list[str] = []
        for offset in range(0, len(raw) - 31, 32):
            entry = raw[offset:offset + 32]
            if entry[0] == 0:
                break
            if entry[0] == 0xE5:
                long_name = []
                continue
            if entry[11] == 0x0F:  # a long-file-name piece, stored last piece first
                piece = entry[1:11] + entry[14:26] + entry[28:32]
                long_name.insert(0, piece.decode("utf-16-le", errors="replace").split("\x00", 1)[0])
                continue
            short = entry[:8].decode("latin-1").rstrip() + ("." + entry[8:11].decode("latin-1").rstrip()
                                                            if entry[8:11].strip() else "")
            name = "".join(long_name) or short
            long_name = []
            if entry[11] & 0x08 or name in (".", ".."):
                continue
            cluster = struct.unpack_from("<H", entry, 26)[0]
            if fat32:  # FAT32 keeps the high half of the first cluster number at offset 20
                cluster |= struct.unpack_from("<H", entry, 20)[0] << 16
            yield name.replace("￿", ""), entry[11], cluster, struct.unpack_from("<I", entry, 28)[0]

    files: list[DiskFile] = []
    budget, directory_budget = MAX_TOTAL_BYTES, MAX_DIRECTORY_BYTES
    if fat32:
        root = read_chain(root_cluster, min(1024 * 1024, directory_budget)) or b""
        directory_budget -= max(len(root), cluster_size)
    else:
        root = bytes(data[root_start:root_start + root_size])
    stack = [(root, "", 0)]
    visited: set[int] = {root_cluster} if fat32 else set()
    while stack and len(files) < MAX_FILES:
        raw, prefix, depth = stack.pop()
        for name, attributes, cluster, size in entries(raw):
            if attributes & 0x10:
                if depth < MAX_DEPTH and cluster not in visited and directory_budget > 0:
                    visited.add(cluster)
                    listing = read_chain(cluster, min(1024 * 1024, directory_budget))
                    directory_budget -= max(len(listing or b""), cluster_size)
                    if listing:
                        stack.append((listing, prefix + name + "/", depth + 1))
                continue
            content = read_chain(cluster, size) if size <= min(MAX_FILE_BYTES, budget) else None
            budget -= len(content or b"")
            files.append(DiskFile(prefix + name, size, content))
            if len(files) >= MAX_FILES:
                break
    return files
