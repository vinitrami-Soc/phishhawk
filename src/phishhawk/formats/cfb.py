"""Compound File Binary (OLE2) reader: the container behind Outlook .msg
files, legacy Office documents and the objects embedded in RTF and PDF.

Read-only and defensive: every sector chain is checked for loops and for
running off the end of the file, and nothing is read beyond the data given.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAX_ENTRIES = 20_000
MAX_STREAM = 64 * 1024 * 1024


class CfbError(ValueError):
    pass


@dataclass
class Entry:
    index: int
    name: str
    kind: int  # 1 storage, 2 stream, 5 root
    start: int
    size: int
    child: int
    left: int
    right: int
    path: tuple[str, ...] = ()

    @property
    def is_stream(self) -> bool:
        return self.kind == 2

    @property
    def is_storage(self) -> bool:
        return self.kind in (1, 5)


class CompoundFile:
    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or not data.startswith(SIGNATURE):
            raise CfbError("not a compound file")
        try:
            self._load(data)
        except (struct.error, IndexError) as exc:
            raise CfbError("truncated compound file") from exc

    def _load(self, data: bytes) -> None:
        self.data = data
        shift = struct.unpack_from("<H", data, 0x1E)[0]
        mini_shift = struct.unpack_from("<H", data, 0x20)[0]
        if shift not in (9, 12) or mini_shift != 6:
            raise CfbError("unsupported sector size")
        self.sector_size = 1 << shift
        self.mini_size = 1 << mini_shift
        self.mini_cutoff = struct.unpack_from("<I", data, 0x38)[0] or 4096
        self.sector_count = max(0, (len(data) - 512) // self.sector_size + 1)
        self.fat = self._read_fat()
        first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self.entries = self._read_directory(first_dir)
        if not self.entries or self.entries[0].kind != 5:
            raise CfbError("no root entry")
        root = self.entries[0]
        self.mini_stream = self._chain_bytes(root.start, root.size, self.fat, self.sector_size, self._sector)
        first_minifat, minifat_count = struct.unpack_from("<II", data, 0x3C)
        minifat_bytes = self._chain_bytes(first_minifat, minifat_count * self.sector_size, self.fat,
                                          self.sector_size, self._sector) if minifat_count else b""
        usable = len(minifat_bytes) // 4
        self.minifat = list(struct.unpack("<%dI" % usable, minifat_bytes[: usable * 4]))
        self._set_paths()

    # ------------------------------------------------------------- sectors --
    def _sector(self, number: int) -> bytes:
        offset = (number + 1) * self.sector_size
        if number >= self.sector_count or offset >= len(self.data):
            raise CfbError("sector %d outside the file" % number)
        return self.data[offset:offset + self.sector_size]

    def _mini_sector(self, number: int) -> bytes:
        offset = number * self.mini_size
        if offset >= len(self.mini_stream):
            raise CfbError("mini sector outside the mini stream")
        return self.mini_stream[offset:offset + self.mini_size]

    def _chain(self, start: int, table: list[int]) -> list[int]:
        chain, seen = [], set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT) and current < len(table):
            if current in seen:
                raise CfbError("sector chain loops")
            seen.add(current)
            chain.append(current)
            current = table[current]
        return chain

    def _chain_bytes(self, start: int, size: int, table: list[int], unit: int, reader) -> bytes:
        size = min(size, MAX_STREAM)
        if start in (ENDOFCHAIN, FREESECT) or size <= 0:
            return b""
        out = bytearray()
        for number in self._chain(start, table):
            out += reader(number)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _read_fat(self) -> list[int]:
        data = self.data
        fat_count = struct.unpack_from("<I", data, 0x2C)[0]
        difat = [n for n in struct.unpack_from("<109I", data, 0x4C) if n not in (FREESECT, ENDOFCHAIN)]
        next_difat, difat_count = struct.unpack_from("<II", data, 0x44)
        per = self.sector_size // 4
        seen: set[int] = set()
        while next_difat not in (ENDOFCHAIN, FREESECT) and len(seen) < max(difat_count, 1) + 1:
            if next_difat in seen:
                raise CfbError("DIFAT loops")
            seen.add(next_difat)
            values = struct.unpack("<%dI" % per, self._sector(next_difat))
            difat += [n for n in values[:-1] if n not in (FREESECT, ENDOFCHAIN)]
            next_difat = values[-1]
        difat = difat[: min(fat_count, self.sector_count) or len(difat)]
        fat: list[int] = []
        for number in difat:
            fat.extend(struct.unpack("<%dI" % per, self._sector(number)))
        if not fat:
            raise CfbError("empty FAT")
        return fat

    def _read_directory(self, first: int) -> list[Entry]:
        raw = self._chain_bytes(first, MAX_ENTRIES * 128, self.fat, self.sector_size, self._sector)
        entries = []
        for index in range(min(len(raw) // 128, MAX_ENTRIES)):
            chunk = raw[index * 128:(index + 1) * 128]
            name_len = struct.unpack_from("<H", chunk, 64)[0]
            name = chunk[: max(0, min(name_len, 64) - 2)].decode("utf-16-le", errors="replace")
            kind = chunk[66]
            left, right, child = struct.unpack_from("<III", chunk, 68)
            start = struct.unpack_from("<I", chunk, 116)[0]
            size = struct.unpack_from("<Q", chunk, 120)[0]
            if self.sector_size == 512:
                size &= 0xFFFFFFFF
            entries.append(Entry(index, name, kind, start, size, child, left, right))
        return entries

    def _set_paths(self) -> None:
        """Walk the tree of every storage (siblings form a binary tree under
        each storage's child pointer), with a visited set against loops."""
        visited = {0}
        stack = [(self.entries[0].child, ())]
        count = len(self.entries)
        while stack:
            index, parent = stack.pop()
            if index == NOSTREAM or index >= count or index in visited:
                continue
            visited.add(index)
            entry = self.entries[index]
            entry.path = parent + (entry.name,)
            stack.append((entry.left, parent))
            stack.append((entry.right, parent))
            if entry.is_storage:
                stack.append((entry.child, entry.path))

    # ----------------------------------------------------------------- API --
    def streams(self) -> list[Entry]:
        return [e for e in self.entries if e.is_stream and e.path]

    def storages(self) -> list[Entry]:
        return [e for e in self.entries if e.kind == 1 and e.path]

    def find(self, *path: str) -> Entry | None:
        wanted = tuple(part.lower() for part in path)
        for entry in self.entries:
            if entry.path and tuple(p.lower() for p in entry.path) == wanted:
                return entry
        return None

    def read(self, entry: Entry) -> bytes:
        if not entry.is_stream:
            return b""
        if entry.size < self.mini_cutoff:
            return self._chain_bytes(entry.start, entry.size, self.minifat, self.mini_size, self._mini_sector)
        return self._chain_bytes(entry.start, entry.size, self.fat, self.sector_size, self._sector)

    def read_path(self, *path: str) -> bytes | None:
        entry = self.find(*path)
        return self.read(entry) if entry is not None else None
