"""Test helpers that write compound files and Outlook .msg files, so the
readers are tested without shipping anyone's real mail."""

from __future__ import annotations

import struct

SECTOR, MINI, CUTOFF = 512, 64, 4096
END, FREE, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def write_cfb(streams: dict[tuple[str, ...], bytes]) -> bytes:
    """A version-3 compound file holding `streams` ({path: data})."""
    storages: list[tuple[str, ...]] = [()]
    for path in streams:
        for depth in range(1, len(path)):
            if path[:depth] not in storages:
                storages.append(path[:depth])
    nodes = [("Root Entry", 5, ())] + [(p[-1], 1, p) for p in storages[1:]] + [(p[-1], 2, p) for p in streams]
    children: dict[tuple[str, ...], list[int]] = {}
    for i, (_, _, path) in enumerate(nodes[1:], 1):
        children.setdefault(path[:-1], []).append(i)

    mini, big = bytearray(), []
    mini_fat: list[int] = []
    placement: dict[int, tuple[int, int]] = {}  # node -> (start, size), big streams placed later
    for i, (_, kind, path) in enumerate(nodes):
        if kind != 2:
            continue
        data = streams[path]
        if len(data) < CUTOFF:
            start = len(mini) // MINI
            count = max(1, -(-len(data) // MINI)) if data else 0
            if count:
                mini_fat += [start + k + 1 for k in range(count - 1)] + [END]
                mini += data.ljust(count * MINI, b"\0")
            placement[i] = (start if count else END, len(data))
        else:
            big.append((i, data))

    def sectors(size: int) -> int:
        return -(-size // SECTOR)

    dir_bytes = len(nodes) * 128
    minifat_bytes = len(mini_fat) * 4
    payload = [sectors(dir_bytes), sectors(minifat_bytes), sectors(len(mini))] + [sectors(len(d)) for _, d in big]
    fat_sectors = 1
    while (fat_sectors + sum(payload)) > fat_sectors * (SECTOR // 4):
        fat_sectors += 1
    fat = [FATSECT] * fat_sectors
    starts = []
    for count in payload:
        starts.append(len(fat) if count else END)
        fat += [len(fat) + k + 1 for k in range(count - 1)] + ([END] if count else [])
    fat += [FREE] * (fat_sectors * (SECTOR // 4) - len(fat))
    dir_start, minifat_start, ministream_start = starts[:3]
    for (i, data), start in zip(big, starts[3:], strict=True):
        placement[i] = (start, len(data))

    entries = bytearray()
    for i, (name, kind, path) in enumerate(nodes):
        siblings = children.get(path[:-1], []) if i else []
        position = siblings.index(i) if i else 0
        right = siblings[position + 1] if i and position + 1 < len(siblings) else NOSTREAM
        kids = children.get(path, []) if kind in (1, 5) else []
        start, size = (ministream_start, len(mini)) if kind == 5 else placement.get(i, (END, 0))
        encoded = (name + "\0").encode("utf-16-le")[:64]
        entries += encoded.ljust(64, b"\0") + struct.pack("<HBBIII", len(encoded), kind, 1, NOSTREAM, right,
                                                         kids[0] if kids else NOSTREAM)
        entries += b"\0" * 16 + b"\0" * 4 + b"\0" * 16 + struct.pack("<IQ", start if kind != 1 else 0, size)
    header = bytearray(SECTOR)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIII", header, 0x2C, fat_sectors, dir_start, 0, CUTOFF)
    struct.pack_into("<IIII", header, 0x3C, minifat_start if mini_fat else END, sectors(minifat_bytes), END, 0)
    difat = list(range(fat_sectors)) + [FREE] * (109 - fat_sectors)
    struct.pack_into("<109I", header, 0x4C, *difat)
    body = struct.pack("<%dI" % len(fat), *fat)
    for blob in (bytes(entries), struct.pack("<%dI" % len(mini_fat), *mini_fat), bytes(mini)):
        body += blob.ljust(sectors(len(blob)) * SECTOR, b"\0")
    for _, data in big:
        body += data.ljust(sectors(len(data)) * SECTOR, b"\0")
    return bytes(header) + body


def _text(prop: int, value: str) -> tuple[str, bytes]:
    return "__substg1.0_%04X001F" % prop, value.encode("utf-16-le")


def _message_streams(prefix: tuple[str, ...], fields: dict, embedded: bool) -> dict[tuple[str, ...], bytes]:
    out: dict[tuple[str, ...], bytes] = {}
    fixed = b""
    if fields.get("submit_ticks"):
        fixed += struct.pack("<IIQ", (0x0039 << 16) | 0x0040, 2, fields["submit_ticks"])
    out[prefix + ("__properties_version1.0",)] = b"\0" * (24 if embedded else 32) + fixed
    for prop, key in ((0x0037, "subject"), (0x007D, "headers"), (0x1000, "body"), (0x0C1A, "sender_name"),
                      (0x0C1F, "sender")):
        if fields.get(key):
            name, data = _text(prop, fields[key])
            out[prefix + (name,)] = data
    if fields.get("html"):
        out[prefix + ("__substg1.0_10130102",)] = fields["html"].encode("utf-8")
    if fields.get("rtf"):
        out[prefix + ("__substg1.0_10090102",)] = fields["rtf"]
    for n, (display, address) in enumerate(fields.get("to", [])):
        storage = prefix + ("__recip_version1.0_#%08X" % n,)
        out[storage + ("__properties_version1.0",)] = b"\0" * 8 + struct.pack("<IIQ", (0x0C15 << 16) | 3, 2, 1)
        for prop, value in ((0x3001, display), (0x39FE, address)):
            name, data = _text(prop, value)
            out[storage + (name,)] = data
    for n, attachment in enumerate(fields.get("attachments", [])):
        storage = prefix + ("__attach_version1.0_#%08X" % n,)
        out[storage + ("__properties_version1.0",)] = b"\0" * 8
        name, data = _text(0x3707, attachment["name"])
        out[storage + (name,)] = data
        if "message" in attachment:
            out.update(_message_streams(storage + ("__substg1.0_3701000D",), attachment["message"], True))
        else:
            out[storage + ("__substg1.0_37010102",)] = attachment["data"]
            if attachment.get("mime"):
                name, data = _text(0x370E, attachment["mime"])
                out[storage + (name,)] = data
    return out


def build_msg(**fields) -> bytes:
    """An Outlook .msg. fields: subject, headers, body, html, rtf, sender,
    sender_name, to [(name, address)], attachments [{name, data, mime} or
    {name, message: {fields}}], submit_ticks."""
    return write_cfb(_message_streams((), fields, embedded=False))
