"""2.1: virtual hard disks (VHD and VHDX) are opened, partitions and all, and
the files on their FAT and NTFS volumes inspected like any attachment."""

import struct

import pytest

import filebuild as fb
from phishhawk.formats import disk, vdisk
from phishhawk.pipeline import triage_bytes

from conftest import build_eml

SHORTCUT = fb.lnk()
PAYLOAD = b"MZ\x90\x00" + bytes(range(256)) * 60  # non-resident on NTFS: read from clusters


def _disk():
    volume = fb.ntfs({"docs/Invoice.pdf.lnk": SHORTCUT, "setup.exe": PAYLOAD}, directories=("docs",))
    return fb.mbr_disk([(0x07, volume), (0x01, fb.fat12({"invoice.js": b"WScript.Shell" * 10}))])


@pytest.mark.parametrize("wrap", [fb.vhd_fixed, fb.vhd_dynamic, fb.vhdx])
def test_every_layout_gives_the_files_of_every_volume(wrap):
    files = {f.name: f for f in vdisk.list_vhd(wrap(_disk()))}
    assert set(files) == {"partition 1/docs/Invoice.pdf.lnk", "partition 1/setup.exe", "partition 2/INVOICE.JS"}
    assert files["partition 1/setup.exe"].data == PAYLOAD
    assert files["partition 1/docs/Invoice.pdf.lnk"].data == SHORTCUT
    assert files["partition 2/INVOICE.JS"].data == b"WScript.Shell" * 10


def test_a_disk_without_a_partition_table_is_one_volume():
    files = vdisk.list_vhd(fb.vhdx(fb.fat12({"run.bat": b"@echo off"})))
    assert [(f.name, f.data) for f in files] == [("RUN.BAT", b"@echo off")]


def test_gpt_partitions_are_found():
    volume = fb.fat12({"a.exe": b"MZ"})
    raw = bytearray(fb.mbr_disk([(0xEE, b"\0" * 512)]))  # a protective MBR, then GPT at LBA 1
    table_lba, start = 2, 64
    entry = bytes(range(1, 17)) + bytes(16) + struct.pack("<QQ", start, start + len(volume) // 512 - 1)
    header = b"EFI PART" + bytes(64) + struct.pack("<QII", table_lba, 1, 128)
    raw[512:512 + len(header)] = header
    raw[table_lba * 512:table_lba * 512 + len(entry)] = entry
    raw = raw.ljust(start * 512, b"\0")[:start * 512] + volume
    assert [f.name for f in vdisk.list_vhd(fb.vhd_fixed(bytes(raw)))] == ["A.EXE"]


def test_fat32_volumes_are_read():
    # Built by hand: FAT32 keeps the FAT size and root cluster in 32-bit fields, and a
    # file's first cluster in two halves (BIG.EXE starts past cluster 65535).
    sector, reserved, big = 512, 32, 0x10003
    fat = bytearray(-(-4 * (big + 1) // sector) * sector)
    struct.pack_into("<IIII", fat, 0, 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF)  # root at 2, file at 3
    struct.pack_into("<I", fat, 4 * big, 0x0FFFFFFF)
    boot = bytearray(sector)
    data_start = (reserved + len(fat) // sector) * sector
    total = data_start // sector + big
    struct.pack_into("<HBHBHHBHHHII", boot, 11, sector, 1, reserved, 1, 0, 0, 0xF8, 0, 0, 0, 0, total)
    struct.pack_into("<I", boot, 36, len(fat) // sector)
    struct.pack_into("<I", boot, 44, 2)  # the root directory's first cluster
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    root = b"SETUP   EXE\x20" + bytes(8) + struct.pack("<H", 0) + bytes(4) + struct.pack("<HI", 3, 2)
    root += b"BIG     EXE\x20" + bytes(8) + struct.pack("<H", big >> 16) + bytes(4) \
        + struct.pack("<HI", big & 0xFFFF, 2)
    image = bytearray(data_start + (big - 1) * sector)
    image[:sector] = boot
    image[reserved * sector:reserved * sector + len(fat)] = fat
    image[data_start:data_start + len(root)] = root
    image[data_start + sector:data_start + sector + 2] = b"MZ"
    image[data_start + (big - 2) * sector:data_start + (big - 2) * sector + 2] = b"ZM"
    assert [(f.name, f.data) for f in disk.list_fat(bytes(image))] == [("SETUP.EXE", b"MZ"), ("BIG.EXE", b"ZM")]


def test_a_mailed_vhdx_is_opened_and_its_payload_judged():
    raw = build_eml(attachments=[(fb.vhdx(_disk()), "application", "octet-stream", "Invoice.vhdx")])
    a = triage_bytes(raw)
    container = a.attachments[0]
    assert container.archive["kind"] == "VHDX disk image" and container.archive["members"] == 3
    labels = [s.label for s in a.signals if s.severity == "high"]
    assert "disk image Invoice.vhdx delivers 3 file(s) without the Mark of the Web" in labels
    assert any("partition 1/docs/Invoice.pdf.lnk" in label for label in labels)
    assert any(f.filename == "partition 1/setup.exe" and f.true_type == "pe" for f in a.attachments)
    assert a.verdict == "LIKELY PHISHING"


def test_a_differencing_disk_without_its_parent_reads_as_empty():
    data = bytearray(fb.vhd_dynamic(_disk()))
    for at in (60, len(data) - 512 + 60):
        struct.pack_into(">I", data, at, 4)  # differencing: unwritten blocks belong to the parent
    assert [f.name for f in vdisk.list_vhd(bytes(data))]  # the blocks it has are still read


def test_reads_stop_at_the_budget(monkeypatch):
    # A block table can point every entry at one block; each read of it counts.
    monkeypatch.setattr(vdisk, "MAX_READ", 64 * 1024)
    with pytest.raises(ValueError):
        vdisk.list_vhd(fb.vhd_dynamic(_disk()))


def test_an_ntfs_parent_loop_is_skipped_not_followed():
    volume = bytearray(fb.ntfs({"a.exe": b"MZ" * 10}))
    record = 4 * 4096 + 24 * 1024  # record 24: the file
    name_at = volume.index(b"a\x00.\x00e\x00x\x00e\x00", record)
    parent_at = name_at - 66
    volume[parent_at:parent_at + 6] = (24).to_bytes(6, "little")  # its own parent
    assert vdisk.list_ntfs(vdisk.Volume(vdisk._Raw(bytes(volume), len(volume)), 0, len(volume))) == []


@pytest.mark.parametrize("data", [b"conectix" + bytes(600), b"vhdxfile" + bytes(0x50000),
                                  bytes(1024) + b"conectix"])
def test_damaged_disks_raise_value_error(data):
    with pytest.raises(ValueError):
        vdisk.list_vhd(data)
