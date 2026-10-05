"""Sandbox handoff: a password-protected ZIP ("infected") holding the message,
every file pulled out of it and a manifest, for any sandbox to detonate."""

import hashlib
import io
import json
import os
import stat
import zipfile

import pytest

from phishhawk import sandbox
from phishhawk.cli import main
from phishhawk.pipeline import Options, triage_bytes

from conftest import build_eml

PASSWORD = b"infected"


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


INNER = b"MZ\x90\x00 pretend payload " * 20
MESSAGE = build_eml(
    subject="Invoice", sender="<billing@1nvoice-desk.top>",
    html='<p>See attached</p><a href="https://pay.1nvoice-desk.top/view">view</a>'
         '<a href="https://www.microsoft.com/privacy">privacy</a><img src="cid:logo">',
    attachments=[(_zip([("invoice.exe", INNER)]), "application", "zip", "invoice.zip"),
                 (b"\x89PNG\r\n\x1a\n logo", "image", "png", "logo.png", "inline"),
                 (b"%PDF-1.4 notes", "application", "pdf", "../../etc/pass\x00wd.pdf")])


def _analysis(data=MESSAGE):
    return triage_bytes(data, "invoice.eml", Options(keep_files=True))


def _open(path):
    return zipfile.ZipFile(path)


def test_the_pack_holds_the_message_every_file_and_a_manifest(tmp_path):
    a = _analysis()
    path = sandbox.pack(str(tmp_path), MESSAGE, a)
    with _open(path) as archive:
        names = archive.namelist()
        assert "message.eml" in names and "manifest.json" in names and "urls.txt" in names
        assert archive.read("message.eml", pwd=PASSWORD) == MESSAGE
        manifest = json.loads(archive.read("manifest.json", pwd=PASSWORD))
        packed = {entry["filename"]: entry for entry in manifest["files"]}
        assert set(packed) == {"invoice.zip", "invoice.exe", "../../etc/pass\x00wd.pdf"}  # as named, as data
        assert packed["../../etc/pass\x00wd.pdf"]["packed_as"].endswith("-pass_wd.pdf")  # stored under a safe name
        inner = packed["invoice.exe"]
        assert inner["parent"] == "invoice.zip" and inner["sha256"] == hashlib.sha256(INNER).hexdigest()
        assert archive.read(inner["packed_as"], pwd=PASSWORD) == INNER
        assert manifest["password"] == "infected"
        assert manifest["message"]["sha256"] == hashlib.sha256(MESSAGE).hexdigest()


def test_every_member_is_encrypted(tmp_path):
    path = sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    with _open(path) as archive:
        for info in archive.infolist():
            assert info.flag_bits & 0x1, info.filename
        with pytest.raises(RuntimeError):
            archive.read("message.eml")  # no password, no content


def test_names_inside_the_pack_cannot_escape_or_hide(tmp_path):
    path = sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    with _open(path) as archive:
        for name in archive.namelist():
            assert not name.startswith(("/", "..")) and ".." not in name.split("/") and "\x00" not in name
            assert name in ("message.eml", "manifest.json", "urls.txt") or name.startswith("files/")


def test_inline_images_stay_out_and_duplicates_are_packed_once(tmp_path):
    twice = build_eml(attachments=[(b"%PDF-1.4 same", "application", "pdf", "a.pdf"),
                                   (b"%PDF-1.4 same", "application", "pdf", "b.pdf"),
                                   (b"\x89PNG\r\n\x1a\n logo", "image", "png", "logo.png", "inline")])
    path = sandbox.pack(str(tmp_path), twice, _analysis(twice))
    with _open(path) as archive:
        assert len([n for n in archive.namelist() if n.startswith("files/")]) == 1


def test_urls_for_detonation_leave_out_trusted_sites(tmp_path):
    path = sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    with _open(path) as archive:
        lines = archive.read("urls.txt", pwd=PASSWORD).decode().splitlines()
    urls = [line for line in lines if not line.startswith("#")]
    assert urls == ["https://pay.1nvoice-desk.top/view"]


def test_files_past_the_size_cap_are_listed_not_packed(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "MAX_PACK", 300)
    path = sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    with _open(path) as archive:
        manifest = json.loads(archive.read("manifest.json", pwd=PASSWORD))
    assert manifest["not_packed"]
    assert all("size" in entry["reason"] for entry in manifest["not_packed"])


def test_the_pack_is_private_and_named_by_the_message_hash(tmp_path):
    path = sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    assert os.path.basename(path) == hashlib.sha256(MESSAGE).hexdigest() + ".zip"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_symlink_where_the_pack_goes_is_refused(tmp_path):
    target = tmp_path / "elsewhere"
    os.symlink(target, tmp_path / (hashlib.sha256(MESSAGE).hexdigest() + ".zip"))
    with pytest.raises(sandbox.SandboxError):
        sandbox.pack(str(tmp_path), MESSAGE, _analysis())
    assert not target.exists()


def test_without_keep_files_no_bytes_are_held():
    a = triage_bytes(MESSAGE, "x.eml")
    assert "_files" not in a.__dict__


def test_scan_writes_a_pack_and_keeps_bytes_out_of_the_report(tmp_path, capsys):
    message = tmp_path / "invoice.eml"
    message.write_bytes(MESSAGE)
    packs = tmp_path / "packs"
    report = tmp_path / "r.json"
    main([str(message), "--offline", "--no-color", "--quiet", "--sandbox", str(packs), "--json", str(report)])
    assert os.listdir(packs) == [hashlib.sha256(MESSAGE).hexdigest() + ".zip"]
    assert "_files" not in report.read_text() and "pretend payload" not in report.read_text()
    assert "sandbox pack" in capsys.readouterr().err
