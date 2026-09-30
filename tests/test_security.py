"""PhishHawk attacked the way a bug-bounty hunter would: every test here was
an exploit against 1.2.0 that now fails. Input is attacker-controlled, and so
is anything a report shows from it."""

import base64
import os
import re
import stat
import struct
import sys
import time
from email.message import EmailMessage

import pytest

from phishhawk.cache import Cache
from phishhawk.cli import main
from phishhawk.enrich import redact_recipients
from phishhawk.lookalike import find_lookalikes
from phishhawk.parse import parse_bytes
from phishhawk.pipeline import Options, triage_bytes, triage_file
from phishhawk.report import console, csvout, html, markdown

from conftest import build_eml, sample

OSC_CLIPBOARD = "\x1b]52;c;ZWNobyBwd25lZA==\x07"
LURE = "[Pay now](https://evil-pay.top/p) ![](https://evil-pay.top/seen.png) <b>x</b>"
HOSTILE = build_eml(
    subject="Invoice %s %s" % (OSC_CLIPBOARD, LURE),
    sender='"Micro\x1b[2J\x1b]8;;https://evil.top/\x07SOFT" <billing@evil-pay.top>',
    html='<a href="https://evil-pay.top/login">https://microsoft.com</a>',
    attachments=[(b"MZ", "application", "octet-stream", "invoice‮fdp.exe")])


def own_colour_removed(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# ------------------------------------------------------------ output injection --

def test_attacker_text_cannot_drive_the_terminal():
    a = triage_bytes(HOSTILE)
    for rendered in (console.render(a, console.Palette(True), verbose=True),
                     console.render_quiet(a, console.Palette(True)),
                     console.render_batch_table([a, a], console.Palette(True))):
        assert "\x1b" not in own_colour_removed(rendered) and "\x07" not in rendered
    assert "\\x1b]52;c;" in console.render(a, console.Palette(False))  # shown, not executed


def test_a_right_to_left_override_is_named_not_obeyed():
    a = triage_bytes(HOSTILE)
    assert "invoice<U+202E>fdp.exe" in console.render(a, console.Palette(False))
    assert "invoice&lt;U+202E&gt;fdp.exe" in html.render([a])
    assert "T1036.002" in a.techniques  # the detection still sees the real name


def test_the_markdown_ticket_has_no_live_links_images_or_html():
    note = markdown.render(triage_bytes(HOSTILE))
    subject_line = next(line for line in note.splitlines() if line.startswith("| **Subject**"))
    assert "](" not in subject_line and "<b>" not in subject_line and "https://" not in subject_line
    assert "hxxps://evil-pay.top/p" in subject_line


def test_csv_cells_carry_no_control_characters():
    out = csvout.render([triage_bytes(HOSTILE)])
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)


# ------------------------------------------------------- forged authentication --

MX = ("Authentication-Results", "mx.acme-labs.example; spf=fail smtp.mailfrom=evil.top; dkim=none")
RECEIVED = ("Received", "from evil.top by mx.acme-labs.example; Tue, 29 Sep 2026 10:00:00 +0000")


def test_a_pass_forged_below_the_receivers_results_is_ignored_and_flagged():
    forged = ("Authentication-Results", "mx.acme-labs.example; spf=pass; dkim=pass; dmarc=pass")
    a = triage_bytes(build_eml(headers=[MX, RECEIVED, forged]))
    assert a.auth == {"spf": "fail", "dkim": "none"}
    labels = [(s.severity, s.label) for s in a.signals if "Authentication-Results" in s.label]
    assert labels == [("medium", "forged Authentication-Results: spf=pass, dkim=pass, dmarc=pass claimed in "
                                 "the name of mx.acme-labs.example, below that server's real results (ignored)")]


def test_an_upstream_servers_pass_is_ignored_but_only_noted():
    upstream = ("Authentication-Results", "relay.partner.example; dmarc=pass")
    a = triage_bytes(build_eml(headers=[MX, RECEIVED, upstream]))
    assert "dmarc" not in a.auth
    assert [s.severity for s in a.signals if "Authentication-Results" in s.label] == ["low"]


def test_one_header_per_check_from_the_same_server_is_read_in_full():
    proton = [("Authentication-Results", "mailin1.protonmail.ch; dkim=pass header.d=a.example"),
              ("Authentication-Results", "mailin1.protonmail.ch; dmarc=none"),
              ("Authentication-Results", "mailin1.protonmail.ch; spf=pass smtp.mailfrom=a.example"), RECEIVED]
    assert triage_bytes(build_eml(headers=proton)).auth == {"dkim": "pass", "dmarc": "none", "spf": "pass"}


def test_trusted_authserv_believes_only_your_own_server():
    forged_only = [RECEIVED, ("Authentication-Results", "mx.google.com; spf=pass; dkim=pass; dmarc=pass")]
    assert triage_bytes(build_eml(headers=forged_only)).auth["dmarc"] == "pass"  # nothing to compare with
    trusted = Options(trusted_authserv=["mx.acme-labs.example"])
    assert triage_bytes(build_eml(headers=forged_only), options=trusted).auth == {}


# ------------------------------------------------------------ unwrap evasion --

def test_a_phish_carrying_a_harmless_attached_message_is_still_caught():
    inner = EmailMessage()
    inner["From"], inner["Subject"] = "colleague@acme-labs.example", "Lunch?"
    inner.set_content("Lunch on Friday?")
    outer = EmailMessage()
    outer["From"] = '"Microsoft 365" <no-reply@micros0ft-verify.top>'
    outer["To"], outer["Subject"] = "victim@acme-labs.example", "Your password expires today"
    outer.set_content("Your password expires today. Keep it: https://micros0ft-verify.top/login")
    outer.add_attachment(inner)
    a = triage_bytes(outer.as_bytes())
    assert a.subject == "Lunch?"  # the attached message is still what is shown...
    assert a.verdict != "NO STRONG INDICATORS"  # ...but the carrier's findings count
    assert any(s.label.startswith("carrier email: ") for s in a.signals)
    assert any("micros0ft-verify.top" in u.url for u in a.urls)


def test_a_genuine_report_gains_nothing_from_the_reporters_note():
    a = triage_file(sample("sample_reported.eml"))
    assert a.reported_by and not any(s.label.startswith("carrier email") for s in a.signals)


# ---------------------------------------------------------- lookalike evasion --

@pytest.mark.parametrize("domain, method", [
    ("paypal-com.top", "combosquat"), ("www-paypal.com", "combosquat"),
    ("paypalcom.top", "combosquat"), ("micros-oft.com", "typosquat"),
])
def test_spelled_out_and_hyphen_split_names_are_found(domain, method):
    assert ("microsoft.com" if "micro" in domain else "paypal.com", method) in \
        [(h.target, h.method) for h in find_lookalikes(domain, "url", [])]


def test_a_hyphen_split_own_domain_is_found():
    hits = find_lookalikes("examplecorp.co.uk", "sender", ["example-corp.co.uk"])
    assert [(h.target, h.method) for h in hits] == [("example-corp.co.uk", "typosquat")]


# ------------------------------------------------------------ hostile files --

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_fifos_devices_and_huge_files_are_skipped_quickly(tmp_path, capsys):
    os.mkfifo(tmp_path / "fifo.eml")
    (tmp_path / "zero.eml").symlink_to("/dev/zero")
    (tmp_path / "big.eml").write_bytes(b"\0" * (2 * 1024 * 1024 + 1))
    with open(sample("sample_benign.eml"), "rb") as handle:
        (tmp_path / "ok.eml").write_bytes(handle.read())
    started = time.perf_counter()
    assert main([str(tmp_path), "--offline", "--no-color", "--quiet", "--max-size", "2"]) == 3
    assert time.perf_counter() - started < 20
    captured = capsys.readouterr()
    assert "big.eml: skipped, larger than 2 MB" in captured.err
    assert "== " in captured.out  # the regular file was still analysed
    assert main([str(tmp_path / "zero.eml"), "--offline", "--no-color"]) == 3
    assert "not a regular file" in capsys.readouterr().err


def test_a_hostile_path_is_printed_inert(tmp_path, capsys):
    main([str(tmp_path / "\x1b]52;c;cHduZWQ=\x07.eml"), "--offline", "--no-color"])
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\\x1b]52" in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_lookup_cache_is_private(tmp_path):
    path = tmp_path / "cache" / "lookups.sqlite3"
    Cache(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_a_link_flood_is_fast_and_flagged():
    """20,000 links took 14 s and made a 19 MB report. Past 1,000 links are
    counted rather than checked, and the flood is a signal of its own, so
    padding cannot push the real link out of sight unnoticed."""
    flood = "".join('<a href="https://h%d.example/p">x</a>' % i for i in range(20_000))
    started = time.perf_counter()
    a = triage_bytes(build_eml(html=flood))
    assert time.perf_counter() - started < 5
    assert len(a.urls) == 1000 and a.urls_dropped == 19_000
    assert any("19000 more links than the 1000 checked" in s.label for s in a.signals)
    assert len(html.render([a])) < 3_000_000


# ------------------------------------------------------------ privacy --

def test_urlscan_submissions_carry_no_recipient_addresses():
    a = parse_bytes(build_eml(to="Victim <Victim@Acme-Labs.example>"))
    b64 = base64.b64encode(b"victim@acme-labs.example").decode()
    assert redact_recipients("https://kit.top/l?e=Victim@Acme-Labs.example", a) == "https://kit.top/l?e=user@example.com"
    assert redact_recipients("https://kit.top/l?e=victim%40acme-labs.example", a).endswith("user%40example.com")
    assert b64 not in redact_recipients("https://kit.top/#" + b64, a)
    assert redact_recipients("https://kit.top/l?cc=boss@acme-labs.example", a).endswith("user@example.com")
    assert redact_recipients("https://kit.top/l?x=crook@evil.top", a).endswith("crook@evil.top")


def test_a_malformed_header_cannot_erase_the_authentication_results():
    # Seen in real phishing: an unfilled kit template in Message-Id made the
    # header parser fail, and with it every SPF/DKIM/DMARC result.
    raw = (b"Received: from x.example by mx.acme-labs.example; Tue, 29 Sep 2026 10:00:00 +0000\r\n"
           b"Authentication-Results: spf=permerror smtp.mailfrom=x.example; dkim=none; dmarc=fail\r\n"
           b"Message-Id: < [an10]. [an6].[anl12] [an11]@x.example>\r\n"
           b"From: a@x.example\r\nSubject: hi\r\n\r\nbody\r\n")
    a = triage_bytes(raw)
    assert a.auth["dmarc"] == "fail" and a.verdict != "NO STRONG INDICATORS"


def test_base64_encoded_authentication_results_are_read():
    # Microsoft 365 writes them as RFC 2047 encoded words.
    encoded = base64.b64encode(b"spf=temperror smtp.mailfrom=x.example; dkim=fail; dmarc=fail").decode()
    raw = ("Received: from x.example by mx.acme-labs.example; Tue, 29 Sep 2026 10:00:00 +0000\r\n"
           "Authentication-Results: =?utf-8?B?%s?=\r\nFrom: a@x.example\r\nSubject: hi\r\n\r\nbody\r\n" % encoded)
    assert triage_bytes(raw.encode()).auth == {"spf": "temperror", "dkim": "fail", "dmarc": "fail"}


# ------------------------------------------------------ 2.0: nothing live in any report --

def test_no_report_shows_a_live_attacker_link():
    """Links hide in QR payloads, shortcut command lines, remote templates,
    invitations and PDF launch actions; every human-facing report must still
    show each one defanged."""
    import filebuild as fb

    hosts = ["evil-lnk.top", "evil-template.top", "evil-invite.top", "evil-rtf.top", "evil-body.top"]
    rels = (b'<Relationships><Relationship Id="r1" Type=".../attachedTemplate" '
            b'Target="https://evil-template.top/t.dotm" TargetMode="External"/></Relationships>')
    ics = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nORGANIZER:mailto:x@evil-invite.top\r\n"
           "DESCRIPTION:join https://evil-invite.top/meet\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    raw = build_eml(text="Open https://evil-body.top/login", attachments=[
        (fb.lnk(target="C:\\Windows\\System32\\mshta.exe", arguments="https://evil-lnk.top/a.hta"),
         "application", "octet-stream", "scan.lnk"),
        (fb.plain_zip({"[Content_Types].xml": b"<Types/>", "word/_rels/settings.xml.rels": rels}),
         "application", "octet-stream", "cv.docx"),
        (b"{\\rtf1{\\*\\template https://evil-rtf.top/t.dot}}", "application", "rtf", "a.rtf"),
        (ics.encode(), "text", "calendar", "invite.ics")])
    a = triage_bytes(raw)
    rendered = {"console": console.render(a, console.Palette(False), verbose=True),
                "html": html.render([a]), "markdown": markdown.render(a)}
    for name, text in rendered.items():
        for host in hosts:
            assert host not in text, "%s shows %s undefanged" % (name, host)
            assert host.replace(".", "[.]") in text, "%s never mentions %s" % (name, host)


# ------------------------------------------- 2.0: headers the email library chokes on --

NUL_FILENAME = (b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
                b"Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Disposition: attachment; filename*=%s''invoice%%2Ehtml\r\n\r\n"
                b"<form><input type=password></form>\r\n--b--\r\n")


@pytest.mark.parametrize("charset", [b"utf\x00-8", b"\xff", b"undefined", b"idna"])
def test_a_charset_name_cannot_turn_a_verdict_into_an_error(charset):
    """A NUL or a non-ASCII byte in an RFC 2231 charset made CPython raise
    inside message_from_bytes; "idna" and "undefined" made get_filename()
    raise. Either way the message errored instead of being triaged. The
    filename is now read as UTF-8 and the attachment is still checked."""
    a = triage_bytes(NUL_FILENAME.replace(b"%s", charset).replace(b"%%", b"%"))
    assert [f.filename for f in a.attachments] == ["invoice.html"]
    assert any("credential form" in s.label for s in a.signals)


@pytest.mark.parametrize("header", [
    b"Content-Type: multipart/mixed; boundary*=idna''b\r\n",
    b"Content-Type: text/plain; charset=\"utf\x00-8\"\r\n",
    b"Content-Type: text/plain; charset=undefined\r\n",
    b"Subject: =?undefined?B?aGVsbG8=?=\r\nFrom: =?utf\x00-8?Q?a?= <a@b.top>\r\n"])
def test_other_hostile_charsets_in_headers_and_bodies(header):
    a = triage_bytes(b"MIME-Version: 1.0\r\n" + header + b"\r\n--b\r\nContent-Type: text/plain\r\n\r\n"
                     b"visit https://evil-pay.top/login\r\n--b--\r\n")
    assert "evil-pay.top" in [u.domain for u in a.urls]


# ------------------------------------------------ 2.0: one extent read a thousand times --

def _iso_sharing_one_extent(count, size):
    """An ISO whose `count` directory records all point at one `size`-byte file."""
    block = 2048

    def record(name, extent, length, directory=False):
        body = struct.pack("<BI", 0, extent) + struct.pack(">I", extent) + struct.pack("<I", length) \
            + struct.pack(">I", length) + b"\0" * 7 + bytes([2 if directory else 0, 0, 0]) \
            + struct.pack("<H", 1) + struct.pack(">H", 1) + bytes([len(name)]) + name
        body += b"\0" * ((len(body) + 1) % 2)
        return bytes([len(body) + 1]) + body

    blocks, current = [], b""
    for i in range(count):
        entry = record(b"F%04d.EXE;1" % i, 18 + 8, size)
        if len(current) + len(entry) > block:
            blocks.append(current.ljust(block, b"\0"))
            current = b""
        current += entry
    blocks.append(current.ljust(block, b"\0"))
    directory = b"".join(blocks).ljust(8 * block, b"\0")
    pvd = bytearray(block)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[156:190] = record(b"\0", 18, 8 * block, True)[:34]
    end = bytearray(block)
    end[0], end[1:6], end[6] = 255, b"CD001", 1
    return b"\0" * (16 * block) + bytes(pvd) + bytes(end) + directory + b"MZ" + b"\0" * (size - 2)


def test_disk_image_records_sharing_one_file_are_read_within_a_budget(monkeypatch):
    """A 20 MB ISO whose 480 records all point at one 20 MB extent made the
    reader hold 9.6 GB. Contents now count against one budget per image."""
    from phishhawk.formats import disk

    monkeypatch.setattr(disk, "MAX_TOTAL_BYTES", 100_000)
    files = disk.list_iso(_iso_sharing_one_extent(100, 30_000))
    assert len(files) == 100
    assert sum(len(f.data) for f in files if f.data) <= 100_000
    assert sum(1 for f in files if f.data) == 3


def test_truncated_fat_image_is_a_value_error():
    from phishhawk.formats import disk

    for data in (b"", b"\xeb\x3c\x90MSDOS5.0", b"\0" * 36):
        with pytest.raises(ValueError):
            disk.list_fat(data)


def test_msg_attachments_sharing_one_sector_chain(monkeypatch):
    """A 5.8 MB .msg whose 150 attachment streams all pointed at one 5 MB
    chain took 137 s and 7.2 GB. Reads now count against four times the
    file's size; attachments past that keep their names, which are evidence."""
    import struct as st

    from olebuild import build_msg
    from phishhawk.formats import cfb as cfbmod
    from phishhawk.formats.cfb import CompoundFile

    monkeypatch.setattr(cfbmod, "READ_ALLOWANCE", 0)
    big = b"MZ" + bytes(60_000)
    attachments = [{"name": "a0.exe", "data": big, "mime": "application/octet-stream"}]
    attachments += [{"name": "a%d.exe" % i, "data": b"M" * 4096, "mime": "application/octet-stream"}
                    for i in range(1, 40)]
    data = bytearray(build_msg(subject="bomb", body="x", sender="a@b.top", attachments=attachments))
    compound = CompoundFile(bytes(data))
    directory = list(compound._chain(st.unpack_from("<I", data, 0x30)[0], compound.fat))
    streams = [e for e in compound.entries if e.name.startswith("__substg1.0_3701")]
    target = next(e for e in streams if e.size == len(big))
    for entry in streams:
        offset = (directory[entry.index // 4] + 1) * 512 + (entry.index % 4) * 128
        st.pack_into("<IQ", data, offset + 116, target.start, target.size)
    a = triage_bytes(bytes(data))
    assert len(a.attachments) == 40
    assert sum(f.size for f in a.attachments) <= 4 * len(data)
    assert all(f.filename.endswith(".exe") for f in a.attachments)


def test_7z_header_dictionary_is_sized_to_the_header(monkeypatch):
    """An LZMA header claiming a 4 GB dictionary made the decoder try to
    allocate 4 GB; nothing in a 4 MB header can reach that far back."""
    import lzma

    import filebuild as fb
    from phishhawk.formats import archives

    data = fb.seven_zip_encoded(["invoice.js"], coder="lzma")
    props = bytes([3 + 2 * 45]) + struct.pack("<I", 1 << 16)
    data = data.replace(props, bytes([3 + 2 * 45]) + struct.pack("<I", 0xFFFFFFFF))
    seen = []
    real = lzma.LZMADecompressor

    def spy(**kw):
        seen.append(kw["filters"][0]["dict_size"])
        return real(**kw)

    monkeypatch.setattr(archives.lzma, "LZMADecompressor", spy)
    assert archives.list_7z(data).names == ["invoice.js"]
    assert seen and seen[0] <= 4 * 1024 * 1024


def test_office_parts_are_read_against_one_budget(monkeypatch):
    """A .docx is a zip, and a zip can hold thousands of parts that each
    inflate to 8 MB."""
    import io
    import zipfile

    from phishhawk.formats import documents

    monkeypatch.setattr(documents, "MAX_OOXML_READ", 64 * 1024)
    buf = io.BytesIO()
    rel = (b'<Relationships><Relationship Type=".../attachedTemplate" Target="https://late.top/t" '
           b'TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for i in range(40):
            filler = b"<Relationships>" + b" " * 8000 + b"</Relationships>"
            archive.writestr("word/_rels/p%02d.xml.rels" % i, filler)
        archive.writestr("word/_rels/z.xml.rels", rel)
    started = time.time()
    found = documents.inspect_ooxml(buf.getvalue())
    assert time.time() - started < 2
    assert "remote-attachedtemplate" not in found.features  # read past the budget: not reached


def test_long_runs_of_letters_do_not_stall_the_regexes():
    """Two patterns backtracked from every position of a long run of
    letters: a 30,000-character To: header took 5 s, and a crafted .rels
    part 0.2 s per element (minutes for a whole file). Both are anchored."""
    from phishhawk.formats import documents

    raw = build_eml(subject="x", text="hello").replace(b"\n\n", b"\nTo: " + b"a" * 200_000 + b"\n\n", 1)
    started = time.time()
    triage_bytes(raw)
    assert time.time() - started < 3
    started = time.time()
    for _ in range(200):
        documents._ATTR_RE.findall("a" * 4000)
    assert time.time() - started < 1


@pytest.mark.parametrize("header", [b"To: " + b'"' * 50_000, b"Cc: " + b'",' * 25_000,
                                    b"Content-Type: text/plain; a=\"" + b'"x">y</a>=' * 5_000])
def test_headers_built_to_stall_the_parser(header):
    """CPython's structured-header parser is quadratic on some input (a To:
    header of 50,000 quotes took 49 s) and parses a header again on every
    read. Over-long structured headers are kept as text; parses are cached."""
    raw = header + b"\nFrom: a@b.top\nSubject: hi\n\nhttps://evil-pay.top/x\n"
    started = time.time()
    a = triage_bytes(raw)
    assert time.time() - started < 3
    assert [u.domain for u in a.urls] == ["evil-pay.top"]


def test_a_boundary_hidden_behind_a_long_content_type_is_still_found():
    """Keeping a long Content-Type as text must not hide the parts behind it."""
    head = b'Content-Type: multipart/mixed; x="' + b"a" * 9000 + b'"; boundary="zz"\n'
    raw = head + (b"From: a@b.top\n\n--zz\nContent-Type: text/plain\n\nhi\n--zz\n"
                  b"Content-Type: application/octet-stream\n"
                  b"Content-Disposition: attachment; filename=\"pay.html\"\n\n"
                  b"<form><input type=password></form>\n--zz--\n")
    a = triage_bytes(raw)
    assert [f.filename for f in a.attachments] == ["pay.html"]
    assert a.verdict != "NO STRONG INDICATORS"


def test_an_attached_message_with_hostile_headers_is_still_unwrapped():
    inner = b"To: " + b'"' * 50_000 + b"\nSubject: inner\n\nhttps://inner-phish.top/x\n"
    raw = (b"From: a@b.top\nSubject: fwd\nContent-Type: multipart/mixed; boundary=b\n\n--b\n"
           b"Content-Type: text/plain\n\nsee attached\n--b\nContent-Type: message/rfc822\n\n"
           + inner + b"\n--b--\n")
    started = time.time()
    a = triage_bytes(raw)
    assert time.time() - started < 3
    assert a.subject == "inner" and "inner-phish.top" in [u.domain for u in a.urls]


def test_links_are_read_the_way_a_browser_reads_them():
    """Control characters ended nowhere: a link followed by 1.4 MB of NUL
    bytes became a 1.4 MB 'URL' that took seconds to show in each report.
    A line break inside an href is dropped by browsers, so it is here too."""
    a = triage_bytes(b"From: a@b.top\n\nhttp://3232235777/" + b"\x00" * 1_400_000)
    assert [u.url for u in a.urls] == ["http://3232235777/"]
    a = triage_bytes(build_eml(html='<a href="https://ev&#10;il-bank.top/lo&#9;gin">Sign in</a>'))
    assert [u.url for u in a.urls] == ["https://evil-bank.top/login"]
    a = triage_bytes(build_eml(text="https://long.top/" + "a" * 50_000))
    assert len(a.urls[0].url) == 8192


def test_eight_bit_text_in_a_charset_the_codec_lookup_rejects():
    """Also a multipart part with no boundary: its body was skipped as a
    container, so its links were never read."""
    raw = (b"MIME-Version: 1.0\nContent-Type: multipart/mixed; charset=\"utf\x00-8\"\n\n"
           b"\xe9\xff no boundary here https://evil-pay.top/login\n")
    assert "evil-pay.top" in [u.domain for u in triage_bytes(raw).urls]


def _attached(inner, depth):
    for level in range(depth):
        inner = (b"From: u%d@corp.example\nSubject: level %d\nContent-Type: multipart/mixed; boundary=w%d\n\n"
                 b"--w%d\nContent-Type: text/plain\n\nsee attached\n--w%d\nContent-Type: message/rfc822\n\n"
                 % (level, level, level, level, level)) + inner + b"\n--w%d--\n" % level
    return inner


def test_an_email_attached_deeper_than_the_unwrapping_still_counts():
    """Three layers are unwrapped; an email attached below them was listed
    as 'attached-message.eml' and never read."""
    inner = b"From: x@evil.top\nSubject: innermost\n\nlogin at https://deep-phish.top/x\n"
    for depth in (1, 3, 4, 5):
        a = triage_bytes(_attached(inner, depth))
        assert "deep-phish.top" in [u.domain for u in a.urls], depth


def test_a_message_that_is_only_another_message():
    raw = b"From: a@b.top\nSubject: fwd\nContent-Type: message/rfc822\n\nFrom: x@evil.top\nSubject: in\n\n" \
          b"https://bare-rfc822.top/x\n"
    a = triage_bytes(raw)
    assert a.subject == "in" and "bare-rfc822.top" in [u.domain for u in a.urls]


def test_a_second_attached_email_is_not_skipped():
    """Unwrapping takes the first attached email; a harmless one placed
    first must not hide the phish attached after it."""
    decoy = b"From: hr@corp.example\nSubject: Minutes\n\nSee you Monday.\n"
    phish = b"From: it@m1crosoft-support.top\nSubject: Password expires\n\nhttps://m1crosoft-support.top/login\n"
    raw = (b"From: a@b.top\nSubject: two\nContent-Type: multipart/mixed; boundary=b\n\n--b\n"
           b"Content-Type: text/plain\n\nfyi\n--b\nContent-Type: message/rfc822\n\n" + decoy
           + b"\n--b\nContent-Type: message/rfc822\n\n" + phish + b"\n--b--\n")
    a = triage_bytes(raw)
    assert "m1crosoft-support.top" in [u.domain for u in a.urls]
    assert a.verdict != "NO STRONG INDICATORS"


def test_mime_nested_past_any_mail_client():
    def nested(depth):
        layers = b"".join(b"Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n" % (i, i) for i in range(depth))
        return b"From: a@b.top\nSubject: deep\n" + layers + b"Content-Type: text/plain\n\nhttps://deep-mime.top/x\n"

    shallow, deep, deepest = triage_bytes(nested(4)), triage_bytes(nested(40)), triage_bytes(nested(3000))
    assert not any("nested" in s.label for s in shallow.signals)
    assert any("nested 40 levels deep" in s.label for s in deep.signals)
    assert any("deeper than a mail parser can follow" in s.label for s in deepest.signals)
    assert "deep-mime.top" in [u.domain for u in deepest.urls]  # the parser gave up; the links did not


def test_thousands_of_headers_are_cheap():
    received = b"".join(b"Received: from h%d.top (h [10.0.0.%d]) by mx; Mon, 1 Jan 2024 00:00:%02d +0000\n"
                        % (i, i % 250, i % 60) for i in range(5000))
    results = b"".join(b"Authentication-Results: fake%d.top; dmarc=pass\n" % i for i in range(3000))
    started = time.time()
    a = triage_bytes(received + results + b"From: a@b.top\n\nhi")
    assert time.time() - started < 3
    assert a.received_hops == 5000 and len(a.hops) == 30 and len(a.forged_auth) <= 20


def test_address_headers_full_of_colons():
    """email.utils.parseaddr recursed once per ':' (group syntax), so a From:
    header with thousands of them raised RecursionError. The address is
    still recovered, and still checked."""
    raw = (b'From: "Pay' + b":x" * 5000 + b'" <billing@paypa1-secure.top>\nTo: a' + b":b" * 5000
           + b" <me@corp.example>\nSubject: hi\n\nhttps://paypa1-secure.top/login\n")
    a = triage_bytes(raw)
    assert a.from_address == "billing@paypa1-secure.top"
    assert any("lookalike" in s.label for s in a.signals)
