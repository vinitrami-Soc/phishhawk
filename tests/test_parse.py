import io
import zipfile

from phishhawk.parse import parse_bytes, parse_file

from conftest import build_eml, sample


def test_phish_headers_auth_and_origin():
    a = parse_file(sample("sample_phish.eml"))
    assert a.from_address == "security-alert@micros0ft-verify-support.top"
    assert a.reply_to_domain == "mail-secure-recovery.xyz"
    assert a.return_path_domain == "mail-relay-07.sendgrid-bulk.top"
    assert a.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert a.originating_ip == "185.243.115.22"  # private Exchange hops skipped
    assert a.received_hops == 2


def test_urls_come_from_every_source():
    a = parse_file(sample("sample_phish.eml"))
    sources = {source for ioc in a.urls for source in ioc.sources}
    hosts = {ioc.host for ioc in a.urls}
    assert {"body-text", "html-href", "html-resource", "header:List-Unsubscribe"} <= sources
    assert {"micros0ft-verify-support.top", "bit.ly", "185.243.115.22", "mail-secure-recovery.xyz"} <= hosts


def test_recipient_domain_is_auto_protected_but_freemail_is_not():
    assert parse_file(sample("sample_phish.eml")).protected_domains == ["example-corp.co.uk"]
    assert parse_bytes(build_eml(to="someone@gmail.com")).protected_domains == []
    assert parse_bytes(build_eml(to="someone@gmail.com"), protected=["corp.example"]).protected_domains \
        == ["corp.example"]
    assert parse_file(sample("sample_phish.eml"), auto_protect=False).protected_domains == []


def test_forwarded_report_is_unwrapped():
    a = parse_file(sample("sample_reported.eml"))
    assert a.subject == "Action required: unusual sign-in activity on your account"
    assert a.from_domain == "micros0ft-verify-support.top"
    assert a.reported_by["from"] == "priya.shah@example-corp.co.uk"
    assert a.reported_by["layers"] == 1
    assert len(a.urls) == 6


def test_no_unwrap_analyses_the_covering_note():
    a = parse_file(sample("sample_reported.eml"), unwrap=False)
    assert a.subject.startswith("FW:")
    assert a.reported_by is None
    assert a.urls == []
    assert a.attachments[0].content_type == "message/rfc822"


def test_zip_members_are_hashed_without_touching_disk():
    a = parse_file(sample("sample_bec_smuggling.eml"))
    members = [f for f in a.attachments if f.parent == "Invoice_0923.zip"]
    assert sorted(m.filename for m in members) == ["Invoice_0923.pdf.js", "readme.txt"]
    assert all(len(m.sha256) == 64 for m in members)
    archive = next(f for f in a.attachments if f.filename == "Invoice_0923.zip").archive
    assert archive["members"] == 2 and not archive["encrypted"]


def _zip(entries, encrypted=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(zipfile.ZipInfo(name), data)
    data = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile cannot write encrypted archives and resets flag_bits on
        # write, so set the "encrypted" bit where real tools put it: the
        # general-purpose flag of every local (PK34) and central (PK12) header.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = data.find(signature)
            while start != -1:
                data[start + offset] |= 0x1
                start = data.find(signature, start + 4)
    return bytes(data)


def test_encrypted_zip_is_listed_but_not_read():
    data = _zip([("payload.exe", b"not really encrypted")], encrypted=True)
    a = parse_bytes(build_eml(attachments=[(data, "application", "zip", "docs.zip")]))
    archive = a.attachments[0].archive
    assert archive["encrypted"] is True
    assert archive["listing"] == ["payload.exe"]
    assert archive["skipped"] == 1
    assert [f.filename for f in a.attachments] == ["docs.zip"]


def test_macro_enabled_office_file_is_detected():
    data = _zip([("[Content_Types].xml", b"<Types/>"), ("word/vbaProject.bin", b"\x00vba")])
    a = parse_bytes(build_eml(attachments=[(data, "application", "vnd.ms-word", "Invoice.docm")]))
    assert "contains a VBA macro project" in a.attachments[0].notes


def test_html_attachment_form_smuggling_and_atob():
    a = parse_file(sample("sample_bec_smuggling.eml"))
    htm = next(f for f in a.attachments if f.filename == "Shared_Document.htm")
    assert htm.html["forms"][0]["has_password"] is True
    assert "base64 decoding (atob)" in htm.html["smuggling"]
    assert htm.html["decoded_urls"] == ["https://files.examp1e-corp.top/share/Q3-payroll-review"]
    decoded = next(u for u in a.urls if "Q3-payroll" in u.url)
    assert any("atob-decoded" in s for s in decoded.sources)


def test_masquerading_file_is_typed_by_magic_bytes():
    a = parse_file(sample("sample_bec_smuggling.eml"))
    fake_pdf = next(f for f in a.attachments if f.filename == "Scan_0922.pdf")
    assert fake_pdf.true_type == "html"


def test_pdf_attachment_links_are_extracted():
    pdf = b"%PDF-1.4\n<< /A << /S /URI /URI (https://doc-share.example/view) >> >>"
    a = parse_bytes(build_eml(attachments=[(pdf, "application", "pdf", "statement.pdf")]))
    assert [u.url for u in a.urls] == ["https://doc-share.example/view"]


def test_inline_images_are_recorded_but_flagged_inline():
    a = parse_bytes(build_eml(attachments=[(b"\x89PNG\r\nfake", "image", "png", "logo.png", "inline")]))
    assert a.attachments[0].inline is True


def test_zero_width_characters_are_counted():
    assert parse_file(sample("sample_bec_smuggling.eml")).zero_width_chars == 3
    # ZWNJ/ZWJ are legitimate in Devanagari and must not count
    assert parse_bytes(build_eml(text="क्‍ष नमस्‌ते")) \
        .zero_width_chars == 0


def test_garbage_input_does_not_crash():
    a = parse_bytes(b"\x00\xff\x13 not an email at all \r\n\r\n\x00")
    assert a.urls == [] and a.attachments == []
