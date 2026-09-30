"""QR-code phishing: codes are found wherever attackers hide them, their links
are analysed like any other link, and hostile images stay harmless."""

import base64
import io
import time
import zlib

import pytest

from phishhawk import qr
from phishhawk.parse import parse_bytes
from phishhawk.pipeline import Options, triage_bytes

from conftest import build_eml

segno = pytest.importorskip("segno")
pytest.importorskip("zxingcpp")
Image = pytest.importorskip("PIL.Image")

LINK = "https://m365-mfa-reset.top/login?u=user"


def png(payload=LINK, scale=4):
    buffer = io.BytesIO()
    segno.make(payload, error="m").save(buffer, kind="png", scale=scale)
    return buffer.getvalue()


def jpeg(payload=LINK):
    buffer = io.BytesIO()
    Image.open(io.BytesIO(png(payload))).convert("RGB").save(buffer, "JPEG", quality=85)
    return buffer.getvalue()


def modules(payload=LINK):
    return [[int(bool(v)) for v in row] for row in segno.make(payload, error="m").matrix]


def pdf(stream, entries):
    return (b"%PDF-1.4\n1 0 obj << /Type /XObject /Subtype /Image " + entries +
            b" /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream\nendobj\n%%EOF")


def up_predicted(gray):
    """Flate data the way PDF writers store PNGs: a filter byte per row."""
    rows, previous, width = [], bytes(gray.width), gray.width
    raw = gray.tobytes()
    for y in range(gray.height):
        row = raw[y * width:(y + 1) * width]
        rows.append(b"\x02" + bytes((a - b) & 0xFF for a, b in zip(row, previous, strict=True)))
        previous = row
    return zlib.compress(b"".join(rows))


def table(grid):
    return "<table>" + "".join(
        "<tr>" + "".join('<td style="background-color:%s"></td>' % ("#000" if v else "#fff") for v in row)
        + "</tr>" for row in grid) + "</table>"


def blocks(grid):
    rows = grid + ([[0] * len(grid[0])] if len(grid) % 2 else [])
    glyph = {(1, 1): "█", (1, 0): "▀", (0, 1): "▄", (0, 0): " "}
    pairs = (zip(rows[i], rows[i + 1], strict=True) for i in range(0, len(rows), 2))
    return "\n".join("".join(glyph[pair] for pair in row) for row in pairs)


def gray_image():
    return Image.open(io.BytesIO(png(scale=3))).convert("L")


CASES = {
    "image attachment": dict(attachments=[(png(), "image", "png", "code.png")]),
    "JPEG attachment": dict(attachments=[(jpeg(), "image", "jpeg", "code.jpg")]),
    "nameless inline image": dict(html="<p>Scan</p>", attachments=[(png(), "image", "png", None, "inline")]),
    "data: URI in the HTML": dict(html='<img src="data:image/png;base64,%s">' % base64.b64encode(png()).decode()),
    "JPEG inside a PDF": dict(attachments=[(pdf(jpeg(), b"/Width 9 /Height 9 /Filter /DCTDecode"),
                                             "application", "pdf", "a.pdf")]),
    "Flate image inside a PDF": dict(attachments=[(pdf(
        zlib.compress(gray_image().tobytes()),
        b"/Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray /Filter /FlateDecode"
        % gray_image().size),
        "application", "pdf", "b.pdf")]),
    "PNG-predicted image inside a PDF": dict(attachments=[(pdf(
        up_predicted(gray_image()),
        b"/Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray /Filter /FlateDecode "
        b"/DecodeParms << /Predictor 15 /Colors 1 /Columns %d >>" % (*gray_image().size, gray_image().width)),
        "application", "pdf", "c.pdf")]),
    "HTML table": dict(html=table(modules())),
    "HTML table left open": dict(html=table(modules()).replace("</table>", "")),
    "block characters in text": dict(text="Scan:\n" + blocks(modules()) + "\n"),
    "block characters in HTML": dict(html="<pre>" + blocks(modules()).replace("\n", "<br>") + "</pre>"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_qr_codes_are_found_wherever_they_hide(name):
    a = parse_bytes(build_eml(**CASES[name]))
    assert [code["url"] for code in a.qr_codes] == [LINK]
    assert any(ioc.url == LINK and any("qr-code in" in s for s in ioc.sources) for ioc in a.urls)


def test_upper_case_payloads_become_normal_links():
    a = parse_bytes(build_eml(attachments=[(png("HTTPS://EVIL-QR.TOP/ABC"), "image", "png", "u.png")]))
    assert a.qr_codes[0]["url"] == "https://evil-qr.top/ABC"


def test_a_qr_code_to_a_login_page_is_high():
    a = triage_bytes(build_eml(text="Your MFA expires today. Scan the code with your phone.",
                               attachments=[(png(), "image", "png", "mfa.png")]))
    signal = next(s for s in a.signals if s.label.startswith("QR code in mfa.png"))
    assert signal.severity == "high"
    assert "a login path" in signal.label and "a high-abuse TLD" in signal.label
    assert a.verdict != "NO STRONG INDICATORS"


def test_a_plain_qr_code_is_medium_and_the_senders_own_site_is_low():
    ticket = png("https://events.example.org/tickets/42")
    plain = triage_bytes(build_eml(text="See you at the event.", attachments=[(ticket, "image", "png", "t.png")]))
    assert [s.severity for s in plain.signals if s.label.startswith("QR code")] == ["medium"]
    own = triage_bytes(build_eml(
        sender='"Shop" <news@shop.example>', text="Download our app.",
        headers=[("Authentication-Results", "mx.example; spf=pass dkim=pass dmarc=pass")],
        attachments=[(png("https://www.shop.example/app"), "image", "png", "app.png")]))
    assert [s.severity for s in own.signals if s.label.startswith("QR code")] == ["low"]


def test_a_qr_code_that_calls_a_number_is_flagged():
    a = triage_bytes(build_eml(attachments=[(png("tel:+18885550142"), "image", "png", "call.png")]))
    assert any(s.label.startswith("QR code in call.png calls or texts") for s in a.signals)


def test_no_qr_switches_decoding_off():
    raw = build_eml(attachments=[(png(), "image", "png", "code.png")])
    assert triage_bytes(raw, options=Options(qr=False)).qr_codes == []


def test_without_the_optional_extra_nothing_breaks(monkeypatch):
    monkeypatch.setattr(qr, "_libraries", lambda: (None, None))
    a = triage_bytes(build_eml(text="Scan the QR code below", attachments=[(png(), "image", "png", "code.png")]))
    assert a.qr_codes == [] and qr.versions() == {}
    assert any("QR-code lure" in s.label for s in a.signals)  # the wording check still works


def test_hostile_images_are_refused_quickly():
    huge = io.BytesIO()
    Image.new("1", (20_000, 20_000)).save(huge, "PNG")  # tiny file, 400 megapixels
    started = time.perf_counter()
    assert qr.decode_image(huge.getvalue()) == []
    assert qr.decode_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * 500) == []
    oversized = pdf(zlib.compress(b"\x00" * 100), b"/Width 90000 /Height 90000 /Filter /FlateDecode")
    assert qr.decode_pdf(oversized) == []
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize("mode", ["1", "L", "RGB"])  # CCITT fax, Flate and JPEG, as Pillow writes them
def test_qr_codes_in_pdfs_written_by_real_software(mode):
    buffer = io.BytesIO()
    Image.open(io.BytesIO(png())).convert(mode).save(buffer, "PDF")
    assert qr.decode_pdf(buffer.getvalue()) == [LINK]


def test_the_quishing_sample_is_caught_through_its_pdf():
    from phishhawk.pipeline import triage_file

    from conftest import sample

    a = triage_file(sample("sample_quishing.eml"))
    assert a.verdict == "LIKELY PHISHING"
    assert [code["where"] for code in a.qr_codes] == ["MFA_Enrolment_Notice.pdf"]
    qr_signals = [s for s in a.signals if s.label.startswith("QR code in MFA_Enrolment_Notice.pdf")]
    assert [s.severity for s in qr_signals] == ["high"]
