"""Generates the .eml fixtures shipped in samples/. Run once; output is committed."""
import os
from email.message import EmailMessage

OUT = "/home/user/vinitrami-Soc.github.io/phishing-ioc-extractor/samples"
os.makedirs(OUT, exist_ok=True)

# --------------------------------------------------------------- phishing ---
ATTACHMENT = """<!doctype html>
<!-- INERT TEST FIXTURE - part of the phishing-ioc-extractor sample corpus.
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

msg = EmailMessage()
msg["Subject"] = "Action required: unusual sign-in activity on your account"
msg["From"] = '"Microsoft Account Team" <security-alert@micros0ft-verify-support.top>'
msg["To"] = "vinit.rami@example-corp.co.uk"
msg["Reply-To"] = "recovery.desk@mail-secure-recovery.xyz"
msg["Date"] = "Tue, 16 Sep 2026 03:14:52 +0000"
msg["Message-ID"] = "<f2a91c77-3b8e-4a21-9d55-0e1b77c3a9d4@mail-relay-07.sendgrid-bulk.top>"
msg["X-Mailer"] = "PHPMailer 6.8.0"
msg["List-Unsubscribe"] = "<https://mail-secure-recovery.xyz/unsub?u=8841>"
msg.set_content(TEXT)
msg.add_alternative(HTML, subtype="html")
msg.add_attachment(ATTACHMENT.encode(), maintype="text", subtype="html",
                   filename="Voicemail_Transcript.pdf.html")

# Headers a real mail flow adds in front, newest hop first.
prepend = [
    ("Return-Path", "<bounce-8841@mail-relay-07.sendgrid-bulk.top>"),
    ("Received", "from mx01.example-corp.co.uk (10.20.4.11) by "
                 "EXCH02.example-corp.local (10.20.4.30) with Microsoft SMTP Server; "
                 "Tue, 16 Sep 2026 03:15:04 +0000"),
    ("Received", "from mail-relay-07.sendgrid-bulk.top (mail-relay-07.sendgrid-bulk.top "
                 "[185.243.115.22]) by mx01.example-corp.co.uk with ESMTPS; "
                 "Tue, 16 Sep 2026 03:15:01 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=fail "
                              "smtp.mailfrom=mail-relay-07.sendgrid-bulk.top; dkim=none; "
                              "dmarc=fail action=quarantine header.from=micros0ft-verify-support.top"),
    ("Received-SPF", "fail (mx01.example-corp.co.uk: domain of "
                     "mail-relay-07.sendgrid-bulk.top does not designate 185.243.115.22 "
                     "as permitted sender)"),
    ("X-Originating-IP", "[185.243.115.22]"),
]
for name, value in reversed(prepend):
    msg._headers.insert(0, (name, value))

with open(os.path.join(OUT, "sample_phish.eml"), "wb") as fh:
    fh.write(msg.as_bytes())

# ----------------------------------------------------------------- benign ---
benign = EmailMessage()
benign["Subject"] = "Your October invoice is ready"
benign["From"] = '"Example Corp Billing" <billing@example-corp.co.uk>'
benign["To"] = "vinit.rami@example-corp.co.uk"
benign["Date"] = "Mon, 01 Sep 2026 09:02:11 +0000"
benign["Message-ID"] = "<20260901090211.7c1a@example-corp.co.uk>"
benign.set_content(
    "Hello Vinit,\n\nYour October invoice is available in the billing portal:\n"
    "https://billing.example-corp.co.uk/invoices/2026-10\n\nThanks,\nBilling team\n"
)
benign.add_alternative(
    '<html><body><p>Hello Vinit,</p><p>Your October invoice is available in the '
    '<a href="https://billing.example-corp.co.uk/invoices/2026-10">billing portal</a>.</p>'
    "<p>Thanks,<br>Billing team</p></body></html>", subtype="html")
for name, value in reversed([
    ("Return-Path", "<billing@example-corp.co.uk>"),
    ("Received", "from smtp.example-corp.co.uk (203.0.113.24) by "
                 "mx01.example-corp.co.uk with ESMTPS; Mon, 01 Sep 2026 09:02:13 +0000"),
    ("Authentication-Results", "mx01.example-corp.co.uk; spf=pass "
                              "smtp.mailfrom=example-corp.co.uk; dkim=pass "
                              "header.d=example-corp.co.uk; dmarc=pass"),
]):
    benign._headers.insert(0, (name, value))

with open(os.path.join(OUT, "sample_benign.eml"), "wb") as fh:
    fh.write(benign.as_bytes())

print("written:", os.listdir(OUT))
