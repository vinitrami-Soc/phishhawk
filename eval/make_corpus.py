#!/usr/bin/env python3
"""Build a labelled synthetic corpus of phishing and legitimate email.

    python eval/make_corpus.py OUT_DIR [--seed 7]

Writes OUT_DIR/phish/*.eml and OUT_DIR/benign/*.eml, named
<scenario>-<n>.eml. Deterministic for a given seed.

The benign half is deliberately hard: genuine security alerts that say
"unusual sign-in activity", newsletters whose bounce domain differs from the
sender, password resets, Safe-Links-wrapped internal mail, Google Drive shares,
Hindi text with zero-width joiners. The phishing half includes cases the
tool is expected to miss (QR-code lures, CEO fraud from a personal-looking
free-mail name), so the numbers are not flattering by construction.

Every domain is fictional or a real brand's own domain; nothing here links
to a live phishing site, and the "payloads" are text.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import random
import zipfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime

ORG = "northwind-traders.co.uk"
PEOPLE = [
    "Aisha Khan",
    "Ben Carter",
    "Chloe Martin",
    "Dev Patel",
    "Emma Lewis",
    "Farid Haddad",
    "Grace Okafor",
    "Hiro Tanaka",
    "Isla Murray",
    "Jonas Weber",
]
PASS_AUTH = "mx.{org}; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass header.from={d}"
FAIL_AUTH = "mx.{org}; spf=fail smtp.mailfrom={d}; dkim=none; dmarc=fail header.from={d}"
BRANDS = {  # brand: (display name, real domain, login host, lure)
    "microsoft": (
        "Microsoft account team",
        "microsoft.com",
        "login.microsoftonline.com",
        "unusual sign-in activity was detected on your account",
    ),
    "paypal": ("PayPal", "paypal.com", "www.paypal.com", "your account has been limited until you verify it"),
    "docusign": (
        "DocuSign",
        "docusign.net",
        "app.docusign.com",
        "a document has been shared with you for signature",
    ),
    "netflix": ("Netflix", "netflix.com", "www.netflix.com", "your payment failed and your membership is on hold"),
    "apple": ("Apple", "apple.com", "appleid.apple.com", "your Apple ID has been locked for security reasons"),
    "amazon": ("Amazon", "amazon.com", "www.amazon.com", "we could not process your last order payment"),
    "dhl": ("DHL Express", "dhl.com", "www.dhl.com", "your parcel is pending: a customs fee is due"),
    "linkedin": ("LinkedIn", "linkedin.com", "www.linkedin.com", "you appeared in 9 searches, sign in to view"),
    "dropbox": ("Dropbox", "dropbox.com", "www.dropbox.com", "a file was shared with you, sign in to view"),
    "adobe": ("Adobe Document Cloud", "adobe.com", "acrobat.adobe.com", "you have received a secure PDF document"),
}
LOOKALIKE = {  # how an attacker disguises each brand
    "microsoft": [
        "micros0ft-account.top",
        "microsoft-security-alert.xyz",
        "rnicrosoft.com",
        "microsoft.com.session-check.icu",
    ],
    "paypal": ["paypa1-resolution.com", "paypal-secure-center.online", "xn--pypal-4ve.com"],
    "docusign": ["docusign-envelope.site", "d0cusign.net"],
    "netflix": ["netflix-billing-update.shop", "netfllx.com"],
    "apple": ["apple-id-locked.support.xyz", "appie-support.com"],
    "amazon": ["amazon-order-review.top", "arnazon.com"],
    "dhl": ["dhl-parcel-tracking.top", "dhl-customs-fee.site"],
    "linkedin": ["linkedln.com", "linkedin-profile-views.online"],
    "dropbox": ["dropbox-fileshare.xyz", "dr0pbox.com"],
    "adobe": ["adobe-secure-docs.site", "ad0be.com"],
}
FREE_HOSTS = [
    "secure-verify-3491.web.app",
    "account-review.pages.dev",
    "doc-portal.netlify.app",
    "signin-check.workers.dev",
    "mailbox-upgrade.firebaseapp.com",
]


class Corpus:
    def __init__(self, out: str, seed: int) -> None:
        self.out = out
        self.rng = random.Random(seed)
        self.counts: dict[str, int] = {}
        self.clock = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
        for label in ("phish", "benign"):
            os.makedirs(os.path.join(out, label), exist_ok=True)

    # ------------------------------------------------------------ helpers --
    def person(self) -> str:
        return self.rng.choice(PEOPLE)

    def recipient(self) -> str:
        name = self.person()
        return '"%s" <%s@%s>' % (name, name.split()[0].lower(), ORG)

    def msg(self, sender: str, subject: str, auth: str | None, sender_domain: str, ip: str = "") -> EmailMessage:
        self.clock += timedelta(minutes=self.rng.randint(7, 400))
        m = EmailMessage()
        m["From"] = sender
        m["To"] = self.recipient()
        m["Subject"] = subject
        m["Date"] = format_datetime(self.clock)
        m["Message-ID"] = "<%08x.%d@%s>" % (self.rng.getrandbits(32), self.rng.randint(1, 99999), sender_domain)
        ip = ip or "%d.%d.%d.%d" % (
            self.rng.choice([45, 91, 103, 185, 194]),
            self.rng.randint(1, 254),
            self.rng.randint(1, 254),
            self.rng.randint(1, 254),
        )
        received = "from mail.%s (mail.%s [%s]) by mx.%s with ESMTPS; %s" % (
            sender_domain,
            sender_domain,
            ip,
            ORG,
            format_datetime(self.clock),
        )
        headers = [("Received", received)]
        if auth:
            headers.insert(0, ("Authentication-Results", auth.format(org=ORG, d=sender_domain)))
        for name, value in reversed(headers):
            m._headers.insert(0, (name, value))
        return m

    def write(self, label: str, scenario: str, message: EmailMessage) -> None:
        self.counts[scenario] = self.counts.get(scenario, 0) + 1
        name = "%s-%02d.eml" % (scenario, self.counts[scenario])
        with open(os.path.join(self.out, label, name), "wb") as handle:
            handle.write(message.as_bytes())

    @staticmethod
    def html(body: str) -> str:
        return '<html><body style="font-family:Arial">%s</body></html>' % body

    # ------------------------------------------------------------- phish --
    def brand_credential(self, n: int) -> None:
        for _ in range(n):
            brand = self.rng.choice(sorted(BRANDS))
            display, real, login, lure = BRANDS[brand]
            fake = self.rng.choice(LOOKALIKE[brand])
            url = "https://%s/%s?session=%d" % (
                fake,
                self.rng.choice(["login", "verify", "signin/secure"]),
                self.rng.randint(1000, 9999),
            )
            m = self.msg(
                '"%s" <no-reply@%s>' % (display, fake), "Action required: %s" % lure.split(",")[0], FAIL_AUTH, fake
            )
            m.set_content("Dear customer,\n\n%s.\nVerify now: %s\n" % (lure.capitalize(), url))
            m.add_alternative(
                self.html(
                    '<p>%s.</p><p><a href="%s">https://%s/account</a></p>' % (lure.capitalize(), url, login)
                ),
                subtype="html",
            )
            self.write("phish", "brand-credential", m)

    def compromised_sender(self, n: int) -> None:
        for _ in range(n):
            brand = self.rng.choice(["microsoft", "docusign", "adobe", "dropbox"])
            display, _, _, lure = BRANDS[brand]
            domain = self.rng.choice(
                ["greenvalley-dental.com", "hartley-roofing.co.uk", "lakeside-yoga.org", "marino-bakery.it"]
            )
            url = "https://%s/%s" % (self.rng.choice(FREE_HOSTS), self.rng.choice(["index.html", "auth", "view"]))
            m = self.msg(
                '"%s" <office@%s>' % (display, domain), "%s: %s" % (display, lure.split(",")[0]), PASS_AUTH, domain
            )
            m.set_content("%s.\nOpen: %s\n" % (lure.capitalize(), url))
            self.write("phish", "compromised-sender", m)

    def html_attachment(self, n: int) -> None:
        for i in range(n):
            smuggle = i % 2 == 0
            host = self.rng.choice(["auth-portal-%d.top" % i, "o365-verify-%d.xyz" % i])
            script = (
                (
                    '<script>var t = atob("%s"); var b = new Blob(["inert"]); URL.createObjectURL(b);</script>'
                    % base64.b64encode(("https://%s/drop" % host).encode()).decode()
                )
                if smuggle
                else ""
            )
            page = (
                '<html><body><h3>Secure document</h3><form action="https://%s/post" method="post">'
                '<input name="u"><input type="password" name="p"></form>%s</body></html>' % (host, script)
            )
            m = self.msg(
                '"Accounts Payable" <ap@%s>' % host,
                "Remittance advice %d" % self.rng.randint(1000, 9999),
                FAIL_AUTH,
                host,
            )
            m.set_content("Please find the remittance attached.\n")
            name = self.rng.choice(["Remittance.htm", "Invoice_%d.html" % i, "Statement.shtml", "Payment.xhtml"])
            m.add_attachment(page.encode(), maintype="text", subtype="html", filename=name)
            self.write("phish", "html-attachment", m)

    def malware(self, n: int) -> None:
        kinds = ["zip-js", "zip-lnk", "iso", "exe-double", "docm", "encrypted-zip"]
        for i in range(n):
            kind = kinds[i % len(kinds)]
            domain = self.rng.choice(["freightline-invoices.com", "payroll-notice.biz", "courier-docs.net"])
            m = self.msg(
                '"%s" <billing@%s>' % (self.person(), domain),
                "Invoice %d overdue" % self.rng.randint(100, 999),
                self.rng.choice([PASS_AUTH, FAIL_AUTH]),
                domain,
            )
            body = "Hi, the overdue invoice is attached. Please process the payment today."
            if kind == "encrypted-zip":
                body += " Password: 4471"
            m.set_content(body + "\n")
            if kind.startswith("zip") or kind == "encrypted-zip":
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as archive:
                    inner = {"zip-js": "Invoice.pdf.js", "zip-lnk": "Invoice.lnk"}.get(kind, "Invoice.exe")
                    archive.writestr(inner, "// inert synthetic payload\n")
                data = bytearray(buf.getvalue())
                if kind == "encrypted-zip":
                    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
                        pos = data.find(sig)
                        while pos != -1:
                            data[pos + off] |= 1
                            pos = data.find(sig, pos + 4)
                m.add_attachment(bytes(data), maintype="application", subtype="zip", filename="Invoice_%d.zip" % i)
            elif kind == "iso":
                m.add_attachment(
                    b"\0" * 0x8001 + b"CD001" + b"\0" * 64,
                    maintype="application",
                    subtype="octet-stream",
                    filename="Invoice_%d.iso" % i,
                )
            elif kind == "exe-double":
                m.add_attachment(
                    b"MZ inert synthetic",
                    maintype="application",
                    subtype="octet-stream",
                    filename="Invoice_%d.pdf.exe" % i,
                )
            else:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as archive:
                    archive.writestr("[Content_Types].xml", "<Types/>")
                    archive.writestr("word/vbaProject.bin", b"\0inert")
                m.add_attachment(
                    buf.getvalue(),
                    maintype="application",
                    subtype="vnd.ms-word.document.macroEnabled.12",
                    filename="Invoice_%d.docm" % i,
                )
            self.write("phish", "malware-attachment", m)

    def masquerade(self, n: int) -> None:
        for i in range(n):
            domain = "scan-delivery-%d.com" % i
            m = self.msg('"Scanner" <scanner@%s>' % domain, "Scanned document", PASS_AUTH, domain)
            m.set_content("Scanned document attached.\n")
            if i % 2:
                m.add_attachment(b"MZ\x90\x00 inert", maintype="image", subtype="jpeg", filename="scan_%d.jpg" % i)
            else:
                m.add_attachment(
                    b"<html><body>inert</body></html>",
                    maintype="application",
                    subtype="pdf",
                    filename="scan_%d.pdf" % i,
                )
            self.write("phish", "masquerade", m)

    def bec_lookalike(self, n: int) -> None:
        fakes = [
            "northw1nd-traders.co.uk",
            "northwind-traders.com",
            "nortwind-traders.co.uk",
            "northwind-traders-finance.com",
            "northwlnd-traders.co.uk",
        ]
        asks = [
            "Please process a wire transfer of GBP %d to our new supplier today. Bank details have changed.",
            "I need you to buy 5 gift cards (GBP %d each) for a client, keep this confidential.",
            "Can you update my payroll bank account before Friday? New bank account details below. Ref %d",
        ]
        for _ in range(n):
            fake = self.rng.choice(fakes)
            boss = self.person()
            m = self.msg('"%s" <%s@%s>' % (boss, boss.split()[0].lower(), fake), "Quick favour", PASS_AUTH, fake)
            m.set_content(
                "Hi,\n\n%s\n\nThanks,\n%s\n"
                % (self.rng.choice(asks) % self.rng.randint(400, 9000), boss.split()[0])
            )
            self.write("phish", "bec-lookalike", m)

    def ceo_freemail(self, n: int) -> None:
        for i in range(n):
            boss = self.person()
            display = [boss, "%s | CEO" % boss, "Finance Team", "Payroll Department"][i % 4]
            m = self.msg(
                '"%s" <%s.%d@gmail.com>' % (display, boss.split()[0].lower(), self.rng.randint(1, 99)),
                "Urgent",
                PASS_AUTH,
                "gmail.com",
            )
            m.set_content("Are you at your desk? I need an urgent payment made today, reply asap.\n")
            self.write("phish", "ceo-freemail", m)

    def callback(self, n: int) -> None:
        vendors = [
            ("Geek Squad", "geeksquad"),
            ("Norton LifeLock", "norton"),
            ("PayPal Billing", "paypal"),
            ("McAfee Total Protection", "mcafee"),
        ]
        for _ in range(n):
            vendor, _ = self.rng.choice(vendors)
            m = self.msg(
                '"%s" <orders.%d@gmail.com>' % (vendor, self.rng.randint(10, 999)),
                "Your subscription has been renewed",
                PASS_AUTH,
                "gmail.com",
            )
            m.set_content(
                "Thank you. Your %s subscription has been renewed successfully for USD %d.99.\n"
                "If you did not authorize this charge, call us at +1 (888) %03d-%04d to cancel this order.\n"
                % (vendor, self.rng.randint(199, 499), self.rng.randint(200, 999), self.rng.randint(0, 9999))
            )
            self.write("phish", "callback", m)

    def reply_to_diversion(self, n: int) -> None:
        for _ in range(n):
            domain = self.rng.choice(["logistics-partners.com", "acme-supplies.co.uk"])
            m = self.msg(
                '"%s" <accounts@%s>' % (self.person(), domain), "Updated payment details", PASS_AUTH, domain
            )
            m["Reply-To"] = "accounts.dept%d@outlook.com" % self.rng.randint(1, 99)
            m.set_content(
                "Our bank details have changed. Please use the new bank account for the overdue invoice.\n"
            )
            self.write("phish", "reply-to-diversion", m)

    def open_redirect(self, n: int) -> None:
        for i in range(n):
            target = "https://%s/login" % self.rng.choice(["m365-verify.top", "secure-docs.icu"])
            wrap = [
                lambda t: "https://www.google.com/url?q=%s&sa=D" % t,
                lambda t: "https://www.google.com/amp/s/%s" % t.split("://", 1)[1],
                lambda t: (
                    "https://www.bing.com/ck/a?!&&p=x&u=a1%s"
                    % base64.urlsafe_b64encode(t.encode()).decode().rstrip("=")
                ),
            ][i % 3]
            m = self.msg(
                '"IT Helpdesk" <helpdesk@%s>' % "service-notices.net",
                "Mailbox is full",
                FAIL_AUTH,
                "service-notices.net",
            )
            m.set_content("Your mailbox is full. Sign in to keep your account: %s\n" % wrap(target))
            self.write("phish", "open-redirect", m)

    def shortener_ip(self, n: int) -> None:
        for i in range(n):
            link = ["https://bit.ly/3kq%dZp" % i, "http://185.220.%d.14/login" % i][i % 2]
            m = self.msg('"Security" <alerts@acct-notify.info>', "Security alert", FAIL_AUTH, "acct-notify.info")
            m.set_content("Suspicious activity on your account. Verify your account: %s\n" % link)
            self.write("phish", "shortener-ip", m)

    def punycode(self, n: int) -> None:
        for host in ["xn--pple-43d.com", "xn--micrsoft-q7a.com", "xn--pypal-4ve.com"][:n]:
            m = self.msg('"Support" <support@%s>' % host, "Verify your account", FAIL_AUTH, host)
            m.set_content("Verify your account: https://%s/verify\n" % host)
            self.write("phish", "punycode", m)

    def forwarded(self, n: int) -> None:
        for i in range(n):
            brand = self.rng.choice(["microsoft", "paypal", "dhl"])
            display, _, login, lure = BRANDS[brand]
            fake = LOOKALIKE[brand][0]
            url = "https://%s/verify" % fake
            if i % 2 == 0:  # forwarded as attachment
                inner = self.msg('"%s" <alert@%s>' % (display, fake), "Action required", FAIL_AUTH, fake)
                inner.set_content("%s.\nVerify: %s\n" % (lure.capitalize(), url))
                outer = self.msg(
                    '"%s" <%s@%s>' % (self.person(), "user", ORG), "FW: Action required", PASS_AUTH, ORG
                )
                outer.set_content("Looks dodgy, please check.\n")
                outer.add_attachment(inner)
            else:  # forwarded inline
                outer = self.msg(
                    '"%s" <%s@%s>' % (self.person(), "user", ORG), "Fwd: Action required", PASS_AUTH, ORG
                )
                outer.set_content(
                    "Is this real?\n\n---------- Forwarded message ---------\nFrom: %s <alert@%s>\n"
                    "Date: Mon, 1 Sep 2026\nSubject: Action required\n\n%s.\nVerify: %s\n"
                    % (display, fake, lure.capitalize(), url)
                )
            self.write("phish", "reported-forward", outer)

    def scams(self, n: int) -> None:
        texts = [
            "I am a barrister writing about an inheritance: you are listed as next of kin to my late client "
            "and the sum of 4.5 million dollars awaits transfer.",
            "I hacked your device and recorded you through your webcam. Send 0.1 BTC to my bitcoin wallet.",
            "Congratulations, you have been selected! Claim your gift card now, the reward is waiting.",
            "URGENT RESPONSE needed: compensation fund of USD 2,500,000 approved, send your ATM card details.",
        ]
        for i in range(n):
            m = self.msg('"%s" <info%d@outlook.com>' % (self.person(), i), "Attention", None, "outlook.com")
            m.set_content(texts[i % len(texts)] + "\n")
            self.write("phish", "scam", m)

    def qr_code(self, n: int) -> None:
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )
        for _ in range(n):
            m = self.msg(
                '"IT Security" <it-security@mfa-refresh.com>', "MFA re-enrolment", PASS_AUTH, "mfa-refresh.com"
            )
            m.set_content("Scan the QR code below with your phone to re-enrol multi-factor authentication.\n")
            m.add_attachment(png, maintype="image", subtype="png", filename="qr.png", disposition="inline")
            self.write("phish", "qr-code", m)

    def safelinks_phish(self, n: int) -> None:
        for _ in range(n):
            target = "https://o365-mailbox-%d.top/login" % self.rng.randint(1, 99)
            wrapped = "https://eur02.safelinks.protection.outlook.com/?url=%s&data=05%%7C01" % target.replace(
                ":", "%3A"
            ).replace("/", "%2F")
            m = self.msg(
                '"Microsoft 365" <noreply@m365-notify.site>',
                "Password expires today",
                FAIL_AUTH,
                "m365-notify.site",
            )
            m.set_content("Your password expires today. Keep your password: %s\n" % wrapped)
            self.write("phish", "safelinks-wrapped", m)

    # ------------------------------------------------------------ benign --
    def internal(self, n: int) -> None:
        topics = [
            ("Team lunch on Friday", "Lunch is booked for 12:30, see the menu: https://intranet.%s/menu" % ORG),
            ("Q3 planning notes", "Notes are on the wiki: https://wiki.%s/q3-planning" % ORG),
            ("Office closed Monday", "Reminder: the office is closed on Monday for maintenance."),
            ("Expense policy update", "The updated policy is here: https://intranet.%s/policies/expenses" % ORG),
        ]
        for _ in range(n):
            subject, text = self.rng.choice(topics)
            m = self.msg('"%s" <%s@%s>' % (self.person(), "comms", ORG), subject, PASS_AUTH, ORG, ip="10.1.2.3")
            m.set_content("Hi all,\n\n%s\n\nThanks\n" % text)
            self.write("benign", "internal", m)

    def genuine_alert(self, n: int) -> None:
        alerts = [
            (
                "Microsoft account team",
                "microsoft.com",
                "Microsoft account unusual sign-in activity",
                "https://account.live.com/Activity",
            ),
            (
                "Google",
                "accounts.google.com",
                "Security alert for your Google Account",
                "https://myaccount.google.com/notifications",
            ),
            ("Apple", "apple.com", "Your Apple ID was used to sign in to iCloud", "https://appleid.apple.com/"),
            (
                "PayPal",
                "paypal.com",
                "You logged in from a new device",
                "https://www.paypal.com/myaccount/security",
            ),
        ]
        for _ in range(n):
            display, domain, subject, link = self.rng.choice(alerts)
            m = self.msg('"%s" <no-reply@%s>' % (display, domain), subject, PASS_AUTH, domain)
            m.set_content(
                "We detected unusual activity. If this was you, you can ignore this email. "
                "Otherwise review your recent activity: %s\n" % link
            )
            self.write("benign", "genuine-alert", m)

    def newsletter(self, n: int) -> None:
        senders = [
            ("The Verge", "theverge.com"),
            ("Monzo", "monzo.com"),
            ("Ocado", "ocado.com"),
            ("GitHub", "github.com"),
            ("Figma", "figma.com"),
        ]
        for _ in range(n):
            display, domain = self.rng.choice(senders)
            m = self.msg(
                '"%s" <news@%s>' % (display, domain), "What's new this week at %s" % display, PASS_AUTH, domain
            )
            m["Return-Path"] = "<bounce-%d@em.sendgrid.net>" % self.rng.randint(1000, 9999)
            m["List-Unsubscribe"] = "<https://%s/unsubscribe?u=%d>" % (domain, self.rng.randint(1, 99999))
            links = "".join(
                '<p><a href="https://click.%s/ls/click?upn=%d">Read more</a></p>'
                % (domain, self.rng.randint(10**6, 10**7))
                for _ in range(6)
            )
            m.set_content("This week's highlights. Read online at https://%s/newsletter\n" % domain)
            m.add_alternative(self.html("<h2>This week</h2>" + links), subtype="html")
            self.write("benign", "newsletter", m)

    def password_reset(self, n: int) -> None:
        services = [
            ("GitHub", "github.com", "https://github.com/password_reset/%d"),
            ("Atlassian", "atlassian.com", "https://id.atlassian.com/login/resetpassword?token=%d"),
            ("Slack", "slack.com", "https://slack.com/reset-password/%d"),
        ]
        for _ in range(n):
            display, domain, link = self.rng.choice(services)
            m = self.msg(
                '"%s" <noreply@%s>' % (display, domain),
                "[%s] Please reset your password" % display,
                PASS_AUTH,
                domain,
            )
            m.set_content(
                "We heard you need a password reset. Use this link within 3 hours: %s\n"
                % (link % self.rng.randint(10**5, 10**6))
            )
            self.write("benign", "password-reset", m)

    def invoice(self, n: int) -> None:
        pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
        for _ in range(n):
            vendor = self.rng.choice(["brightline-cleaning.co.uk", "harbour-print.com", "kestrel-it.co.uk"])
            m = self.msg(
                '"Accounts" <accounts@%s>' % vendor,
                "Invoice INV-%d" % self.rng.randint(1000, 9999),
                PASS_AUTH,
                vendor,
            )
            m.set_content("Please find this month's invoice attached. Payment terms 30 days.\n")
            m.add_attachment(
                pdf, maintype="application", subtype="pdf", filename="INV-%d.pdf" % self.rng.randint(1, 999)
            )
            self.write("benign", "invoice", m)

    def calendar(self, n: int) -> None:
        for _ in range(n):
            m = self.msg('"%s" <%s@%s>' % (self.person(), "pm", ORG), "Invitation: Sprint review", PASS_AUTH, ORG)
            m.set_content("You have been invited to Sprint review.\n")
            m.add_attachment(
                b"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nSUMMARY:Sprint review\nEND:VEVENT\nEND:VCALENDAR\n",
                maintype="text",
                subtype="calendar",
                filename="invite.ics",
            )
            self.write("benign", "calendar", m)

    def hindi(self, n: int) -> None:
        for _ in range(n):
            m = self.msg('"%s" <%s@%s>' % (self.person(), "hr", ORG), "दिवाली की शुभकामनाएँ", PASS_AUTH, ORG)
            m.set_content(
                "सभी को दिवाली की हार्दिक शुभकामनाएँ। कार्यालय शुक्रवार को बंद रहेगा। क्\u200dष त्र\u200cय श्र\u200dद्धा\n"
            )
            self.write("benign", "hindi", m)

    def marketing_shortener(self, n: int) -> None:
        for _ in range(n):
            m = self.msg('"Ocado" <offers@ocado.com>', "Your weekly offers", PASS_AUTH, "ocado.com")
            m.set_content("This week's offers: https://bit.ly/ocado-offers-%d\n" % self.rng.randint(1, 99))
            self.write("benign", "marketing-shortener", m)

    def docusign(self, n: int) -> None:
        for _ in range(n):
            m = self.msg(
                '"DocuSign" <dse@docusign.net>', "Please DocuSign: Contract renewal", PASS_AUTH, "docusign.net"
            )
            m.set_content(
                "%s sent you a document to review and sign: https://app.docusign.com/signing/%d\n"
                % (self.person(), self.rng.randint(10**7, 10**8))
            )
            self.write("benign", "docusign", m)

    def hr_docx(self, n: int) -> None:
        for _ in range(n):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr("word/document.xml", "<w:document/>")
            m = self.msg('"People Team" <people@%s>' % ORG, "Updated handbook", PASS_AUTH, ORG, ip="10.1.2.3")
            m.set_content("The updated handbook is attached.\n")
            m.add_attachment(
                buf.getvalue(),
                maintype="application",
                subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
                filename="Handbook.docx",
            )
            self.write("benign", "hr-docx", m)

    def csv_zip(self, n: int) -> None:
        for _ in range(n):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                archive.writestr("sales.csv", "region,amount\nnorth,100\n")
            m = self.msg('"Reports" <reports@%s>' % ORG, "Weekly sales export", PASS_AUTH, ORG, ip="10.1.2.3")
            m.set_content("Export attached.\n")
            m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="sales.zip")
            self.write("benign", "csv-zip", m)

    def safelinks_internal(self, n: int) -> None:
        for _ in range(n):
            target = "https://wiki.%s/page/%d" % (ORG, self.rng.randint(1, 999))
            wrapped = "https://eur02.safelinks.protection.outlook.com/?url=%s&data=05" % (
                target.replace(":", "%3A").replace("/", "%2F")
            )
            m = self.msg(
                '"%s" <%s@%s>' % (self.person(), "team", ORG), "Docs for tomorrow", PASS_AUTH, ORG, ip="10.1.2.3"
            )
            m.set_content("Here is the page for tomorrow: %s\n" % wrapped)
            self.write("benign", "safelinks-internal", m)

    def shipping(self, n: int) -> None:
        for _ in range(n):
            carrier, domain = self.rng.choice(
                [("DHL", "dhl.com"), ("UPS", "ups.com"), ("Royal Mail", "royalmail.com")]
            )
            m = self.msg('"%s" <noreply@%s>' % (carrier, domain), "Your parcel is on its way", PASS_AUTH, domain)
            m.set_content(
                "Track your parcel: https://www.%s/track?id=%d\n" % (domain, self.rng.randint(10**8, 10**9))
            )
            self.write("benign", "shipping", m)

    def reply_chain(self, n: int) -> None:
        for _ in range(n):
            m = self.msg(
                '"%s" <%s@%s>' % (self.person(), "ops", ORG),
                "RE: rota for next week",
                PASS_AUTH,
                ORG,
                ip="10.1.2.3",
            )
            m.set_content("Works for me, I'll take Tuesday.\n\n> Can someone cover Tuesday?\n")
            self.write("benign", "reply-chain", m)

    def drive_share(self, n: int) -> None:
        for _ in range(n):
            m = self.msg(
                '"%s (via Google Drive)" <drive-shares-dm-noreply@google.com>' % self.person(),
                'Document shared with you: "Budget 2027"',
                PASS_AUTH,
                "google.com",
            )
            m.set_content(
                "%s shared a document with you: https://drive.google.com/file/d/%d/view\n"
                % (self.person(), self.rng.randint(10**9, 10**10))
            )
            self.write("benign", "drive-share", m)


def build(out: str, seed: int = 7) -> dict[str, int]:
    c = Corpus(out, seed)
    c.brand_credential(14)
    c.compromised_sender(8)
    c.html_attachment(8)
    c.malware(12)  # noqa: E702
    c.masquerade(4)
    c.bec_lookalike(8)
    c.ceo_freemail(8)
    c.callback(6)  # noqa: E702
    c.reply_to_diversion(5)
    c.open_redirect(6)
    c.shortener_ip(4)
    c.punycode(3)  # noqa: E702
    c.forwarded(6)
    c.scams(4)
    c.qr_code(3)
    c.safelinks_phish(3)  # noqa: E702
    c.internal(8)
    c.genuine_alert(8)
    c.newsletter(8)
    c.password_reset(5)
    c.invoice(5)  # noqa: E702
    c.calendar(3)
    c.hindi(3)
    c.marketing_shortener(3)
    c.docusign(3)
    c.hr_docx(3)  # noqa: E702
    c.csv_zip(2)
    c.safelinks_internal(4)
    c.shipping(4)
    c.reply_chain(3)
    c.drive_share(3)  # noqa: E702
    return c.counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    counts = build(args.out, args.seed)
    print("wrote %d emails across %d scenarios to %s" % (sum(counts.values()), len(counts), args.out))
