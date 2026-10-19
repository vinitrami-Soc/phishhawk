"""Sending mail: plain text through the SMTP server in the settings, with STARTTLS (port 587), TLS from the
first byte (465) or, for a relay on this machine, neither. Certificates are always verified."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from .config import ServerSettings

TIMEOUT = 20  # seconds for each step with the SMTP server


def send(settings: ServerSettings, to: str, subject: str, body: str) -> None:
    """One message to one address. Raises OSError or smtplib.SMTPException when it cannot be handed over."""
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=parseaddr(settings.smtp_from)[1].rpartition("@")[2] or None)
    message["Auto-Submitted"] = "auto-generated"  # an automatic message: no out-of-office replies to it
    message.set_content(body)
    context = ssl.create_default_context()
    if settings.smtp_security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT,
                                                context=context)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT)
    with server:
        if settings.smtp_security == "starttls":
            server.starttls(context=context)
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password.get_secret_value())
        server.send_message(message)
