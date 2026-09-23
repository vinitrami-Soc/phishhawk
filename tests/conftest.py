"""Shared fixtures. Everything is offline: API clients get fake sessions."""

import os
from email.message import EmailMessage

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def sample(name: str) -> str:
    return os.path.join(SAMPLES, name)


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Answers from a callable(method, url, kwargs) or a queue of responses."""

    def __init__(self, responder=None, queue=None):
        self.responder = responder
        self.queue = list(queue or [])
        self.calls = []

    def _answer(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        if self.responder is not None:
            return self.responder(method, url, kwargs)
        return self.queue.pop(0)

    def get(self, url, **kwargs):
        return self._answer("get", url, kwargs)

    def post(self, url, **kwargs):
        return self._answer("post", url, kwargs)


def vt_stats(malicious, suspicious=0, label=""):
    attributes = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                          "harmless": 60, "undetected": 5, "timeout": 0},
                  "last_analysis_date": 1758000000}
    if label:
        attributes["popular_threat_classification"] = {"suggested_threat_label": label}
    return {"data": {"attributes": attributes}}


def build_eml(subject="Test", sender='"Sender" <a@sender.example>', to="user@example-corp.co.uk",
              text="hello", html=None, attachments=(), headers=()):
    """attachments: iterable of (bytes, maintype, subtype, filename[, disposition])."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    for name, value in headers:
        msg[name] = value
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for item in attachments:
        data, maintype, subtype, filename = item[:4]
        disposition = item[4] if len(item) > 4 else "attachment"
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename,
                           disposition=disposition)
    return msg.as_bytes()
