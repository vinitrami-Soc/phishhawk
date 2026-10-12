"""Uploads stay in memory: a message must never reach the disk in clear (spec 5.2), so a request body is never
spooled to a temporary file, and one larger than the limit is refused before it is read."""

import asyncio
import tempfile

MB = 1024 * 1024


def big_message(size):
    head = b"From: a@example.com\r\nTo: b@example.org\r\nSubject: big\r\nContent-Type: text/plain\r\n\r\n"
    return head + b"x" * (size - len(head))


def test_an_upload_larger_than_a_megabyte_stays_in_memory(alice, monkeypatch):
    rolled = []
    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", lambda self: rolled.append(self))
    answer = alice.post("/api/v1/submissions", files={"file": ("big.eml", big_message(3 * MB), "message/rfc822")})
    assert answer.status_code == 202, answer.text
    assert rolled == []


def call(app, method, headers):
    """The app called directly, with a body it must not read: (status, body, whether it read it)."""
    sent, reads = [], []

    async def receive():
        reads.append(True)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": "/api/v1/submissions", "raw_path": b"/api/v1/submissions",
             "query_string": b"", "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
             "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 5000), "root_path": "",
             "http_version": "1.1"}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], body, bool(reads)


def test_a_body_over_the_limit_is_refused_before_it_is_read(app):
    # 4 x MAX_UPLOAD_MB (25) for a whole batch upload, so 101 MB is too much
    headers = {"content-length": str(101 * MB), "content-type": "multipart/form-data"}
    status, body, read = call(app, "POST", headers)
    assert (status, read) == (413, False)
    assert b"larger than 100 MB" in body


def test_a_body_without_a_length_is_refused(app):
    status, _, read = call(app, "POST", {"transfer-encoding": "chunked", "content-type": "multipart/form-data"})
    assert (status, read) == (411, False)
