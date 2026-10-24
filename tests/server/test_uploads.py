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


def call(app, method, headers, path="/api/v1/submissions"):
    """The app called directly, with a body it must not read: (status, body, whether it read it)."""
    sent, reads = [], []

    async def receive():
        reads.append(True)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
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


def test_a_large_body_is_read_only_for_someone_logged_in(app):
    """Only an upload may be larger than a megabyte, and only a caller with a valid session or API token may
    send one: anyone else could make the server hold 100 MB requests in memory without logging in."""
    headers = {"content-length": str(50 * MB), "content-type": "multipart/form-data; boundary=x"}
    for credential in ({}, {"cookie": "phishhawk_session=made-up"}, {"authorization": "Bearer phk_made-up"}):
        for path in ("/api/v1/submissions", "/"):
            status, _, read = call(app, "POST", headers | credential, path)
            assert (status, read) == (401, False), (credential, path)


def test_nothing_but_an_upload_may_be_larger_than_a_megabyte(app, admin):
    cookie = "; ".join("%s=%s" % pair for pair in admin.cookies.items())
    for method, path in (("POST", "/api/v1/session"), ("POST", "/login"), ("PATCH", "/api/v1/settings"),
                         ("POST", "/api/v1/mailboxes")):
        for credential in ({}, {"cookie": cookie}):
            headers = {"content-length": str(2 * MB), "content-type": "application/json"} | credential
            status, body, read = call(app, method, headers, path)
            assert (status, read) == (413, False), (path, credential)
    assert b"larger than 1 MB" in body


def test_accepting_an_upload_does_not_hold_up_everyone_else(app, alice, monkeypatch):
    """Accepting an upload (opening an archive, sealing each message, writing its rows) takes seconds for a big
    batch. It runs on a worker thread: the server answers other requests meanwhile, instead of all of them waiting
    for it."""
    import time

    import httpx

    from phishhawk.server.routes import api

    def slow(*args, **kwargs):
        time.sleep(1)
        return {"id": 1, "status": "queued"}

    monkeypatch.setattr(api, "accept_upload", slow)

    async def upload_and_ask():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver",
                                     cookies=dict(alice.cookies.items()),
                                     headers=dict(alice.headers)) as client:
            message = {"file": ("m.eml", big_message(2048), "message/rfc822")}
            upload = asyncio.create_task(client.post("/api/v1/submissions", files=message))
            started = time.monotonic()
            await asyncio.sleep(0.2)  # the upload is being accepted now
            other = await client.get("/robots.txt")
            waited = time.monotonic() - started
            return (await upload).status_code, other.status_code, waited

    uploaded, answered, waited = asyncio.run(upload_and_ask())
    assert (uploaded, answered) == (202, 200)
    assert waited < 0.7, waited  # 0.2 s of its own; the upload's second is not on its account

