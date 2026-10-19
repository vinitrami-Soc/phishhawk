"""Helpers the server tests share."""

import contextlib
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests

PASSWORD = "correct horse battery"
COMMAND = [sys.executable, "-m", "phishhawk", "server"]
# A Postgres server to run the web app's tests on, as postgresql://user@host:port/database: each test gets a
# database of its own there. Unset, the tests use SQLite in their own folder.
TEST_DATABASE = os.environ.get("PHISHHAWK_TEST_DATABASE_URL", "")


@contextlib.contextmanager
def fresh_database():
    """The URL of an empty database for one test, dropped afterwards; "" without TEST_DATABASE."""
    if not TEST_DATABASE:
        yield ""
        return
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    server = make_url(TEST_DATABASE.replace("postgresql://", "postgresql+psycopg://", 1))
    name = "phishhawk_test_" + secrets.token_hex(6)
    admin = create_engine(server, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    with admin.connect() as connection:
        connection.execute(text('CREATE DATABASE "%s"' % name))
    try:
        yield server.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as connection:
            connection.execute(text('DROP DATABASE IF EXISTS "%s" WITH (FORCE)' % name))
        admin.dispose()


def home(db):
    """The ID of the default organization, where the fixtures' users and data are."""
    from phishhawk.server import auth

    return auth.default_workspace(db)


def login(app, username, password=PASSWORD):
    """A client logged in as username, sending its CSRF token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post("/api/v1/session", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client


@dataclass
class Running:
    base: str
    process: subprocess.Popen
    log: Path
    env: dict[str, str]  # what it was started with: another worker can join it


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def running_server(tmp_path, **settings):
    """phishhawk server run as a real process on a free port, with an admin
    "root"; stopped with SIGTERM afterwards if the test has not stopped it.
    Keyword arguments are more PHISHHAWK_* variables."""
    from phishhawk.server.crypto import new_key

    port = _free_port()
    database = contextlib.ExitStack()
    url = database.enter_context(fresh_database())
    env = dict(os.environ, PHISHHAWK_DATA_DIR=str(tmp_path), PHISHHAWK_PORT=str(port),
               PHISHHAWK_SECRET_KEY=new_key(), PHISHHAWK_ENCRYPTION_KEY=new_key(), PHISHHAWK_COOKIE_SECURE="false",
               **({"PHISHHAWK_DATABASE_URL": url} if url else {}), **settings)
    log = tmp_path / "server.log"
    with open(log, "wb") as output:  # a file, not a pipe: a stray worker would hold a pipe open
        process = subprocess.Popen(COMMAND + ["run"], env=env, stdout=output, stderr=subprocess.STDOUT)
    try:
        base = "http://127.0.0.1:%d" % port
        deadline = time.monotonic() + 30
        while True:
            try:
                requests.get(base + "/healthz", timeout=1)
                break
            except requests.ConnectionError:
                assert time.monotonic() < deadline, log.read_text("utf-8", "replace")
                time.sleep(0.2)
        subprocess.run(COMMAND + ["create-admin", "root", "--password-stdin"], env=env, input=PASSWORD + "\n",
                       text=True, check=True, capture_output=True)
        yield Running(base, process, log, env)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=60)
        database.close()


@contextlib.contextmanager
def smtp_sink():
    """A mail server on this machine that keeps what it is sent, for a real server's mail: (its port, the raw
    messages, in order). It takes every message and checks nothing."""
    import socketserver
    import threading

    received: list[bytes] = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 sink\r\n")
            while line := self.rfile.readline():
                verb = line[:4].upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 go on\r\n")
                    lines = []
                    while (part := self.rfile.readline()) not in (b".\r\n", b""):
                        lines.append(part[1:] if part.startswith(b".") else part)  # a leading dot was doubled
                    received.append(b"".join(lines))
                    self.wfile.write(b"250 kept\r\n")
                elif verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 ok\r\n")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()
        server.server_close()

