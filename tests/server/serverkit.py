"""Helpers the server tests share."""

import contextlib
import os
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


def login(app, username):
    """A client logged in as username, sending its CSRF token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.post("/api/v1/session", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client


@dataclass
class Running:
    base: str
    process: subprocess.Popen
    log: Path


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
    env = dict(os.environ, PHISHHAWK_DATA_DIR=str(tmp_path), PHISHHAWK_PORT=str(port),
               PHISHHAWK_SECRET_KEY=new_key(), PHISHHAWK_ENCRYPTION_KEY=new_key(), PHISHHAWK_COOKIE_SECURE="false",
               **settings)
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
        yield Running(base, process, log)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=60)
