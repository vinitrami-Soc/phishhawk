"""phishhawk server run, as a real process: health, log in, submit a bundled
sample, verdict within 5 seconds offline, every file downloads, clean stop."""

import os
import signal
import time

import requests

from .serverkit import PASSWORD, running_server
from conftest import sample

KINDS = ["json", "stix", "misp", "md", "csv", "html", "manifest"]


def _children(pid):
    """Linux only; elsewhere the check that no worker outlives the server is skipped."""
    path = "/proc/%d/task/%d/children" % (pid, pid)
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        return [int(child) for child in handle.read().split()]


def _alive(pid):
    """Running, not a zombie waiting to be reaped."""
    try:
        with open("/proc/%d/stat" % pid) as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_run_serves_a_sample_end_to_end_and_stops_cleanly(tmp_path):
    with running_server(tmp_path) as server:
        web = requests.Session()
        login = web.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
        web.headers["X-CSRF-Token"] = login.json()["csrf"]
        with open(sample("sample_phish.eml"), "rb") as handle:
            started = time.monotonic()
            submitted = web.post(server.base + "/api/v1/submissions", files={"file": ("m.eml", handle)},
                                 data={"offline": "true"})
        assert submitted.status_code == 202, submitted.text
        status = submitted.json()
        while status["status"] in ("queued", "running") and time.monotonic() - started < 30:
            time.sleep(0.1)
            status = web.get(server.base + "/api/v1/submissions/%d" % status["id"]).json()
        elapsed = time.monotonic() - started
        assert status["status"] == "done", status
        assert elapsed < 5, "submit to verdict took %.1f s" % elapsed
        analysis = web.get(server.base + "/api/v1/analyses/%d" % status["analysis_id"]).json()
        assert analysis["verdict"] == "LIKELY PHISHING"
        assert [f["kind"] for f in analysis["files"]] == KINDS
        for entry in analysis["files"]:
            got = web.get(server.base + "/api/v1/analyses/%d/files/%s" % (analysis["id"], entry["name"]))
            assert got.status_code == 200 and len(got.content) == entry["size"]
        children = _children(server.process.pid)
        server.process.send_signal(signal.SIGTERM)
        server.process.wait(timeout=60)
        assert server.process.returncode == 0, server.log.read_text("utf-8", "replace")
    time.sleep(1)
    assert not [pid for pid in children if _alive(pid)], "a worker outlived the server"
