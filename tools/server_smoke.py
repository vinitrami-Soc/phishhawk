#!/usr/bin/env python3
"""Check a running PhishHawk web app from outside, the way an analyst uses it.

    SMOKE_PASSWORD=... python tools/server_smoke.py http://127.0.0.1:8000 --user admin

Waits for /healthz, logs in, submits samples/sample_phish.eml offline, waits
for the verdict, downloads every file and checks the HTML report is served
sandboxed. Exits 1 at the first step that fails. CI runs it against the
Compose stack; admins can run it after an upgrade.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "sample_phish.eml")
KINDS = ["json", "stix", "misp", "md", "csv", "html", "manifest"]


def check(base: str, user: str, password: str, wait: float = 60) -> None:
    deadline = time.monotonic() + wait
    while True:
        try:
            health = requests.get(base + "/healthz", timeout=5).json()
            break
        except (requests.ConnectionError, ValueError):
            if time.monotonic() > deadline:
                raise AssertionError("no answer from %s/healthz" % base) from None
            time.sleep(1)
    print("health: %s, version %s" % (health["status"], health["version"]))
    web = requests.Session()
    login = web.post(base + "/api/v1/session", json={"username": user, "password": password}, timeout=10)
    assert login.status_code == 200, "log in: HTTP %d" % login.status_code
    web.headers["X-CSRF-Token"] = login.json()["csrf"]
    with open(SAMPLE, "rb") as handle:
        submitted = web.post(base + "/api/v1/submissions", files={"file": ("sample_phish.eml", handle)},
                             data={"offline": "true"}, timeout=30)
    assert submitted.status_code == 202, "submit: HTTP %d" % submitted.status_code
    status = submitted.json()
    while status["status"] in ("queued", "running"):
        assert time.monotonic() < deadline + wait, "no verdict after %d s" % wait
        time.sleep(0.5)
        status = web.get(base + "/api/v1/submissions/%d" % status["id"], timeout=10).json()
    assert status["status"] == "done", "analysis: %s" % status.get("error")
    analysis = web.get(base + "/api/v1/analyses/%d" % status["analysis_id"], timeout=10).json()
    print("verdict: %s, score %s, report %s" % (analysis["verdict"], analysis["score"], analysis["report_id"]))
    assert [f["kind"] for f in analysis["files"]] == KINDS, "files: %s" % analysis["files"]
    for entry in analysis["files"]:
        got = web.get(base + "/api/v1/analyses/%d/files/%s" % (analysis["id"], entry["name"]), timeout=30)
        assert got.status_code == 200 and len(got.content) == entry["size"], "download %s" % entry["name"]
    html = next(f["name"] for f in analysis["files"] if f["kind"] == "html")
    page = web.get(base + "/analyses/%d/files/%s" % (analysis["id"], html), timeout=30)
    assert page.headers.get("content-security-policy", "").startswith("sandbox"), "report not sandboxed"
    print("downloads: all %d files; HTML report served sandboxed" % len(analysis["files"]))
    web.delete(base + "/api/v1/session", timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("base", help="the app's address, e.g. http://127.0.0.1:8000")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password-env", default="SMOKE_PASSWORD", metavar="NAME",
                        help="the environment variable that holds the password (default: SMOKE_PASSWORD)")
    args = parser.parse_args()
    try:
        check(args.base.rstrip("/"), args.user, os.environ[args.password_env])
    except (AssertionError, KeyError, requests.RequestException) as exc:
        print("FAILED: %s" % exc, file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
