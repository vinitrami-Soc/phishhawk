"""Milestone M2's check (spec 11): 500 bundled and synthetic messages run as one batch without blocking the UI,
and the campaigns match what the CLI's 'phishhawk campaign' reports for the same messages. A real server and
worker process; it takes a few minutes, so CI runs it in a step of its own (PHISHHAWK_M2_CHECK=1)."""

import hashlib
import io
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
import requests

from phishhawk.campaign import correlate
from phishhawk.pipeline import triage_bytes

from .serverkit import PASSWORD, running_server
from conftest import sample

pytestmark = pytest.mark.skipif(not os.environ.get("PHISHHAWK_M2_CHECK"),
                                reason="the 500-message check runs on its own (PHISHHAWK_M2_CHECK=1)")
ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ("sample_bec_smuggling.eml", "sample_benign.eml", "sample_phish.eml", "sample_quishing.eml",
           "sample_reported.eml")


def _messages(tmp_path):
    """The bundled samples, then synthetic messages from eval/make_corpus.py: 500, each one different."""
    found = {}
    for name in SAMPLES:
        with open(sample(name), "rb") as handle:
            data = handle.read()
        found[hashlib.sha256(data).hexdigest()] = data
    for seed in (7, 8, 9):
        out = tmp_path / ("corpus%d" % seed)
        subprocess.run([sys.executable, str(ROOT / "eval" / "make_corpus.py"), str(out), "--seed", str(seed)],
                       check=True, capture_output=True)
        for path in sorted(out.rglob("*.eml")):
            data = path.read_bytes()
            found.setdefault(hashlib.sha256(data).hexdigest(), data)
    messages = list(found.values())[:500]
    assert len(messages) == 500
    return messages


def test_500_messages_run_as_one_batch_without_blocking_the_ui_and_campaigns_match_the_cli(tmp_path):
    messages = _messages(tmp_path)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for number, data in enumerate(messages):
            bundle.writestr("m%03d.eml" % number, data)
    (tmp_path / "server").mkdir()
    with running_server(tmp_path / "server") as server:
        web = requests.Session()
        csrf = web.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD}).json()
        web.headers["X-CSRF-Token"] = csrf["csrf"]
        started = time.monotonic()
        created = web.post(server.base + "/api/v1/submissions", data={"offline": "true"},
                           files=[("files", ("reported.zip", archive.getvalue(), "application/zip"))])
        assert created.status_code == 202, created.text
        batch_id, slowest = created.json()["batch_id"], 0.0
        while True:
            for path in ("/queue", "/api/v1/analyses", "/campaigns"):  # what an analyst opens meanwhile
                begun = time.perf_counter()
                assert web.get(server.base + path).status_code == 200
                slowest = max(slowest, time.perf_counter() - begun)
            batch = web.get(server.base + "/api/v1/batches/%d" % batch_id).json()
            if batch["status"] in ("done", "failed") and web.get(server.base + "/healthz").json()["queue"] == 0:
                break
            assert time.monotonic() - started < 1200, batch["counts"]
            time.sleep(0.5)
        took = time.monotonic() - started
        assert batch["status"] == "done" and batch["counts"]["done"] == 500, batch["counts"]
        assert len(batch["files"]) == 7 and all(f["available"] for f in batch["files"])
        assert slowest < 1.0, "a page took %.2f s while the batch ran" % slowest
        print("500 messages in %.0f s; the slowest page took %.2f s" % (took, slowest))

        rows = {m["position"]: m for m in batch["messages"]}
        sha = {"m%03d.eml" % (position - 1): web.get(server.base + "/api/v1/analyses/%d" % row["analysis_id"])
               .json()["sha256"] for position, row in rows.items()}
        campaigns = {}
        for campaign in web.get(server.base + "/api/v1/campaigns").json():
            detail = web.get(server.base + "/api/v1/campaigns/%d" % campaign["id"]).json()
            campaigns[frozenset(m["sha256"] for m in detail["messages"])] = campaign
    expected = correlate([("m%03d.eml" % n, triage_bytes(data, "m%03d.eml" % n))
                          for n, data in enumerate(messages)])
    assert len(campaigns) == len(expected["clusters"]) > 5
    for cluster in expected["clusters"]:
        campaign = campaigns[frozenset(sha[m["path"]] for m in cluster["messages"])]
        assert (campaign["size"], campaign["first_seen"], campaign["last_seen"], campaign["verdicts"],
                campaign["senders"]) == (cluster["size"], cluster["first_seen"], cluster["last_seen"],
                                         cluster["verdicts"], cluster["senders"])
        assert [s["kind"] for s in campaign["shared"]] == [s["kind"] for s in cluster["shared"]]
