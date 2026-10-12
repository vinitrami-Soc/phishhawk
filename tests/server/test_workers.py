"""Several workers on one Postgres database: each job is claimed by one of them (FOR UPDATE SKIP LOCKED), and
the audit chain stays whole. SQLite runs one worker, so this runs on Postgres only (serverkit.TEST_DATABASE)."""

import subprocess
import time

import pytest
import requests
from sqlalchemy import create_engine, text

from .serverkit import COMMAND, PASSWORD, TEST_DATABASE, running_server
from conftest import build_eml

pytestmark = pytest.mark.skipif(not TEST_DATABASE, reason="several workers need Postgres")


def test_three_workers_share_a_batch_and_each_job_runs_once(tmp_path):
    with running_server(tmp_path) as server:  # the web process and its worker
        others = [subprocess.Popen(COMMAND + ["worker"], env=server.env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL) for _ in range(2)]
        try:
            web = requests.Session()
            login = web.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
            web.headers["X-CSRF-Token"] = login.json()["csrf"]
            files = [("files", ("m%d.eml" % i, build_eml(subject="Message %d" % i,
                                                          sender="<s%d@sender%d.example>" % (i, i)), "x/y"))
                     for i in range(40)]
            batch = web.post(server.base + "/api/v1/submissions", files=files, data={"offline": "true"}).json()
            deadline = time.monotonic() + 300
            while True:
                status = web.get(server.base + "/api/v1/batches/%d" % batch["batch_id"]).json()["status"]
                if status == "done" and web.get(server.base + "/healthz").json()["queue"] == 0:
                    break
                assert time.monotonic() < deadline, status
                time.sleep(0.5)
        finally:
            for worker in others:
                worker.terminate()
                worker.wait(60)
        engine = create_engine(server.env["PHISHHAWK_DATABASE_URL"].replace("postgresql://", "postgresql+psycopg://"))
        with engine.connect() as db:
            assert db.execute(text("SELECT count(*) FROM analyses")).scalar() == 40
            assert db.execute(text("SELECT count(DISTINCT submission_id) FROM analyses")).scalar() == 40
            assert db.execute(text("SELECT max(attempts) FROM jobs")).scalar() == 1
            assert db.execute(text("SELECT count(*) FROM jobs WHERE status <> 'done'")).scalar() == 0
        engine.dispose()
        verified = subprocess.run(COMMAND + ["audit", "verify"], env=server.env, capture_output=True, text=True)
        assert verified.returncode == 0, verified.stdout + verified.stderr
