"""Every route, called as anonymous, analyst, admin and with both kinds of
API token: the status says who may do what (spec 7.2)."""

import pytest

from phishhawk.server import worker

from .serverkit import login
from conftest import build_eml, sample

# (method, path, (anonymous, analyst, admin, read token, submit token))
MATRIX = [
    ("GET", "/api/v1/session", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/analyses", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/analyses/{analysis}", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/submissions/{submission}", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/batches/{batch}", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/batches/{batch}/files/{batch_file}", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/campaigns", (401, 200, 200, 200, 200)),
    ("GET", "/api/v1/campaigns/{campaign}", (401, 200, 200, 200, 200)),
    ("POST", "/api/v1/analyses/{analysis}/reanalyze", (401, 202, 202, 403, 202)),
    ("GET", "/api/v1/messages/{message}/raw", (401, 403, 200, 403, 403)),
    ("DELETE", "/api/v1/messages/{message}", (401, 403, 200, 403, 403)),
    ("POST", "/api/v1/messages/{message}/hold", (401, 403, 200, 403, 403)),
    ("DELETE", "/api/v1/messages/{message}/hold", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/settings", (401, 403, 200, 403, 403)),
    ("PATCH", "/api/v1/settings", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/users", (401, 403, 200, 403, 403)),
    ("POST", "/api/v1/users", (401, 403, 201, 403, 403)),
    ("GET", "/api/v1/tokens", (401, 403, 200, 403, 403)),
    ("GET", "/api/v1/audit", (401, 200, 200, 200, 200)),
    ("GET", "/settings", (303, 403, 200, 403, 403)),
    ("GET", "/users", (303, 403, 200, 403, 403)),
    ("GET", "/queue", (303, 200, 200, 200, 200)),
    ("GET", "/batches/{batch}", (303, 200, 200, 200, 200)),
    ("GET", "/campaigns", (303, 200, 200, 200, 200)),
    ("GET", "/campaigns/{campaign}", (303, 200, 200, 200, 200)),
]
BODIES = {("PATCH", "/api/v1/settings"): {"retention_days": 20},
          ("POST", "/api/v1/users"): {"username": "carol", "password": "another long password", "role": "analyst"}}


@pytest.fixture
def world(app, services, admin):
    """One analysed message submitted by the admin, and one token of each scope."""
    with open(sample("sample_phish.eml"), "rb") as handle:
        submitted = admin.post("/api/v1/submissions", files={"file": ("m.eml", handle.read(), "message/rfc822")},
                               data={"offline": "true"}).json()
    worker.run_one(services)
    analysis = admin.get("/api/v1/submissions/%d" % submitted["id"]).json()["analysis_id"]
    message = admin.get("/api/v1/analyses/%d" % analysis).json()["message_id"]
    users = {u["username"]: u["id"] for u in admin.get("/api/v1/users").json()}
    tokens = {scope: admin.post("/api/v1/tokens", json={"name": scope, "scope": scope,
                                                        "user_id": users["admin"]}).json()["token"]
              for scope in ("read", "submit")}
    doc = (b"%PDF-1.4 shared", "application", "pdf", "shared.pdf")  # one campaign
    two = [("files", ("m%d.eml" % i, build_eml(subject="Batch %d" % i, attachments=[doc]), "message/rfc822"))
           for i in range(2)]
    batch = admin.post("/api/v1/submissions", files=two, data={"offline": "true"}).json()["batch_id"]
    while worker.run_one(services):  # its messages, then its combined exports
        pass
    batch_file = admin.get("/api/v1/batches/%d" % batch).json()["files"][0]["name"]
    campaign = admin.get("/api/v1/campaigns").json()[0]["id"]
    return {"analysis": analysis, "message": message, "submission": submitted["id"], "tokens": tokens,
            "batch": batch, "batch_file": batch_file, "campaign": campaign}


@pytest.mark.parametrize("method, path, expected", MATRIX)
def test_the_role_matrix(app, anon, world, method, path, expected):
    from fastapi.testclient import TestClient

    url = path.format(**world)
    callers = [anon, login(app, "alice"), login(app, "admin")]
    for scope in ("read", "submit"):
        client = TestClient(app)
        client.headers["Authorization"] = "Bearer " + world["tokens"][scope]
        callers.append(client)
    for caller, status in zip(callers, expected, strict=True):
        response = caller.request(method, url, json=BODIES.get((method, path)), follow_redirects=False)
        assert response.status_code == status, (caller.headers.get("authorization", "session"), url,
                                                response.status_code, response.text[:200])
