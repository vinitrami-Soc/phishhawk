"""The daily limit on the messages each workspace submits (design spec, section 8): 500 a day for an
organization and 100 for someone on their own unless the owner sets others. Past it an upload answers 429 with
the seconds until the day (UTC) ends; another workspace is not held back."""

from phishhawk.server import appsettings, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER

from .test_accounts import PERSON, _open_signup, _signed_in
from .test_workspaces import _invoices, beta  # noqa: F401 - beta is a fixture

RAW = {"raw": "From: a@b.example\nTo: c@d.example\nSubject: Hello\n\nHello", "offline": "true"}


def _upload(client, messages):
    files = [("files", ("m%d.eml" % i, m, "message/rfc822")) for i, m in enumerate(messages)]
    return client.post("/api/v1/submissions", files=files, data={"offline": "true"})


def test_a_workspace_submits_at_most_its_daily_messages(admin, alice, beta, services):  # noqa: F811
    assert admin.patch("/api/v1/server-settings", json={"daily_messages_organization": 3}).status_code == 200
    assert alice.post("/api/v1/submissions", data=RAW).status_code == 202
    assert _upload(alice, _invoices(2)).status_code == 202  # 3 of 3
    while worker.run_one(services):
        pass
    refused = alice.post("/api/v1/submissions", data=RAW)
    assert refused.status_code == 429
    assert 0 < int(refused.headers["Retry-After"]) <= 86400
    assert "3 messages a day" in refused.json()["detail"] and "00:00 UTC" in refused.json()["detail"]
    analysis = alice.get("/api/v1/analyses").json()[0]["id"]
    assert alice.post("/api/v1/analyses/%d/reanalyze" % analysis).status_code == 429  # a new analysis counts too
    assert beta.post("/api/v1/submissions", data=RAW).status_code == 202  # every workspace has its own


def test_a_batch_past_the_limit_is_refused_whole(admin, alice):
    admin.patch("/api/v1/server-settings", json={"daily_messages_organization": 2})
    assert alice.post("/api/v1/submissions", data=RAW).status_code == 202
    refused = _upload(alice, _invoices(2))
    assert refused.status_code == 429 and "2 messages" in refused.json()["detail"]
    assert len(alice.get("/api/v1/analyses").json()) == 0 and alice.post("/api/v1/submissions",
                                                                         data=RAW).status_code == 202


def test_someone_on_their_own_has_the_individual_limit(anon, services):
    _open_signup(services)
    with transaction(services.sessions) as s:
        appsettings.set_value(s, SERVER, "daily_messages_individual", 1)
    _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    assert anon.post("/api/v1/submissions", data=RAW).status_code == 202
    assert anon.post("/api/v1/submissions", data=RAW).status_code == 429


def test_the_owner_sets_both_limits(admin):
    shown = admin.get("/api/v1/server-settings").json()
    assert (shown["daily_messages_organization"], shown["daily_messages_individual"]) == (500, 100)
    for field in ("daily_messages_organization", "daily_messages_individual"):
        refused = admin.patch("/api/v1/server-settings", json={field: 0})
        assert refused.status_code == 422 and refused.json()["detail"].startswith(field)
