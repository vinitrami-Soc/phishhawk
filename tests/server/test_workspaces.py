"""Workspaces: everything an organization or an individual keeps is its own, and no workspace reads or changes
another's (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md, sections 2 and 3)."""

import datetime as dt

import pytest
from sqlalchemy import select

from phishhawk.server import appsettings, audit, auth, jobs, rotation, worker
from phishhawk.server.crypto import Box, new_key
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER, AuditRecord, Campaign, Job, Message, Workspace

from .serverkit import PASSWORD, login
from conftest import build_eml

DOC = (b"%PDF-1.4 invoice 7731", "application", "pdf", "invoice.pdf")


def _build_invoices(n):
    return [build_eml(subject="Invoice %d" % i, sender="<a%d@one%d.example>" % (i, i), to="alice@corp.example",
                      attachments=[DOC], headers=[("Date", "Mon, 05 Oct 2026 09:00:00 +0000")]) for i in range(n)]


INVOICES = _build_invoices(2)  # the same bytes every time: the same messages


def _invoices(n):
    """n messages that share an attachment: one campaign."""
    return INVOICES[:n]


def _submit(client, services, messages):
    files = [("files", ("m%d.eml" % i, m, "message/rfc822")) for i, m in enumerate(messages)]
    created = client.post("/api/v1/submissions", files=files, data={"offline": "true"})
    assert created.status_code == 202, created.text
    while worker.run_one(services):
        pass
    return created.json()


@pytest.fixture
def beta(app, services):
    """The admin of a second organization, Beta."""
    with transaction(services.sessions) as s:
        workspace = Workspace(name="Beta", kind="organization")
        s.add(workspace)
        s.flush()
        auth.create_user(s, "beta", PASSWORD, "admin", workspace_id=workspace.id)
    return login(app, "beta")


@pytest.fixture
def theirs(alice, services):
    """What the default organization keeps: a batch of two messages, their analyses and the campaign of both."""
    created = _submit(alice, services, _invoices(2))
    batch = alice.get("/api/v1/batches/%d" % created["batch_id"]).json()
    analysis = alice.get("/api/v1/analyses/%d" % batch["messages"][0]["analysis_id"]).json()
    campaign = alice.get("/api/v1/campaigns").json()
    assert len(campaign) == 1 and batch["files"]
    return {"batch": batch, "analysis": analysis, "campaign": campaign[0],
            "submission": created["submission_ids"][0]}


def test_a_user_without_a_workspace_joins_the_default_organization(db):
    with transaction(db) as s:
        first = auth.create_user(s, "first", PASSWORD, "admin")
        second = auth.create_user(s, "second", PASSWORD, "analyst")
        workspace = s.get(Workspace, first.workspace_id)
        assert (workspace.name, workspace.kind) == ("Default organization", "organization")
        assert second.workspace_id == first.workspace_id


def test_the_first_admin_owns_the_server(db):
    with transaction(db) as s:
        analyst = auth.create_user(s, "watcher", PASSWORD, "analyst")
        first = auth.create_user(s, "first", PASSWORD, "admin")
        second = auth.create_user(s, "second", PASSWORD, "admin")
        assert (analyst.owner, first.owner, second.owner) == (False, True, False)


def test_the_actor_knows_its_workspace_from_a_session_and_from_a_token(db):
    with transaction(db) as s:
        solo = Workspace(name="Sam Lee", kind="individual")
        s.add(solo)
        s.flush()
        user = auth.create_user(s, "sam", PASSWORD, "admin", workspace_id=solo.id)
        cookie, _ = auth.open_session(s, user, "secret")
        token = auth.create_token(s, user, "script", "read")
    with transaction(db) as s:
        assert auth.find_session(s, cookie, "secret", 60).workspace_id == solo.id
        assert auth.find_token(s, token).workspace_id == solo.id


def test_the_session_says_which_workspace_and_whether_its_user_owns_the_server(admin, alice):
    mine = admin.get("/api/v1/session").json()
    assert mine["workspace"]["name"] == "Default organization"
    assert mine["workspace"]["kind"] == "organization"
    assert mine["owner"] is True
    theirs = alice.get("/api/v1/session").json()
    assert theirs["workspace"] == mine["workspace"]
    assert theirs["owner"] is False


def test_another_workspace_reads_none_of_theirs(beta, theirs):
    a, b = theirs["analysis"], theirs["batch"]
    for path in ("/api/v1/analyses/%d" % a["id"],
                 "/api/v1/analyses/%d/files/%s" % (a["id"], a["files"][0]["name"]),
                 "/api/v1/submissions/%d" % theirs["submission"], "/api/v1/batches/%d" % b["id"],
                 "/api/v1/batches/%d/files/%s" % (b["id"], b["files"][0]["name"]),
                 "/api/v1/messages/%d/raw" % a["message_id"], "/api/v1/campaigns/%d" % theirs["campaign"]["id"]):
        answer = beta.get(path)
        assert answer.status_code == 404, path
        assert "invoice" not in answer.text.lower(), path
    assert beta.get("/api/v1/analyses").json() == []
    assert beta.get("/api/v1/analyses", params={"q": a["sha256"]}).json() == []
    assert beta.get("/api/v1/campaigns").json() == []


def test_another_workspace_changes_none_of_theirs(beta, theirs, alice):
    a = theirs["analysis"]
    assert beta.post("/api/v1/analyses/%d/reanalyze" % a["id"]).status_code == 404
    assert beta.post("/api/v1/messages/%d/hold" % a["message_id"]).status_code == 404
    assert beta.delete("/api/v1/messages/%d/hold" % a["message_id"]).status_code == 404
    for extent in ("tier1", "all"):
        assert beta.delete("/api/v1/messages/%d" % a["message_id"], params={"scope": extent}).status_code == 404
    still = alice.get("/api/v1/analyses/%d" % a["id"]).json()
    assert still["hold"] is False and still["tier1_deleted_at"] is None and still["subject"] == "Invoice 0"


def test_the_same_message_in_two_workspaces_is_two_messages(beta, theirs, alice, services):
    mine = _submit(beta, services, _invoices(2))
    rows = beta.get("/api/v1/batches/%d" % mine["batch_id"]).json()["messages"]
    analysis = beta.get("/api/v1/analyses/%d" % rows[0]["analysis_id"]).json()
    assert analysis["sha256"] == theirs["analysis"]["sha256"]
    assert analysis["message_id"] != theirs["analysis"]["message_id"]
    assert len(beta.get("/api/v1/analyses").json()) == 2 and len(alice.get("/api/v1/analyses").json()) == 2
    ours, = beta.get("/api/v1/campaigns").json()
    assert ours["id"] != theirs["campaign"]["id"] and ours["size"] == 2
    assert alice.get("/api/v1/campaigns").json() == [theirs["campaign"]]  # untouched by Beta's rebuild


def test_each_workspace_has_its_own_settings(admin, beta):
    answer = admin.patch("/api/v1/settings", json={"protected_domains": ["corp.example"], "retention_days": 7,
                                                   "campaign_window_days": 3, "keys": {"virustotal": "k" * 64}})
    assert answer.status_code == 200, answer.text
    mine = beta.get("/api/v1/settings").json()
    assert mine["protected_domains"] == [] and mine["keys"]["virustotal"] == ""
    assert (mine["retention_days"], mine["campaign_window_days"]) != (7, 3)
    assert mine["server_limits"] == ["max_upload_mb", "max_batch_messages"]


def test_the_server_limits_are_the_owners_to_change_and_apply_to_everyone(admin, beta):
    current = beta.get("/api/v1/settings").json()
    refused = beta.patch("/api/v1/settings", json={"max_upload_mb": 5})
    assert refused.status_code == 403 and "owner" in refused.json()["detail"]
    same = {name: current[name] for name in ("retention_days", "max_upload_mb", "max_batch_messages",
                                             "campaign_window_days")}
    # the Settings screen sends every limit: unchanged, the server's are no change
    assert beta.patch("/api/v1/settings", json=same | {"retention_days": 9}).status_code == 200
    assert admin.patch("/api/v1/settings", json={"max_upload_mb": 5}).status_code == 200
    assert beta.get("/api/v1/settings").json()["max_upload_mb"] == 5
    assert beta.get("/api/v1/settings").json()["retention_days"] == 9
    assert admin.get("/api/v1/settings").json()["retention_days"] != 9


def test_an_analysis_uses_the_settings_of_its_workspace(services, db):
    with transaction(db) as s:
        ours = auth.default_workspace(s)
        other = Workspace(name="Beta", kind="organization")
        s.add(other)
        s.flush()
        appsettings.set_value(s, ours, "protected_domains", ["corp.example"])
        appsettings.set_value(s, ours, "providers", ["virustotal"])
        appsettings.set_secret(s, services.box, ours, "key:virustotal", "k" * 64)
        assert appsettings.trait_key(s, services.box) == appsettings.trait_key(s, services.box)  # one per server
        theirs = appsettings.analysis_options(s, services.box, services.settings, False, other.id)
        mine = appsettings.analysis_options(s, services.box, services.settings, False, ours)
    assert mine != theirs
    assert "corp.example" in repr(mine) and "corp.example" not in repr(theirs)
    assert "k" * 64 in repr(mine) and "k" * 64 not in repr(theirs)
    assert mine.cache_path != theirs.cache_path  # a lookup made with one workspace's key is not another's


def test_a_workspace_whose_campaigns_are_an_hour_old_is_rebuilt_whatever_another_does(beta, theirs, alice,
                                                                                         services):
    _submit(beta, services, _invoices(2))
    with transaction(services.sessions) as s:
        for campaign in s.scalars(select(Campaign)):
            if campaign.id == theirs["campaign"]["id"]:
                campaign.rebuilt_at -= dt.timedelta(minutes=61)
    worker.schedule(services)
    with transaction(services.sessions) as s:
        queued = s.scalars(select(Job.payload).where(Job.kind == "campaign_rebuild", Job.status == "queued")).all()
        default = auth.default_workspace(s)
    assert queued == [{"workspace_id": default}]


def test_key_rotation_reseals_every_workspaces_secrets(services, db):
    with transaction(db) as s:
        other = Workspace(name="Beta", kind="organization")
        s.add(other)
        s.flush()
        theirs = other.id
        appsettings.set_secret(s, services.box, auth.default_workspace(s), "key:urlscan", "ours-1234")
        appsettings.set_secret(s, services.box, theirs, "key:urlscan", "theirs-5678")
    new_box = Box.from_b64(new_key())
    with transaction(db) as s:
        assert rotation.rotate(s, services.store, new_box, actor="cli")["secrets"] == 2
    with transaction(db) as s:
        assert appsettings.get_secret(s, new_box, auth.default_workspace(s), "key:urlscan") == "ours-1234"
        assert appsettings.get_secret(s, new_box, theirs, "key:urlscan") == "theirs-5678"


def test_the_sweep_uses_each_workspaces_retention(beta, theirs, admin, services):
    _submit(beta, services, _invoices(1))
    assert admin.patch("/api/v1/settings", json={"retention_days": 1}).status_code == 200
    with transaction(services.sessions) as s:
        for message in s.scalars(select(Message)):
            message.first_seen_at -= dt.timedelta(days=2)
        jobs.enqueue(s, "retention_sweep")
    assert worker.run_one(services)
    assert admin.get("/api/v1/analyses/%d" % theirs["analysis"]["id"]).json()["tier1_deleted_at"] is not None
    kept = beta.get("/api/v1/analyses").json()
    assert kept and all(row["tier1_deleted_at"] is None for row in kept)


def test_another_workspace_sees_none_of_their_users_tokens_or_mailboxes(admin, beta, app):
    token = admin.post("/api/v1/tokens", json={"name": "script", "scope": "read",
                                               "user_id": admin.get("/api/v1/session").json()["user_id"]})
    assert token.status_code == 201, token.text
    box = admin.post("/api/v1/mailboxes", json={"name": "Reports", "kind": "imap", "secret": "pw",
                                                "config": {"host": "imap.example", "user": "soc@corp.example"}})
    assert box.status_code == 201, box.text
    alice_id = next(u["id"] for u in admin.get("/api/v1/users").json() if u["username"] == "alice")
    assert [u["username"] for u in beta.get("/api/v1/users").json()] == ["beta"]
    assert beta.get("/api/v1/tokens").json() == [] and beta.get("/api/v1/mailboxes").json() == []
    box_id = box.json()["id"]
    assert beta.patch("/api/v1/users/%d" % alice_id, json={"disabled": True}).status_code == 404
    assert beta.post("/api/v1/tokens", json={"name": "x", "scope": "read", "user_id": alice_id}).status_code == 404
    token_id, = [t["id"] for t in admin.get("/api/v1/tokens").json()]
    assert beta.delete("/api/v1/tokens/%d" % token_id).status_code == 404
    assert beta.get("/api/v1/mailboxes/%d" % box_id).status_code == 404
    assert beta.patch("/api/v1/mailboxes/%d" % box_id, json={"enabled": False}).status_code == 404
    assert beta.post("/api/v1/mailboxes/%d/poll" % box_id).status_code == 404
    assert beta.delete("/api/v1/mailboxes/%d" % box_id).status_code == 404
    assert admin.get("/api/v1/mailboxes/%d" % box_id).json()["enabled"] is True
    assert not any(t["revoked"] for t in admin.get("/api/v1/tokens").json())
    assert login(app, "alice").get("/api/v1/session").status_code == 200  # still enabled
    same_name = beta.post("/api/v1/mailboxes", json={"name": "Reports", "kind": "imap", "secret": "pw",
                                                     "config": {"host": "imap.example",
                                                                "user": "soc@beta.example"}})
    assert same_name.status_code == 201, same_name.text  # names are unique within a workspace


def test_each_admin_reads_the_audit_records_of_their_own_workspace(admin, beta, alice, anon, services):
    with transaction(services.sessions) as s:
        audit.record(s, "root", "create_admin", "user", 1, workspace_id=None)  # as written before workspaces
    assert anon.post("/api/v1/session", json={"username": "nobody", "password": "wrong"}).status_code == 401
    alice.get("/api/v1/session")
    beta.patch("/api/v1/settings", json={"providers": []})
    seen = {r["action"] for r in admin.get("/api/v1/audit").json()}
    assert {"create_admin", "login_failed", "login"} <= seen and "settings" not in seen
    theirs = beta.get("/api/v1/audit").json()
    assert {r["actor"] for r in theirs} == {"beta"} and {r["action"] for r in theirs} == {"login", "settings"}
    assert {r["actor"] for r in alice.get("/api/v1/audit").json()} == {"alice"}
    with transaction(services.sessions) as s:
        assert audit.verify(s) == []
        failed = s.scalars(select(AuditRecord.workspace_id).where(AuditRecord.action == "login_failed")).one()
        assert failed == SERVER


def test_a_records_workspace_is_part_of_its_hash(services):
    with transaction(services.sessions) as s:
        audit.record(s, "system", "test", workspace_id=SERVER)
    with transaction(services.sessions) as s:
        s.scalars(select(AuditRecord)).one().workspace_id = 7
    with transaction(services.sessions) as s:
        assert audit.verify(s) == ["record 1 was changed"]


def test_the_built_in_pages_show_another_workspace_none_of_theirs(beta, theirs):
    a, b = theirs["analysis"], theirs["batch"]
    for path in ("/analyses/%d" % a["id"], "/analyses/%d/files/%s" % (a["id"], a["files"][0]["name"]),
                 "/submissions/%d" % theirs["submission"], "/batches/%d" % b["id"],
                 "/batches/%d/files/%s" % (b["id"], b["files"][0]["name"]),
                 "/campaigns/%d" % theirs["campaign"]["id"]):
        assert beta.get(path).status_code == 404, path
    for path in ("/", "/queue", "/queue?q=" + a["sha256"], "/campaigns", "/users", "/audit", "/settings",
                 "/mailboxes"):
        page = beta.get(path)
        assert page.status_code == 200, path
        assert "Invoice" not in page.text and "alice" not in page.text, path
        assert "/analyses/%d" % a["id"] not in page.text, path
        assert "/campaigns/%d" % theirs["campaign"]["id"] not in page.text, path
    for path in ("/messages/%d/delete" % a["message_id"], "/messages/%d/hold" % a["message_id"],
                 "/analyses/%d/reanalyze" % a["id"]):
        assert beta.post(path, data={"csrf_token": beta.headers["X-CSRF-Token"]}).status_code == 404, path


def _ids(admin, theirs):
    """An ID of the default organization's for every kind of row a path names."""
    token = admin.post("/api/v1/tokens", json={"name": "guard", "scope": "read",
                                               "user_id": admin.get("/api/v1/session").json()["user_id"]})
    assert token.status_code == 201, token.text
    box = admin.post("/api/v1/mailboxes", json={"name": "Guarded", "kind": "imap", "secret": "pw",
                                                "config": {"host": "imap.example", "user": "soc@corp.example"}})
    assert box.status_code == 201, box.text
    invite = admin.post("/api/v1/invites", json={"role": "analyst", "note": "guard"})
    assert invite.status_code == 201, invite.text
    a = theirs["analysis"]
    return {"invite_id": invite.json()["id"],
            "analysis_id": a["id"], "submission_id": theirs["submission"], "batch_id": theirs["batch"]["id"],
            "message_id": a["message_id"], "campaign_id": theirs["campaign"]["id"], "mailbox_id": box.json()["id"],
            "user_id": a["submitted_by"], "token_id": admin.get("/api/v1/tokens").json()[0]["id"],
            "name": a["files"][0]["name"]}


def _routes(routes):
    """Every route, inside the routers the app includes too (FastAPI keeps those as one entry each)."""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is None:
            yield route
        else:
            yield from _routes(inner.routes)


def test_every_route_that_names_a_row_is_scoped(app, admin, beta, theirs):
    """Walks the app's routes: a new route that names a row, added without scope.py, fails here."""
    ids = _ids(admin, theirs)
    checked = 0
    for route in _routes(app.routes):
        path = getattr(route, "path", "")
        if "_id}" not in path:
            continue
        url = path.format(**ids)
        for method in sorted(getattr(route, "methods", set()) - {"HEAD"}):
            # a body every route takes, so nothing is refused (422) before the row is looked for
            form = {"data": {"csrf_token": beta.headers["X-CSRF-Token"]}}
            answer = beta.request(method, url, **({"json": {}} if path.startswith("/api/") else form))
            assert answer.status_code == 404, (method, path, answer.status_code, answer.text[:200])
            checked += 1
    assert checked >= 30  # the API's and the built-in pages'
    assert admin.get("/api/v1/analyses/%d" % ids["analysis_id"]).json()["tier1_deleted_at"] is None
    assert [m["id"] for m in admin.get("/api/v1/mailboxes").json()] == [ids["mailbox_id"]]
