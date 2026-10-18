"""Deleting accounts and workspaces (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md,
section 9): an admin deletes a member, the server's owner deletes a workspace with everything in it, and an
individual deletes their own account and workspace."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from phishhawk.server import audit
from phishhawk.server.db import transaction
from phishhawk.server.models import (
    SERVER,
    Analysis,
    AuditRecord,
    Batch,
    Feedback,
    Job,
    Mailbox,
    Message,
    Setting,
    User,
    VerdictFeedback,
    Workspace,
)

from .serverkit import PASSWORD, login
from .test_accounts import PERSON, _open_signup, _signed_in
from .test_workspaces import _invoices, _submit, beta  # noqa: F401 - beta is a fixture


def _blobs(services):
    return {p.name for p in (services.settings.data_dir / "blobs").rglob("*") if p.is_file()}


def _workspace_id(services, name):
    with transaction(services.sessions) as s:
        return s.scalars(select(Workspace.id).where(Workspace.name == name)).one()


def test_the_owner_sees_each_workspace_by_name_kind_and_members_only(admin, alice, beta):  # noqa: F811
    listed = admin.get("/api/v1/workspaces")
    assert listed.status_code == 200, listed.text
    assert [(w["name"], w["kind"], w["members"]) for w in listed.json()] == [
        ("Default organization", "organization", 3), ("Beta", "organization", 1)]
    assert set(listed.json()[0]) == {"id", "name", "kind", "members", "created_at"}  # no one's profile
    assert alice.get("/api/v1/workspaces").status_code == 403
    assert beta.get("/api/v1/workspaces").status_code == 403  # an admin, but not the owner


def test_the_owner_deletes_a_workspace_with_everything_in_it(admin, beta, services):  # noqa: F811
    _submit(admin, services, _invoices(1))
    kept = _blobs(services)
    _submit(beta, services, [m.replace(b"Invoice", b"Beta invoice") for m in _invoices(2)])
    assert beta.patch("/api/v1/settings", json={"retention_days": 20}).status_code == 200
    box = {"name": "Reports", "kind": "imap", "secret": "pw", "config": {"host": "imap.example", "user": "soc"}}
    assert beta.post("/api/v1/mailboxes", json=box).status_code == 201
    assert beta.post("/api/v1/feedback", json={"kind": "idea", "message": "Hello"}).status_code == 201
    assert _blobs(services) > kept
    gone = _workspace_id(services, "Beta")

    assert admin.delete("/api/v1/workspaces/%d" % gone).status_code == 204
    assert beta.get("/api/v1/session").status_code == 401  # signed out: the account is gone too
    assert [w["name"] for w in admin.get("/api/v1/workspaces").json()] == ["Default organization"]
    assert _blobs(services) == kept  # its messages, reports and exports, not anyone else's
    with transaction(services.sessions) as s:
        for model in (User, Message, Analysis, Batch, Mailbox, Setting, Job, Feedback, VerdictFeedback):
            left = s.scalar(select(func.count()).select_from(model).where(model.workspace_id == gone))
            assert left == 0, model.__name__
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "workspace_delete")).one()
        assert (record.actor, record.workspace_id) == ("admin", SERVER)
        assert record.details == {"workspace": gone, "name": "Beta", "kind": "organization", "members": 1,
                                  "messages": 2}
        assert audit.verify(s) == []  # its records stay: the chain still holds


def test_only_the_owner_deletes_a_workspace_and_never_their_own(app, admin, alice, beta, services):  # noqa: F811
    theirs, mine = _workspace_id(services, "Beta"), _workspace_id(services, "Default organization")
    assert beta.delete("/api/v1/workspaces/%d" % theirs).status_code == 404  # to anyone else there are none
    assert beta.delete("/api/v1/workspaces/%d" % mine).status_code == 404
    assert alice.delete("/api/v1/workspaces/%d" % theirs).status_code == 403
    refused = admin.delete("/api/v1/workspaces/%d" % mine)
    assert refused.status_code == 409 and "your own" in refused.json()["detail"]
    assert admin.delete("/api/v1/workspaces/999999").status_code == 404
    me = admin.get("/api/v1/session").json()["user_id"]
    token = admin.post("/api/v1/tokens", json={"name": "ops", "scope": "submit", "user_id": me}).json()["token"]
    robot = TestClient(app, headers={"Authorization": "Bearer " + token})
    assert robot.delete("/api/v1/workspaces/%d" % theirs).status_code == 403  # a person at a browser only
    assert len(admin.get("/api/v1/workspaces").json()) == 2


def test_an_admin_deletes_a_member_and_the_work_they_did_stays(app, admin, alice, bob, services):
    users = {u["username"]: u["id"] for u in admin.get("/api/v1/users").json()}
    _submit(alice, services, _invoices(1))
    analysis = admin.get("/api/v1/analyses").json()[0]["id"]
    assert alice.put("/api/v1/analyses/%d/feedback" % analysis, json={"opinion": "missed"}).status_code == 200
    assert alice.post("/api/v1/feedback", json={"kind": "idea", "message": "Mine"}).status_code == 201

    assert bob.delete("/api/v1/users/%d" % users["alice"]).status_code == 403  # admins only
    assert admin.delete("/api/v1/users/%d" % users["admin"]).status_code == 422  # not yourself
    assert admin.delete("/api/v1/users/%d" % users["alice"]).status_code == 204
    assert alice.get("/api/v1/session").status_code == 401
    assert "alice" not in [u["username"] for u in admin.get("/api/v1/users").json()]
    assert [a["id"] for a in admin.get("/api/v1/analyses").json()] == [analysis]  # the workspace's, not hers
    assert admin.get("/api/v1/analyses/%d/feedback" % analysis).json()["answers"] == []  # her word went with her
    assert admin.get("/api/v1/feedback").json() == []
    assert admin.delete("/api/v1/users/%d" % users["alice"]).status_code == 404
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "user_delete")).one()
        assert (record.actor, record.details) == ("admin", {"username": "alice", "role": "analyst"})


def test_no_admin_deletes_the_servers_owner(app, admin):
    assert admin.post("/api/v1/users", json={"username": "carol", "password": PASSWORD,
                                             "role": "admin"}).status_code == 201
    owner = admin.get("/api/v1/session").json()["user_id"]
    refused = login(app, "carol").delete("/api/v1/users/%d" % owner)
    assert refused.status_code == 403 and "owner" in refused.json()["detail"]


def test_an_individual_deletes_their_own_account_and_workspace(anon, admin, services):
    _open_signup(services)
    kept = _blobs(services)
    me = _signed_in(anon, anon.post("/api/v1/signup", json=PERSON | {"kind": "individual"}))
    _submit(anon, services, _invoices(1))
    assert _blobs(services) > kept

    wrong = anon.request("DELETE", "/api/v1/me", json={"password": "not the password"})
    assert wrong.status_code == 403 and "password" in wrong.json()["detail"]
    done = anon.request("DELETE", "/api/v1/me", json={"password": PASSWORD})
    assert done.status_code == 204, done.text
    assert "phishhawk_session" not in anon.cookies
    assert anon.get("/api/v1/session").status_code == 401
    assert me["workspace"]["id"] not in [w["id"] for w in admin.get("/api/v1/workspaces").json()]
    assert _blobs(services) == kept
    assert TestClient(anon.app).post("/api/v1/session", json={"username": "sam",
                                                                "password": PASSWORD}).status_code == 401
    with transaction(services.sessions) as s:
        record = s.scalars(select(AuditRecord).where(AuditRecord.action == "account_delete")).one()
        assert (record.actor, record.workspace_id) == ("sam", SERVER)
        assert record.details == {"workspace": me["workspace"]["id"], "kind": "individual", "messages": 1}


def test_in_an_organization_an_admin_deletes_accounts(alice, admin):
    for person in (alice, admin):  # the owner too: the server would have no one to run it
        refused = person.request("DELETE", "/api/v1/me", json={"password": PASSWORD})
        assert refused.status_code == 403, refused.text
    assert "admin" in alice.request("DELETE", "/api/v1/me", json={"password": PASSWORD}).json()["detail"]
    assert alice.get("/api/v1/session").status_code == 200
