"""The JSON API end to end: login, CSRF, submit, worker, view, download,
delete, and the headers on every response."""

from phishhawk.server import worker
from phishhawk.server.security import REPORT_CSP

from conftest import sample


def _raw(name="sample_bec_smuggling.eml"):
    with open(sample(name), "rb") as handle:
        return handle.read()


def _analysed(client, services, name="sample_bec_smuggling.eml"):
    response = client.post("/api/v1/submissions", files={"file": ("m.eml", _raw(name), "message/rfc822")},
                           data={"offline": "true"})
    assert response.status_code == 202, response.text
    assert set(response.json()) == {"id", "status", "error", "analysis_id", "submitted_at"}
    submission_id = response.json()["id"]
    assert worker.run_one(services)
    status = client.get("/api/v1/submissions/%d" % submission_id).json()
    assert status["status"] == "done", status
    return status["analysis_id"]


def test_every_response_has_the_security_headers(anon):
    for path in ("/healthz", "/api/v1/analyses"):
        headers = anon.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"], path
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"


def test_health_reports_the_queue(anon):
    body = anon.get("/healthz").json()
    assert body["status"] == "ok" and body["queue"] == 0


def test_login_sets_a_strict_http_only_cookie_and_wrong_passwords_are_audited(app, anon, admin):
    response = anon.post("/api/v1/session", json={"username": "alice", "password": "not the password"})
    assert response.status_code == 401
    good = anon.post("/api/v1/session", json={"username": "alice", "password": "correct horse battery"})
    cookie = good.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    actions = [r["action"] for r in admin.get("/api/v1/audit").json()]
    assert "login_failed" in actions


def test_a_state_change_without_the_csrf_token_is_refused(alice):
    token = alice.headers.pop("X-CSRF-Token")
    files = {"file": ("m.eml", _raw(), "message/rfc822")}
    assert alice.post("/api/v1/submissions", files=files).status_code == 403
    alice.headers["X-CSRF-Token"] = token
    assert alice.post("/api/v1/submissions", files=files).status_code == 202


def test_submit_analyse_view_and_download(alice, services):
    analysis_id = _analysed(alice, services)
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    assert body["verdict"] == "LIKELY PHISHING" and body["report"]["verdict"] == "LIKELY PHISHING"
    assert body["subject"].startswith("Urgent") and body["lookups"] == []
    assert body["submitted_by_name"] == "alice"  # a frontend shows who submitted it without the users list
    names = {f["kind"]: f["name"] for f in body["files"]}
    report = alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, names["html"]))
    assert report.status_code == 200 and report.headers["content-security-policy"] == REPORT_CSP
    csv = alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, names["csv"]))
    assert csv.headers["content-disposition"] == 'attachment; filename="%s"' % names["csv"]
    raw = alice.get("/api/v1/messages/%d/raw" % body["message_id"])
    assert raw.content == _raw() and raw.headers["content-disposition"].startswith("attachment")
    assert alice.get("/api/v1/analyses?q=examp1e-corp").json()[0]["id"] == analysis_id
    assert alice.get("/api/v1/analyses?q=%s" % body["report_id"]).json()[0]["id"] == analysis_id


def test_only_the_submitter_or_an_admin_deletes_and_only_an_admin_deletes_completely(alice, bob, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    assert bob.delete("/api/v1/messages/%d" % message_id).status_code == 403
    assert bob.get("/api/v1/messages/%d/raw" % message_id).status_code == 403
    assert alice.delete("/api/v1/messages/%d?scope=all" % message_id).status_code == 403
    assert alice.delete("/api/v1/messages/%d" % message_id).json() == {"deleted": "tier1"}
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    assert body["report"] is None and body["verdict"] == "LIKELY PHISHING" and body["subject"] is None
    html = next(f["name"] for f in body["files"] if f["kind"] == "html")
    assert alice.get("/api/v1/analyses/%d/files/%s" % (analysis_id, html)).status_code == 410
    assert admin.delete("/api/v1/messages/%d?scope=all" % message_id).json() == {"deleted": "all"}
    assert alice.get("/api/v1/analyses/%d" % analysis_id).status_code == 404


def test_repeated_wrong_passwords_are_throttled(anon):
    codes = [anon.post("/api/v1/session", json={"username": "alice", "password": "wrong password!"}).status_code
             for _ in range(4)]
    assert codes[:3] == [401, 401, 401] and codes[3] == 429
