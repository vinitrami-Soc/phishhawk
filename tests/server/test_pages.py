"""The pages, used the way a browser uses them (the CSRF token as a form
field): log in, submit, the analysis page and its report, settings, users,
tokens, hold and delete, and logging out."""

import secrets

from sqlalchemy import select

from phishhawk.server import appsettings, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditRecord, Message
from phishhawk.server.security import REPORT_CSP

from conftest import sample


def _browser(client):
    """Send the CSRF token in forms only, as the pages do."""
    return client.headers.pop("X-CSRF-Token")


def _raw():
    with open(sample("sample_phish.eml"), "rb") as handle:
        return handle.read()


def _analysed(client, services):
    body = client.post("/api/v1/submissions", files={"file": ("m.eml", _raw())}, data={"offline": "true"}).json()
    worker.run_one(services)
    return client.get("/api/v1/submissions/%d" % body["id"]).json()["analysis_id"]


def test_pages_and_static_files_have_the_security_headers(anon):
    for path in ("/login", "/static/app.css"):
        headers = anon.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"], path
        assert "frame-ancestors 'none'" in headers["content-security-policy"], path
        assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"


def test_pages_redirect_to_login_and_the_login_form_works(anon):
    assert anon.get("/queue", follow_redirects=False).headers["location"] == "/login"
    response = anon.post("/login", data={"username": "alice", "password": "correct horse battery"},
                         follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/"
    page = anon.get("/").text
    assert page.count("<h1") == 1 and 'name="csrf_token"' in page and '<label for="files">' in page


def test_the_page_flow_from_submit_to_the_analysis_page(alice, services):
    csrf = _browser(alice)
    response = alice.post("/", data={"csrf_token": csrf, "raw": _raw().decode(), "offline": "true"},
                          files={"file": ("", b"", "application/octet-stream")}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/submissions/")
    assert "refresh" in alice.get(response.headers["location"]).text  # still queued
    worker.run_one(services)
    page = alice.get(response.headers["location"])  # redirected to the analysis page
    assert "LIKELY PHISHING" in page.text and "<iframe" in page.text and 'sandbox="allow-popups' in page.text


def test_the_report_opens_sandboxed_and_is_gone_after_deletion(alice, services):
    analysis_id = _analysed(alice, services)
    body = alice.get("/api/v1/analyses/%d" % analysis_id).json()
    report = "/analyses/%d/files/%s" % (analysis_id, next(f["name"] for f in body["files"] if f["kind"] == "html"))
    opened = alice.get(report)
    assert opened.status_code == 200 and opened.headers["content-security-policy"] == REPORT_CSP
    alice.delete("/api/v1/messages/%d" % body["message_id"])
    assert alice.get(report).status_code == 410


def test_the_settings_form_enables_providers_keeps_keys_masked_and_sets_limits(admin, services):
    csrf = _browser(admin)
    key = "vt-" + secrets.token_hex(8) + "1234"  # made at run time, for the secret scanner
    form = {"csrf_token": csrf, "provider_virustotal": "1", "key_virustotal": key,
            "protected_domains": "example-corp.co.uk\nexample.org", "retention_days": "7", "max_upload_mb": "10"}
    response = admin.post("/settings", data=form, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/settings?saved=1"
    page = admin.get("/settings").text
    assert "...1234" in page and key not in page
    with transaction(services.sessions) as s:
        assert appsettings.get_value(s, "providers") == ["virustotal"]
        assert appsettings.get_value(s, "protected_domains") == ["example-corp.co.uk", "example.org"]
        assert appsettings.limit(s, services.settings, "retention_days") == 7
        assert s.scalars(select(AuditRecord).where(AuditRecord.action == "settings")).one()


def test_an_admin_adds_a_user_and_a_token_that_is_shown_once_then_revoked(admin, anon):
    csrf = _browser(admin)
    form = {"csrf_token": csrf, "username": "carol", "password": "carol's long password", "role": "analyst"}
    assert admin.post("/users", data=form, follow_redirects=False).status_code == 303
    carol = next(u for u in admin.get("/api/v1/users").json() if u["username"] == "carol")
    page = admin.post("/tokens", data={"csrf_token": csrf, "name": "intelpulse", "scope": "read",
                                       "user_id": str(carol["id"])}).text
    token = page.split("phk_", 1)[1].split("<", 1)[0]
    bearer = {"Authorization": "Bearer phk_" + token}
    assert anon.get("/api/v1/analyses", headers=bearer).status_code == 200
    assert "phk_" + token not in admin.get("/users").text  # shown once
    token_id = admin.get("/api/v1/tokens").json()[0]["id"]
    assert admin.post("/tokens/%d/revoke" % token_id, data={"csrf_token": csrf},
                      follow_redirects=False).status_code == 303
    assert anon.get("/api/v1/analyses", headers=bearer).status_code == 401


def test_a_short_password_is_refused_with_the_reason(admin):
    csrf = _browser(admin)
    response = admin.post("/users", data={"csrf_token": csrf, "username": "dave", "password": "short",
                                          "role": "analyst"})
    assert response.status_code == 422 and "at least 12 characters" in response.text


def test_a_held_message_cannot_be_deleted_until_it_is_released(alice, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    admin_csrf, alice_csrf = _browser(admin), _browser(alice)
    assert admin.post("/messages/%d/hold" % message_id, data={"csrf_token": admin_csrf},
                      follow_redirects=False).status_code == 303
    refused = alice.post("/messages/%d/delete" % message_id, data={"csrf_token": alice_csrf})
    assert refused.status_code == 409 and "on hold" in refused.text
    assert admin.delete("/api/v1/messages/%d?scope=all" % message_id,
                        headers={"X-CSRF-Token": admin_csrf}).status_code == 409
    admin.post("/messages/%d/hold" % message_id, data={"csrf_token": admin_csrf, "hold": "false"})
    assert alice.post("/messages/%d/delete" % message_id, data={"csrf_token": alice_csrf},
                      follow_redirects=False).status_code == 303
    with transaction(services.sessions) as s:
        message = s.get(Message, message_id)
        assert message.raw_blob is None and message.deletion_reason == "manual"


def test_logging_out_ends_the_session(alice):
    csrf = _browser(alice)
    response = alice.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert alice.get("/", follow_redirects=False).headers["location"] == "/login"


def test_the_analysis_page_offers_only_what_the_viewer_may_do(alice, bob, admin, services):
    analysis_id = _analysed(alice, services)
    message_id = alice.get("/api/v1/analyses/%d" % analysis_id).json()["message_id"]
    page = "/analyses/%d" % analysis_id
    assert "Raw message" in alice.get(page).text and "Delete now" in alice.get(page).text
    assert "Raw message" not in bob.get(page).text and "Delete now" not in bob.get(page).text
    admin.post("/api/v1/messages/%d/hold" % message_id)
    assert "Delete now" not in alice.get(page).text
    held = admin.get(page).text
    assert "Release hold" in held and "Delete completely" not in held
