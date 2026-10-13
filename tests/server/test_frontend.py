"""A frontend built elsewhere (the owner builds one in Google AI Studio),
served from this origin at /app/ under the app's CSP, and the endpoint it
asks after a reload who is logged in."""

import pytest

PAGE = '<!doctype html><title>PhishHawk</title><div id="root"></div>' \
       '<script type="module" src="/app/assets/app.js"></script>'


@pytest.fixture
def built(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(PAGE)
    (dist / "assets" / "app.js").write_text("document.title = 'PhishHawk'")
    (tmp_path / "secret.txt").write_text("outside the build")
    return dist


@pytest.fixture
def frontend(services, built):
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    services.settings.frontend_dir = str(built)
    return TestClient(create_app(services=services))


def test_the_frontend_is_served_under_the_app_csp_and_its_own_routes_reload(frontend):
    for path in ("/app/", "/app/queue", "/app/analyses/12"):
        page = frontend.get(path)
        assert page.status_code == 200 and 'id="root"' in page.text, path
        assert "script-src 'self'" in page.headers["content-security-policy"], path
    script = frontend.get("/app/assets/app.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]


def test_a_missing_file_or_a_path_outside_the_build_is_not_found(frontend):
    assert frontend.get("/app/assets/missing.js").status_code == 404
    assert frontend.get("/app/%2e%2e/secret.txt").status_code == 404


def test_without_a_built_frontend_nothing_is_served_at_app(anon):
    assert anon.get("/app/").status_code == 404


def test_with_a_frontend_the_servers_address_opens_it_and_the_built_in_pages_stay(frontend):
    page = frontend.get("/", follow_redirects=False)
    assert page.status_code == 307 and page.headers["location"] == "/app/"
    assert frontend.get("/login").status_code == 200


def test_without_a_frontend_the_servers_address_is_the_built_in_home(anon):
    assert anon.get("/", follow_redirects=False).headers["location"] == "/login"


def test_the_session_endpoint_says_who_is_calling(alice, admin, anon):
    assert anon.get("/api/v1/session").status_code == 401
    alice_id = next(u["id"] for u in admin.get("/api/v1/users").json() if u["username"] == "alice")
    assert alice.get("/api/v1/session").json() == {"user_id": alice_id, "username": "alice", "role": "analyst",
                                                   "via": "session", "scope": "full",
                                                   "csrf": alice.headers["X-CSRF-Token"], "owner": False,
                                                   "profile": {"first_name": "", "last_name": "", "location": "",
                                                               "job_title": ""},
                                                   "workspace": {"id": 1, "name": "Default organization",
                                                                 "kind": "organization"}}
