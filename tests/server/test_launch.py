"""Launch checks: HTTPS behind a reverse proxy, no search engine indexing,
compressed and cached frontend files, a login throttle that cannot grow
without bound, and domain settings that must be domains."""

import pytest

PROXY = ("172.18.0.1", 50000)  # a reverse proxy as the container sees it, on a Docker network


@pytest.fixture
def secure(services):
    """The app as Compose runs it: Secure cookies, trusting proxies on Docker's networks."""
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    services.settings.cookie_secure = True
    services.settings.trusted_proxies = "127.0.0.1,172.16.0.0/12"
    return TestClient(create_app(services=services), client=PROXY)


def test_plain_http_is_sent_to_https_and_the_health_check_is_not(secure):
    page = secure.get("/login?next=%2Fqueue", follow_redirects=False)
    assert page.status_code == 308 and page.headers["location"] == "https://testserver/login?next=%2Fqueue"
    assert secure.get("/healthz").status_code == 200


def test_plain_http_to_this_machine_stays_as_browsers_accept_secure_cookies_there(secure):
    # Compose publishes port 8000 on this machine; the container sees Docker's gateway, not 127.0.0.1
    for base in ("http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"):
        assert secure.get(base + "/login", follow_redirects=False).status_code == 200, base


def test_https_from_a_trusted_proxy_is_served_with_hsts(secure):
    page = secure.get("/login", headers={"X-Forwarded-Proto": "https"})
    assert page.status_code == 200 and page.headers["strict-transport-security"] == "max-age=31536000"


def test_forwarded_headers_from_an_untrusted_address_are_ignored(services):
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    services.settings.cookie_secure = True  # trusted_proxies stays 127.0.0.1; the test client is not it
    page = TestClient(create_app(services=services)).get("/login", headers={"X-Forwarded-Proto": "https"})
    assert page.status_code == 200 and "strict-transport-security" not in page.headers


def test_the_login_throttle_keys_on_the_address_the_proxy_reports(services, app):
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    services.settings.trusted_proxies = "172.16.0.0/12"
    app = create_app(services=services)  # the users from the app fixture are in the database
    client = TestClient(app, client=PROXY)
    wrong = {"username": "alice", "password": "wrong password"}
    for _ in range(3):
        client.post("/api/v1/session", json=wrong, headers={"X-Forwarded-For": "203.0.113.7"})
    assert app.state.throttle.wait("ip:203.0.113.7") > 0
    assert app.state.throttle.wait("ip:172.18.0.1") == 0


def test_nothing_is_indexed_by_search_engines(anon):
    robots = anon.get("/robots.txt")
    assert robots.status_code == 200 and robots.text == "User-agent: *\nDisallow: /\n"
    for path in ("/robots.txt", "/login", "/api/v1/session", "/healthz"):
        assert anon.get(path).headers["x-robots-tag"] == "noindex, nofollow", path


@pytest.fixture
def frontend(services, tmp_path):
    from fastapi.testclient import TestClient

    from phishhawk.server.app import create_app

    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text('<!doctype html><title>PhishHawk</title>\n'
                                     '<meta name="robots" content="noindex, nofollow" />\n<div id="root"></div>')
    (dist / "assets" / "index-3f9a1c.js").write_text("console.log('PhishHawk');\n" * 200)
    services.settings.frontend_dir = str(dist)
    return TestClient(create_app(services=services))


def test_frontend_files_are_compressed_and_api_answers_are_not(frontend, admin):
    script = frontend.get("/app/assets/index-3f9a1c.js", headers={"Accept-Encoding": "gzip"})
    assert script.headers["content-encoding"] == "gzip" and script.text.startswith("console.log")
    # API answers carry the CSRF token and text from reported mail: never compressed (BREACH)
    answer = admin.get("/api/v1/session", headers={"Accept-Encoding": "gzip"})
    assert "content-encoding" not in answer.headers


def test_hashed_frontend_files_are_cached_for_a_year_and_the_page_is_always_checked(frontend):
    script = frontend.get("/app/assets/index-3f9a1c.js")
    assert script.headers["cache-control"] == "public, max-age=31536000, immutable"
    for path in ("/app/", "/app/queue"):
        assert frontend.get(path).headers["cache-control"] == "no-cache", path


PUBLIC_PAGES = ("/app/about", "/app/privacy", "/app/help")
PRIVATE = ("/app/", "/app/queue", "/app/analyses/1", "/login", "/api/v1/session")


def test_until_the_owner_lets_them_in_the_public_pages_stay_out_of_search_engines(frontend):
    assert frontend.get("/robots.txt").text == "User-agent: *\nDisallow: /\n"
    for path in PUBLIC_PAGES:
        page = frontend.get(path)
        assert page.headers["x-robots-tag"] == "noindex, nofollow", path
        assert '<meta name="robots" content="noindex, nofollow" />' in page.text, path


def test_with_indexing_on_only_the_product_privacy_and_help_pages_are_indexed(frontend):
    frontend.app.state.services.settings.index_public_pages = True
    robots = frontend.get("/robots.txt").text
    assert robots == ("User-agent: *\nAllow: /app/about$\nAllow: /app/privacy$\nAllow: /app/help$\n"
                      "Allow: /app/assets/\nAllow: /app/brand/\nDisallow: /\n")
    for path in PUBLIC_PAGES:
        page = frontend.get(path)
        assert page.status_code == 200 and page.headers["x-robots-tag"] == "all", path  # no restriction
        assert 'name="robots"' not in page.text and 'id="root"' in page.text, path
    for path in PRIVATE:
        page = frontend.get(path)
        assert page.headers["x-robots-tag"] == "noindex, nofollow", path
        if path.startswith("/app/"):
            assert '<meta name="robots" content="noindex, nofollow" />' in page.text, path


def test_the_built_frontend_carries_the_robots_tag_the_server_takes_out():
    from pathlib import Path

    from phishhawk.server.frontend import NOINDEX

    page = (Path(__file__).parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert page.count(NOINDEX) == 1


def test_anyone_can_read_who_runs_this_server_once_its_operator_says(anon):
    assert anon.get("/api/v1/operator").json() == {"name": "", "email": ""}
    settings = anon.app.state.services.settings
    settings.operator_name, settings.operator_email = "Example Security Ltd, United Kingdom", "privacy@example.org"
    assert anon.get("/api/v1/operator").json() == {"name": "Example Security Ltd, United Kingdom",
                                                    "email": "privacy@example.org"}


def test_the_login_throttle_forgets_the_oldest_names_beyond_its_limit():
    from phishhawk.server import auth

    now = [0.0]
    throttle = auth.LoginThrottle(clock=lambda: now[0], limit=100)
    for n in range(250):
        throttle.failed("user:spray%d" % n, "ip:198.51.100.9")
    assert len(throttle) <= 100
    assert throttle.wait("ip:198.51.100.9") > 0  # the address that keeps failing is still slowed down


def test_domain_settings_must_be_domains(admin):
    saved = admin.patch("/api/v1/settings", json={"protected_domains": [" Example.COM. ", "bücher.example"]})
    assert saved.status_code == 200
    assert saved.json()["protected_domains"] == ["example.com", "xn--bcher-kva.example"]
    for bad in ("not a domain", "https://example.com/", "example", "-bad.example", "a..example"):
        answer = admin.patch("/api/v1/settings", json={"block_domains": [bad]})
        assert answer.status_code == 422 and answer.json()["detail"].startswith("not a domain"), bad



def test_a_rejected_value_on_the_settings_page_saves_nothing(admin):
    before = admin.get("/api/v1/settings").json()
    form = {"protected_domains": "example.com", "block_domains": "bad domain", "retention_days": "30",
            "max_upload_mb": "25", "max_batch_messages": "500", "campaign_window_days": "90"}
    page = admin.post("/settings", data=form, follow_redirects=False)
    assert page.status_code == 422 and "not a domain: bad domain" in page.text
    assert admin.get("/api/v1/settings").json() == before
