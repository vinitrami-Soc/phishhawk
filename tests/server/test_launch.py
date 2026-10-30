"""Launch checks: HTTPS behind a reverse proxy, no search engine indexing
unless the owner allows it (then only the public pages, with their own head
tags, and a sitemap), compressed and cached frontend files, a login throttle
that cannot grow without bound, and domain settings that must be domains."""

import re

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
                                     '<meta name="description" content="Phishing triage." />\n'
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
    assert robots == ("User-agent: *\nAllow: /$\nAllow: /app/about$\nAllow: /app/privacy$\nAllow: /app/help$\n"
                      "Allow: /app/assets/\nAllow: /app/brand/\n"
                      "Allow: /api/v1/session$\nAllow: /api/v1/setup$\nAllow: /api/v1/signup$\n"
                      "Allow: /api/v1/password-reset$\nAllow: /api/v1/operator$\n"
                      "Disallow: /\n")  # no public address: no sitemap
    for path in PUBLIC_PAGES:
        page = frontend.get(path)
        assert page.status_code == 200 and page.headers["x-robots-tag"] == "all", path  # no restriction
        assert 'name="robots"' not in page.text and 'id="root"' in page.text, path
    for path in PRIVATE:
        page = frontend.get(path)
        assert page.headers["x-robots-tag"] == "noindex, nofollow", path
        if path.startswith("/app/"):
            assert '<meta name="robots" content="noindex, nofollow" />' in page.text, path


PUBLIC_URL = "https://phishhawk.example.org"


def _indexed(frontend, public_url=PUBLIC_URL):
    settings = frontend.app.state.services.settings
    settings.index_public_pages = True
    settings.public_url = public_url
    return frontend


def test_robots_txt_names_the_sitemap_once_the_public_address_is_known(frontend):
    robots = _indexed(frontend).get("/robots.txt").text
    assert robots.startswith("User-agent: *\nAllow: /$\n")
    assert robots.endswith("Disallow: /\nSitemap: https://phishhawk.example.org/sitemap.xml\n")


def test_robots_txt_lets_search_engines_fetch_the_sitemap_it_names(frontend):
    # Google obeys robots.txt when it fetches a sitemap too: behind Disallow: / alone, Search Console says
    # "Couldn't fetch"
    robots = _indexed(frontend).get("/robots.txt").text
    assert robots == ("User-agent: *\nAllow: /$\nAllow: /app/about$\nAllow: /app/privacy$\nAllow: /app/help$\n"
                      "Allow: /app/assets/\nAllow: /app/brand/\n"
                      "Allow: /api/v1/session$\nAllow: /api/v1/setup$\nAllow: /api/v1/signup$\n"
                      "Allow: /api/v1/password-reset$\nAllow: /api/v1/operator$\nAllow: /sitemap.xml$\n"
                      "Disallow: /\nSitemap: https://phishhawk.example.org/sitemap.xml\n")


def test_robots_txt_lets_search_engines_ask_what_the_public_pages_ask_before_sign_in(frontend):
    # Google draws a page with its script, and fetches nothing robots.txt refuses: refused these, the public
    # pages show "PhishHawk is not answering" (the browser test checks the drawn pages)
    from phishhawk.server.frontend import PUBLIC_READS

    robots = _indexed(frontend).get("/robots.txt").text
    assert PUBLIC_READS == ("session", "setup", "signup", "password-reset", "operator")
    for read in PUBLIC_READS:
        assert "Allow: /api/v1/%s$\n" % read in robots, read
    assert "Allow: /api/v1/\n" not in robots  # each one exactly, nothing more of the API


def test_robots_txt_the_sitemap_and_the_health_check_answer_head_as_well(frontend):
    # uptime monitors and some crawlers ask with HEAD first: the same answer, without the body
    client = _indexed(frontend)
    for path in ("/robots.txt", "/sitemap.xml", "/healthz"):
        whole, head = client.get(path), client.head(path)
        assert head.status_code == whole.status_code == 200, path
        assert head.headers["content-type"] == whole.headers["content-type"] and head.content == b"", path


def test_with_indexing_on_a_visitor_without_a_session_gets_the_product_page_at_the_home_page(frontend):
    home = _indexed(frontend).get("/", follow_redirects=False)
    assert home.status_code == 200 and home.headers["x-robots-tag"] == "all"
    assert home.headers["vary"] == "Cookie" and home.headers["cache-control"] == "no-cache"
    page = home.text
    assert 'name="robots"' not in page and page.count('name="description"') == 1
    assert "<title>Phishing email triage · PhishHawk</title>" in page
    assert '<link rel="canonical" href="https://phishhawk.example.org/" />' in page
    assert '<meta property="og:image" content="https://phishhawk.example.org/app/brand/og-image.png" />' in page
    assert '<meta name="twitter:card" content="summary_large_image" />' in page
    # the site's name for search results (schema.org WebSite). Not SoftwareApplication: Search Console reports
    # that as an invalid item without a rating or review, and PhishHawk has none to show
    assert ('<script type="application/ld+json">{"@context": "https://schema.org", "@type": "WebSite", '
            '"name": "PhishHawk", "url": "https://phishhawk.example.org/"}</script>') in page
    assert "SoftwareApplication" not in page and "aggregateRating" not in page
    assert "<h1>Every reported email, triaged and explained.</h1>" in page  # the landing page's own words
    assert frontend.head("/").status_code == 200


def test_with_a_session_the_home_page_still_opens_the_console(frontend):
    _indexed(frontend).cookies.set("phishhawk_session", "anything")
    home = frontend.get("/", follow_redirects=False)
    assert home.status_code == 307 and home.headers["location"] == "/app/" and home.headers["vary"] == "Cookie"


def test_each_public_page_names_its_own_address_and_the_product_page_points_at_the_home_page(frontend):
    _indexed(frontend)
    pages = {path: frontend.get(path).text for path in ("/", *PUBLIC_PAGES)}
    assert '<link rel="canonical" href="https://phishhawk.example.org/" />' in pages["/app/about"]
    assert '<link rel="canonical" href="https://phishhawk.example.org/app/help" />' in pages["/app/help"]
    assert '<link rel="canonical" href="https://phishhawk.example.org/app/privacy" />' in pages["/app/privacy"]
    titles = {path: re.search(r"<title>(.*?)</title>", page).group(1) for path, page in pages.items()}
    assert titles["/app/help"] != titles["/app/privacy"] != titles["/"]
    assert all("ld+json" not in pages[path] for path in PUBLIC_PAGES)  # the home page alone


def test_the_sitemap_lists_the_public_pages_once_indexing_is_on_and_the_address_is_known(frontend):
    assert frontend.get("/sitemap.xml").status_code == 404  # indexing off
    assert _indexed(frontend, public_url="").get("/sitemap.xml").status_code == 404
    sitemap = _indexed(frontend).get("/sitemap.xml")
    assert sitemap.status_code == 200 and sitemap.headers["content-type"].startswith("application/xml")
    assert sitemap.headers["cache-control"] == "public, max-age=3600"
    assert re.findall(r"<loc>(.*?)</loc>", sitemap.text) == [PUBLIC_URL + "/", PUBLIC_URL + "/app/privacy",
                                                             PUBLIC_URL + "/app/help"]


def test_with_indexing_off_the_home_page_and_the_public_pages_are_as_they_were(frontend):
    frontend.app.state.services.settings.public_url = PUBLIC_URL
    home = frontend.get("/", follow_redirects=False)
    assert home.status_code == 307 and home.headers["location"] == "/app/" and "vary" not in home.headers
    for path in PUBLIC_PAGES:
        page = frontend.get(path).text
        assert "canonical" not in page and "og:" not in page and "<title>PhishHawk</title>" in page, path


def test_without_the_public_address_the_home_page_names_no_site():
    # WebSite needs the home page's address: without one, no block at all rather than one Google calls invalid
    from phishhawk.server.frontend import with_head

    page = with_head('<title>PhishHawk</title>\n<div id="root"></div>', "", "")
    assert "ld+json" not in page and "<title>Phishing email triage · PhishHawk</title>" in page


def test_the_head_of_each_public_page_is_short_and_escaped():
    from phishhawk.server.frontend import HEADS, with_head

    for name, head in HEADS.items():
        assert len(head.title) <= 60 and len(head.share_title) <= 60 and len(head.description) <= 155, name
    hostile = 'https://x.example/"><script>alert(1)</script>'
    page = with_head('<title>PhishHawk</title>\n<div id="root"></div>', "", hostile)
    assert "<script>alert" not in page and "&quot;&gt;&lt;script&gt;" in page and "\\u003cscript" in page


def test_the_server_titles_are_the_ones_the_frontend_sets():
    from pathlib import Path

    from phishhawk.server.frontend import HEADS

    routes = (Path(__file__).parents[2] / "frontend" / "src" / "app" / "routes.ts").read_text(encoding="utf-8")
    titles = dict(re.findall(r"^\s+(about|privacy|help): '([^']+)',$", routes, re.M))
    assert {name: head.title for name, head in HEADS.items()} == {
        "": "%s · PhishHawk" % titles["about"], "about": "%s · PhishHawk" % titles["about"],
        "privacy": "%s · PhishHawk" % titles["privacy"], "help": "%s · PhishHawk" % titles["help"]}


def test_the_product_page_summary_says_what_the_landing_page_says():
    # Search engines compare the HTML with the drawn page: different words would look like cloaking.
    from pathlib import Path

    from phishhawk.server.frontend import PRODUCT

    landing = Path(__file__).parents[2] / "frontend" / "src" / "screens" / "LandingScreen.tsx"
    drawn = " ".join(landing.read_text(encoding="utf-8").split())
    for words in re.findall(r">([^<]+)<", PRODUCT.summary):
        assert words in drawn, words


def test_the_built_frontend_carries_the_robots_tag_the_server_takes_out():
    from pathlib import Path

    from phishhawk.server.frontend import NOINDEX

    page = (Path(__file__).parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert page.count(NOINDEX) == 1
    # and the title, description and empty root the server fills in for the public pages
    assert page.count("<title>PhishHawk</title>") == 1 and page.count('<meta name="description"') == 1
    assert page.count('<div id="root"></div>') == 1


def test_anyone_can_read_who_runs_this_server_and_where_once_its_operator_says(anon):
    # someone using a PhishHawk they did not set up sends their mail to someone else's server: the privacy page
    # says whose, and where it runs
    assert anon.get("/api/v1/operator").json() == {"name": "", "email": "", "hosting": ""}
    settings = anon.app.state.services.settings
    settings.operator_name, settings.operator_email = "Example Security Ltd, United Kingdom", "privacy@example.org"
    settings.operator_hosting = hosting = "a cloud server in London, reached through Cloudflare"
    assert anon.get("/api/v1/operator").json() == {"name": "Example Security Ltd, United Kingdom",
                                                    "email": "privacy@example.org", "hosting": hosting}


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
