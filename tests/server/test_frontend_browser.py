"""The frontend in frontend/, built with `npm run build`, served by a real
server at /app/ and driven in headless Chromium: read the product page a
visitor sees first and sign in from it, analyse a bundled
sample offline, read the verdict, the sandboxed report and the files; upload
two messages as a batch and follow them to their combined reports and their
campaign; connect a mailbox (a test IMAP server) and find its reports in the
queue; create an organization's account from the product page and join it from
a second browser with its invitation link; confirm an email address and reset
a forgotten password with the links a real server mails; then check phone, tablet and
desktop widths for anything past the right edge. No console errors, so nothing broke the CSP. Skipped unless
PHISHHAWK_FRONTEND_BUILD names the build (CI's frontend job makes it);
PHISHHAWK_CHROMIUM may name the browser's executable."""

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests

from .serverkit import PASSWORD, running_server, smtp_sink
from conftest import build_eml, sample

sync_api = pytest.importorskip("playwright.sync_api")
BUILD = os.environ.get("PHISHHAWK_FRONTEND_BUILD", "")
pytestmark = pytest.mark.skipif(not (BUILD and Path(BUILD, "index.html").is_file()),
                                reason="no frontend build (set PHISHHAWK_FRONTEND_BUILD)")
WIDTHS = (320, 360, 390, 768, 820, 1024, 1440)

# Elements that reach past the right edge of the window, leaving out those inside a strip that scrolls
# sideways on purpose (the tabs on a phone) and the sign-in button's glow.
PAST_EDGE = """(scope = 'main') => {
  const w = document.documentElement.clientWidth;
  return [...document.querySelectorAll(scope + ' *')].filter((e) => {
    const r = e.getBoundingClientRect();
    if (!r.width || e.closest('.lm-stage')) return false;
    for (let p = e.parentElement; p && p !== document.body; p = p.parentElement) {
      const clips = /(auto|scroll|hidden|clip)/.test(getComputedStyle(p).overflowX);
      if (clips && p.getBoundingClientRect().right <= w + 1) return false;
    }
    return r.right > w + 1;
  }).slice(0, 3).map((e) => e.tagName + '.' + String(e.className).slice(0, 60));
}"""

# Table headings too narrow for their own words, at this width.
HEADINGS_CUT = """() => [...document.querySelectorAll('main th')]
  .filter((th) => th.getBoundingClientRect().width && th.scrollWidth > th.clientWidth + 1)
  .map((th) => th.textContent.trim())"""

# The light and dark switch in the command bar: as tall as Sign out beside it, and on the same line
# (differences in height and in middle, in pixels).
TOGGLE_BESIDE_SIGN_OUT = """() => {
  const t = document.querySelector('.ph-commandbar__toggle').getBoundingClientRect();
  const s = document.querySelector('.ph-commandbar .atd-modern__cta').getBoundingClientRect();
  return [Math.round(t.height - s.height), Math.round(t.top + t.height / 2 - (s.top + s.height / 2))];
}"""


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as playwright:
        try:
            chromium = playwright.chromium.launch(executable_path=os.environ.get("PHISHHAWK_CHROMIUM") or None)
        except sync_api.Error as exc:
            pytest.skip("no Chromium for Playwright: %s" % str(exc).splitlines()[0])
        yield chromium
        chromium.close()


HEADLINE = "Every reported email, triaged and explained."


def _visitor(browser):
    """A page nobody is signed in on, and the list its console errors and page errors go to."""
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    errors = []
    # the frontend asks who is signed in before anyone is: that one 401 is expected
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "401" not in m.text else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    return page, errors


def _sign_in_as_root(page):
    page.wait_for_selector("#login-username")
    page.fill("#login-username", "root")
    page.fill("#login-password", PASSWORD)
    page.locator("form [type=submit]").click()
    page.wait_for_selector(".ph-commandbar")


def _signed_in(browser, server):
    """A page signed in as root, from the product page's Sign in, and the list its errors go to."""
    page, errors = _visitor(browser)
    page.goto(server.base + "/")  # the server's address opens the frontend: the product page
    page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
    assert page.url == server.base + "/app/"
    page.get_by_role("banner").get_by_role("link", name="Sign in").click()
    _sign_in_as_root(page)
    assert page.url == server.base + "/app/"
    return page, errors


def test_a_visitor_reads_the_product_page_signs_in_and_comes_back_on_signing_out(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _visitor(browser)
        page.goto(server.base + "/app/")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        assert page.title() == "Phishing email triage · PhishHawk"
        assert page.locator("#login-username").count() == 0

        # the questions open in place
        answer = page.get_by_text("It never sends them the message itself.")
        sync_api.expect(answer).to_be_hidden()
        page.get_by_text("Does a reported email leave our server?").click()
        sync_api.expect(answer).to_be_visible()

        # the ways to use it filter by who uses them
        ways = page.locator("#ways")
        sync_api.expect(ways.get_by_role("heading", name="Report mailboxes")).to_be_visible()
        ways.get_by_role("button", name="Analysts").click()
        sync_api.expect(ways.get_by_role("button", name="Analysts")).to_have_attribute("aria-pressed", "true")
        sync_api.expect(ways.get_by_role("heading", name="Report mailboxes")).to_have_count(0)
        sync_api.expect(ways.get_by_role("heading", name="Web console")).to_be_visible()

        # the footer's columns
        footer = page.get_by_role("contentinfo")
        for column in ("Product", "Get started", "Learn", "For admins"):
            sync_api.expect(footer.get_by_role("heading", name=column)).to_be_visible()

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url in (server.base + "/app/", server.base + "/app/help", server.base + "/app/login"):
                page.goto(url)
                page.wait_for_timeout(600)
                assert page.evaluate(PAST_EDGE, "body") == [], (width, url)
        page.set_viewport_size({"width": 1280, "height": 900})

        # a private page asks to sign in, and opens after it; the sign-in page leads back to the product page
        page.goto(server.base + "/app/analyses")
        page.get_by_role("link", name="PhishHawk home").wait_for()
        _sign_in_as_root(page)
        assert page.url == server.base + "/app/analyses"

        # signed in, the start page is the console and the product page is still at /app/about
        page.goto(server.base + "/app/about")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        page.get_by_role("banner").get_by_role("link", name="Open console").click()
        page.wait_for_selector(".ph-commandbar")
        assert page.url == server.base + "/app/"

        # signing out leads back to the product page
        page.locator(".ph-commandbar .atd-modern__cta").click()
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        assert page.url == server.base + "/app/"
        assert errors == []


def test_a_visitor_reads_who_runs_the_server_where_and_what_leaves_it_on_the_privacy_page(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve()),
                        PHISHHAWK_OPERATOR_NAME="Example Security Ltd, United Kingdom",
                        PHISHHAWK_OPERATOR_EMAIL="privacy@example.org",
                        PHISHHAWK_OPERATOR_HOSTING="a cloud server in London, behind Cloudflare") as server:
        page, errors = _visitor(browser)
        page.goto(server.base + "/app/privacy")
        page.get_by_role("heading", name="Who runs this PhishHawk").wait_for()
        sync_api.expect(page.get_by_text("Example Security Ltd, United Kingdom")).to_be_visible()
        write = page.get_by_role("link", name="privacy@example.org")
        sync_api.expect(write).to_have_attribute("href", "mailto:privacy@example.org")
        # someone using a PhishHawk they did not set up learns where their mail goes
        sync_api.expect(page.get_by_text("a cloud server in London, behind Cloudflare")).to_be_visible()
        sync_api.expect(page.get_by_text("goes out through the mail provider")).to_be_visible()
        sync_api.expect(page.get_by_text("may set cookies of its own")).to_be_visible()
        assert errors == []

        # what the product page says about where mail is analysed holds on a server someone else runs
        page.goto(server.base + "/app/about")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        sync_api.expect(page.get_by_text("Runs on your server", exact=True)).to_have_count(0)
        sync_api.expect(page.get_by_text("Runs where you choose", exact=True)).to_be_visible()
        sync_api.expect(page.get_by_text("There is no sign-up")).to_have_count(0)


def test_with_indexing_on_the_address_itself_is_the_product_page_search_engines_read(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve()),
                        PHISHHAWK_INDEX_PUBLIC_PAGES="true",
                        PHISHHAWK_PUBLIC_URL="https://phishhawk.example.org") as server:
        page, errors = _visitor(browser)
        page.goto(server.base + "/")
        headline = page.get_by_role("heading", level=1, name=HEADLINE)
        headline.wait_for()
        assert page.url == server.base + "/"  # no redirect: this address is the one search engines list
        sync_api.expect(headline).to_have_count(1)  # the server's summary made way for the drawn page
        assert page.title() == "Phishing email triage · PhishHawk"  # the server's title, kept by the script

        # the help page search traffic comes to: how to get an email out of each mail app
        page.goto(server.base + "/app/help")
        page.get_by_role("heading", name="Download an email as .eml from Gmail").wait_for()
        for where in ("from Outlook", "from Apple Mail", "on a phone"):
            sync_api.expect(page.get_by_role("heading", name="Download an email as .eml " + where)).to_be_visible()
        assert errors == []  # the JSON-LD block and the head tags break no rule of the CSP


# adds up every layout shift the visitor did not cause, as Google's Cumulative Layout Shift does
SHIFTS = """window.__shift = 0;
new PerformanceObserver(list => {
  for (const e of list.getEntries()) if (!e.hadRecentInput) window.__shift += e.value;
}).observe({type: 'layout-shift', buffered: true});"""


def test_the_pages_search_engines_list_do_not_jump_while_they_load(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve()),
                        PHISHHAWK_INDEX_PUBLIC_PAGES="true",
                        PHISHHAWK_PUBLIC_URL="https://phishhawk.example.org") as server:
        for path, heading in (("/", HEADLINE), ("/app/privacy", "Privacy and terms"),
                              ("/app/help", "Help")):
            page, errors = _visitor(browser)
            page.add_init_script(SHIFTS)
            page.goto(server.base + path)
            page.get_by_role("heading", level=1, name=heading, exact=True).wait_for()
            page.wait_for_timeout(2000)  # the pictures and the reveals settle
            assert page.evaluate("window.__shift") < 0.1, path  # Google's line for a page that holds still
            assert errors == []
            page.close()


RENDERER = """() => { const gl = document.createElement('canvas').getContext('webgl2');
  const info = gl && gl.getExtension('WEBGL_debug_renderer_info');
  return info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : ''; }"""


def test_without_a_gpu_the_sign_in_button_is_drawn_still(browser, tmp_path):
    # WebGL drawn by the processor (SwiftShader) made every frame of the liquid-metal effect a long task:
    # PageSpeed measured 11 to 27 seconds of blocking time on the product page
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _visitor(browser)
        page.goto(server.base + "/app/")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        if not re.search("swiftshader|llvmpipe|software", page.evaluate(RENDERER), re.I):
            pytest.skip("this browser draws WebGL on a GPU")
        page.wait_for_timeout(1000)  # the effect starts once the button is on screen
        sync_api.expect(page.locator(".lm-fx")).to_have_count(0)  # no canvas, no WebGL context
        assert page.locator(".lm").first.get_attribute("data-render") == "static"
        assert errors == []


PUBLIC_URL = "https://phishhawk.example.org"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SITEMAP = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def _robots_allow(robots, path):
    """Whether robots.txt lets a crawler fetch `path`, read the way Google reads it (RFC 9309): the longest
    matching rule wins and Allow wins a tie; * matches anything, and a final $ the end of the path."""
    best = (0, True)  # no rule matches: allowed
    for line in robots.splitlines():
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field in ("allow", "disallow") and value:
            pattern = re.escape(value.rstrip("$")).replace(r"\*", ".*") + ("$" if value.endswith("$") else "")
            if re.match(pattern, path):
                best = max(best, (len(value), field == "allow"))
    return best[1]


def test_robots_allow_reads_rules_the_way_google_does():
    # the same answers as protego, the parser Scrapy uses to read robots.txt as Google does
    robots = ("User-agent: *\nAllow: /$\nAllow: /app/help$\nAllow: /app/assets/\nDisallow: /\n"
              "Disallow: /app/assets/*.map\n")
    assert _robots_allow(robots, "/") and _robots_allow(robots, "/app/help")
    assert _robots_allow(robots, "/app/assets/index.js") and not _robots_allow(robots, "/app/assets/index.js.map")
    assert not _robots_allow(robots, "/app/help/") and not _robots_allow(robots, "/app/")
    assert not _robots_allow(robots, "/sitemap.xml")
    assert _robots_allow("User-agent: *\nDisallow: /\nAllow: /\n", "/anything")  # a tie goes to Allow
    assert _robots_allow("User-agent: *\n", "/anything")


def test_a_search_engine_fetches_and_draws_every_page_the_sitemap_lists(browser, tmp_path):
    """What Googlebot does, against the real build: robots.txt, the sitemap it names, each page the sitemap
    lists and every file that page and its styles load, all allowed and all there, with HEAD as well as GET;
    then each page drawn by its script while every request robots.txt refuses is refused, as Google draws
    it. Search Console's "Couldn't fetch" and a page indexed as an error page both start here."""
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve()),
                        PHISHHAWK_INDEX_PUBLIC_PAGES="true", PHISHHAWK_PUBLIC_URL=PUBLIC_URL) as server:
        bot = requests.Session()
        bot.headers["User-Agent"] = GOOGLEBOT
        robots = bot.get(server.base + "/robots.txt").text

        def fetch(path):
            assert _robots_allow(robots, path), "robots.txt keeps search engines from " + path
            for method in ("HEAD", "GET"):
                answer = bot.request(method, server.base + path, allow_redirects=False)
                assert answer.status_code == 200, (method, path, answer.status_code)
            return answer

        named = re.findall(r"^sitemap:\s*(\S+)$", robots, re.I | re.M)
        assert named == [PUBLIC_URL + "/sitemap.xml"]
        sitemap = fetch("/sitemap.xml")
        assert sitemap.headers["content-type"] == "application/xml"
        locs = [loc.text for loc in ET.fromstring(sitemap.content).iter(SITEMAP + "loc")]
        assert locs == [PUBLIC_URL + "/", PUBLIC_URL + "/app/privacy", PUBLIC_URL + "/app/help"]

        for loc in locs:
            page = fetch(loc[len(PUBLIC_URL):])
            assert page.headers["content-type"].startswith("text/html") and page.headers["x-robots-tag"] == "all"
            assert "noindex" not in page.text and '<link rel="canonical" href="%s" />' % loc in page.text
            loaded = re.findall(r'(?:src|href|content)="(?:%s)?(/[^"]*)"' % re.escape(PUBLIC_URL), page.text)
            assert "/app/brand/og-image.png" in loaded and any(path.endswith(".css") for path in loaded)
            for path in loaded:
                answer = fetch(path)
                if path.endswith(".css"):  # the fonts and pictures the styles load
                    for inner in re.findall(r"url\((/[^)]+)\)", answer.text):
                        fetch(inner)
            assert fetch("/app/brand/og-image.png").headers["content-type"] == "image/png"

        for private in ("/app/", "/app/queue", "/app/analyses/1", "/login", "/api/v1/analyses",
                        "/api/v1/password-reset/a-token", "/api/v1/sessions"):
            assert not _robots_allow(robots, private), private

        # drawn as Google draws them: every request robots.txt refuses is refused
        refused = []

        def as_robots_say(route):
            parts = urlsplit(route.request.url)
            path = parts.path + ("?" + parts.query if parts.query else "")
            if route.request.url.startswith(server.base) and not _robots_allow(robots, path):
                refused.append(path)
                return route.abort()
            return route.continue_()

        context = browser.new_context(user_agent=GOOGLEBOT, viewport={"width": 1280, "height": 900})
        context.route("**/*", as_robots_say)
        page, errors = context.new_page(), []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        headings = {"/": HEADLINE, "/app/about": HEADLINE, "/app/privacy": "Privacy and terms",
                    "/app/help": "Help"}
        for path, heading in headings.items():
            page.goto(server.base + path, wait_until="networkidle")
            page.get_by_role("heading", level=1, name=heading, exact=True).wait_for()
            sync_api.expect(page.get_by_text("PhishHawk is not answering.")).to_have_count(0)
        context.close()
        assert refused == [] and errors == []


def test_an_analyst_works_a_message_in_the_frontend_at_every_width(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _signed_in(browser, server)
        page.get_by_role("heading", level=1, name="Analyze a reported message").wait_for()
        sync_api.expect(page.get_by_text("How do I get the email?")).to_have_count(0)
        sync_api.expect(page.get_by_role("switch", name="Show technical details")).to_have_count(0)

        page.get_by_role("button", name="Paste the message").click()
        with open(sample("sample_phish.eml"), encoding="utf-8") as message:
            page.fill("textarea[aria-label='Raw message']", message.read())
        page.get_by_role("switch", name="Offline analysis").click()
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/analyses/*", timeout=60000)
        page.get_by_text("LIKELY PHISHING").first.wait_for(timeout=30000)
        analysis = page.url
        sync_api.expect(page.get_by_role("switch", name="Show technical details")).to_have_count(0)

        page.get_by_role("tab", name="Report").click()
        report = page.frame_locator("iframe[title='Full report']").locator("body")
        assert "LIKELY PHISHING" in report.inner_text(timeout=15000)
        page.get_by_role("tab", name="Files").click()
        with page.expect_download() as download:
            page.locator("a[download]").first.click()
        assert download.value.suggested_filename.startswith("phishhawk-")

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url in (server.base + "/app/", analysis, server.base + "/app/analyses", server.base + "/app/audit",
                        server.base + "/app/help"):
                page.goto(url)
                if url.endswith("/app/"):  # with a file chosen, its name and Remove share the row
                    page.set_input_files("input[type=file]", sample("sample_phish.eml"))
                page.wait_for_timeout(600)
                # the whole page, the top bar included: nine pages, the user and Sign out fit at every width
                assert page.evaluate(PAST_EDGE, "body") == [], (width, url)
                assert page.evaluate(HEADINGS_CUT) == [], (width, url)
            assert page.evaluate(TOGGLE_BESIDE_SIGN_OUT) == [0, 0], width
            # the admin pages and who is signed in are in More, whatever the width
            page.get_by_role("button", name="More").click()
            menu = page.locator(".ph-commandbar__menu")
            sync_api.expect(menu.get_by_role("link", name="Settings")).to_be_visible()
            sync_api.expect(menu.get_by_text("root")).to_be_visible()
            sync_api.expect(menu.get_by_text("Admin")).to_be_visible()
            page.get_by_role("button", name="More").click()
        assert errors == []


def test_a_batch_leads_to_its_combined_reports_and_its_campaign_at_every_width(browser, tmp_path):
    invoice = (b"%PDF-1.4 invoice 7731", "application", "pdf", "invoice.pdf")
    files = []
    for number in range(2):  # the same attachment from two senders: one campaign
        path = tmp_path / ("invoice%d.eml" % number)
        path.write_bytes(build_eml(subject="Invoice %d" % number, sender="<a%d@one%d.example>" % (number, number),
                                   to="alice@corp.example", attachments=[invoice]))
        files.append(str(path))
    (tmp_path / "server").mkdir()
    with running_server(tmp_path / "server", PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _signed_in(browser, server)
        page.set_input_files("input[type=file]", files)
        page.get_by_text("analysed as a batch").first.wait_for()
        page.get_by_role("switch", name="Offline analysis").click()
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/batches/*", timeout=60000)
        page.get_by_text("Every message is done.").wait_for(timeout=120000)
        batch = page.url
        page.get_by_text("Combined reports").wait_for(timeout=30000)
        opened = page.get_by_role("link", name="Open").first
        assert opened.get_attribute("target") == "_blank" and "noopener" in opened.get_attribute("rel")
        with page.expect_download() as download:
            page.get_by_role("link", name="Download").first.click()
        assert download.value.suggested_filename.startswith("phishhawk-")
        assert page.locator("a[href^='/app/analyses/']").count() == 2

        for _ in range(60):  # the campaigns are rebuilt after the analyses, in the worker
            page.goto(server.base + "/app/campaigns")
            page.wait_for_selector("h1")
            page.wait_for_timeout(500)
            if page.locator("a[href^='/app/campaigns/']").count():
                break
        page.locator("a[href^='/app/campaigns/']").first.click()
        page.get_by_text("What links them").wait_for()
        assert "Attachment (SHA-256)" in page.inner_text("main")
        assert page.locator("main a[href^='/app/analyses/']").count() == 2
        campaign = page.url

        page.goto(server.base + "/app/analyses")
        page.get_by_role("button", name="Paste").click()
        page.get_by_text("No analyses match this search.").wait_for()
        page.get_by_role("button", name="Batch").click()
        page.get_by_role("button", name="Only mine").click()
        page.wait_for_timeout(600)
        assert page.locator("main table a[href^='/app/analyses/']").count() == 2
        page.get_by_label("From").fill("2999-01-01")
        page.get_by_text("No analyses match this search.").wait_for()

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url in (batch, server.base + "/app/campaigns", campaign, server.base + "/app/analyses"):
                page.goto(url)
                page.wait_for_timeout(600)
                assert page.evaluate(PAST_EDGE) == [], (width, url)
        assert errors == []


def test_an_admin_connects_a_mailbox_and_its_reports_reach_the_queue(browser, tmp_path, monkeypatch):
    import secrets

    from .fakeimap import FakeImapServer
    from .test_mailbox_imap import USER, report

    password = secrets.token_hex(10)
    imap = FakeImapServer(tmp_path / "imap", USER, password)
    monkeypatch.setenv("SSL_CERT_FILE", str(imap.ca_file))  # the worker trusts the test server's CA
    imap.add(report(1))
    imap.add(report(2))
    (tmp_path / "server").mkdir()
    with running_server(tmp_path / "server", PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _signed_in(browser, server)
        page.goto(server.base + "/app/mailboxes")
        page.get_by_text("No mailbox yet.").wait_for()
        page.get_by_role("button", name="Add mailbox").first.click()
        page.get_by_label("Name").fill("Reports")
        page.get_by_label("Host").fill("127.0.0.1")
        page.get_by_label("Port").fill(str(imap.port))
        page.get_by_label("User").fill(USER)
        page.get_by_label("Password", exact=True).fill(password)
        page.get_by_role("dialog").get_by_role("button", name="Add mailbox").click()
        page.get_by_text("Not polled yet").first.wait_for()
        assert password not in page.content()
        page.get_by_role("button", name="Poll now").click()
        page.get_by_text("2 imported").wait_for(timeout=60000)
        assert "OK" in page.inner_text("main")

        page.goto(server.base + "/app/analyses")
        rows = page.locator("main table a[href^='/app/analyses/']")
        sync_api.expect(rows).to_have_count(2, timeout=60000)
        # the filter empties the table while it asks again: wait for its answer, then for the rows
        with page.expect_response(lambda response: "source=mailbox" in response.url) as filtered:
            page.get_by_role("button", name="Mailbox").click()
        assert filtered.value.status == 200
        sync_api.expect(rows).to_have_count(2, timeout=60000)
        sync_api.expect(page.locator("main table").get_by_text("Reports")).to_have_count(2)  # submitted by it

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(server.base + "/app/mailboxes")
            page.get_by_text("Report mailboxes").wait_for()
            page.wait_for_timeout(600)
            assert page.evaluate(PAST_EDGE) == [], width
        assert errors == []
    imap.close()
    assert imap.violations == []


def _account(page, username):
    """Fills the fields every new account has."""
    page.get_by_label("Username", exact=True).fill(username)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_label("First name", exact=True).fill(username.capitalize())
    page.get_by_label("Last name", exact=True).fill("Example")
    page.get_by_label("Location", exact=True).fill("Pune")


# What the theme toggle, fixed at the bottom left, covers once the page is scrolled to its end.
UNDER_TOGGLE = """() => {
  window.scrollTo({ top: document.documentElement.scrollHeight, behavior: 'instant' });
  const t = document.querySelector('[aria-label="Dark theme"]').getBoundingClientRect();
  return [...document.querySelectorAll('main a, main p, main button, main input, main label')].filter((e) => {
    const r = e.getBoundingClientRect();
    return r.width && r.left < t.right && r.right > t.left && r.top < t.bottom && r.bottom > t.top;
  }).map((e) => e.tagName + ' ' + e.textContent.trim().slice(0, 40));
}"""

# How far below its section's title each Save button sits, in pixels.
SAVE_BELOW_TITLE = """() => [...document.querySelectorAll('main button')]
  .filter((b) => b.textContent.trim() === 'Save')
  .map((b) => [b.getBoundingClientRect().top, b.parentElement.querySelector('h2').getBoundingClientRect().top])
  .map(([button, title]) => Math.round(button - title))"""


def test_an_organization_signs_up_and_its_invitation_brings_in_a_second_person(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        owner, owner_errors = _signed_in(browser, server)  # root owns the server: it lets anyone create an account
        owner.goto(server.base + "/app/settings")
        title = owner.get_by_role("heading", name="Sign-up and daily messages", exact=True)
        signup = owner.locator("main div.grid").filter(has=title).last  # the section, not the page around it
        sync_api.expect(signup.get_by_label("Messages a day, each organization")).to_have_value("500")
        sync_api.expect(signup.get_by_label("Messages a day, each person on their own")).to_have_value("100")
        signup.get_by_role("switch", name="Anyone can create an account").click()
        # beside its title on a wide screen, as in every other section
        below = owner.evaluate(SAVE_BELOW_TITLE)
        assert len(below) == 4 and max(below) < 16, below
        with owner.expect_response(lambda response: response.request.method == "PATCH") as saved:
            signup.get_by_role("button", name="Save").click()
        assert saved.value.url.endswith("/api/v1/server-settings") and saved.value.status == 200

        page, errors = _visitor(browser)
        page.goto(server.base + "/")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        page.get_by_role("banner").get_by_role("link", name="Create account").click()
        page.get_by_role("button", name="My organization").click()
        _account(page, "olivia")
        page.get_by_label("Organization", exact=True).fill("Acme SOC")
        page.locator("form [type=submit]").click()
        # an organization's admin is set up first: invite, mailbox, providers, then the tour; skipped here
        page.get_by_role("heading", name="Invite your team").wait_for()
        assert page.url == server.base + "/app/welcome"
        sync_api.expect(page.get_by_role("list", name="Setup steps").get_by_role("listitem")).to_have_count(4)
        page.get_by_role("button", name="Skip setup").click()
        page.wait_for_url(server.base + "/app/")
        page.get_by_role("button", name="Paste the message").wait_for()

        page.goto(server.base + "/app/users")
        page.get_by_role("button", name="Invite").first.click()
        page.get_by_role("button", name="Make the link").click()
        link = page.locator("code").filter(has_text="/app/join/").inner_text().strip()
        assert link.startswith(server.base + "/app/join/")
        # the whole link, Copy and Done fit in the dialog: nothing in it scrolls sideways
        assert page.evaluate("() => { const d = document.querySelector('dialog[open]');"
                             " return d.scrollWidth - d.clientWidth }") <= 1

        guest, guest_errors = _visitor(browser)  # another browser, where nobody is signed in
        guest.goto(link)
        guest.get_by_role("heading", level=1, name="Join Acme SOC").wait_for()
        _account(guest, "priya")
        guest.locator("form [type=submit]").click()
        guest.get_by_role("heading", name="A look around").wait_for()  # someone invited is only shown around
        sync_api.expect(guest.get_by_role("list", name="Setup steps")).to_have_count(0)
        me = guest.evaluate("fetch('/api/v1/session').then((r) => r.json())")
        assert (me["username"], me["role"], me["workspace"]["name"]) == ("priya", "analyst", "Acme SOC")
        assert guest.evaluate("fetch('/api/v1/analyses').then((r) => r.json())") == []  # none of root's
        guest.goto(link)
        guest.get_by_role("heading", level=1, name="This invitation is for a new account").wait_for()

        visitor, visitor_errors = _visitor(browser)
        for width in WIDTHS:
            for screen, path, ready in ((page, "/app/users", "Invitations"),
                                        (page, "/app/profile", "Your profile"),
                                        (page, "/app/welcome", "Invite your team"),
                                        (visitor, "/app/signup", "Who is it for?")):
                screen.set_viewport_size({"width": width, "height": 900})
                screen.goto(server.base + path)
                screen.get_by_text(ready).first.wait_for()
                screen.wait_for_timeout(400)
                assert screen.evaluate(PAST_EDGE) == [], (width, path)
            # where the bar shows its icon alone, Sign out still has its name for a screen reader
            sync_api.expect(page.get_by_role("button", name="Sign out")).to_have_count(1)
            visitor.get_by_role("button", name="Just me").click()
            visitor.get_by_label("Username", exact=True).wait_for()
            assert visitor.evaluate(PAST_EDGE) == [], (width, "the sign-up form")
            assert visitor.evaluate(UNDER_TOGGLE) == [], (width, "the sign-up form")
        visitor.locator("form [type=submit]").click()  # nothing filled in: the first refusal is about First name
        visitor.get_by_text("Required.").wait_for()
        tops = [visitor.get_by_label(name, exact=True).bounding_box()["y"] for name in ("First name", "Last name")]
        assert tops[0] == tops[1], tops  # side by side, even when only one of them has something to say
        visitor_errors = [e for e in visitor_errors if "status of 422" not in e]  # that refusal
        assert errors == [] and guest_errors == [] and visitor_errors == [] and owner_errors == []


def _open_signup(server):
    """root owns the server: it lets anyone create an account."""
    import requests

    owner = requests.Session()
    signed_in = owner.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
    csrf = signed_in.json()["csrf"]
    opened = owner.patch(server.base + "/api/v1/server-settings", json={"signup_open": True},
                         headers={"X-CSRF-Token": csrf})
    assert opened.status_code == 200, opened.text


def test_someone_who_signs_up_alone_is_set_up_shown_around_and_analyses_a_first_message(browser, tmp_path):
    import re

    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        _open_signup(server)
        page, errors = _visitor(browser)
        page.goto(server.base + "/")
        page.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        page.get_by_role("banner").get_by_role("link", name="Create account").click()
        page.get_by_role("button", name="Just me").click()
        _account(page, "noor")
        page.locator("form [type=submit]").click()

        # the setup after sign-up, for one person: reputation providers (offline is fine), then the tour
        page.get_by_role("heading", name="Reputation providers").wait_for()
        assert page.url == server.base + "/app/welcome"
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(server.base + "/app/welcome")
            page.get_by_role("heading", name="Reputation providers").wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "providers")
            page.get_by_role("button", name="Skip", exact=True).click()
            page.get_by_role("heading", name="A look around").wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "the tour")
            sync_api.expect(page.get_by_role("link", name=re.compile("^Show me"))).to_have_count(5)
        page.set_viewport_size({"width": 1280, "height": 900})
        page.get_by_role("button", name="Finish").click()
        page.wait_for_url(server.base + "/app/")
        assert page.evaluate("fetch('/api/v1/session').then((r) => r.json())")["onboarded"] is True

        # the upload page speaks plainly and shows how to get the email out of a mail app
        page.get_by_role("heading", level=1, name="Check an email").wait_for()
        sync_api.expect(page.get_by_text("Drop the email file here, or choose it")).to_be_visible()
        page.get_by_text("Gmail (on a computer)").click()
        sync_api.expect(page.get_by_text("Choose Download message.")).to_be_visible()
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(server.base + "/app/")
            page.get_by_role("heading", level=1, name="Check an email").wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "the simple upload page")
        page.set_viewport_size({"width": 1280, "height": 900})

        # and so does the top bar: the technical pages are in it only with the switch on
        bar = page.locator(".ph-commandbar")
        sync_api.expect(bar.get_by_role("link", name="Check an email")).to_be_visible()
        sync_api.expect(bar.get_by_role("link", name="My emails")).to_be_visible()
        for technical in ("Triage", "Queue", "Campaigns", "Audit"):
            sync_api.expect(bar.get_by_role("link", name=technical, exact=True)).to_have_count(0)
        page.get_by_role("button", name="More").click()
        menu = page.locator(".ph-commandbar__menu")
        sync_api.expect(menu.get_by_role("link", name="Settings")).to_be_visible()
        for technical in ("Health", "Users", "Tokens", "Mailboxes"):
            sync_api.expect(menu.get_by_role("link", name=technical, exact=True)).to_have_count(0)
        page.get_by_role("button", name="More").click()
        sync_api.expect(page.get_by_role("heading", name="Your recent checks")).to_be_visible()

        # the first analysis
        page.get_by_role("button", name="Paste the message").click()
        with open(sample("sample_phish.eml"), encoding="utf-8") as message:
            page.fill("textarea[aria-label='Raw message']", message.read())
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/analyses/*", timeout=60000)

        # someone on their own gets the verdict in plain words and what to do, not the tabs
        headline = page.get_by_role("heading", level=1, name="This email is very likely a scam.")
        headline.wait_for(timeout=30000)
        sync_api.expect(page.get_by_role("heading", name="Why we think so")).to_be_visible()
        sync_api.expect(page.get_by_role("heading", name="What to do now")).to_be_visible()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_have_count(0)
        simple = page.url

        # the switch brings back the technical page while the tab is open; a reload starts simple again
        page.get_by_role("switch", name="Show technical details").click()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_be_visible()
        sync_api.expect(bar.get_by_role("link", name="Campaigns")).to_be_visible()  # the bar changes with the page
        page.locator("main a[href='/app/analyses']").first.click()
        page.locator("main table a[href^='/app/analyses/']").first.click()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_be_visible()
        page.reload()
        headline.wait_for()
        sync_api.expect(page.get_by_role("tab", name="ATT&CK")).to_have_count(0)
        sync_api.expect(bar.get_by_role("link", name="My emails")).to_be_visible()
        page.locator("main a[href='/app/analyses']").first.click()
        page.get_by_role("heading", level=1, name="My emails").wait_for()
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(simple)
            headline.wait_for()
            page.wait_for_timeout(400)
            assert page.evaluate(PAST_EDGE, "body") == [], (width, "the simple analysis")
        page.set_viewport_size({"width": 1280, "height": 900})

        # from now on the console opens at Triage
        page.goto(server.base + "/app/")
        page.get_by_role("button", name="Paste the message").wait_for()
        assert page.url == server.base + "/app/"
        assert errors == []


def test_people_say_whether_a_verdict_was_right_and_send_the_owner_feedback(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _signed_in(browser, server)  # root owns the server
        page.get_by_role("button", name="Paste the message").click()
        with open(sample("sample_phish.eml"), encoding="utf-8") as message:
            page.fill("textarea[aria-label='Raw message']", message.read())
        page.get_by_role("switch", name="Offline analysis").click()
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/analyses/*", timeout=60000)
        analysis = page.url

        # "Was this verdict right?": one answer, with a note, kept after a reload
        question = page.get_by_role("radiogroup", name="Was this verdict right?")
        question.get_by_role("radio", name="It was not phishing").click()
        page.get_by_label("Note (optional)").fill("Our own phishing drill.")
        page.get_by_role("button", name="Send my answer").click()
        page.get_by_text("Thank you. Your answer was saved.").wait_for()
        page.reload()
        answered = page.get_by_role("radio", name="It was not phishing")
        sync_api.expect(answered).to_have_attribute("aria-checked", "true")

        # the Queue's Disputed filter finds it
        page.goto(server.base + "/app/analyses")
        with page.expect_response(lambda response: "disputed=true" in response.url) as filtered:
            page.get_by_role("button", name="Disputed").click()
        assert filtered.value.status == 200
        sync_api.expect(page.locator("main table a[href^='/app/analyses/']")).to_have_count(1)

        # feedback from the footer, with the page it came from
        page.get_by_role("contentinfo").get_by_role("button", name="Feedback").click()
        page.get_by_text("An idea").click()
        page.get_by_label("Your message").fill("Show the disputed ones on Triage too.")
        page.get_by_role("button", name="Send", exact=True).click()
        page.get_by_text("Sent. Thank you.").wait_for()

        # the owner's Feedback page: the feedback, the answers on verdicts and the download
        page.goto(server.base + "/app/feedback")
        page.get_by_text("Show the disputed ones on Triage too.").wait_for()
        sync_api.expect(page.get_by_text("from /app/analyses")).to_be_visible()
        sync_api.expect(page.locator("main a[href='%s']" % analysis.replace(server.base, ""))).to_have_count(1)
        download = page.evaluate("fetch('/api/v1/feedback/verdicts?format=csv').then((r) => r.text())")
        assert download.startswith("workspace_id,analysis_id,") and analysis.rsplit("/", 1)[1] in download
        page.get_by_role("button", name="Mark done").click()
        sync_api.expect(page.get_by_role("button", name="Reopen")).to_be_visible()

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url, ready in ((analysis, "Was this verdict right?"),
                               (server.base + "/app/feedback", "Answers on verdicts")):
                page.goto(url)
                page.get_by_text(ready).first.wait_for()
                page.wait_for_timeout(400)
                assert page.evaluate(PAST_EDGE, "body") == [], (width, url)
        assert errors == []


def test_an_admin_deletes_a_member_the_owner_a_workspace_and_someone_alone_their_account(browser, tmp_path):
    import requests

    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        _open_signup(server)
        for kind, username, organization in (("organization", "ana", "Ana Labs"), ("individual", "noor", "")):
            person = requests.Session()
            made = person.post(server.base + "/api/v1/signup", json={
                "kind": kind, "username": username, "password": PASSWORD, "first_name": username.capitalize(),
                "last_name": "Example", "location": "Pune", "job_title": "", "organization": organization})
            assert made.status_code == 201, made.text
            person.post(server.base + "/api/v1/me/onboarded", headers={"X-CSRF-Token": made.json()["csrf"]})
        root = requests.Session()
        signed_in = root.post(server.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
        kim = {"username": "kim", "password": PASSWORD, "role": "analyst"}
        root.headers["X-CSRF-Token"] = signed_in.json()["csrf"]
        added = root.post(server.base + "/api/v1/users", json=kim)
        assert added.status_code == 201, added.text
        page, errors = _signed_in(browser, server)  # root owns the server

        # an admin deletes a member
        page.goto(server.base + "/app/users")
        page.get_by_role("button", name="Delete kim").click()
        page.get_by_role("dialog").get_by_role("button", name="Delete", exact=True).click()
        page.get_by_text("kim was deleted.").wait_for()
        sync_api.expect(page.get_by_role("button", name="Delete kim")).to_have_count(0)
        sync_api.expect(page.get_by_role("button", name="Delete root")).to_have_count(0)  # never yourself

        # the owner sees every workspace by name, kind and members, and deletes one, never their own
        page.goto(server.base + "/app/settings")
        workspaces = page.get_by_role("region", name="Workspaces")
        workspaces.get_by_text("Ana Labs").wait_for()
        sync_api.expect(workspaces.get_by_text("Noor Example")).to_be_visible()
        sync_api.expect(workspaces.get_by_role("button", name="Delete Default organization")).to_have_count(0)
        workspaces.get_by_role("button", name="Delete Ana Labs").click()
        page.get_by_role("dialog").get_by_role("button", name="Delete workspace").click()
        page.get_by_text("Ana Labs was deleted.").wait_for()
        sync_api.expect(workspaces.get_by_text("Ana Labs")).to_have_count(0)

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url, ready in ((server.base + "/app/users", "Last sign-in"),
                               (server.base + "/app/settings", "Noor Example")):
                page.goto(url)
                page.get_by_text(ready).first.wait_for()
                page.wait_for_timeout(400)
                assert page.evaluate(PAST_EDGE, "body") == [], (width, url)

        # someone on their own deletes their account, with their password, and is back on the product page
        alone, alone_errors = _visitor(browser)
        alone.goto(server.base + "/app/login")
        alone.fill("#login-username", "noor")
        alone.fill("#login-password", PASSWORD)
        alone.locator("form [type=submit]").click()
        alone.wait_for_selector(".ph-commandbar")
        for width in WIDTHS:
            alone.set_viewport_size({"width": width, "height": 900})
            alone.goto(server.base + "/app/profile")
            alone.get_by_role("heading", name="Delete your account").wait_for()
            alone.wait_for_timeout(400)
            assert alone.evaluate(PAST_EDGE, "body") == [], (width, "profile")
        alone.set_viewport_size({"width": 1280, "height": 900})
        section = alone.get_by_role("region", name="Delete your account")
        section.get_by_label("Password", exact=True).fill("not the password")
        section.get_by_role("button", name="Delete my account").click()
        alone.get_by_role("dialog").get_by_role("button", name="Delete my account").click()
        sync_api.expect(alone.get_by_role("dialog").get_by_role("alert")).to_contain_text("password")
        alone.get_by_role("dialog").get_by_role("button", name="Cancel").click()
        section.get_by_label("Password", exact=True).fill(PASSWORD)
        section.get_by_role("button", name="Delete my account").click()
        alone.get_by_role("dialog").get_by_role("button", name="Delete my account").click()
        alone.get_by_role("heading", level=1, name=HEADLINE).wait_for()
        assert alone.url == server.base + "/app/"
        assert alone.evaluate("fetch('/api/v1/session').then((r) => r.status)") == 401
        assert [w["name"] for w in page.evaluate("fetch('/api/v1/workspaces').then((r) => r.json())")] == [
            "Default organization"]
        alone_errors = [e for e in alone_errors if "status of 403" not in e]  # the wrong password
        assert errors == [] and alone_errors == []


SITE = "https://phishhawk.example.org"


def _mail_link(received, count, server):
    """The link in the count-th message the server sent, opened on this server: its public URL is another."""
    import email
    import email.policy
    import re
    import time

    deadline = time.monotonic() + 30
    while len(received) < count:
        assert time.monotonic() < deadline, "no mail came: %d of %d" % (len(received), count)
        time.sleep(0.2)
    body = email.message_from_bytes(received[count - 1], policy=email.policy.default).get_body().get_content()
    return server.base + re.search(re.escape(SITE) + r"(/app/[A-Za-z0-9/_-]+)", body).group(1)


def test_someone_who_forgot_their_password_sets_a_new_one_with_a_link_by_email(browser, tmp_path):
    settings = {"PHISHHAWK_FRONTEND_DIR": str(Path(BUILD).resolve()), "PHISHHAWK_PUBLIC_URL": SITE,
                "PHISHHAWK_SMTP_HOST": "127.0.0.1", "PHISHHAWK_SMTP_SECURITY": "none",
                "PHISHHAWK_SMTP_FROM": "PhishHawk <no-reply@example.org>"}
    with smtp_sink() as (port, received), \
            running_server(tmp_path, PHISHHAWK_SMTP_PORT=str(port), **settings) as server:
        page, errors = _signed_in(browser, server)
        page.goto(server.base + "/app/profile")
        page.get_by_text("None yet. Without one, a forgotten password needs an admin.").wait_for()
        address = page.locator("form").filter(has=page.get_by_label("Email address"))
        address.get_by_label("Email address").fill("Root@Corp.example")
        sync_api.expect(address.get_by_role("button", name="Save email")).to_be_disabled()  # the password first
        address.get_by_label("Current password").fill(PASSWORD)
        address.get_by_role("button", name="Save email").click()
        page.get_by_text("root@corp.example is not confirmed yet").wait_for()

        page.goto(_mail_link(received, 1, server))
        page.get_by_role("heading", name="Confirm your email address").wait_for()
        page.get_by_role("button", name="Confirm my address").click()
        page.get_by_role("heading", name="Your email address is confirmed").wait_for()
        page.get_by_role("link", name="Your profile").click()
        page.get_by_text("root@corp.example is confirmed").wait_for()

        visitor, visitor_errors = _visitor(browser)
        visitor.goto(server.base + "/app/login")
        visitor.get_by_role("link", name="Forgot password?").click()
        visitor.get_by_role("heading", level=1, name="Forgot your password?").wait_for()
        visitor.get_by_label("Username or email").fill("ROOT@corp.example")
        visitor.locator("form [type=submit]").click()
        visitor.get_by_role("heading", level=1, name="Check your email").wait_for()
        visitor.get_by_text("If an account matches, a link is on its way").wait_for()
        reset = _mail_link(received, 2, server)
        assert "/app/reset/" in reset

        visitor.goto(reset)
        visitor.get_by_text("For the account root.").wait_for()
        visitor.get_by_label("New password").fill("too short")
        visitor.locator("form [type=submit]").click()
        sync_api.expect(visitor.get_by_label("New password")).to_have_attribute("aria-invalid", "true")
        visitor.get_by_label("New password").fill("a brand new long password")
        visitor.locator("form [type=submit]").click()
        visitor.get_by_role("heading", level=1, name="Your password is changed").wait_for()
        page.reload()
        page.wait_for_selector("#login-username")  # root's other session ended with the old password
        visitor.get_by_role("main").get_by_role("link", name="Sign in").click()
        visitor.fill("#login-username", "root")
        visitor.fill("#login-password", "a brand new long password")
        visitor.locator("form [type=submit]").click()
        visitor.wait_for_selector(".ph-commandbar")
        visitor.goto(reset)
        visitor.get_by_text("This link is for a forgotten password").wait_for()  # signed in: the profile instead
        visitor.goto(server.base + "/app/forgot")
        visitor.wait_for_url(server.base + "/app/profile")

        stranger, stranger_errors = _visitor(browser)
        for width in WIDTHS:
            stranger.set_viewport_size({"width": width, "height": 900})
            used = reset[len(server.base):]
            for path, ready in (("/app/forgot", "Forgot your password?"), (used, "This link cannot be used")):
                stranger.goto(server.base + path)
                stranger.get_by_role("heading", level=1, name=ready).wait_for()
                stranger.wait_for_timeout(300)
                assert stranger.evaluate(PAST_EDGE) == [], (width, path)
        refused = ("status of 422", "status of 404")  # the short password, and the used link
        visitor_errors = [e for e in visitor_errors if not any(r in e for r in refused)]
        stranger_errors = [e for e in stranger_errors if not any(r in e for r in refused)]
        assert errors == [] and visitor_errors == [] and stranger_errors == []
