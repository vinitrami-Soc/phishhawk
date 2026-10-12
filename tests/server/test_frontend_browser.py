"""The frontend in frontend/, built with `npm run build`, served by a real
server at /app/ and driven in headless Chromium: read the product page a
visitor sees first and sign in from it, analyse a bundled
sample offline, read the verdict, the sandboxed report and the files; upload
two messages as a batch and follow them to their combined reports and their
campaign; connect a mailbox (a test IMAP server) and find its reports in the
queue; then check phone, tablet and desktop widths for anything past the
right edge. No console errors, so nothing broke the CSP. Skipped unless
PHISHHAWK_FRONTEND_BUILD names the build (CI's frontend job makes it);
PHISHHAWK_CHROMIUM may name the browser's executable."""

import os
from pathlib import Path

import pytest

from .serverkit import PASSWORD, running_server
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


def test_an_analyst_works_a_message_in_the_frontend_at_every_width(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page, errors = _signed_in(browser, server)

        page.get_by_role("button", name="Paste the message").click()
        with open(sample("sample_phish.eml"), encoding="utf-8") as message:
            page.fill("textarea[aria-label='Raw message']", message.read())
        page.get_by_role("switch", name="Offline analysis").click()
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/analyses/*", timeout=60000)
        page.get_by_text("LIKELY PHISHING").first.wait_for(timeout=30000)
        analysis = page.url

        page.get_by_role("tab", name="Report").click()
        report = page.frame_locator("iframe[title='Full report']").locator("body")
        assert "LIKELY PHISHING" in report.inner_text(timeout=15000)
        page.get_by_role("tab", name="Files").click()
        with page.expect_download() as download:
            page.locator("a[download]").first.click()
        assert download.value.suggested_filename.startswith("phishhawk-")

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for url in (server.base + "/app/", analysis, server.base + "/app/help"):
                page.goto(url)
                if url.endswith("/app/"):  # with a file chosen, its name and Remove share the row
                    page.set_input_files("input[type=file]", sample("sample_phish.eml"))
                page.wait_for_timeout(600)
                assert page.evaluate(PAST_EDGE) == [], (width, url)
            assert page.evaluate(TOGGLE_BESIDE_SIGN_OUT) == [0, 0], width
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
