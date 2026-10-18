"""The frontend in frontend/, built with `npm run build`, served by a real
server at /app/ and driven in headless Chromium: read the product page a
visitor sees first and sign in from it, analyse a bundled
sample offline, read the verdict, the sandboxed report and the files; upload
two messages as a batch and follow them to their combined reports and their
campaign; connect a mailbox (a test IMAP server) and find its reports in the
queue; create an organization's account from the product page and join it from
a second browser with its invitation link; then check phone, tablet and
desktop widths for anything past the right edge. No console errors, so nothing broke the CSP. Skipped unless
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
        title = owner.get_by_role("heading", name="Sign-up", exact=True)
        signup = owner.locator("main div.grid").filter(has=title).last  # the section, not the page around it
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

        # the first analysis
        page.get_by_role("button", name="Paste the message").click()
        with open(sample("sample_phish.eml"), encoding="utf-8") as message:
            page.fill("textarea[aria-label='Raw message']", message.read())
        page.get_by_role("button", name="Analyze").click()
        page.wait_for_url("**/app/analyses/*", timeout=60000)
        page.get_by_text("LIKELY PHISHING").first.wait_for(timeout=30000)

        # from now on the console opens at Triage
        page.goto(server.base + "/app/")
        page.get_by_role("button", name="Paste the message").wait_for()
        assert page.url == server.base + "/app/"
        assert errors == []
