"""The frontend in frontend/, built with `npm run build`, served by a real
server at /app/ and driven in headless Chromium: sign in, analyse a bundled
sample offline, read the verdict, the sandboxed report and the files, then
check phone, tablet and desktop widths for anything past the right edge. No
console errors, so nothing broke the CSP. Skipped unless
PHISHHAWK_FRONTEND_BUILD names the build (CI's frontend job makes it);
PHISHHAWK_CHROMIUM may name the browser's executable."""

import os
from pathlib import Path

import pytest

from .serverkit import PASSWORD, running_server
from conftest import sample

sync_api = pytest.importorskip("playwright.sync_api")
BUILD = os.environ.get("PHISHHAWK_FRONTEND_BUILD", "")
pytestmark = pytest.mark.skipif(not (BUILD and Path(BUILD, "index.html").is_file()),
                                reason="no frontend build (set PHISHHAWK_FRONTEND_BUILD)")
WIDTHS = (320, 360, 390, 768, 820, 1024, 1440)

# Elements that reach past the right edge of the window, leaving out those inside a strip that scrolls
# sideways on purpose (the tabs on a phone) and the sign-in button's glow.
PAST_EDGE = """() => {
  const w = document.documentElement.clientWidth;
  return [...document.querySelectorAll('main *')].filter((e) => {
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


def test_an_analyst_works_a_message_in_the_frontend_at_every_width(browser, tmp_path):
    with running_server(tmp_path, PHISHHAWK_FRONTEND_DIR=str(Path(BUILD).resolve())) as server:
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        # the frontend asks who is signed in before anyone is: that one 401 is expected
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "401" not in m.text else None)
        page.on("pageerror", lambda exc: errors.append(str(exc)))

        page.goto(server.base + "/")  # the server's address opens the frontend
        page.wait_for_selector("#login-username")
        assert page.url == server.base + "/app/"
        page.fill("#login-username", "root")
        page.fill("#login-password", PASSWORD)
        page.locator("form [type=submit]").click()
        page.wait_for_selector(".ph-commandbar")

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
