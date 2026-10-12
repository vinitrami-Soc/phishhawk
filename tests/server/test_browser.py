"""The web app in a real browser (headless Chromium through Playwright):
keyboard-only login, submit, verdict, download; no horizontal scrolling from
320 to 1440 px; no console errors, so nothing broke the CSP. Skipped when
Playwright or a Chromium for it is missing; PHISHHAWK_CHROMIUM may name the
browser's executable."""

import os

import pytest

from .serverkit import PASSWORD, running_server
from conftest import sample

sync_api = pytest.importorskip("playwright.sync_api")
WIDTHS = (320, 390, 768, 1024, 1440)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as playwright:
        try:
            chromium = playwright.chromium.launch(executable_path=os.environ.get("PHISHHAWK_CHROMIUM") or None)
        except sync_api.Error as exc:
            pytest.skip("no Chromium for Playwright: %s" % str(exc).splitlines()[0])
        yield chromium
        chromium.close()


def _tab_to(page, element_id, limit=15):
    for _ in range(limit):
        page.keyboard.press("Tab")
        if page.evaluate("document.activeElement.id") == element_id:
            return
    raise AssertionError("Tab never reached #%s" % element_id)


def test_an_analyst_works_a_message_with_the_keyboard(browser, tmp_path):
    with running_server(tmp_path) as server:
        page = browser.new_page()
        errors = []
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.goto(server.base + "/login")
        _tab_to(page, "username")
        page.keyboard.type("root")
        _tab_to(page, "password")
        page.keyboard.type(PASSWORD)
        page.keyboard.press("Enter")
        page.wait_for_url(server.base + "/")
        page.set_input_files("#files", sample("sample_phish.eml"))  # the file picker is the system's own
        _tab_to(page, "raw")
        page.keyboard.press("Tab")  # the offline box
        page.keyboard.press("Space")
        page.keyboard.press("Tab")
        page.keyboard.press("Enter")
        page.wait_for_url("**/analyses/*", timeout=30_000)
        assert "LIKELY PHISHING" in page.locator("h1").inner_text()
        assert "LIKELY PHISHING" in page.frame_locator("iframe.report").locator("body").inner_text()
        with page.expect_download() as download:
            page.get_by_role("link", name="CSV indicators").click()
        assert download.value.suggested_filename.endswith(".csv")
        analysis = page.url
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 800})
            for path in (server.base + "/", server.base + "/queue", analysis, server.base + "/audit"):
                page.goto(path)
                overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                assert overflow <= 0, "%s scrolls sideways at %d px" % (path, width)
        assert not errors, errors
