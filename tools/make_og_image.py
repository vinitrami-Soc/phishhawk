"""Render the link-preview image for the public pages: the picture LinkedIn,
Slack, WhatsApp and search results show next to a link to PhishHawk.

    pip install -e ".[assets]" && playwright install chromium
    (cd frontend && npm ci --ignore-scripts)   # for the Geist font
    python tools/make_og_image.py

Writes frontend/public/brand/og-image.png, 1200 x 630, which the server names
in og:image (src/phishhawk/server/frontend.py, SHARE_IMAGE). It stops if the
file comes out larger than 300 KB.
Set PHISHHAWK_CHROMIUM to a Chromium binary to use it instead of Playwright's own.
"""

from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "frontend" / "public" / "brand" / "og-image.png"
MARK = ROOT / "frontend" / "public" / "brand" / "phishhawk-mark.svg"
FONTS = ROOT / "frontend" / "node_modules" / "@fontsource-variable" / "geist" / "files"
FONT = FONTS / "geist-latin-wght-normal.woff2"
WIDTH, HEIGHT = 1200, 630
LIMIT = 300 * 1024

PAGE = """<!doctype html>
<meta charset="utf-8">
<style>
  @font-face { font-family: Geist; src: url("%(font)s") format("woff2"); font-weight: 100 900; }
  html, body { margin: 0; width: %(width)dpx; height: %(height)dpx; }
  body {
    background: radial-gradient(900px 520px at 88%% 0%%, rgba(103, 232, 249, .16), transparent 60%%),
                radial-gradient(760px 480px at 0%% 100%%, rgba(249, 115, 22, .14), transparent 60%%), #000;
    color: #f4f4f5; font-family: Geist, system-ui, sans-serif; display: grid; align-content: center;
    padding: 0 88px; box-sizing: border-box;
  }
  .name { display: flex; align-items: center; gap: 22px; font-size: 44px; font-weight: 600;
          letter-spacing: -.02em; }
  .name img { width: 76px; height: 76px; }
  h1 { margin: 44px 0 0; font-size: 72px; line-height: 1.04; font-weight: 600; letter-spacing: -.045em;
       max-width: 960px; }
  h1 span { background: linear-gradient(100deg, #67e8f9, #f97316); -webkit-background-clip: text;
            color: transparent; }
  p { margin: 30px 0 0; font-size: 28px; color: #a8a8b0; }
</style>
<div class="name"><img src="%(mark)s" alt="">PhishHawk</div>
<h1>Is this email phishing? <span>Find out in seconds.</span></h1>
<p>Free and open source, for anyone checking their own mail and for SOC teams.</p>
"""


def main() -> int:
    from playwright.sync_api import sync_playwright

    if not FONT.is_file():
        print("Geist is missing: run npm ci --ignore-scripts in frontend/ first", file=sys.stderr)
        return 1
    page_html = PAGE % {"font": FONT.as_uri(), "mark": MARK.as_uri(), "width": WIDTH, "height": HEIGHT}
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("PHISHHAWK_CHROMIUM") or None)
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT})
        source = OUT.with_suffix(".html")
        source.write_text(page_html, encoding="utf-8")  # a file:// page may load the font and the mark beside it
        try:
            page.goto(source.as_uri())
            page.evaluate("document.fonts.ready")
            page.screenshot(path=str(OUT))
        finally:
            source.unlink()
            browser.close()
    size = OUT.stat().st_size
    if size > LIMIT:
        print("%s is %d KB, over the %d KB limit" % (OUT, size // 1024, LIMIT // 1024), file=sys.stderr)
        return 1
    print("wrote %s (%d KB)" % (OUT.relative_to(ROOT), size // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
