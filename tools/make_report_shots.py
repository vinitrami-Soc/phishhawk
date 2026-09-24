"""Render the HTML report screenshots in docs/images from a real run.

    pip install -e ".[assets]" && playwright install chromium
    python tools/make_report_shots.py

Writes report-light.png and report-dark.png (the top of the report, as a
browser shows it) and report-print.png (the first two A4 pages, as printed).
The sample is the BEC message, because it exercises the most of the report.
Set PHISHHAWK_CHROMIUM to a Chromium binary to use it instead of Playwright's own.
"""

from __future__ import annotations

import io
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
sys.path.insert(0, str(ROOT / "src"))

from phishhawk.pipeline import triage_file  # noqa: E402
from phishhawk.report import html  # noqa: E402

WIDTH, TOP = 1180, 1240


def main() -> int:
    try:
        import pymupdf
        from PIL import Image
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        print("needs the assets extra and a Chromium for Playwright: %s" % exc, file=sys.stderr)
        return 1

    os.chdir(ROOT)  # the report shows the path it was given; keep it repo-relative
    analysis = triage_file("samples/sample_bec_smuggling.eml")
    with tempfile.TemporaryDirectory() as tmp:
        page_path = pathlib.Path(tmp) / "report.html"
        page_path.write_text(html.render([analysis]), encoding="utf-8")
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=os.environ.get("PHISHHAWK_CHROMIUM") or None)
            for scheme in ("light", "dark"):
                page = browser.new_page(viewport={"width": WIDTH, "height": TOP}, color_scheme=scheme)
                page.goto(page_path.as_uri())
                page.wait_for_timeout(400)
                page.screenshot(path=str(IMAGES / ("report-%s.png" % scheme)))
                print("wrote docs/images/report-%s.png" % scheme)
            page = browser.new_page()
            page.goto(page_path.as_uri())
            page.emulate_media(media="print")
            pdf = page.pdf(format="A4", print_background=True, prefer_css_page_size=True)
            browser.close()

    doc = pymupdf.open(stream=pdf, filetype="pdf")
    pages = [Image.open(io.BytesIO(doc[i].get_pixmap(dpi=110).tobytes("png"))).convert("RGB") for i in range(2)]
    gap = 28
    sheet = Image.new("RGB", (sum(p.width for p in pages) + gap * 3, pages[0].height + gap * 2), "#e4e7ee")
    x = gap
    for p in pages:
        sheet.paste(p, (x, gap))
        x += p.width + gap
    sheet.save(IMAGES / "report-print.png", optimize=True)
    print("wrote docs/images/report-print.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
