"""A frontend built elsewhere (docs/FRONTEND.md), served from this origin at
/app/: its files, and its index.html for any path without a file extension,
so the frontend's own routes survive a reload. Everything else in the build
folder's parent stays out of reach. Vite names every file in assets/ after
its content, so those are cached for a year; the page itself is checked on
every load, so a new build is picked up at once. The page tells search engines
to stay away; when the owner lets them in, the pages anyone may read before
signing in are sent without that tag, and with a head of their own (HEADS):
search engines and link previews read the HTML, not what the script draws."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from starlette.exceptions import HTTPException
from starlette.responses import HTMLResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

IMMUTABLE = "public, max-age=31536000, immutable"
NOINDEX = '<meta name="robots" content="noindex, nofollow" />'  # in frontend/index.html
PUBLIC_PAGES = ("about", "privacy", "help")  # readable before signing in (frontend/src/app/routes.ts)
REPOSITORY = "https://github.com/vinitrami-Soc/phishhawk"
SHARE_IMAGE = "/app/brand/og-image.png"  # 1200 x 630, made by tools/make_og_image.py


@dataclass(frozen=True)
class Head:
    title: str  # what the frontend's pageTitle sets (routes.ts), so the tab does not change once it runs
    share_title: str  # link previews
    description: str
    path: str  # the address search engines should list
    summary: str = ""  # the page's own words, in #root until the script draws the page


# The product page: the landing page's own words (frontend/src/screens/LandingScreen.tsx), so the summary says
# what the drawn page says.
PRODUCT = Head(
    title="Phishing email triage · PhishHawk",
    share_title="Is this email phishing? Check it free with PhishHawk",
    description="Check if an email is phishing in seconds. Free, open-source triage for people checking their own "
                "mail and SOC teams: a verdict, evidence and next steps.",
    path="/",
    summary="<main><p>Phishing email triage, on your own server</p>"
            "<h1>Every reported email, triaged and explained.</h1>"
            "<p>An analyst drops in a reported email. PhishHawk reads its headers, links, attachments and QR "
            "codes, and gives back a verdict with the evidence behind it, a full report and files for your other "
            "tools. All of it on a server your organisation runs.</p></main>",
)
HEADS = {
    "": PRODUCT,  # the server's own address, for a visitor without a session
    "about": PRODUCT,  # the same page, listed at the address above
    "privacy": Head(
        title="Privacy and terms · PhishHawk",
        share_title="PhishHawk privacy and terms",
        description="What PhishHawk keeps and for how long, who runs this server, and how reported mail is "
                    "encrypted and deleted.",
        path="/app/privacy",
    ),
    "help": Head(
        title="Help · PhishHawk",
        share_title="How to download an email as .eml and check it for phishing",
        description="How to download an email as .eml from Gmail, Outlook or Apple Mail, check it for phishing, "
                    "and read what each PhishHawk verdict means.",
        path="/app/help",
    ),
}
TITLE = re.compile(r"<title>.*?</title>", re.S)
DESCRIPTION = re.compile(r'<meta name="description"[^>]*>\s*')


def _software(description: str, url: str) -> str:
    """What the product is, for search engines (schema.org), as a data block: it never runs, so the CSP allows it.
    No rating or review: PhishHawk has none to show."""
    data = {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "PhishHawk",
            "description": description, **({"url": url} if url else {}),
            "applicationCategory": "SecurityApplication", "operatingSystem": "Web, Linux, macOS, Windows",
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "GBP"},
            "license": "https://opensource.org/licenses/MIT", "sameAs": [REPOSITORY]}
    text = json.dumps(data, ensure_ascii=False)
    # nothing in it can close the script element
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def with_head(page: str, name: str, public_url: str) -> str:
    """The page with the head of the public page `name`: its title, description, address and link preview, and
    the product page's summary. Addresses are built from the server's public URL, never from the request, and
    left out without one."""
    head = HEADS[name]
    base = public_url.rstrip("/")
    url = base + head.path if base else ""

    def attr(value: str) -> str:
        return html.escape(value, quote=True)

    tags = ['<meta name="description" content="%s" />' % attr(head.description)]
    if url:
        tags.append('<link rel="canonical" href="%s" />' % attr(url))
    tags += ['<meta property="og:type" content="website" />',
             '<meta property="og:site_name" content="PhishHawk" />',
             '<meta property="og:title" content="%s" />' % attr(head.share_title),
             '<meta property="og:description" content="%s" />' % attr(head.description)]
    if url:
        tags += ['<meta property="og:url" content="%s" />' % attr(url),
                 '<meta property="og:image" content="%s" />' % attr(base + SHARE_IMAGE),
                 '<meta name="twitter:card" content="summary_large_image" />']
    else:
        tags.append('<meta name="twitter:card" content="summary" />')
    if name == "":
        tags.append('<script type="application/ld+json">%s</script>' % _software(head.description, url))
    page = DESCRIPTION.sub("", page, count=1)
    page = TITLE.sub(lambda _: "<title>%s</title>\n%s" % (attr(head.title), "\n".join(tags)), page, count=1)
    if head.summary:
        page = page.replace('<div id="root"></div>', '<div id="root">%s</div>' % head.summary, 1)
    return page


class Frontend(StaticFiles):
    def __init__(self, directory: str, indexed: Callable[[], bool] = lambda: False,
                 public_url: Callable[[], str] = lambda: "") -> None:
        super().__init__(directory=directory, html=True)
        self.page = Path(directory) / "index.html"
        self.indexed = indexed
        self.public_url = public_url

    def public_page(self, name: str) -> HTMLResponse:
        """A page anyone may read before signing in, as search engines should see it."""
        page = with_head(self.page.read_text(encoding="utf-8").replace(NOINDEX, ""), name, self.public_url())
        return HTMLResponse(page, headers={"Cache-Control": "no-cache", "X-Robots-Tag": "all"})

    async def get_response(self, path: str, scope: Scope) -> Response:
        if path.strip("/") in PUBLIC_PAGES and self.indexed():
            return self.public_page(path.strip("/"))
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or "." in path.rsplit("/", 1)[-1]:
                raise
            response = await super().get_response("index.html", scope)
        response.headers["Cache-Control"] = IMMUTABLE if path.startswith("assets/") else "no-cache"
        return response
