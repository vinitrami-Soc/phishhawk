"""Accessibility of the HTML report: structure a screen reader can navigate,
keyboard focus that stays visible, text that clears WCAG AA contrast in both
themes, and meaning that never rests on colour alone."""

import collections
import re

import pytest

from phishhawk.pipeline import triage_file
from phishhawk.report import html

from conftest import sample


@pytest.fixture(scope="module")
def bec():
    return triage_file(sample("sample_bec_smuggling.eml"))


@pytest.fixture(scope="module")
def pages(bec):
    benign = triage_file(sample("sample_benign.eml"))
    return {"single": html.render([bec]), "batch": html.render([bec, benign])}


def test_one_h1_and_headings_that_never_skip_a_level(pages):
    for name, page in pages.items():
        levels = [int(n) for n in re.findall(r"<h([1-6])[\s>]", page)]
        assert levels.count(1) == 1, name
        assert all(b <= a + 1 for a, b in zip(levels, levels[1:], strict=False)), name


def test_every_id_is_unique_and_every_region_is_named(pages):
    for name, page in pages.items():
        ids = re.findall(r'\sid="([^"]+)"', page)
        assert not [i for i, n in collections.Counter(ids).items() if n > 1], name
        for region in re.findall(r'<section class="card panel[^"]*"[^>]*>', page):
            assert re.search(r'aria-label="[^"]+"', region), region


def test_a_skip_link_leads_to_the_verdict(pages):
    body = pages["single"].split("<body>", 1)[1]
    assert body.startswith('<a class="skip" href="#msg-1-summary">Skip to the verdict</a>')
    assert ".skip:focus" in pages["single"]


def test_tables_have_captions_and_styled_lists_stay_lists(pages):
    page = pages["single"]
    assert page.count("<table") == page.count('<caption class="sr-only">') > 0
    for cls in ("steps", "top", "urls", "looks", "techs", "tactics", "limits"):
        for tag in re.findall(r'<(?:ul|ol) class="%s"[^>]*>' % cls, page):
            assert 'role="list"' in tag, tag
    assert ".sr-only{" in page


def test_focus_stays_visible_and_clear_of_the_sticky_bar(pages):
    page = pages["single"]
    assert ":focus-visible{outline:2px solid var(--brand)" in page
    assert "scroll-padding-top:" in page


def test_changed_characters_are_described_in_words(bec):
    page = html.render([bec])
    # the marks are visual; a screen reader hears which character changed
    assert '<span class="sr-only">character 6 is &quot;1&quot;, not &quot;l&quot;</span>' in page


def test_no_text_is_dimmed_with_opacity(pages):
    assert not re.search(r"\.legend \.zero\{opacity", pages["single"])


# --------------------------------------------------------------- contrast --

def _tokens(block: str) -> dict:
    return dict(re.findall(r"--([\w-]+):([^;]+);", block))


def _rgb(value: str, under=(255, 255, 255)) -> tuple:
    value = value.strip()
    if value.startswith("#"):
        h = value[1:]
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    r, g, b, a = (float(x) for x in re.match(r"rgba\(([^)]+)\)", value).group(1).split(","))
    return tuple(round(c * a + u * (1 - a)) for c, u in zip((r, g, b), under, strict=True))


def _luminance(rgb) -> float:
    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(fg, bg) -> float:
    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# Every text colour the report puts on a surface, by token.
TEXT_PAIRS = [
    ("ink", "paper"), ("ink-2", "paper"), ("ink-3", "paper"), ("ink-2", "ground"), ("ink-3", "ground"),
    ("ink-3", "ground-2"), ("ink-2", "ground-2"), ("brand-ink", "paper"), ("brand-ink-2", "brand-wash"),
    ("brand-ink-2", "brand-wash-2"), ("amber-ink", "amber-wash"), ("amber-ink", "paper"), ("cyan-ink", "paper"),
    ("sev-ok", "paper"), ("sev-critical", "paper"), ("pill-high", "pill-high-bg"),
    ("pill-medium", "pill-medium-bg"),
    ("pill-low", "pill-low-bg"), ("pill-critical", "pill-critical-bg"), ("on-high", "fill-high"),
    ("on-medium", "fill-medium"), ("on-low", "fill-low"), ("sev-ok", "sev-ok-bg"),
]


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_text_colours_clear_wcag_aa_in_both_themes(theme):
    tokens = _tokens(html.LIGHT)
    if theme == "dark":
        tokens.update(_tokens(html.DARK))
    paper = _rgb(tokens["paper"])
    failures = []
    for fg, bg in TEXT_PAIRS:
        background = _rgb(tokens[bg], under=paper)
        ratio = _contrast(_rgb(tokens[fg], under=background), background)
        if ratio < 4.5:
            failures.append("%s on %s: %.2f" % (fg, bg, ratio))
    assert not failures, failures
