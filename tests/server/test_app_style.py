"""The web app's colours clear WCAG AA (4.5:1) for every text colour on every
surface it is used on, in the light and the dark scheme."""

import re
from importlib.resources import files

import pytest

from conftest import contrast, css_rgb, css_tokens

CSS = (files("phishhawk.server") / "static" / "app.css").read_text(encoding="utf-8")

# Every text colour the app puts on a surface, by token.
TEXT_PAIRS = [
    ("ink", "bg"), ("ink", "paper"), ("ink-2", "bg"), ("ink-2", "paper"), ("ink-3", "bg"), ("ink-3", "paper"),
    ("link", "paper"), ("link", "bg"), ("bad", "paper"), ("ok", "paper"), ("on-brand", "brand"),
    ("top-ink", "top"), ("top-brand", "top"), ("top-muted", "top"),
]


def _scheme(dark):
    light = re.search(r":root\{([^}]*)\}", CSS).group(1)
    tokens = css_tokens(light + ";")
    if dark:
        tokens.update(css_tokens(re.search(r"prefers-color-scheme:dark\)\{:root\{([^}]*)\}", CSS).group(1) + ";"))
    return tokens


@pytest.mark.parametrize("dark", [False, True], ids=["light", "dark"])
def test_text_colours_clear_wcag_aa(dark):
    tokens = _scheme(dark)
    failures = ["%s on %s: %.2f" % (fg, bg, ratio) for fg, bg in TEXT_PAIRS
                if (ratio := contrast(css_rgb(tokens[fg]), css_rgb(tokens[bg]))) < 4.5]
    assert not failures, failures


def test_no_colour_is_written_outside_the_tokens():
    rules = re.sub(r":root\{[^}]*\}", "", CSS)
    assert not re.findall(r"#[0-9a-fA-F]{3,6}\b", rules)
