"""Start-up banner: the ASCII-art hawk beside figlet lettering.

Printed to stderr, so it never lands in piped or redirected output. It
shrinks to fit the terminal: side by side from 80 columns, lettering only
from 42, and a single line below that.
"""

from __future__ import annotations

import shutil

from . import __version__
from ._logo_art import EMBLEM, EMBLEM_COLOURS, HAWK, PHISH

TAGLINE = "sharp-eyed phishing triage for the SOC"
GAP = 3


def _paint(text: str, code: str, enabled: bool) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if enabled and text else text


def _emblem_rows(colour: bool) -> tuple[list[str], int]:
    rows = [(line, tones) for line, tones in zip(EMBLEM, EMBLEM_COLOURS, strict=True)]
    while rows and not rows[0][0].strip():
        rows.pop(0)
    while rows and not rows[-1][0].strip():
        rows.pop()
    width = max(len(line.rstrip()) for line, _ in rows)
    painted = []
    for line, tones in rows:
        visible = line[:width].rstrip()
        padding = " " * (width - len(visible))
        if not colour:
            painted.append(visible + padding)
            continue
        out, current = [], None
        for char, tone in zip(visible, tones, strict=False):
            want = tone if char != " " else None
            if want != current:
                out.append("\033[0m" if want is None else "\033[38;5;%dm" % want)
                current = want
            out.append(char)
        if current is not None:
            out.append("\033[0m")
        painted.append("".join(out) + padding)
    return painted, width


def _lettering(colour: bool) -> list[str]:
    lines = [_paint(line, "1;38;5;255", colour) for line in PHISH]
    lines.append("")
    lines += [_paint(line, "1;38;5;208", colour) for line in HAWK]
    lines.append("")
    lines.append(_paint(TAGLINE, "38;5;250", colour))
    lines.append(_paint("v%s  ·  MIT  ·  phishhawk -h for help" % __version__, "2", colour))
    return lines


def render(colour: bool = True, width: int | None = None) -> str:
    width = width or shutil.get_terminal_size((80, 24)).columns
    text_width = max(len(line) for line in PHISH + HAWK)
    art, art_width = _emblem_rows(colour)
    letters = _lettering(colour)

    if width >= art_width + GAP + text_width:
        height = max(len(art), len(letters))
        top = (height - len(letters)) // 2
        letters = [""] * top + letters + [""] * (height - top - len(letters))
        art = art + [" " * art_width] * (height - len(art))
        return "\n".join((a + " " * GAP + t).rstrip() for a, t in zip(art, letters, strict=True)) + "\n"
    if width >= text_width + 1:
        return "\n".join(letters) + "\n"
    return _paint("PhishHawk", "1;38;5;208", colour) + " v%s - %s\n" % (__version__, TAGLINE)
