#!/usr/bin/env python3
"""Draw the README charts from eval/results.json.

    python tools/make_charts.py

writes docs/images/chart-{kpis,evaluation,verdicts}-{light,dark}.svg. Plain SVG,
no plotting library: every number on a chart is read from the results file,
so the images cannot drift from the evaluation. Colours are the validated
ordinal blue ramp (two steps per mode) plus a neutral grey.
"""

from __future__ import annotations

import json
import os
from html import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "docs", "images")
FONT = "system-ui,-apple-system,'Segoe UI',Roboto,sans-serif"
WIDTH = 760

THEMES = {
    "light": {"surface": "#fcfcfb", "border": "rgba(11,11,11,0.10)", "ink": "#0b0b0b", "ink2": "#52514e",
              "muted": "#898781", "grid": "#e1e0d9", "axis": "#c3c2b7", "good": "#006300",
              "before": "#86b6ef", "after": "#1c5cab", "missed": "#898781"},
    "dark": {"surface": "#1a1a19", "border": "rgba(255,255,255,0.10)", "ink": "#ffffff", "ink2": "#c3c2b7",
             "muted": "#898781", "grid": "#2c2c2a", "axis": "#383835", "good": "#0ca30c",
             "before": "#256abf", "after": "#9ec5f4", "missed": "#898781"},
}


def luminance(hex_colour: str) -> float:
    rgb = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def text(x, y, content, fill, size=13, weight=400, anchor="start"):
    return ('<text x="%.1f" y="%.1f" fill="%s" font-size="%s" font-weight="%d" text-anchor="%s">%s</text>'
            % (x, y, fill, size, weight, anchor, escape(content)))


def frame(body: list[str], height: float, t: dict, title: str, subtitle: str) -> str:
    head = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
        'font-family="%s" role="img" aria-label="%s">' % (WIDTH, height, WIDTH, height, FONT, escape(title)),
        "<title>%s</title>" % escape(title),
        '<rect x="0.5" y="0.5" width="%d" height="%d" rx="12" fill="%s" stroke="%s"/>'
        % (WIDTH - 1, height - 1, t["surface"], t["border"]),
        text(28, 38, title, t["ink"], 16, 600),
        text(28, 60, subtitle, t["ink2"], 12.5),
    ]
    return "\n".join(head + body + ["</svg>"]) + "\n"


def legend(items, x, y, t):
    """Legend row under the subtitle: coloured dot + text in secondary ink."""
    out = []
    for label, colour in items:
        out.append('<circle cx="%.1f" cy="%.1f" r="5" fill="%s"/>' % (x + 5, y, colour))
        out.append(text(x + 16, y + 4, label, t["ink2"], 12))
        x += 16 + 6.9 * len(label) + 26
    return out


# ------------------------------------------------------------------ KPIs --

def kpis(data: dict, t: dict) -> str:
    sets, base = data["sets"], data["baseline"]
    holdout = sets["holdout"]["result"]
    fpr = sets["cpython"]["result"]["flagged"]["false_positive_rate"]
    worst = max(sets[k]["result"]["timing_ms"]["max"] for k in sets) / 1000
    emails = sum(sets[k]["result"]["emails"] for k in sets)
    tiles = [
        ("Real phishing flagged", "%.0f%%" % (100 * holdout["flagged"]["recall"]),
         "held-out, no API keys", "▲ from %.0f%%" % (100 * base["holdout_flagged_recall"])),
        ("False positives", "%.1f%%" % (100 * fpr), "on legitimate test mail",
         "▼ from %.1f%%" % (100 * base["cpython_false_positive_rate"])),
        ("Worst-case parse", "%.2f s" % worst, "slowest of %d messages" % emails,
         "▼ from %.0f s" % base["worst_case_parse_seconds"]),
        ("Automated tests", str(data["tests"]), "Python 3.10 to 3.13", "incl. evaluation gate"),
    ]
    body, gap, top = [], 12, 84
    tile_w = (WIDTH - 56 - gap * 3) / 4
    for i, (label, value, note, delta) in enumerate(tiles):
        x = 28 + i * (tile_w + gap)
        body.append('<rect x="%.1f" y="%d" width="%.1f" height="116" rx="10" fill="none" stroke="%s"/>'
                    % (x, top, tile_w, t["grid"]))
        body.append(text(x + 16, top + 26, label, t["ink2"], 12.5))
        body.append(text(x + 16, top + 62, value, t["ink"], 30, 600))
        body.append(text(x + 16, top + 84, note, t["muted"], 11.5))
        colour = t["good"] if delta[0] in "▲▼" else t["muted"]
        body.append(text(x + 16, top + 103, delta, colour, 11.5, 600 if delta[0] in "▲▼" else 400))
    return frame(body, top + 116 + 28, t, "PhishHawk 1.1.0 at a glance",
                 "Offline evaluation: parser and heuristics only, no reputation lookups")


# ------------------------------------------------------------- dumbbells --

def dumbbell_panel(rows, y0, x0, x1, maximum, ticks, fmt, t, heading):
    out = [text(28, y0, heading, t["ink"], 13, 600)]
    y = y0 + 34
    scale = lambda v: x0 + (x1 - x0) * v / maximum  # noqa: E731
    top = y - 16
    bottom = y + 36 * (len(rows) - 1) + 16
    for tick in ticks:
        tx = scale(tick)
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>'
                   % (tx, top, tx, bottom, t["axis"] if tick == 0 else t["grid"]))
        out.append(text(tx, bottom + 18, fmt(tick), t["muted"], 11.5, anchor="middle"))
    for label, before, after in rows:
        out.append(text(28, y + 4.5, label, t["ink2"], 13))
        bx, ax = scale(before), scale(after)
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="2" '
                   'stroke-linecap="round"/>' % (bx, y, ax, y, t["before"]))
        for cx, colour in ((bx, t["before"]), (ax, t["after"])):
            out.append('<circle cx="%.1f" cy="%.1f" r="6" fill="%s" stroke="%s" stroke-width="2"/>'
                       % (cx, y, colour, t["surface"]))
        # each value sits on the far side of its own dot, so close pairs never collide
        after_right = after >= before
        out.append(text(bx + (-12 if after_right else 12), y + 4.5, fmt(before), t["ink2"], 12,
                        anchor="end" if after_right else "start"))
        out.append(text(ax + (12 if after_right else -12), y + 4.5, fmt(after), t["ink"], 12.5, 600,
                        anchor="start" if after_right else "end"))
        y += 36
    return out, bottom + 18


def evaluation(data: dict, t: dict) -> str:
    sets, base = data["sets"], data["baseline"]
    x0, x1 = 250, WIDTH - 70
    pct = lambda v: "%.0f%%" % v if v == int(v) else "%.1f%%" % v  # noqa: E731
    body = legend([("Before real-mail testing", t["before"]), ("PhishHawk 1.1.0", t["after"])], 28, 86, t)
    rows = [("Held-out sample (200)", 100 * base["holdout_flagged_recall"],
             100 * sets["holdout"]["result"]["flagged"]["recall"]),
            ("Tuning sample (200)", 100 * base["tune_flagged_recall"],
             100 * sets["tune"]["result"]["flagged"]["recall"])]
    panel, y = dumbbell_panel(rows, 124, x0, x1, 100, [0, 25, 50, 75, 100], pct, t,
                              "Real phishing flagged · higher is better")
    body += panel
    rows = [("CPython test mail (48)", 100 * base["cpython_false_positive_rate"],
             100 * sets["cpython"]["result"]["flagged"]["false_positive_rate"])]
    panel, y = dumbbell_panel(rows, y + 40, x0, x1, 15, [0, 5, 10, 15], pct, t,
                              "Legitimate mail flagged by mistake · lower is better")
    body += panel
    return frame(body, y + 26, t, "Testing against real mail changed the numbers",
                 "Same messages scored before and after; each panel has its own scale")


# ----------------------------------------------------------- verdict bars --

def verdicts(data: dict, t: dict) -> str:
    sets = data["sets"]
    groups = [("Held-out phishing", sets["holdout"]["result"]["verdicts"]["phish"]),
              ("Tuning phishing", sets["tune"]["result"]["verdicts"]["phish"]),
              ("Legitimate mail", sets["cpython"]["result"]["verdicts"]["benign"])]
    order = [("LIKELY PHISHING", "likely phishing", t["after"]), ("SUSPICIOUS", "suspicious", t["before"]),
             ("NO STRONG INDICATORS", "not flagged", t["missed"])]
    body = legend([(name.capitalize(), colour) for _, name, colour in order], 28, 86, t)
    x0, x1, y, height = 200, WIDTH - 28, 110, 24
    for label, counts in groups:
        total = sum(counts.values())
        body.append(text(28, y + 16.5, "%s (%d)" % (label, total), t["ink2"], 13))
        x = x0
        segments = [(counts.get(key, 0), name, colour) for key, name, colour in order if counts.get(key, 0)]
        for index, (count, name, colour) in enumerate(segments):
            width = (x1 - x0) * count / total - (2 if index < len(segments) - 1 else 0)
            last = index == len(segments) - 1
            radius = 4 if last else 0
            path = ("M%.1f %.1f h%.1f a%d %d 0 0 1 %d %d v%.1f a%d %d 0 0 1 -%d %d h-%.1f z"
                    % (x, y, width - radius, radius, radius, radius, radius, height - 2 * radius,
                       radius, radius, radius, radius, width - radius)) if last else \
                "M%.1f %.1f h%.1f v%d h-%.1f z" % (x, y, width, height, width)
            body.append('<path d="%s" fill="%s"/>' % (path, colour))
            ink = "#ffffff" if luminance(colour) < 0.3 else "#0b0b0b"
            for caption in ("%d %s" % (count, name), str(count)):
                if width > 7.1 * len(caption) + 20:  # only inside when it fits with padding
                    body.append(text(x + 10, y + 16.5, caption, ink, 12, 600))
                    break
            x += width + 2
        y += height + 22
    return frame(body, y + 6, t, "Where every message landed",
                 "Verdicts from offline scans; 'not flagged' is the right answer only for legitimate mail")


def main() -> None:
    with open(os.path.join(ROOT, "eval", "results.json"), encoding="utf-8") as handle:
        data = json.load(handle)
    os.makedirs(IMAGES, exist_ok=True)
    for name, draw in (("kpis", kpis), ("evaluation", evaluation), ("verdicts", verdicts)):
        for mode, theme in THEMES.items():
            path = os.path.join(IMAGES, "chart-%s-%s.svg" % (name, mode))
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(draw(data, theme))
            print("wrote", os.path.relpath(path, ROOT))


if __name__ == "__main__":
    main()
