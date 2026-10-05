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

HELD_OUT_LEGIT = ("ham_holdout", "enron", "fixtures", "msg")  # every legitimate set never tuned on
BEFORE, BEFORE_NAME, AFTER_NAME = "2_0_0", "2.0", "2.1"  # the release compared against, and this one
REAL_SETS = ("pot_holdout", "pot_tune", "holdout", "tune", "nazario", "ham_holdout", "enron", "fixtures", "msg",
             "ham_tune", "cpython")


def kpis(data: dict, t: dict) -> str:
    sets, base = data["sets"], data["baseline"]
    holdout = sets["pot_holdout"]["result"]
    fp = sum(sets[k]["result"]["flagged"]["fp"] for k in HELD_OUT_LEGIT)
    legit = sum(sets[k]["result"]["emails"] for k in HELD_OUT_LEGIT)
    fp_before = sum(round(base["%s_false_positive_rate_%s" % (k, BEFORE)] * sets[k]["result"]["emails"])
                    for k in HELD_OUT_LEGIT)
    tiles = [
        ("Real phishing flagged", pct(exact(holdout["flagged"])),
         "of {:,} unseen emails".format(holdout["emails"]),
         "▲ from %s in %s" % (pct(round(100 * base["pot_holdout_flagged_recall_%s" % BEFORE], 1)), BEFORE_NAME)),
        ("Called likely phishing", pct(exact(holdout["strict"])),
         "of the same emails",
         "▲ from %s in %s" % (pct(round(100 * base["pot_holdout_strict_recall_%s" % BEFORE], 1)), BEFORE_NAME)),
        ("False positives", "%.1f%%" % (100 * fp / legit),
         "%d of %s legit emails" % (fp, "{:,}".format(legit)),
         "▼ from %.1f%% in %s" % (100 * fp_before / legit, BEFORE_NAME)),
        ("Automated tests", str(data["tests"]), "Python 3.10 to 3.13",
         "▲ from %d in %s" % (base["tests_%s" % BEFORE], BEFORE_NAME)),
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
    return frame(body, top + 116 + 28, t, "PhishHawk at a glance",
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
        if abs(ax - bx) < 44:  # dots almost touch: one label, "before → after", past both
            label = "%s → %s" % (fmt(before), fmt(after)) if fmt(before) != fmt(after) else "%s, both" % fmt(after)
            out.append(text(max(ax, bx) + 12, y + 4.5, label, t["ink"], 12.5, 600))
            y += 36
            continue
        # each value sits on the far side of its own dot, so close pairs never
        # collide; a value near zero goes inside instead of into the row labels
        after_right = after >= before
        for cx, value, ink, size, weight, right in ((bx, before, t["ink2"], 12, 400, not after_right),
                                                    (ax, after, t["ink"], 12.5, 600, after_right)):
            if not right and cx - 12 - 7 * len(fmt(value)) < x0 - 6:
                right = True
            out.append(text(cx + (12 if right else -12), y + 4.5, fmt(value), ink, size, weight,
                            anchor="start" if right else "end"))
        y += 36
    return out, bottom + 18


def exact(counts: dict, measure: str = "recall") -> float:
    """A rate from its counts, to one decimal: the stored rates are rounded twice."""
    if measure == "recall":
        return round(100 * counts["tp"] / (counts["tp"] + counts["fn"]), 1)
    return round(100 * counts["fp"] / (counts["fp"] + counts["tn"]), 1)


def pct(value: float) -> str:
    return "%.0f%%" % value if value == int(value) else "%.1f%%" % value


def evaluation(data: dict, t: dict) -> str:
    sets, base = data["sets"], data["baseline"]
    x0, x1 = 250, WIDTH - 70
    body = legend([(BEFORE_NAME, t["before"]), (AFTER_NAME, t["after"])], 28, 86, t)

    def row(label: str, key: str, measure: str, strict: bool = False) -> tuple[str, float, float]:
        counts = sets[key]["result"]["strict" if strict else "flagged"]
        name = ("strict_recall" if strict else "flagged_recall") if measure == "recall" else measure
        baseline = base["%s_%s_%s" % (key, name, BEFORE)]
        return "%s (%s)" % (label, "{:,}".format(sets[key]["result"]["emails"])), \
            round(100 * baseline, 1), exact(counts, measure)

    rows = [row("Unseen phishing, 2022-2026", "pot_holdout", "recall"),
            row("Earlier held-out sample", "holdout", "recall"),
            row("Phishing from 2005-2007", "nazario", "recall")]
    panel, y = dumbbell_panel(rows, 124, x0, x1, 100, [0, 25, 50, 75, 100], pct, t,
                              "Real phishing flagged · higher is better")
    body += panel
    rows = [row("Unseen phishing, 2022-2026", "pot_holdout", "recall", strict=True),
            row("Earlier held-out sample", "holdout", "recall", strict=True),
            row("Phishing from 2005-2007", "nazario", "recall", strict=True)]
    panel, y = dumbbell_panel(rows, y + 40, x0, x1, 100, [0, 25, 50, 75, 100], pct, t,
                              "Called likely phishing, not just suspicious · higher is better")
    body += panel
    rows = [row("Everyday mail", "ham_holdout_easy", "false_positive_rate"),
            row("Spam-like mail", "ham_holdout_hard", "false_positive_rate"),
            row("Enron business mail", "enron", "false_positive_rate"),
            row("Mail-library edge cases", "fixtures", "false_positive_rate")]
    panel, y = dumbbell_panel(rows, y + 40, x0, x1, 30, [0, 10, 20, 30], pct, t,
                              "Legitimate mail flagged by mistake · lower is better")
    body += panel
    return frame(body, y + 26, t, "PhishHawk %s against %s on real mail" % (AFTER_NAME, BEFORE_NAME),
                 "Held-out sets only, scored once after all tuning, both versions on the same messages")


# ----------------------------------------------------------- verdict bars --

def verdicts(data: dict, t: dict) -> str:
    sets = data["sets"]
    legit: dict[str, int] = {}
    for key in HELD_OUT_LEGIT:
        for verdict, n in sets[key]["result"]["verdicts"]["benign"].items():
            legit[verdict] = legit.get(verdict, 0) + n
    groups = [("Unseen phishing", sets["pot_holdout"]["result"]["verdicts"]["phish"]),
              ("Phishing 2005-07", sets["nazario"]["result"]["verdicts"]["phish"]),
              ("Legitimate mail", legit)]
    order = [("LIKELY PHISHING", "likely phishing", t["after"]), ("SUSPICIOUS", "suspicious", t["before"]),
             ("NO STRONG INDICATORS", "not flagged", t["missed"])]
    body = legend([(name.capitalize(), colour) for _, name, colour in order], 28, 86, t)
    x0, x1, y, height = 200, WIDTH - 28, 110, 24
    for label, counts in groups:
        total = sum(counts.values())
        body.append(text(28, y + 16.5, "%s (%s)" % (label, "{:,}".format(total)), t["ink2"], 13))
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
