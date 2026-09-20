#!/usr/bin/env python3
"""Render a real run of the extractor into docs/demo.svg.

Runs the CLI under a pseudo-terminal so the colours are genuine, parses the
ANSI escapes and writes a self-contained terminal-styled SVG. No screenshot
tool, no recording software, and the image regenerates in one command:

    python docs/make_demo.py                       # offline run (default)
    VT_API_KEY=... python docs/make_demo.py --live  # keyed run, VT lines included

Nothing is faked: whatever the tool prints is what lands in the SVG.
"""

from __future__ import annotations

import argparse
import os
import pty
import re
import select
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Terminal theme (kept close to the portfolio's dark palette).
BG = "#0f1319"
CHROME = "#171c25"
FG = "#d5dbe5"
COLOURS = {
    "31": "#ff6b6b",  # red    - malicious / high severity
    "32": "#3ddc97",  # green  - clean / pass
    "33": "#ffc24b",  # yellow - suspicious / medium
    "36": "#5aa9ff",  # cyan   - report chrome
}
DIM = "#7b8798"
FONT = "ui-monospace,SFMono-Regular,Menlo,Consolas,'DejaVu Sans Mono',monospace"
FONT_SIZE = 13.0
CHAR_W = FONT_SIZE * 0.601
LINE_H = FONT_SIZE * 1.42
PAD_X, PAD_TOP, PAD_BOTTOM, CHROME_H = 18.0, 14.0, 16.0, 32.0

SGR_RE = re.compile(r"\033\[([0-9;]*)m")


def run_under_pty(argv: list[str]) -> str:
    """Run a command with a real tty on stdout so ANSI colours are emitted."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(argv, stdout=slave, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, cwd=ROOT,
                            env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "120"})
    os.close(slave)
    chunks: list[bytes] = []
    while True:
        try:
            ready, _, _ = select.select([master], [], [], 120)
        except OSError:
            break
        if not ready:
            break
        try:
            data = os.read(master, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.close(master)
    proc.wait(timeout=30)
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_ansi(text: str) -> list[list[tuple[str, str, bool, bool]]]:
    """-> lines of (text, colour, bold, dim) spans."""
    lines: list[list[tuple[str, str, bool, bool]]] = []
    colour, bold, dim = FG, False, False
    for raw_line in text.replace("\r\n", "\n").replace("\r", "").split("\n"):
        spans: list[tuple[str, str, bool, bool]] = []
        position = 0
        for match in SGR_RE.finditer(raw_line):
            if match.start() > position:
                spans.append((raw_line[position:match.start()], colour, bold, dim))
            for code in (match.group(1) or "0").split(";"):
                if code in ("", "0"):
                    colour, bold, dim = FG, False, False
                elif code == "1":
                    bold = True
                elif code == "2":
                    dim = True
                elif code in COLOURS:
                    colour = COLOURS[code]
            position = match.end()
        if position < len(raw_line):
            spans.append((raw_line[position:], colour, bold, dim))
        lines.append(spans)
    while lines and not any(t.strip() for t, *_ in lines[-1]):
        lines.pop()
    return lines


def escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def to_svg(lines, title: str) -> str:
    width_chars = max((sum(len(t) for t, *_ in line) for line in lines), default=80)
    width = PAD_X * 2 + width_chars * CHAR_W
    height = CHROME_H + PAD_TOP + len(lines) * LINE_H + PAD_BOTTOM

    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" '
        'viewBox="0 0 %.0f %.0f" font-family="%s" font-size="%.1f">'
        % (width, height, width, height, FONT, FONT_SIZE),
        '<rect width="100%%" height="100%%" rx="9" fill="%s"/>' % BG,
        '<path d="M0 9a9 9 0 0 1 9-9h%.0f a9 9 0 0 1 9 9v%.0fH0z" fill="%s"/>'
        % (width - 18, CHROME_H - 9, CHROME),
    ]
    for index, dot in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append('<circle cx="%.0f" cy="%.0f" r="5.5" fill="%s"/>'
                   % (20 + index * 19, CHROME_H / 2, dot))
    out.append('<text x="%.0f" y="%.1f" fill="%s" font-size="11" '
               'text-anchor="middle">%s</text>'
               % (width / 2, CHROME_H / 2 + 4, DIM, escape(title)))

    y = CHROME_H + PAD_TOP + FONT_SIZE
    for line in lines:
        if any(t.strip() for t, *_ in line):
            # Only one span on the line means nothing sits next to it, so a bold
            # face cannot push a neighbour out of its column.
            allow_bold = len([1 for t, *_ in line if t.strip()]) == 1
            column = 0
            for text, colour, bold, dim in line:
                stripped = text.strip(" ")
                if stripped:
                    # Position the visible glyphs only: spaces are invisible, and
                    # letting the font lay them out is what drifts columns.
                    offset = column + (len(text) - len(text.lstrip(" ")))
                    out.append(
                        '<text xml:space="preserve" x="%.2f" y="%.2f" fill="%s"%s%s>%s</text>'
                        % (PAD_X + offset * CHAR_W, y, colour,
                           ' font-weight="600"' if (bold and allow_bold) else "",
                           ' opacity=".62"' if dim else "", escape(stripped))
                    )
                column += len(text)
        y += LINE_H
    out.append("</svg>")
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="allow network enrichment (needs $VT_API_KEY)")
    parser.add_argument("--eml", default="samples/sample_phish.eml")
    parser.add_argument("--out", default=os.path.join(HERE, "demo.svg"))
    args = parser.parse_args()

    argv = [sys.executable, "phishing_ioc_extractor.py", args.eml]
    if not args.live:
        argv.append("--offline")
    elif not os.environ.get("VT_API_KEY") and not os.environ.get("VIRUSTOTAL_API_KEY"):
        print("warning: --live without VT_API_KEY, VirusTotal lines will be empty",
              file=sys.stderr)

    title = "$ python phishing_ioc_extractor.py %s%s" % (
        args.eml, "" if args.live else " --offline")
    lines = parse_ansi(run_under_pty(argv))
    if not lines:
        print("error: no output captured", file=sys.stderr)
        return 1
    lines.insert(0, [(title, "#3ddc97", True, False)])
    lines.insert(1, [("", FG, False, False)])

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(to_svg(lines, os.path.basename(args.eml)))
    print("wrote %s (%d lines)" % (args.out, len(lines)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
