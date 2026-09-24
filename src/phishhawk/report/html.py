"""Self-contained HTML report, in the IntelPulse console's design language.

Everything in a phishing email is attacker-controlled, so every value is
escaped, nothing is fetched (the two fonts travel inside the file as data:
URIs, the logo and icons are inline SVG), and a Content-Security-Policy
forbids scripts and network access outright: even an escaping bug could not
turn the report into an XSS. Malicious URLs are shown defanged and never made
clickable; the only links go to VirusTotal and MITRE ATT&CK.

Layout follows IntelPulse: paper cards on a cool ground, one flame accent,
Outfit for the interface and JetBrains Mono only for machine data. Severity
is never carried by colour alone: every badge has a glyph and a word. The page
prints to A4 with the summary on the first page and the evidence after it.
"""

from __future__ import annotations

from base64 import b64encode
from functools import lru_cache
from html import escape
from importlib.resources import files as package_files

from .. import __version__
from ..extract import defang_host, defang_url
from ..models import Analysis, FileIoc
from .common import (
    children_of,
    human_size,
    recommendations,
    sorted_signals,
    summary_sentences,
    technique_rows,
    top_level_files,
    urlscan_text,
    utc_now,
    vt_text,
)

# Badge levels, as in the IntelPulse console: critical in ink, high in flame,
# medium neutral, low azure, plus informational and ok.
VERDICT_LEVEL = {"MALICIOUS": "critical", "LIKELY PHISHING": "high", "SUSPICIOUS": "medium",
                 "NO STRONG INDICATORS": "ok"}
TONE_LEVEL = {"red": "high", "amber": "medium", "green": "ok", "dim": "info"}

# One glyph per level, drawn in an 8x8 box so it looks the same on every system.
GLYPHS = {
    "critical": '<path d="M4 .6 7.6 7.4H.4z"/>',
    "high": '<path d="M4 .3 7.7 4 4 7.7.3 4z"/>',
    "medium": '<rect x="1" y="1" width="6" height="6" rx=".8"/>',
    "low": '<circle cx="4" cy="4" r="3.2"/>',
    "info": '<rect x=".5" y="3" width="7" height="2" rx="1"/>',
    "ok": '<path d="M1 4.2 3.1 6.3 7 1.9" fill="none" stroke="currentColor" stroke-width="1.6" '
          'stroke-linecap="round" stroke-linejoin="round"/>',
}

ICONS = {
    "url": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/>'
           '<path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    "file": '<path d="M20 11.5 12.4 19a5 5 0 0 1-7.1-7.1l7.8-7.7a3.3 3.3 0 0 1 4.7 4.7L10 16.7'
            'a1.7 1.7 0 0 1-2.4-2.4l7-7"/>',
    "signal": '<path d="M12 4 2.5 20h19z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
    "attack": '<rect x="4" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="4" width="6.5" height="6.5" '
              'rx="1.5"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="13.5" '
              'width="6.5" height="6.5" rx="1.5"/>',
}

LOGO = """<svg class="logo" viewBox="0 0 200 200" aria-hidden="true" focusable="false">
<defs><linearGradient id="ph-head" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fbbf24"/>
<stop offset="1" stop-color="#ea580c"/></linearGradient><linearGradient id="ph-beak" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#f1f5f9"/><stop offset="1" stop-color="#94a3b8"/></linearGradient></defs>
<rect width="200" height="200" rx="40" fill="#0b1220"/>
<path fill="url(#ph-head)" d="M46 184C42 160 42 140 46 124L26 128 44 112C44 106 45 100 47 95L24 96 50 84
C62 62 92 46 124 46 146 46 162 56 172 70 180 80 186 92 186 104 186 110 184 116 180 120 179 113 176 109 171 107.5
165 107 159 108 154 110 147 122 139 133 135 147 131 159 131 172 133 184Z"/>
<path fill="url(#ph-beak)" d="M160 60C170 66 179 76 183 88 186 96 187 104 185 111 184 115 182 118 180 120
179 113 176 109 171 107.5 165 107 159 108 155 109 159 94 160 76 160 60Z"/>
<path fill="#0b1220" d="M180 120C180 114 178 110 174 108L179 107C182 110 182 116 180 120Z"/>
<path fill="none" stroke="#0b1220" stroke-width="4" stroke-linecap="round" d="M160 65C160 80 159 95 155 109"/>
<path fill="#0b1220" d="M106 64 164 66 154 74 112 72Z"/>
<circle cx="137" cy="84" r="10.5" fill="#0b1220"/><circle cx="137" cy="84" r="6.2" fill="#22d3ee"/>
</svg>"""

FONT_FILES = (("Outfit", "Outfit-Variable-latin.woff2"),
              ("JetBrains Mono", "JetBrainsMono-Variable-latin.woff2"))

CSS = """
/* Tokens: IntelPulse's validated light palette. --ink-3 is darkened from the
   console's #7b8490 so 10.5px labels clear 4.5:1 on paper and on the ground. */
:root{
  --ground:#f6f7f9;--ground-2:#eef0f4;--paper:#fff;--line:#e8ebf0;--line-2:#d9dee6;
  --ink:#1c1c1c;--ink-2:#4a4f57;--ink-3:#646c78;
  --flame:#fe5729;--flame-ink:#d93d15;--flame-ink-2:#b3300e;--flame-wash:#fff1ec;--on-flame:#fff;
  --azure:#4a9fdd;--azure-ink:#0b6ea8;--azure-wash:#eaf4fd;
  --sev-critical:#b3122f;--sev-high:#b3400a;--sev-medium:#7a6500;--sev-low:#0b6ea8;
  --sev-info:#566072;--sev-ok:#07704b;--sev-ok-bg:rgba(7,112,75,.10);
  --shade-sm:0 1px 2px rgba(20,28,43,.05);--shade:0 8px 24px -12px rgba(20,28,43,.18);
  --r-sm:10px;--r:16px;--r-lg:22px;--r-full:999px;
  --sans:"Outfit",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color-scheme:light dark;
}
@media screen and (prefers-color-scheme:dark){:root{
  --ground:#0d0f12;--ground-2:#1b1f26;--paper:#15181d;--line:#262b33;--line-2:#333a45;
  --ink:#f3f5f8;--ink-2:#b3bcc9;--ink-3:#8f99a8;
  --flame-ink:#ff6a3d;--flame-ink-2:#ff8f6b;--flame-wash:#2a150f;--on-flame:#14100e;
  --azure-ink:#7cc0f0;--azure-wash:#10202c;
  --sev-critical:#ff8095;--sev-high:#ff9e5e;--sev-medium:#e3ce63;--sev-low:#6fb0e3;
  --sev-info:#9aa6b8;--sev-ok:#5fe0a8;--sev-ok-bg:rgba(95,224,168,.14);
  --shade-sm:0 1px 2px rgba(0,0,0,.5);--shade:0 10px 26px -14px rgba(0,0,0,.8);
}}

*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--ground);color:var(--ink);font:400 14px/1.55 var(--sans);
  -webkit-font-smoothing:antialiased;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:1120px;margin:0 auto;padding:24px 20px 56px}
.mono,code,pre{font-family:var(--mono);font-size:12.5px}
.ioc{overflow-wrap:anywhere;word-break:break-word}
a{color:var(--azure-ink);text-decoration:underline;text-underline-offset:3px;
  text-decoration-color:color-mix(in srgb,currentColor 35%,transparent)}
a:hover{text-decoration-color:currentColor}
a:focus-visible{outline:2px solid var(--flame);outline-offset:2px;border-radius:4px}
.label{font-size:10.5px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-3)}
.muted{color:var(--ink-3)}
.sub{color:var(--ink-3);font-size:12px;margin-top:2px}

/* top bar */
.topbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:650;letter-spacing:-.03em}
.logo{width:34px;height:34px;display:block;border-radius:10px}
.pill{display:inline-flex;align-items:center;gap:8px;white-space:nowrap;padding:5px 12px;
  border-radius:var(--r-full);background:var(--paper);border:1px solid var(--line);box-shadow:var(--shade-sm);
  font-size:12px;color:var(--ink-2)}
.pill .mono{font-size:11.5px;color:var(--ink)}
.version{font:600 11px var(--sans);letter-spacing:.02em;padding:3px 9px;border-radius:var(--r-full);
  background:var(--ground-2);color:var(--ink-2);border:1px solid var(--line-2)}
.topbar .pill{margin-left:auto}

/* cards */
.card{background:var(--paper);border:1px solid var(--line);border-radius:var(--r-lg);box-shadow:var(--shade-sm)}
.stack{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
section.msg{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
section.msg+section.msg{margin-top:48px}

/* verdict hero */
.hero{position:relative;overflow:hidden;padding:22px 24px 20px;display:grid;
  grid-template-columns:minmax(0,1fr) auto;gap:24px;align-items:start}
.hero-score{min-width:150px;padding-left:24px;border-left:1px solid var(--line);text-align:right}
.hero-score .score{margin-top:6px;font-size:52px;font-weight:600;letter-spacing:-.05em;line-height:1;
  color:var(--tone)}
.hero::before{content:"";position:absolute;inset:0 auto 0 0;width:5px;background:var(--tone)}
.lvl-critical{--tone:var(--sev-critical)}.lvl-high{--tone:var(--flame-ink)}
.lvl-medium{--tone:var(--sev-medium)}.lvl-ok{--tone:var(--sev-ok)}
.verdict{display:flex;align-items:center;gap:10px;margin:4px 0 2px;color:var(--tone);
  font-size:30px;font-weight:650;letter-spacing:-.035em;line-height:1.1}
.verdict svg{width:18px;height:18px;flex:0 0 18px;fill:currentColor}
h1{font-size:20px;font-weight:600;letter-spacing:-.025em;line-height:1.3;margin:14px 0 12px;overflow-wrap:anywhere}
.meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 18px;margin:0;font-size:13px}
.meta dt{color:var(--ink-3)}
.meta dd{margin:0;min-width:0;overflow-wrap:anywhere;color:var(--ink-2)}

/* KPI row */
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.kpi{padding:14px;display:grid;gap:12px;align-content:start}
.kpi-top{display:flex;align-items:center;gap:9px;min-width:0}
.kpi-ic{width:30px;height:30px;flex:0 0 30px;border-radius:var(--r-sm);display:grid;place-items:center;
  background:var(--ground-2);color:var(--ink-2)}
.kpi-ic svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;
  stroke-linejoin:round}
.kpi-top b{font-size:12.5px;font-weight:500;color:var(--ink-2);line-height:1.25}
.kpi .val{font-size:32px;font-weight:600;letter-spacing:-.04em;line-height:1}

/* panels */
.grid-2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
.panel{padding:16px 18px;min-width:0}
.panel-head{display:flex;align-items:center;gap:10px;margin-bottom:12px}
h2{font-size:14.5px;font-weight:600;letter-spacing:-.01em;margin:0}
.count{font:600 11px var(--sans);padding:2px 8px;border-radius:var(--r-full);background:var(--ground-2);
  color:var(--ink-2)}
.kv{display:grid;margin:0}
.kv>div{display:grid;grid-template-columns:118px minmax(0,1fr);gap:12px;padding:8px 0;
  border-top:1px solid var(--line);align-items:baseline;font-size:13px}
.kv>div:first-child{border-top:0;padding-top:0}
.kv dt{color:var(--ink-3);font-size:12px}
.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}
.kv .mono{font-size:12px}
.badges{display:flex;flex-wrap:wrap;gap:5px}
.summary{margin:0 0 12px;color:var(--ink-2);font-size:13px;line-height:1.6}
.steps{list-style:none;margin:0;padding:0;display:grid;gap:10px;counter-reset:step}
.steps li{display:grid;grid-template-columns:24px minmax(0,1fr);gap:10px;align-items:start;font-size:13.5px;
  counter-increment:step}
.steps li::before{content:counter(step);width:24px;height:24px;border-radius:var(--r-full);display:grid;
  place-items:center;font:600 11.5px var(--sans);background:var(--flame-wash);color:var(--flame-ink-2);
  margin-top:-1px}

/* badges: the console's severity pills, plus the glyph */
.badge{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;flex:0 0 auto;
  font:600 11px var(--sans);letter-spacing:.02em;text-transform:uppercase;
  padding:3px 10px 3px 9px;border-radius:var(--r-full);border:1px solid transparent}
.badge svg{width:8px;height:8px;fill:currentColor}
.b-critical{background:var(--ink);color:var(--paper)}
.b-high{background:var(--flame-wash);color:var(--flame-ink-2);
  border-color:color-mix(in srgb,var(--flame) 22%,transparent)}
.b-medium{background:var(--ground-2);color:var(--ink-2);border-color:var(--line)}
.b-low{background:var(--azure-wash);color:var(--azure-ink)}
.b-info{background:var(--ground-2);color:var(--ink-3);border-color:var(--line)}
.b-ok{background:var(--sev-ok-bg);color:var(--sev-ok)}
.t-critical{color:var(--sev-critical)}.t-high{color:var(--sev-high)}.t-medium{color:var(--sev-medium)}
.t-low{color:var(--sev-low)}.t-ok{color:var(--sev-ok)}.t-info{color:var(--ink-3)}
.chip{display:inline-block;font:500 11.5px var(--mono);padding:2px 8px;margin:0 4px 4px 0;
  border-radius:var(--r-full);
  background:var(--azure-wash);border:1px solid color-mix(in srgb,var(--azure) 30%,transparent);
  color:var(--azure-ink);text-decoration:none;white-space:nowrap}
.chip:hover{border-color:var(--azure-ink)}
.tag{display:inline-block;font:600 10.5px var(--sans);letter-spacing:.04em;text-transform:uppercase;
  padding:2px 8px;border-radius:var(--r-full);background:var(--ground-2);color:var(--ink-2);
  border:1px solid var(--line);white-space:nowrap}
.tag.own{background:var(--flame-wash);color:var(--flame-ink-2);border-color:transparent}

/* severity bar: one row, segments sized by count, each labelled */
.sevbar{display:flex;gap:4px;margin:0 0 14px}
.sevbar span{display:grid;place-items:center;min-width:max-content;height:34px;padding-inline:12px;
  border-radius:var(--r-sm);font-size:12px;font-weight:600;white-space:nowrap}
.sevbar .s-high{background:var(--flame-ink);color:var(--on-flame)}
.sevbar .s-medium{background:var(--ground-2);color:var(--ink-2)}
.sevbar .s-low{background:var(--azure-wash);color:var(--azure-ink)}

/* tables */
.table-wrap{min-width:0}
.tbl{width:100%;table-layout:fixed;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:8px 10px;font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;
  color:var(--ink-3);font-weight:600;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.tbl td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl .mono{font-size:12px}
.idx{display:inline-grid;place-items:center;min-width:22px;height:22px;padding:0 5px;border-radius:7px;
  background:var(--ground-2);font:600 11px var(--mono);color:var(--ink-2)}
.notes{list-style:none;margin:6px 0 0;padding:0;display:grid;gap:2px}
.notes li{position:relative;padding-left:14px;font-size:12px;color:var(--sev-high)}
.notes li::before{content:"!";position:absolute;left:2px;top:0;font:700 12px var(--mono)}
.child td:first-child{padding-left:30px}
.child .arrow{color:var(--ink-3);margin-right:4px}
.hash{font-size:11.5px;word-break:break-all}
.flagged td:first-child{box-shadow:inset 3px 0 0 var(--flame)}
pre.iocs{margin:0;padding:14px 16px;background:var(--ground);border:1px solid var(--line);
  border-radius:var(--r-sm);font:12px/1.65 var(--mono);color:var(--ink-2);white-space:pre-wrap;
  overflow-wrap:anywhere}

footer{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;justify-content:space-between;margin-top:28px;
  padding-top:16px;border-top:1px solid var(--line-2);font-size:12px;color:var(--ink-3)}
footer b{color:var(--ink-2);font-weight:600}

@media (max-width:760px){
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  .grid-2{grid-template-columns:minmax(0,1fr)}
  .topbar .pill{margin-left:0}
  .verdict{font-size:25px}
}
@media (max-width:560px){
  .wrap{padding:16px 12px 40px}
  .kpi .val{font-size:26px}
  .hero{padding:18px 18px 16px 20px;grid-template-columns:minmax(0,1fr);gap:14px}
  .hero-score{padding:12px 0 0;border-left:0;border-top:1px solid var(--line);text-align:left;
    display:flex;align-items:baseline;justify-content:space-between}
  .hero-score .score{font-size:40px;margin:0}
  .meta{grid-template-columns:minmax(0,1fr);gap:0}
  .meta dt{margin-top:6px}
  .kv>div{grid-template-columns:minmax(0,1fr);gap:2px}
  .sevbar{flex-direction:column}
  .sevbar span{justify-content:start}
  /* The table stops being a table: each row becomes a block with its labels. */
  .tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:auto}
  .tbl colgroup,.tbl thead{display:none}
  .tbl tr{border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;margin-bottom:8px}
  .tbl td{border:0;padding:4px 0;display:grid;grid-template-columns:7.5em minmax(0,1fr);gap:10px;
    align-items:baseline}
  .tbl td::before{content:attr(data-label);font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;
    color:var(--ink-3);font-weight:600}
  .tbl td.lead{display:block;padding-bottom:6px}
  .tbl td.lead::before{content:none}
  .child td:first-child{padding-left:0}
  .flagged td:first-child{box-shadow:none}
  .flagged{border-left:3px solid var(--flame)}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media (forced-colors:active){
  .badge,.sevbar span,.chip,.tag,.idx{border:1px solid CanvasText}
  .hero::before{background:CanvasText}
}

/* Print: A4, paper white, the summary on page one and the evidence after it. */
@page{size:A4;margin:14mm 12mm 16mm;
  @bottom-left{content:"PhishHawk triage report";font:9pt "Outfit",sans-serif;color:#646c78}
  @bottom-right{content:"Page " counter(page) " of " counter(pages);font:9pt "Outfit",sans-serif;color:#646c78}}
@media print{
  body{background:#fff;font-size:12px}
  .panel{padding:12px 14px}
  .panel-head{margin-bottom:8px}
  .tbl{font-size:11.5px}
  .tbl th{padding:6px 8px}
  .tbl td{padding:6px 8px}
  .tbl .mono,.hash{font-size:10.5px}
  .notes li{font-size:10.5px}
  .sevbar{margin-bottom:10px}
  .sevbar span{height:26px}
  .badge{padding:2px 8px 2px 7px;font-size:10px}
  .chip{font-size:10.5px;padding:1px 7px;margin-bottom:3px}
  pre.iocs{font-size:10.5px;padding:10px 12px}
  .wrap{max-width:none;padding:0}
  .card{box-shadow:none;border-color:#d9dee6}
  .pill{box-shadow:none}
  .kpis{grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  .grid-2{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}
  .hero{grid-template-columns:minmax(0,1fr) auto}
  .hero-score{padding:0 0 0 24px;border-top:0;border-left:1px solid var(--line);text-align:right;display:block}
  /* Chromium cannot fragment grid items across pages cleanly: a table split
     over a page break was drawn under the next card. Block flow fixes it. */
  main.stack,section.msg,.evidence{display:block}
  section.msg>*+*,.evidence>*+*{margin-top:12px}
  .card{-webkit-box-decoration-break:clone;box-decoration-break:clone}
  .evidence{break-before:page}
  section.msg+section.msg{margin-top:0;break-before:page}
  .batch+section.msg{break-before:page}
  .hero,.kpi,.grid-2>.card,.sevbar,.kv>div,.steps li,.tbl tr,pre.iocs{break-inside:avoid}
  .panel-head,h1,h2{break-after:avoid}
  .tbl thead{display:table-header-group}
  a{text-decoration:none;color:inherit}
  .chip{color:#0b6ea8}
  footer{break-inside:avoid}
}
"""


@lru_cache(maxsize=1)
def font_faces() -> str:
    """@font-face rules with the fonts inlined; empty if the files are missing."""
    faces = []
    folder = package_files(__package__).joinpath("fonts")
    for family, name in FONT_FILES:
        try:
            data = folder.joinpath(name).read_bytes()
        except OSError:
            continue  # the system font stack takes over
        faces.append('@font-face{font-family:"%s";font-style:normal;font-weight:100 900;font-display:swap;'
                     'src:url(data:font/woff2;base64,%s) format("woff2")}' % (family, b64encode(data).decode()))
    return "\n".join(faces)


def _svg(paths: str, cls: str = "", box: str = "0 0 8 8") -> str:
    klass = ' class="%s"' % cls if cls else ""
    return '<svg%s viewBox="%s" aria-hidden="true" focusable="false">%s</svg>' % (klass, box, paths)


def _link(url: str, text: str, cls: str = "") -> str:
    klass = ' class="%s"' % cls if cls else ""
    return '<a%s href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (klass, escape(url), escape(text))


def _badge(text: str, level: str) -> str:
    return '<span class="badge b-%s">%s%s</span>' % (level, _svg(GLYPHS[level]), escape(text))


def _tone_text(text: str, tone: str) -> str:
    return '<span class="t-%s">%s</span>' % (TONE_LEVEL.get(tone, "info"), escape(text)) if text else ""


def _notes(notes: list[str]) -> str:
    if not notes:
        return ""
    return '<ul class="notes">%s</ul>' % "".join("<li>%s</li>" % escape(n) for n in notes)


def _table(headers: list[str], widths: list[int], rows: list[tuple[str, list[str]]]) -> str:
    """rows: (row class, cells). The first cell leads the row when it collapses on a phone."""
    cols = "".join('<col style="width:%d%%">' % w for w in widths)
    head = "".join("<th scope=\"col\">%s</th>" % escape(h) for h in headers)
    body = []
    for cls, cells in rows:
        tds = []
        for i, cell in enumerate(cells):
            lead = ' class="lead"' if i == 0 else ""
            tds.append('<td%s data-label="%s"><div>%s</div></td>' % (lead, escape(headers[i]), cell))
        body.append("<tr%s>%s</tr>" % (' class="%s"' % cls if cls else "", "".join(tds)))
    return ('<div class="table-wrap"><table class="tbl"><colgroup>%s</colgroup><thead><tr>%s</tr></thead>'
            "<tbody>%s</tbody></table></div>" % (cols, head, "".join(body)))


def _panel(title: str, body: str, count: int | None = None, cls: str = "") -> str:
    badge = '<span class="count">%d</span>' % count if count is not None else ""
    return ('<section class="card panel %s"><header class="panel-head"><h2>%s</h2>%s</header>%s</section>'
            % (cls, title, badge, body))


def _vt_cell(report) -> str:
    if not report:
        return '<span class="t-info">not queried</span>'
    text, tone = vt_text(report)
    cell = _tone_text(text, tone)
    if report.get("link") and report.get("status") in ("ok", "not_found"):
        cell += '<div class="sub">%s</div>' % _link(report["link"], "open in VirusTotal")
    return cell


def _auth_badges(a: Analysis) -> str:
    if not a.auth:
        return '<span class="muted">no Authentication-Results header</span>'
    badges = []
    for mechanism, value in a.auth.items():
        level = "ok" if value == "pass" else ("high" if value in ("fail", "softfail") else "medium")
        badges.append(_badge("%s %s" % (mechanism, value), level))
    return '<div class="badges">%s</div>' % "".join(badges)


def _file_rows(a: Analysis, f: FileIoc, depth: int) -> list[tuple[str, list[str]]]:
    arrow = '<span class="arrow" aria-hidden="true">&#8627;</span>' if depth else ""
    mismatch = any(n.startswith("claims ") for n in f.notes)
    real = " &middot; really %s" % escape(f.true_type) if mismatch else ""
    cls = " ".join(c for c in ("child" if depth else "", "flagged" if f.flagged else "") if c)
    rows = [(cls, ['%s<span class="ioc">%s</span>%s' % (arrow, escape(f.filename), _notes(f.notes)),
                   '%s%s<div class="sub">%s</div>' % (escape(f.content_type), real, escape(human_size(f.size))),
                   '<span class="mono hash">%s</span>' % escape(f.sha256),
                   _vt_cell(f.vt)])]
    for child in children_of(a, f):
        rows += _file_rows(a, child, depth + 1)
    return rows


def _defanged_iocs(a: Analysis) -> str:
    lines = []
    for ioc in a.iocs():
        value = ioc["value"]
        if ioc["type"] == "url":
            value = defang_url(value)
        elif ioc["type"] != "sha256":
            value = defang_host(value)
        lines.append("%-7s %s" % (ioc["type"], value))
    return "\n".join(lines)


def _hero(a: Analysis, level: str) -> str:
    meta = [("From", "%s &lt;%s&gt;" % (escape(a.from_display), escape(defang_host(a.from_address)))),
            ("Date", escape(a.date or "")), ("To", escape(a.to or "")),
            ("Message-ID", '<span class="mono ioc">%s</span>' % escape(a.message_id or "")),
            ("File", '<span class="mono ioc">%s</span>' % escape(a.path))]
    return ('<div class="card hero lvl-%s"><div><div class="label">Verdict</div>'
            '<div class="verdict">%s<span>%s</span></div><h1>%s</h1><dl class="meta">%s</dl></div>'
            '<div class="hero-score"><div class="label">Risk score</div><div class="score">%d</div></div></div>'
            % (level, _svg(GLYPHS[level]), escape(a.verdict), escape(a.subject or "(no subject)"),
               "".join("<dt>%s</dt><dd>%s</dd>" % m for m in meta if m[1]), a.score))


def _kpis(a: Analysis, files: list[FileIoc]) -> str:
    tiles = [("url", "URLs", len(a.urls)), ("file", "Files", len(files)), ("signal", "Signals", len(a.signals)),
             ("attack", "ATT&CK techniques", len(a.techniques))]
    return '<div class="kpis">%s</div>' % "".join(
        '<div class="card kpi"><div class="kpi-top"><span class="kpi-ic">%s</span><b>%s</b></div>'
        '<div class="val">%d</div></div>' % (_svg(ICONS[icon], box="0 0 24 24"), escape(label), value)
        for icon, label, value in tiles)


def _sender(a: Analysis) -> str:
    rows = []
    for label, value in (("Reply-To", a.reply_to), ("Return-Path", a.return_path),
                         ("Originating IP", a.originating_ip)):
        if value:
            rows.append((label, '<span class="mono">%s</span>' % escape(defang_host(value))))
    rows.append(("Auth", _auth_badges(a)))
    if a.protected_domains:
        rows.append(("Protected", escape(", ".join(a.protected_domains))))
    if a.reported_by:
        rows.append(("Reported by", escape(a.reported_by.get("from", ""))))
    body = '<dl class="kv">%s</dl>' % "".join("<div><dt>%s</dt><dd>%s</dd></div>" % r for r in rows)
    return _panel("Sender &amp; authentication", body)


def _actions(a: Analysis) -> str:
    summary = " ".join(escape(s) for s in summary_sentences(a))
    steps = "".join("<li><span>%s</span></li>" % escape(x) for x in recommendations(a))
    return _panel("Recommended actions", '<p class="summary">%s</p><ol class="steps">%s</ol>' % (summary, steps))


def _severity_bar(a: Analysis) -> str:
    counts = [(level, sum(1 for s in a.signals if s.severity == level)) for level in ("high", "medium", "low")]
    segments = "".join('<span class="s-%s" style="flex-grow:%d">%d %s</span>' % (level, n, n, level.capitalize())
                       for level, n in counts if n)
    return '<div class="sevbar" role="img" aria-label="%s">%s</div>' % (
        escape(", ".join("%d %s" % (n, level) for level, n in counts if n)), segments)


def _evidence(a: Analysis, files: list[FileIoc]) -> list[str]:
    out = []
    if a.signals:
        rows = []
        for s in sorted_signals(a):
            techs = "".join(_link("https://attack.mitre.org/techniques/%s/" % t.replace(".", "/"), t, "chip")
                            for t in s.techniques)
            rows.append(("", [_badge(s.severity, {"high": "high", "medium": "medium"}.get(s.severity, "low")),
                              escape(s.label), techs or '<span class="muted">-</span>']))
        table = _table(["Severity", "Finding", "ATT&CK"], [13, 62, 25], rows)
        out.append(_panel("Signals", _severity_bar(a) + table, len(a.signals)))

    if a.lookalikes:
        rows = [("flagged", ['<span class="mono ioc t-high">%s</span>' % escape(defang_host(h.domain)),
                             '<span class="tag">%s</span>' % escape(h.method),
                             '<span class="mono ioc">%s</span>%s' % (
                                 escape(defang_host(h.target)),
                                 ' <span class="tag own">YOUR DOMAIN</span>' if h.target in a.protected_domains
                                 else ""),
                             escape(h.where)])
                for h in a.lookalikes]
        out.append(_panel("Lookalike domains", _table(["Domain", "Technique", "Imitates", "Seen as"],
                                                      [34, 16, 34, 16], rows), len(a.lookalikes)))

    if a.urls:
        rows = []
        for i, ioc in enumerate(a.urls, 1):
            scan_text, scan_tone = urlscan_text(ioc.urlscan)
            rows.append(("flagged" if ioc.flagged else "",
                         ['<span class="idx">%d</span>' % i,
                          '<span class="mono ioc">%s</span>%s' % (escape(ioc.defanged), _notes(ioc.notes)),
                          '<span class="sub">%s</span>' % escape(", ".join(ioc.sources)),
                          _vt_cell(ioc.vt),
                          _tone_text(scan_text, scan_tone) or '<span class="muted">-</span>']))
        out.append(_panel("URLs", _table(["#", "URL (defanged)", "Seen in", "VirusTotal", "urlscan.io"],
                                         [6, 46, 18, 15, 15], rows), len(a.urls)))

    if files:
        rows = []
        for f in top_level_files(a):
            if not f.inline:
                rows += _file_rows(a, f, 0)
        out.append(_panel("Attachments", _table(["File", "Type", "SHA256", "VirusTotal"], [30, 18, 34, 18], rows),
                          len(files)))

    if a.domain_intel or a.ip_intel:
        rows = []
        for domain, info in a.domain_intel.items():
            if info.get("status") == "ok":
                age = info["age_days"]
                tone = "red" if age < 30 else ("amber" if age < 90 else "green")
                detail = "registered %s (%s) &middot; %s" % (
                    escape(info["registered"]), _tone_text("%d days old" % age, tone),
                    escape(info.get("registrar") or "registrar unknown"))
            else:
                detail = _tone_text("RDAP: %s" % info.get("status"), "dim")
            rows.append(("", ['<span class="mono ioc">%s</span>' % escape(defang_host(domain)), "Domain age",
                              detail]))
        ip = a.ip_intel
        if ip:
            if ip.get("status") == "ok":
                tone = "red" if ip["score"] >= 75 else ("amber" if ip["score"] >= 25 else "green")
                detail = "%s &middot; %d reports &middot; %s %s" % (
                    _tone_text("confidence %d%%" % ip["score"], tone), ip.get("reports", 0),
                    escape(ip.get("country", "")), escape(ip.get("isp", "")))
            else:
                detail = _tone_text("AbuseIPDB: %s" % ip.get("status"), "dim")
            rows.append(("", ['<span class="mono ioc">%s</span>' % escape(defang_host(a.originating_ip)),
                              "IP reputation", detail]))
        out.append(_panel("Infrastructure", _table(["Indicator", "Check", "Result"], [34, 18, 48], rows)))

    rows = technique_rows(a)
    if rows:
        cells = [("", [_link(r["url"], r["id"], "chip"), escape(r["name"]),
                       '<span class="sub">%s</span>' % escape(
                           "; ".join(r["evidence"][:3]) + (" ..." if len(r["evidence"]) > 3 else ""))])
                 for r in rows]
        out.append(_panel("MITRE ATT&amp;CK", _table(["Technique", "Name", "Evidence"], [16, 30, 54], cells),
                          len(rows)))

    iocs = _defanged_iocs(a)
    if iocs:
        out.append(_panel("Indicators (defanged, copy-ready)", '<pre class="iocs">%s</pre>' % escape(iocs),
                          len(iocs.splitlines())))
    return out


def _section(a: Analysis, anchor: str) -> str:
    level = VERDICT_LEVEL.get(a.verdict, "ok")
    files = [f for f in a.attachments if not f.inline]
    out = ['<section class="msg" id="%s" aria-label="%s">' % (anchor, escape(a.subject or a.path)),
           _hero(a, level), _kpis(a, files),
           '<div class="grid-2">%s%s</div>' % (_sender(a), _actions(a))]
    evidence = _evidence(a, files)
    if evidence:
        out.append('<div class="evidence stack">%s</div>' % "".join(evidence))
    out.append("</section>")
    return "\n".join(out)


def _batch(analyses: list[Analysis]) -> str:
    rows = [("", ['<a href="#msg-%d">%s</a>' % (i, escape(a.subject or a.path)),
                  _badge(a.verdict, VERDICT_LEVEL.get(a.verdict, "ok")), '<span class="mono">%d</span>' % a.score])
            for i, a in enumerate(analyses, 1)]
    table = _table(["Subject", "Verdict", "Score"], [62, 28, 10], rows)
    return _panel("Batch (%d messages)" % len(analyses), table, cls="batch")


def render(analyses: list[Analysis]) -> str:
    title = "Phishing triage" if len(analyses) != 1 else "Phishing triage: %s" % analyses[0].verdict
    body = ['<div class="wrap"><header class="topbar"><div class="brand">%s<span>PhishHawk</span></div>'
            '<span class="version">v%s</span><span class="pill">Generated <span class="mono">%s</span></span>'
            "</header>" % (LOGO, __version__, utc_now()),
            '<main class="stack">']
    if len(analyses) > 1:
        body.append(_batch(analyses))
    body += [_section(a, "msg-%d" % i) for i, a in enumerate(analyses, 1)]
    body.append("</main>")
    body.append("<footer><span><b>PhishHawk</b> v%s</span><span>Every indicator is defanged. This report loads "
                "nothing from the network and runs no scripts.</span></footer></div>" % __version__)
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; img-src data:; font-src data:\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            "<meta name=\"color-scheme\" content=\"light dark\">"
            "<title>%s</title><style>%s\n%s</style></head><body>%s</body></html>\n"
            % (escape(title), font_faces(), CSS, "\n".join(body)))
