"""Self-contained HTML report: IntelPulse's layout in PhishHawk's colours.

Everything in a phishing email is attacker-controlled, so every value is
escaped, nothing is fetched (the two fonts travel inside the file as data:
URIs, the logo, icons and score ring are inline SVG), and a
Content-Security-Policy forbids scripts and network access outright: even an
escaping bug could not turn the report into an XSS. Malicious URLs are shown
defanged and never made clickable; the only links go to VirusTotal and MITRE
ATT&CK.

Layout follows the IntelPulse console: paper cards on a cool ground, Outfit
for the interface and JetBrains Mono only for machine data. Colour follows the
PhishHawk logo: its amber-to-orange gradient is the severity ramp (validated
as an ordinal ramp in both themes) and its cyan eye marks links. Severity is
never carried by colour alone: every badge and legend row has a glyph and a
word. The page follows the system's light or dark mode, and a radio switch
overrides it with CSS alone. It prints to A4 with the summary on the first
page and the evidence after it.
"""

from __future__ import annotations

import math
from base64 import b64encode
from functools import lru_cache
from html import escape
from importlib.resources import files as package_files

from .. import __version__
from ..attack import TACTIC_ORDER, technique_tactic
from ..extract import defang_host, defang_url
from ..models import Analysis, FileIoc, vt_is_malicious
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

VERDICT_LEVEL = {"MALICIOUS": "critical", "LIKELY PHISHING": "high", "SUSPICIOUS": "medium",
                 "NO STRONG INDICATORS": "ok"}
TONE_LEVEL = {"red": "high", "amber": "medium", "green": "ok", "dim": "info"}
SEVERITIES = ("high", "medium", "low")
POINTS = {"high": 3, "medium": 2, "low": 1}
LOW_CAP = 3          # low signals add at most 3 points between them (models.Analysis.score)
RING_FULL = 30       # the ring is full at 30 points; most real phish score 5 to 20
THRESHOLDS = ((4, "suspicious"), (8, "likely phishing"))
PROVIDERS = {"virustotal": "VirusTotal", "urlscan": "urlscan.io", "rdap": "RDAP", "abuseipdb": "AbuseIPDB"}

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
    "lookup": '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.3-4.3"/>',
    "inbox": '<path d="M4 13h4l1.5 3h5L16 13h4"/><path d="M5.5 5h13L21 13v6H3v-6z"/>',
    "auto": '<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor"/>',
    "light": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4'
             'M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
    "dark": '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
}

THEME_CHOICES = (("auto", "Auto", "Follow the system setting"), ("light", "Light", "Always light"),
                 ("dark", "Dark", "Always dark"))

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

# Colour tokens, one block per theme. The severity fills are the logo's
# amber-to-orange gradient, validated as an ordinal ramp (one hue, monotone
# lightness, visible steps) on paper and on the dark card: darker is more severe
# on paper, brighter is more severe on the dark card. Every text pairing clears 4.5:1.
LIGHT = """
  --ground:#f6f7f9;--ground-2:#eef0f4;--paper:#fff;--line:#e8ebf0;--line-2:#d9dee6;
  --ink:#1c1c1c;--ink-2:#4a4f57;--ink-3:#646c78;
  --brand:#ea580c;--brand-ink:#c2410c;--brand-ink-2:#9a3412;--brand-wash:#fff7ed;--brand-wash-2:#ffedd5;
  --amber:#f59e0b;--amber-ink:#92400e;--amber-wash:#fffbeb;
  --cyan-ink:#0e7490;
  --fill-high:#9a3412;--fill-medium:#ea580c;--fill-low:#f59e0b;
  --on-high:#fff;--on-medium:#1c0f05;--on-low:#1c0f05;
  --sev-critical:#b3122f;--sev-ok:#07704b;--sev-ok-bg:rgba(7,112,75,.10);
  --pill-high-bg:#9a3412;--pill-high:#fff;--pill-medium-bg:#ffedd5;--pill-medium:#9a3412;
  --pill-low-bg:#fffbeb;--pill-low:#92400e;--pill-critical-bg:#b3122f;--pill-critical:#fff;
  --shade-sm:0 1px 2px rgba(20,28,43,.05);
"""

DARK = """
  --ground:#0d0f12;--ground-2:#1b1f26;--paper:#15181d;--line:#262b33;--line-2:#333a45;
  --ink:#f3f5f8;--ink-2:#b3bcc9;--ink-3:#8f99a8;
  --brand-ink:#fb923c;--brand-ink-2:#fdba74;--brand-wash:#2a1709;--brand-wash-2:#3a1f0c;
  --amber-ink:#fbbf24;--amber-wash:#2a200a;--cyan-ink:#22d3ee;
  --fill-high:#fbb040;--fill-medium:#ea580c;--fill-low:#9a3412;
  --on-high:#1c0f05;--on-medium:#1c0f05;--on-low:#fff;
  --sev-critical:#ff8095;--sev-ok:#5fe0a8;--sev-ok-bg:rgba(95,224,168,.14);
  --pill-high-bg:#fbb040;--pill-high:#1c0f05;--pill-medium-bg:rgba(251,146,60,.16);--pill-medium:#fb923c;
  --pill-low-bg:rgba(251,191,36,.12);--pill-low:#fbbf24;--pill-critical-bg:#ff8095;--pill-critical:#1c0f05;
  --shade-sm:0 1px 2px rgba(0,0,0,.5);
"""

# Auto follows the system setting. The switch in the top bar overrides it
# without a script: :has() reads which radio is checked. Print stays on paper.
THEMES = (":root{color-scheme:light dark;" + LIGHT + "}\n"
          "@media screen and (prefers-color-scheme:dark){:root{" + DARK + "}}\n"
          "@media screen{:root:has(#theme-light:checked){color-scheme:light;" + LIGHT + "}\n"
          ":root:has(#theme-dark:checked){color-scheme:dark;" + DARK + "}}\n")

CSS = """
:root{
  --r-sm:10px;--r:16px;--r-lg:22px;--r-full:999px;
  --sans:"Outfit",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}

*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--ground);color:var(--ink);font:400 14px/1.55 var(--sans);
  -webkit-font-smoothing:antialiased;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:1120px;margin:0 auto;padding:24px 20px 56px}
.mono,code,pre{font-family:var(--mono);font-size:12.5px}
.ioc{overflow-wrap:anywhere;word-break:break-word}
a{color:var(--cyan-ink);text-decoration:underline;text-underline-offset:3px;
  text-decoration-color:color-mix(in srgb,currentColor 35%,transparent)}
a:hover{text-decoration-color:currentColor}
a:focus-visible{outline:2px solid var(--brand);outline-offset:2px;border-radius:4px}
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
  background:var(--brand-wash);color:var(--brand-ink-2);border:1px solid var(--brand-wash-2)}
.topbar .pill{margin-left:auto}
/* theme switch: radios styled as a segmented control, no script */
.theme{display:inline-flex;gap:2px;padding:3px;border:1px solid var(--line);border-radius:var(--r-full);
  background:var(--paper);box-shadow:var(--shade-sm)}
.theme input{position:absolute;width:1px;height:1px;margin:0;opacity:0;pointer-events:none}
.theme label{display:inline-flex;align-items:center;gap:5px;padding:3px 10px 3px 8px;border-radius:var(--r-full);
  font-size:12px;color:var(--ink-3);cursor:pointer;user-select:none}
.theme label:hover{color:var(--ink)}
.theme svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round}
.theme input:checked+label{background:var(--brand-wash);color:var(--brand-ink-2);font-weight:600}
.theme input:focus-visible+label{outline:2px solid var(--brand);outline-offset:1px}
@supports not selector(:has(*)){.theme{display:none}}

/* cards */
.card{background:var(--paper);border:1px solid var(--line);border-radius:var(--r-lg);box-shadow:var(--shade-sm)}
.stack{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
section.msg{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}
section.msg+section.msg{margin-top:48px}

/* verdict hero: the verdict and message on the left, the score ring on the right */
.hero{position:relative;overflow:hidden;padding:22px 24px 20px;display:grid;
  grid-template-columns:minmax(0,1fr) 300px;gap:28px;align-items:start}
.hero::before{content:"";position:absolute;inset:0 auto 0 0;width:6px;background:var(--stripe)}
.lvl-critical{--tone:var(--sev-critical);--stripe:var(--sev-critical)}
.lvl-high{--tone:var(--brand-ink);--stripe:linear-gradient(180deg,#fbbf24,#ea580c 55%,#9a3412)}
.lvl-medium{--tone:var(--amber-ink);--stripe:linear-gradient(180deg,#fbbf24,#ea580c)}
.lvl-ok{--tone:var(--sev-ok);--stripe:var(--sev-ok)}
.verdict{display:flex;align-items:center;gap:10px;margin:4px 0 0;color:var(--tone);
  font-size:30px;font-weight:650;letter-spacing:-.035em;line-height:1.1}
.verdict svg{width:18px;height:18px;flex:0 0 18px;fill:currentColor}
.why{margin:6px 0 0;color:var(--ink-2);font-size:13.5px}
.why b{color:var(--ink);font-weight:600}
h1{font-size:20px;font-weight:600;letter-spacing:-.025em;line-height:1.3;margin:16px 0 12px;overflow-wrap:anywhere}
.meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 18px;margin:0;font-size:13px}
.meta dt{color:var(--ink-3)}
.meta dd{margin:0;min-width:0;overflow-wrap:anywhere;color:var(--ink-2)}
.facts{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.fact{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:var(--r-full);
  background:var(--ground);border:1px solid var(--line);font-size:12px;color:var(--ink-2)}
.fact svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;
  stroke-linejoin:round;color:var(--ink-3)}
.fact b{font-weight:600;color:var(--ink)}

/* the score ring: filled to the score on a 0-30 scale, split by where the
   points came from; ticks mark the verdict thresholds */
.hero-side{padding-left:26px;border-left:1px solid var(--line);display:grid;gap:12px;align-content:start}
.ring-row{display:flex;align-items:center;gap:18px}
.ring{width:132px;height:132px;flex:0 0 132px;display:block}
.ring .track{fill:none;stroke:var(--ground-2);stroke-width:13}
.ring .seg{fill:none;stroke-width:13}
.ring .seg-high{stroke:var(--fill-high)}.ring .seg-medium{stroke:var(--fill-medium)}
.ring .seg-low{stroke:var(--fill-low)}
.ring .notch{stroke:var(--paper);stroke-width:2.5}
.ring .tick{stroke:var(--ink-3);stroke-width:1.5;stroke-linecap:round}
.ring .num{font:650 34px var(--sans);letter-spacing:-.04em;fill:var(--tone)}
.ring .cap{font:600 9.5px var(--sans);letter-spacing:.1em;fill:var(--ink-3)}
.scale{list-style:none;margin:0;padding:0;display:grid;gap:8px;min-width:0}
.scale li{display:grid;grid-template-columns:22px minmax(0,1fr);gap:6px;align-items:baseline;font-size:12px;
  color:var(--ink-2);line-height:1.3;white-space:nowrap}
.scale b{font:600 12px var(--mono);color:var(--ink);border-left:2px solid var(--ink-3);padding-left:6px}
.legend{list-style:none;margin:0;padding:10px 0 0;border-top:1px solid var(--line);display:grid;gap:7px}
.legend li{display:grid;grid-template-columns:14px 4.2em minmax(0,1fr) auto;gap:8px;align-items:center;
  font-size:12.5px}
.legend .lv{font-weight:600;color:var(--ink)}
.legend .sw{width:14px;height:14px;border-radius:4px;display:grid;place-items:center}
.legend .sw svg{width:8px;height:8px;fill:currentColor}
.sw-high{background:var(--fill-high);color:var(--on-high)}.sw-medium{background:var(--fill-medium);color:var(--on-medium)}
.sw-low{background:var(--fill-low);color:var(--on-low)}
.legend .n{color:var(--ink-2);white-space:nowrap}
.legend .pts{font:600 12px var(--mono);color:var(--ink);white-space:nowrap}
.legend .pts i{font:400 11px var(--sans);color:var(--ink-3);margin-left:4px}
.legend .zero{opacity:.55}
.ring-note{margin:0;font-size:11.5px;color:var(--ink-3);line-height:1.5}

/* KPI row */
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.kpi{padding:14px;display:grid;gap:10px;align-content:start}
.kpi-top{display:flex;align-items:center;gap:9px;min-width:0}
.kpi-ic{width:30px;height:30px;flex:0 0 30px;border-radius:var(--r-sm);display:grid;place-items:center;
  background:var(--brand-wash);color:var(--brand-ink)}
.kpi-ic svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;
  stroke-linejoin:round}
.kpi-top b{font-size:12.5px;font-weight:500;color:var(--ink-2);line-height:1.25}
.kpi .val{font-size:32px;font-weight:600;letter-spacing:-.04em;line-height:1}
.kpi-foot{font-size:11.5px;color:var(--ink-3);line-height:1.4}
.kpi-foot b{color:var(--ink-2);font-weight:600}

/* panels */
.grid-2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
.panel{padding:16px 18px;min-width:0}
.panel-head{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
h2{font-size:14.5px;font-weight:600;letter-spacing:-.01em;margin:0}
.count{font:600 11px var(--sans);padding:2px 8px;border-radius:var(--r-full);background:var(--ground-2);
  color:var(--ink-2)}
.head-note{margin-left:auto;font-size:12px;color:var(--ink-3)}
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
  place-items:center;font:600 11.5px var(--sans);background:var(--brand-wash-2);color:var(--brand-ink-2);
  margin-top:-1px}

/* badges: a glyph and a word on every severity */
.badge{display:inline-flex;align-items:center;gap:5px;white-space:nowrap;flex:0 0 auto;
  font:600 11px var(--sans);letter-spacing:.02em;text-transform:uppercase;
  padding:3px 10px 3px 9px;border-radius:var(--r-full);border:1px solid transparent}
.badge svg{width:8px;height:8px;fill:currentColor}
.b-critical{background:var(--pill-critical-bg);color:var(--pill-critical)}
.b-high{background:var(--pill-high-bg);color:var(--pill-high)}
.b-medium{background:var(--pill-medium-bg);color:var(--pill-medium);
  border-color:color-mix(in srgb,var(--brand) 22%,transparent)}
.b-low{background:var(--pill-low-bg);color:var(--pill-low);
  border-color:color-mix(in srgb,var(--amber) 30%,transparent)}
.b-info{background:var(--ground-2);color:var(--ink-3);border-color:var(--line)}
.b-ok{background:var(--sev-ok-bg);color:var(--sev-ok)}
.t-critical{color:var(--sev-critical)}.t-high{color:var(--brand-ink)}.t-medium{color:var(--amber-ink)}
.t-ok{color:var(--sev-ok)}.t-info{color:var(--ink-3)}
.chip{display:inline-block;font:500 11.5px var(--mono);padding:2px 8px;margin:0 4px 4px 0;
  border-radius:var(--r-full);background:var(--ground-2);border:1px solid var(--line-2);
  color:var(--ink);text-decoration:none;white-space:nowrap}
.chip:hover{border-color:var(--brand)}
.tag{display:inline-block;font:600 10.5px var(--sans);letter-spacing:.04em;text-transform:uppercase;
  padding:2px 8px;border-radius:var(--r-full);background:var(--ground-2);color:var(--ink-2);
  border:1px solid var(--line);white-space:nowrap}
.tag.own{background:var(--brand-wash-2);color:var(--brand-ink-2);border-color:transparent}

/* severity bar: one row, segments sized by count, each labelled */
.sevbar{display:flex;gap:3px;margin:0 0 14px}
.sevbar span{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:max-content;
  height:34px;padding-inline:12px;border-radius:var(--r-sm);font-size:12px;font-weight:600;white-space:nowrap}
.sevbar svg{width:8px;height:8px;fill:currentColor}
.sevbar .s-high{background:var(--fill-high);color:var(--on-high)}
.sevbar .s-medium{background:var(--fill-medium);color:var(--on-medium)}
.sevbar .s-low{background:var(--fill-low);color:var(--on-low)}

/* ATT&CK: where in an intrusion the evidence sits */
.tactics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;margin:0 0 14px;padding:0;
  list-style:none}
.tactics li{position:relative;padding:10px 12px;border-radius:var(--r-sm);background:var(--ground);
  border:1px solid var(--line);min-width:0}
.tactics li.on{background:var(--brand-wash);border-color:color-mix(in srgb,var(--brand) 30%,transparent)}
.tactics .t-name{display:block;font-size:12px;font-weight:600;color:var(--ink-2);line-height:1.3}
.tactics li.on .t-name{color:var(--brand-ink-2)}
.tactics .t-n{display:block;margin-top:4px;font-size:11.5px;color:var(--ink-3)}
.tactics li.on .t-n{color:var(--ink-2)}

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
.notes li{position:relative;padding-left:14px;font-size:12px;color:var(--brand-ink)}
.notes li::before{content:"!";position:absolute;left:2px;top:0;font:700 12px var(--mono)}
.shown{margin-top:4px;font-size:12px;color:var(--ink-3)}
.shown q{color:var(--ink-2)}
.child td:first-child{padding-left:30px}
.child .arrow{color:var(--ink-3);margin-right:4px}
.hashes{margin:0;display:grid;gap:3px}
.hashes div{display:grid;grid-template-columns:54px minmax(0,1fr);gap:6px;align-items:baseline}
.hashes dt{font:600 9.5px var(--sans);letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3)}
.hashes dd{margin:0;font:11.5px var(--mono);word-break:break-all;color:var(--ink-2)}
.hashes div:first-child dd{color:var(--ink)}
.flagged td:first-child{box-shadow:inset 3px 0 0 var(--brand)}
.types{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}
.types b{margin-left:3px;font-family:var(--mono);color:var(--ink)}
pre.iocs{margin:0;padding:14px 16px;background:var(--ground);border:1px solid var(--line);
  border-radius:var(--r-sm);font:12px/1.65 var(--mono);color:var(--ink-2);white-space:pre-wrap;
  overflow-wrap:anywhere}
.errors{margin:0;padding-left:18px;color:var(--ink-2);font-size:13px}

footer{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;justify-content:space-between;margin-top:28px;
  padding-top:16px;border-top:1px solid var(--line-2);font-size:12px;color:var(--ink-3)}
footer b{color:var(--ink-2);font-weight:600}

@media (max-width:900px){
  .hero{grid-template-columns:minmax(0,1fr)}
  .hero-side{padding:16px 0 0;border-left:0;border-top:1px solid var(--line)}
  .tactics{grid-template-columns:repeat(3,minmax(0,1fr))}
}
@media (max-width:760px){
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  .grid-2{grid-template-columns:minmax(0,1fr)}
  .topbar .pill{margin-left:0}
  .verdict{font-size:25px}
}
@media (max-width:560px){
  .wrap{padding:16px 12px 40px}
  .kpi .val{font-size:26px}
  .hero{padding:18px 18px 16px 20px;gap:14px}
  .ring{width:112px;height:112px;flex-basis:112px}
  .meta{grid-template-columns:minmax(0,1fr);gap:0}
  .meta dt{margin-top:6px}
  .kv>div{grid-template-columns:minmax(0,1fr);gap:2px}
  .sevbar{flex-direction:column}
  .sevbar span{justify-content:flex-start}
  .tactics{grid-template-columns:repeat(2,minmax(0,1fr))}
  .head-note{margin-left:0;flex-basis:100%}
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
  .flagged{border-left:3px solid var(--brand)}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media (forced-colors:active){
  .badge,.sevbar span,.chip,.tag,.idx,.legend .sw,.tactics li{border:1px solid CanvasText}
  .hero::before{background:CanvasText}
  .ring .seg{stroke:CanvasText}
}

/* Print: A4, paper white, the summary on page one and the evidence after it. */
@page{size:A4;margin:14mm 12mm 16mm;
  @bottom-left{content:"PhishHawk triage report";font:9pt "Outfit",sans-serif;color:#646c78}
  @bottom-right{content:"Page " counter(page) " of " counter(pages);font:9pt "Outfit",sans-serif;color:#646c78}}
@media print{
  body{background:#fff;font-size:12px}
  .theme{display:none}
  .wrap{max-width:none;padding:0}
  .card{box-shadow:none;border-color:#d9dee6}
  .pill{box-shadow:none}
  .hero{grid-template-columns:minmax(0,1fr) 250px;gap:18px;padding:18px 20px 16px}
  .hero-side{padding:0 0 0 16px;border-top:0;border-left:1px solid var(--line);gap:10px}
  .ring{width:104px;height:104px;flex-basis:104px}
  .ring-row{gap:12px}
  .legend li{font-size:11.5px;grid-template-columns:14px 4.4em minmax(0,1fr) auto;gap:6px}
  .legend .pts{font-size:11px}
  .ring-note{font-size:10.5px}
  .verdict{font-size:26px}
  h1{font-size:17px;margin:12px 0 10px}
  .meta{font-size:12px;gap:4px 14px}
  .kpis{grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  .kpi{padding:11px 12px;gap:7px}
  .kpi .val{font-size:26px}
  .grid-2{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}
  .kv>div{padding:6px 0;font-size:12px}
  .steps{gap:7px}
  .steps li{font-size:12px}
  /* Chromium cannot fragment grid items across pages cleanly: a table split
     over a page break was drawn under the next card. Block flow fixes it. */
  main.stack,section.msg,.evidence{display:block}
  section.msg>*+*,.evidence>*+*{margin-top:12px}
  .card{-webkit-box-decoration-break:clone;box-decoration-break:clone}
  .panel{padding:12px 14px}
  .panel-head{margin-bottom:8px}
  .tbl{font-size:11.5px}
  .tbl th{padding:6px 8px}
  .tbl td{padding:6px 8px}
  .tbl .mono,.hashes dd{font-size:10.5px}
  .notes li,.shown{font-size:10.5px}
  .sevbar{margin-bottom:10px}
  .sevbar span{height:26px}
  .tactics{grid-template-columns:repeat(5,minmax(0,1fr));margin-bottom:10px}
  .tactics li{padding:7px 9px}
  .badge{padding:2px 8px 2px 7px;font-size:10px}
  .chip{font-size:10.5px;padding:1px 7px;margin-bottom:3px}
  pre.iocs{font-size:10.5px;padding:10px 12px}
  .evidence{break-before:page}
  section.msg+section.msg{margin-top:0;break-before:page}
  .batch+section.msg{break-before:page}
  .hero,.kpi,.grid-2>.card,.sevbar,.tactics,.kv>div,.steps li,.tbl tr,pre.iocs{break-inside:avoid}
  .panel-head,h1,h2{break-after:avoid}
  .tbl thead{display:table-header-group}
  a{text-decoration:none;color:inherit}
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


def _icon(name: str) -> str:
    return _svg(ICONS[name], box="0 0 24 24")


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


def _count(n: int, word: str) -> str:
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


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


def _panel(title: str, body: str, count: int | None = None, cls: str = "", note: str = "") -> str:
    badge = '<span class="count">%d</span>' % count if count is not None else ""
    extra = '<span class="head-note">%s</span>' % note if note else ""
    return ('<section class="card panel %s"><header class="panel-head"><h2>%s</h2>%s%s</header>%s</section>'
            % (cls, title, badge, extra, body))


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


# ------------------------------------------------------------------ score --

def severity_counts(a: Analysis) -> dict[str, int]:
    return {level: sum(1 for s in a.signals if s.severity == level) for level in SEVERITIES}


def score_parts(a: Analysis) -> dict[str, int]:
    """Points each severity contributed; they add up to Analysis.score."""
    counts = severity_counts(a)
    return {"high": counts["high"] * POINTS["high"], "medium": counts["medium"] * POINTS["medium"],
            "low": min(counts["low"], LOW_CAP)}


def verdict_reason(a: Analysis) -> str:
    """One sentence: which rule produced the verdict."""
    high = severity_counts(a)["high"]
    if a.verdict == "MALICIOUS":
        hits = sum(vt_is_malicious(u.vt) for u in a.urls) + sum(vt_is_malicious(f.vt) for f in a.attachments)
        return ("VirusTotal: <b>%s</b> flagged by 2 or more engines, which makes a message malicious."
                % _count(hits, "indicator"))
    if a.verdict == "LIKELY PHISHING":
        if high >= 2:
            return "<b>%s</b>; two or more make a message likely phishing." % _count(high, "high-severity signal")
        return ("<b>1 high-severity signal</b> and a risk score of <b>%d</b>; one high signal with a score of 8 "
                "or more makes a message likely phishing." % a.score)
    if a.verdict == "SUSPICIOUS":
        if high:
            return "<b>1 high-severity signal</b>; one is enough to call a message suspicious."
        return ("A risk score of <b>%d</b> with no high-severity signal; a score of 4 or more makes a message "
                "suspicious." % a.score)
    return "No high-severity signal, and a risk score of <b>%d</b>, below the suspicious threshold of 4." % a.score


def _ring(a: Analysis) -> str:
    size, c, r, width = 132, 66, 52, 13
    circ = 2 * math.pi * r
    parts = score_parts(a)
    total = sum(parts.values())
    scale = min(total, RING_FULL) / RING_FULL / total * circ if total else 0
    rotate = 'transform="rotate(-90 %d %d)"' % (c, c)
    where = ", ".join("%d points from %s signals" % (parts[s], s) for s in SEVERITIES if parts[s])
    out = ['<svg class="ring" viewBox="0 0 %d %d" role="img" aria-label="Risk score %d; %s">'
           % (size, size, a.score, escape(where or "no signals")),
           '<circle class="track" cx="%d" cy="%d" r="%d"/>' % (c, c, r)]
    start, drawn = 0.0, [s for s in SEVERITIES if parts[s]]
    for level in drawn:
        length = parts[level] * scale
        gap = 2.5 if len(drawn) > 1 and length > 5 else 0
        out.append('<circle class="seg seg-%s" cx="%d" cy="%d" r="%d" stroke-dasharray="%.2f %.2f" '
                   'stroke-dashoffset="%.2f" %s/>' % (level, c, c, r, max(length - gap, .5), circ, -start, rotate))
        start += length
    for value, _ in THRESHOLDS:
        angle = math.radians(value / RING_FULL * 360 - 90)
        cos, sin = math.cos(angle), math.sin(angle)
        inner, outer = r - width / 2 - 1, r + width / 2 + 1
        out.append('<line class="notch" x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f"/>'
                   % (c + inner * cos, c + inner * sin, c + outer * cos, c + outer * sin))
        out.append('<line class="tick" x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f"/>'
                   % (c + (outer + 1) * cos, c + (outer + 1) * sin, c + (outer + 5) * cos, c + (outer + 5) * sin))
    out.append('<text class="num" x="%d" y="%d" text-anchor="middle">%d</text>' % (c, c + 8, a.score))
    out.append('<text class="cap" x="%d" y="%d" text-anchor="middle">POINTS</text>' % (c, c + 26))
    out.append("</svg>")
    return "".join(out)


def _legend(a: Analysis) -> str:
    counts, parts = severity_counts(a), score_parts(a)
    rows = []
    for level in SEVERITIES:
        capped = "<i>capped</i>" if level == "low" and counts["low"] > LOW_CAP else ""
        rows.append('<li class="%s"><span class="sw sw-%s">%s</span><span class="lv">%s</span>'
                    '<span class="n">%s</span><span class="pts">%d pts%s</span></li>'
                    % ("zero" if not counts[level] else "", level, _svg(GLYPHS[level]), level.capitalize(),
                       _count(counts[level], "signal"), parts[level], capped))
    return '<ul class="legend">%s</ul>' % "".join(rows)


def _scale() -> str:
    return '<ul class="scale">%s</ul>' % "".join(
        "<li><b>%d</b><span>%s</span></li>" % (value, name.capitalize()) for value, name in THRESHOLDS)


# ------------------------------------------------------------- sections --

def _hero(a: Analysis, level: str) -> str:
    meta = [("From", "%s &lt;%s&gt;" % (escape(a.from_display), escape(defang_host(a.from_address)))),
            ("Date", escape(a.date or "")), ("To", escape(a.to or "")),
            ("Message-ID", '<span class="mono ioc">%s</span>' % escape(a.message_id or "")),
            ("File", '<span class="mono ioc">%s</span>' % escape(a.path))]
    sources = [PROVIDERS.get(s, s) for s in a.enrichment_sources]
    facts = ['<span class="fact">%s Reputation lookups: <b>%s</b></span>'
             % (_icon("lookup"), escape(", ".join(sources)) if sources else "none (offline)")]
    if a.reported_by:
        who = a.reported_by.get("display") or a.reported_by.get("from", "")
        facts.append('<span class="fact">%s Reported by <b>%s</b>%s</span>'
                     % (_icon("inbox"), escape(who),
                        " on %s" % escape(a.reported_by["date"]) if a.reported_by.get("date") else ""))
    side = ('<div class="hero-side"><div class="label">Risk score</div><div class="ring-row">%s%s</div>%s'
            '<p class="ring-note">Ticks on the ring mark the thresholds; it is full at %d points. Likely phishing '
            'at %d also needs a high-severity signal, and low signals add at most %d points.</p></div>'
            % (_ring(a), _scale(), _legend(a), RING_FULL, THRESHOLDS[1][0], LOW_CAP))
    return ('<div class="card hero lvl-%s"><div><div class="label">Verdict</div>'
            '<div class="verdict">%s<span>%s</span></div><p class="why">%s</p><h1>%s</h1>'
            '<dl class="meta">%s</dl><div class="facts">%s</div></div>%s</div>'
            % (level, _svg(GLYPHS[level]), escape(a.verdict), verdict_reason(a),
               escape(a.subject or "(no subject)"),
               "".join("<dt>%s</dt><dd>%s</dd>" % m for m in meta if m[1]), "".join(facts), side))


def _kpis(a: Analysis, files: list[FileIoc]) -> str:
    counts = severity_counts(a)
    flagged_urls = sum(1 for u in a.urls if u.flagged)
    attached = [f for f in files if not f.parent]
    inside = len(files) - len(attached)
    file_foot = ["<b>%d</b> attached" % len(attached)]
    if inside:
        file_foot.append("<b>%d</b> inside archives" % inside)
    file_foot.append("<b>%d</b> flagged" % sum(1 for f in files if f.flagged))
    tactics = {technique_tactic(t) for t in a.techniques} - {""}
    tiles = [("url", "URLs", len(a.urls), "<b>%d</b> flagged" % flagged_urls),
             ("file", "Files", len(files), " &middot; ".join(file_foot)),
             ("signal", "Signals", len(a.signals),
              " &middot; ".join("<b>%d</b> %s" % (counts[s], s) for s in SEVERITIES)),
             ("attack", "ATT&CK techniques", len(a.techniques),
              "across <b>%s</b>" % _count(len(tactics), "tactic"))]
    return '<div class="kpis">%s</div>' % "".join(
        '<div class="card kpi"><div class="kpi-top"><span class="kpi-ic">%s</span><b>%s</b></div>'
        '<div class="val">%d</div><div class="kpi-foot">%s</div></div>'
        % (_icon(icon), escape(label), value, foot) for icon, label, value, foot in tiles)


def _sender(a: Analysis) -> str:
    rows = []
    for label, value in (("Reply-To", a.reply_to), ("Return-Path", a.return_path),
                         ("Originating IP", a.originating_ip)):
        if value:
            rows.append((label, '<span class="mono">%s</span>' % escape(defang_host(value))))
    rows.append(("Received hops", str(a.received_hops)))
    rows.append(("Auth", _auth_badges(a)))
    if a.protected_domains:
        rows.append(("Protected", escape(", ".join(a.protected_domains))))
    if a.reported_by:
        rb = a.reported_by
        rows.append(("Reported by", "%s &lt;%s&gt;" % (escape(rb.get("display", "")), escape(rb.get("from", "")))))
    if a.forwarded_from:
        fwd = a.forwarded_from
        rows.append(("Forwarded from", "%s &lt;%s&gt;" % (escape(fwd.get("display", "")),
                                                        escape(defang_host(fwd.get("address", ""))))))
    if a.body_emails:
        rows.append(("In the body", '<span class="mono">%s</span>'
                     % escape(", ".join(defang_host(e) for e in a.body_emails[:5]))))
    body = '<dl class="kv">%s</dl>' % "".join("<div><dt>%s</dt><dd>%s</dd></div>" % r for r in rows)
    return _panel("Sender &amp; authentication", body)


def _actions(a: Analysis) -> str:
    summary = " ".join(escape(s) for s in summary_sentences(a))
    steps = "".join("<li><span>%s</span></li>" % escape(x) for x in recommendations(a))
    return _panel("Recommended actions", '<p class="summary">%s</p><ol class="steps">%s</ol>' % (summary, steps))


def _severity_bar(a: Analysis) -> str:
    counts = severity_counts(a)
    segments = "".join('<span class="s-%s" style="flex-grow:%d">%s%d %s</span>'
                       % (level, n, _svg(GLYPHS[level]), n, level.capitalize())
                       for level, n in counts.items() if n)
    return '<div class="sevbar" role="img" aria-label="%s">%s</div>' % (
        escape(", ".join("%d %s" % (n, level) for level, n in counts.items() if n)), segments)


def _tactic_strip(rows: list[dict]) -> str:
    per = {t: 0 for t in TACTIC_ORDER}
    for r in rows:
        tactic = technique_tactic(r["id"])
        if tactic in per:
            per[tactic] += 1
    return '<ol class="tactics" aria-label="ATT&amp;CK tactics">%s</ol>' % "".join(
        '<li class="%s"><span class="t-name">%s</span><span class="t-n">%s</span></li>'
        % ("on" if n else "", escape(t), _count(n, "technique") if n else "not seen") for t, n in per.items())


def _file_rows(a: Analysis, f: FileIoc, depth: int) -> list[tuple[str, list[str]]]:
    arrow = '<span class="arrow" aria-hidden="true">&#8627;</span>' if depth else ""
    mismatch = any(n.startswith("claims ") for n in f.notes)
    real = " &middot; really %s" % escape(f.true_type) if mismatch else ""
    cls = " ".join(c for c in ("child" if depth else "", "flagged" if f.flagged else "") if c)
    hashes = "".join('<div><dt>%s</dt><dd>%s</dd></div>' % (label, escape(value))
                     for label, value in (("SHA-256", f.sha256), ("SHA-1", f.sha1), ("MD5", f.md5)) if value)
    rows = [(cls, ['%s<span class="ioc">%s</span>%s' % (arrow, escape(f.filename), _notes(f.notes)),
                   '%s%s<div class="sub">%s</div>' % (escape(f.content_type), real, escape(human_size(f.size))),
                   '<dl class="hashes">%s</dl>' % hashes,
                   _vt_cell(f.vt)])]
    for child in children_of(a, f):
        rows += _file_rows(a, child, depth + 1)
    return rows


def _defanged_iocs(a: Analysis) -> list[tuple[str, str]]:
    out = []
    for ioc in a.iocs():
        value = ioc["value"]
        if ioc["type"] == "url":
            value = defang_url(value)
        elif ioc["type"] != "sha256":
            value = defang_host(value)
        out.append((ioc["type"], value))
    return out


def _url_cell(ioc) -> str:
    shown = [t for t in ioc.anchor_texts if t.strip() and t.strip() != ioc.url]
    text = ""
    if shown:
        label = shown[0].strip()
        if len(label) > 90:
            label = label[:90] + "..."
        text = '<div class="shown">Link text: <q>%s</q></div>' % escape(label)
    return '<span class="mono ioc">%s</span>%s%s' % (escape(ioc.defanged), text, _notes(ioc.notes))


def _evidence(a: Analysis, files: list[FileIoc]) -> list[str]:
    out = []
    if a.signals:
        rows = []
        for s in sorted_signals(a):
            techs = "".join(_link("https://attack.mitre.org/techniques/%s/" % t.replace(".", "/"), t, "chip")
                            for t in s.techniques)
            rows.append(("", [_badge(s.severity, s.severity if s.severity in POINTS else "low"),
                              escape(s.label), techs or '<span class="muted">-</span>']))
        table = _table(["Severity", "Finding", "ATT&CK"], [13, 62, 25], rows)
        out.append(_panel("Signals", _severity_bar(a) + table, len(a.signals),
                          note="risk score %d = %s" % (a.score, " + ".join(
                              "%d %s" % (p, s) for s, p in score_parts(a).items() if p)) if a.score else ""))

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
                         ['<span class="idx">%d</span>' % i, _url_cell(ioc),
                          '<span class="sub">%s</span>' % escape(", ".join(ioc.sources)),
                          _vt_cell(ioc.vt),
                          _tone_text(scan_text, scan_tone) or '<span class="muted">-</span>']))
        flagged = sum(1 for u in a.urls if u.flagged)
        out.append(_panel("URLs", _table(["#", "URL (defanged)", "Seen in", "VirusTotal", "urlscan.io"],
                                         [6, 46, 18, 15, 15], rows), len(a.urls), note="%d flagged" % flagged))

    if files:
        rows = []
        for f in top_level_files(a):
            if not f.inline:
                rows += _file_rows(a, f, 0)
        out.append(_panel("Attachments", _table(["File", "Type", "Hashes", "VirusTotal"], [27, 17, 40, 16], rows),
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
        order = {t: i for i, t in enumerate(TACTIC_ORDER)}
        rows = sorted(rows, key=lambda r: (order.get(technique_tactic(r["id"]), 99), r["id"]))
        cells = [("", ['<span class="sub">%s</span>' % escape(technique_tactic(r["id"])),
                       _link(r["url"], r["id"], "chip"), escape(r["name"]),
                       '<span class="sub">%s</span>' % escape(
                           "; ".join(r["evidence"][:3]) + (" ..." if len(r["evidence"]) > 3 else ""))])
                 for r in rows]
        out.append(_panel("MITRE ATT&amp;CK", _tactic_strip(rows) + _table(
            ["Tactic", "Technique", "Name", "Evidence"], [16, 13, 26, 45], cells), len(rows)))

    iocs = _defanged_iocs(a)
    if iocs:
        per_type: dict[str, int] = {}
        for kind, _ in iocs:
            per_type[kind] = per_type.get(kind, 0) + 1
        types = '<div class="types">%s</div>' % "".join(
            '<span class="tag">%s <b>%d</b></span>' % (escape(k), n) for k, n in per_type.items())
        text = "\n".join("%-7s %s" % (kind, value) for kind, value in iocs)
        out.append(_panel("Indicators (defanged, copy-ready)", types + '<pre class="iocs">%s</pre>' % escape(text),
                          len(iocs)))

    if a.errors:
        out.append(_panel("Processing notes", '<ul class="errors">%s</ul>'
                          % "".join("<li>%s</li>" % escape(e) for e in a.errors), len(a.errors)))
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


def _theme_switch() -> str:
    return '<div class="theme" role="radiogroup" aria-label="Colour theme">%s</div>' % "".join(
        '<input type="radio" name="theme" id="theme-%s"%s><label for="theme-%s" title="%s">%s%s</label>'
        % (key, " checked" if key == "auto" else "", key, hint, _icon(key), name)
        for key, name, hint in THEME_CHOICES)


def render(analyses: list[Analysis]) -> str:
    title = "Phishing triage" if len(analyses) != 1 else "Phishing triage: %s" % analyses[0].verdict
    body = ['<div class="wrap"><header class="topbar"><div class="brand">%s<span>PhishHawk</span></div>'
            '<span class="version">v%s</span><span class="pill">Generated <span class="mono">%s</span></span>%s'
            "</header>" % (LOGO, __version__, utc_now(), _theme_switch()),
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
            % (escape(title), font_faces(), THEMES + CSS, "\n".join(body)))
