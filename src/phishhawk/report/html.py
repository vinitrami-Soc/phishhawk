"""Self-contained HTML report.

Everything in a phishing email is attacker-controlled, so every value is
escaped, nothing is fetched (no fonts, no CDN, no images), and a
Content-Security-Policy forbids scripts and network access outright: even an
escaping bug could not turn the report into an XSS. Malicious URLs are shown
defanged and never made clickable; the only links go to VirusTotal,
urlscan.io, AbuseIPDB, RDAP and MITRE ATT&CK.
"""

from __future__ import annotations

from html import escape

from .. import __version__
from ..extract import defang_host, defang_url
from ..models import Analysis, FileIoc
from .common import (
    VERDICT_TONE,
    children_of,
    human_size,
    plural,
    recommendations,
    sorted_signals,
    summary_sentences,
    technique_rows,
    top_level_files,
    urlscan_text,
    utc_now,
    vt_text,
)

CSS = """
:root{--bg:#f5f6f8;--panel:#fff;--ink:#101828;--mut:#475467;--dim:#667085;--line:#e4e7ec;
--red:#b42318;--red-bg:#fef3f2;--amber:#b54708;--amber-bg:#fffaeb;--green:#067647;--green-bg:#ecfdf3;
--blue:#175cd3;--code:#f2f4f7;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f17;--panel:#111827;--ink:#e6e8ec;--mut:#a4abb8;
--dim:#7d8594;--line:#232b3a;--red:#f97066;--red-bg:rgba(249,112,102,.1);--amber:#fdb022;
--amber-bg:rgba(253,176,34,.1);--green:#47cd89;--green-bg:rgba(71,205,137,.1);--blue:#84adff;--code:#0d1320}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 20px 60px}
.top{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.brand{font-weight:700;letter-spacing:-.01em}.brand span,.gen{color:var(--dim);font-weight:400;font-size:12.5px}
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
section.msg{margin-bottom:56px}
.verdict{background:var(--panel);border:1px solid var(--line);border-left:6px solid var(--tone);
border-radius:12px;padding:18px 22px;margin-bottom:18px}
.tone-red{--tone:var(--red)}.tone-amber{--tone:var(--amber)}.tone-green{--tone:var(--green)}
.v-label{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.v-main{font-size:26px;font-weight:750;color:var(--tone);letter-spacing:-.01em;margin:2px 0}
.v-sub{color:var(--mut)}
h1{font-size:19px;margin:22px 0 6px;letter-spacing:-.01em;overflow-wrap:anywhere}
h2{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);margin:30px 0 10px}
.card h2{margin-top:0}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:10px 0 0;color:var(--mut)}
dl.meta dt{color:var(--dim)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card ol,.card ul{margin:6px 0 0;padding-left:20px}.card li{margin:4px 0}
.tbl{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);
font-weight:600;padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
.ioc{overflow-wrap:anywhere;word-break:break-all}
.note{color:var(--amber);font-size:12.5px;margin-top:3px}
.sub{color:var(--dim);font-size:12.5px;margin-top:2px}
.chip{display:inline-block;font-size:11px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;
padding:2px 8px;border-radius:99px;white-space:nowrap}
.c-red{color:var(--red);background:var(--red-bg)}.c-amber{color:var(--amber);background:var(--amber-bg)}
.c-green{color:var(--green);background:var(--green-bg)}.c-dim{color:var(--dim);background:var(--code)}
.t-red{color:var(--red)}.t-amber{color:var(--amber)}.t-green{color:var(--green)}.t-dim{color:var(--dim)}
.tech{display:inline-block;margin:2px 4px 2px 0}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
pre{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto;
white-space:pre-wrap;word-break:break-all;margin:0}
.child td:first-child{padding-left:34px}
.idx td,.idx th{padding:8px 14px}
footer{color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
@media print{body{background:#fff}.verdict,.card,.tbl{break-inside:avoid}}
"""


def _link(url: str, text: str) -> str:
    return '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (escape(url), escape(text))


def _chip(text: str, tone: str) -> str:
    return '<span class="chip c-%s">%s</span>' % (tone, escape(text))


def _tone_text(text: str, tone: str) -> str:
    return '<span class="t-%s">%s</span>' % (tone, escape(text)) if text else ""


def _table(headers: list[str], rows: list[str]) -> str:
    head = "".join("<th>%s</th>" % escape(h) for h in headers)
    return '<div class="tbl"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        head, "".join(rows))


def _vt_cell(report) -> str:
    if not report:
        return '<span class="t-dim">not queried</span>'
    text, tone = vt_text(report)
    cell = _tone_text(text, tone)
    if report.get("link") and report.get("status") in ("ok", "not_found"):
        cell += '<div class="sub">%s</div>' % _link(report["link"], "open in VirusTotal")
    return cell


def _auth_chips(a: Analysis) -> str:
    if not a.auth:
        return '<span class="t-dim">no Authentication-Results header</span>'
    chips = []
    for mechanism, value in a.auth.items():
        tone = "green" if value == "pass" else ("red" if value in ("fail", "softfail") else "amber")
        chips.append(_chip("%s %s" % (mechanism, value), tone))
    return " ".join(chips)


def _file_rows(a: Analysis, f: FileIoc, depth: int) -> list[str]:
    cls = ' class="child"' if depth else ""
    prefix = "&#8627; " if depth else ""
    notes = "".join('<div class="note">%s</div>' % escape(n) for n in f.notes)
    mismatch = any(n.startswith("claims ") for n in f.notes)
    real = " &middot; really %s" % escape(f.true_type) if mismatch else ""
    rows = ['<tr%s><td>%s<span class="ioc">%s</span>%s</td><td>%s%s<div class="sub">%s</div></td>'
            '<td class="mono ioc">%s</td><td>%s</td></tr>'
            % (cls, prefix, escape(f.filename), notes, escape(f.content_type), real,
               escape(human_size(f.size)), escape(f.sha256), _vt_cell(f.vt))]
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


def _section(a: Analysis, anchor: str) -> str:
    tone = VERDICT_TONE.get(a.verdict, "green")
    files = [f for f in a.attachments if not f.inline]
    out = ['<section class="msg" id="%s">' % anchor]
    out.append('<div class="verdict tone-%s"><div class="v-label">Verdict</div>'
               '<div class="v-main">%s</div><div class="v-sub">risk score %d &middot; %s &middot; %s &middot; '
               '%s &middot; %s</div></div>'
               % (tone, escape(a.verdict), a.score, plural(len(a.urls), "URL"),
                  plural(len(files), "file"), plural(len(a.signals), "signal"),
                  escape(plural(len(a.techniques), "ATT&CK technique"))))
    out.append("<h1>%s</h1>" % escape(a.subject or "(no subject)"))
    meta = [("From", "%s &lt;%s&gt;" % (escape(a.from_display), escape(defang_host(a.from_address)))),
            ("Date", escape(a.date or "")), ("To", escape(a.to or "")),
            ("Message-ID", '<span class="mono">%s</span>' % escape(a.message_id or "")),
            ("File", '<span class="mono">%s</span>' % escape(a.path))]
    out.append('<dl class="meta">%s</dl>' % "".join("<dt>%s</dt><dd>%s</dd>" % m for m in meta if m[1]))

    sender = ['<div class="card"><h2>Sender &amp; authentication</h2><dl class="meta">']
    for label, value in (("Reply-To", a.reply_to), ("Return-Path", a.return_path),
                         ("Originating IP", a.originating_ip)):
        if value:
            sender.append('<dt>%s</dt><dd class="mono">%s</dd>' % (label, escape(defang_host(value))))
    sender.append("<dt>Auth</dt><dd>%s</dd>" % _auth_chips(a))
    if a.protected_domains:
        sender.append("<dt>Protected</dt><dd>%s</dd>" % escape(", ".join(a.protected_domains)))
    if a.reported_by:
        sender.append("<dt>Reported by</dt><dd>%s</dd>" % escape(a.reported_by.get("from", "")))
    sender.append("</dl></div>")
    actions = "".join("<li>%s</li>" % escape(x) for x in recommendations(a))
    summary = " ".join(escape(s) for s in summary_sentences(a))
    out.append('<div class="grid">%s<div class="card"><h2>Recommended actions</h2>'
               '<p class="sub" style="margin:0 0 4px">%s</p><ol>%s</ol></div></div>'
               % ("".join(sender), summary, actions))

    if a.signals:
        rows = []
        for s in sorted_signals(a):
            tone = {"high": "red", "medium": "amber"}.get(s.severity, "dim")
            techs = "".join('<span class="tech">%s</span>' % _link(
                "https://attack.mitre.org/techniques/%s/" % t.replace(".", "/"), t) for t in s.techniques)
            rows.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _chip(s.severity, tone), escape(s.label), techs))
        out += ["<h2>Signals</h2>", _table(["Severity", "Finding", "ATT&CK"], rows)]

    if a.lookalikes:
        rows = ['<tr><td class="mono ioc t-red">%s</td><td>%s</td><td class="mono">%s%s</td><td>%s</td></tr>'
                % (escape(defang_host(h.domain)), escape(h.method), escape(defang_host(h.target)),
                   " &middot; YOUR DOMAIN" if h.target in a.protected_domains else "", escape(h.where))
                for h in a.lookalikes]
        out += ["<h2>Lookalike domains</h2>", _table(["Domain", "Technique", "Imitates", "Seen as"], rows)]

    if a.urls:
        rows = []
        for ioc in a.urls:
            notes = "".join('<div class="note">%s</div>' % escape(n) for n in ioc.notes)
            scan_text, scan_tone = urlscan_text(ioc.urlscan)
            scan = _tone_text(scan_text, scan_tone) or '<span class="t-dim">-</span>'
            rows.append('<tr><td><span class="mono ioc">%s</span>%s</td><td class="sub">%s</td>'
                        "<td>%s</td><td>%s</td></tr>"
                        % (escape(ioc.defanged), notes, escape(", ".join(ioc.sources)),
                           _vt_cell(ioc.vt), scan))
        out += ["<h2>URLs</h2>", _table(["URL (defanged)", "Seen in", "VirusTotal", "urlscan.io"], rows)]

    if files:
        rows = []
        for f in top_level_files(a):
            if not f.inline:
                rows += _file_rows(a, f, 0)
        out += ["<h2>Attachments</h2>", _table(["File", "Type", "SHA256", "VirusTotal"], rows)]

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
            rows.append('<tr><td class="mono">%s</td><td>Domain age</td><td>%s</td></tr>'
                        % (escape(defang_host(domain)), detail))
        ip = a.ip_intel
        if ip:
            if ip.get("status") == "ok":
                tone = "red" if ip["score"] >= 75 else ("amber" if ip["score"] >= 25 else "green")
                detail = "%s &middot; %d reports &middot; %s %s" % (
                    _tone_text("confidence %d%%" % ip["score"], tone), ip.get("reports", 0),
                    escape(ip.get("country", "")), escape(ip.get("isp", "")))
            else:
                detail = _tone_text("AbuseIPDB: %s" % ip.get("status"), "dim")
            rows.append('<tr><td class="mono">%s</td><td>IP reputation</td><td>%s</td></tr>'
                        % (escape(defang_host(a.originating_ip)), detail))
        out += ["<h2>Infrastructure</h2>", _table(["Indicator", "Check", "Result"], rows)]

    rows = technique_rows(a)
    if rows:
        cells = ["<tr><td>%s</td><td>%s</td><td class=\"sub\">%s</td></tr>" % (
            _link(r["url"], r["id"]), escape(r["name"]),
            escape("; ".join(r["evidence"][:3]) + (" ..." if len(r["evidence"]) > 3 else "")))
            for r in rows]
        out += ["<h2>MITRE ATT&amp;CK</h2>", _table(["Technique", "Name", "Evidence"], cells)]

    iocs = _defanged_iocs(a)
    if iocs:
        out += ["<h2>Indicators (defanged, copy-ready)</h2>", "<pre>%s</pre>" % escape(iocs)]
    out.append("</section>")
    return "\n".join(out)


def render(analyses: list[Analysis]) -> str:
    title = "Phishing triage" if len(analyses) != 1 else "Phishing triage: %s" % analyses[0].verdict
    body = ['<div class="wrap"><header class="top"><div class="brand">phishhawk <span>v%s</span></div>'
            '<div class="gen">Generated %s</div></header>' % (__version__, utc_now())]
    if len(analyses) > 1:
        rows = ['<tr><td><a href="#msg-%d">%s</a></td><td>%s</td><td>%d</td></tr>' % (
            i, escape(a.subject or a.path), _chip(a.verdict, VERDICT_TONE.get(a.verdict, "green")), a.score)
            for i, a in enumerate(analyses, 1)]
        body += ["<h2>Batch (%d messages)</h2>" % len(analyses),
                 '<div class="idx">%s</div>' % _table(["Subject", "Verdict", "Score"], rows)]
    body += [_section(a, "msg-%d" % i) for i, a in enumerate(analyses, 1)]
    body.append("<footer>Every indicator is defanged. This report loads nothing from the network "
                "and runs no scripts.</footer></div>")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; img-src data:\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            "<title>%s</title><style>%s</style></head><body>%s</body></html>\n"
            % (escape(title), CSS, "\n".join(body)))
