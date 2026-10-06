import csv
import io
import json
import re

import pytest

from phishhawk.pipeline import triage_bytes, triage_file
from phishhawk.report import console, csvout, html, markdown, stix
from phishhawk.report.common import recommendations, to_dict

from conftest import build_eml, sample

HOSTILE_SUBJECT = '<script>alert(1)</script> =HYPERLINK("http://x") | pipe'
HOSTILE_FILE = '"><img src=x onerror=alert(1)>.html'


@pytest.fixture(scope="module")
def phish():
    return triage_file(sample("sample_phish.eml"))


@pytest.fixture(scope="module")
def hostile():
    eml = build_eml(subject=HOSTILE_SUBJECT, text="go https://evil-login.top/verify now",
                    attachments=[(b"<html><form><input type=password></form></html>", "text", "html",
                                  HOSTILE_FILE)])
    return triage_bytes(eml, path="hostile.eml")


def test_console_without_colour_has_no_escape_codes(phish):
    text = console.render(phish, console.Palette(False), verbose=True)
    assert "\033[" not in text
    for section in ("SENDER", "LOOKALIKE DOMAINS", "URLS", "ATTACHMENTS", "SIGNALS", "MITRE ATT&CK", "SUMMARY"):
        assert "-- " + section in text
    assert "MD5    :" in text  # verbose only


def test_colour_codes_never_break_column_alignment():
    """Padding must happen before colouring, or the escape bytes eat it."""
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    text = re.sub(r"\033\[[0-9;]*m", "", console.render(bec, console.Palette(True)))

    def rows(section):
        block = text.split("-- " + section, 1)[1].split("\n\n", 1)[0]
        return [line for line in block.splitlines()[1:] if line.strip()]

    assert all(line[9] == "]" for line in rows("SIGNALS"))                       # "  [medium] ..."
    assert all(line[12] == " " and line[13] != " " for line in rows("MITRE ATT&CK"))
    assert all(line[32:34] == "  " and line[34] != " " for line in rows("LOOKALIKE DOMAINS"))


def test_json_is_complete_and_serialisable(phish):
    payload = json.loads(json.dumps(to_dict(phish)))
    assert payload["verdict"] == "LIKELY PHISHING"
    assert {row["id"] for row in payload["techniques"]} >= {"T1566.002", "T1656"}
    assert payload["iocs"] and payload["recommendations"]
    assert payload["urls"][0]["defanged"].startswith("hxxp")


def test_recommendations_escalate_with_the_evidence():
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    actions = " ".join(recommendations(bec))
    assert "BEC" in actions and "EDR" in actions and "revoke" in actions
    assert recommendations(triage_file(sample("sample_benign.eml")))[0].startswith("Close")


def test_stix_bundle_is_spec_valid_and_deduplicated(phish):
    stix2 = pytest.importorskip("stix2")
    reported = triage_file(sample("sample_reported.eml"))  # same campaign, reported separately
    bundle = stix.build_bundle([phish, reported])
    parsed = stix2.parse(json.loads(json.dumps(bundle)), allow_custom=False)
    indicators = [o for o in parsed.objects if o.type == "indicator"]
    # The forwarded copy carries the same Message-ID: one message, one report,
    # one set of indicators - however many users report it.
    assert len(indicators) == len(phish.iocs())
    assert len([o for o in parsed.objects if o.type == "report"]) == 1
    bec = triage_file(sample("sample_bec_smuggling.eml"))
    two = stix2.parse(json.loads(json.dumps(stix.build_bundle([phish, bec]))), allow_custom=False)
    assert len([o for o in two.objects if o.type == "report"]) == 2
    patterns = {o.pattern for o in indicators}
    assert "[domain-name:value = 'micros0ft-verify-support.top']" in patterns


def test_stix_pattern_escaping():
    assert stix._escape("it's \\ here") == "it\\'s \\\\ here"


def test_html_escapes_attacker_content_and_locks_itself_down(hostile):
    page = html.render([hostile])
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert 'src="http' not in page and "<script" not in page.lower().replace("&lt;script", "")
    assert "https://evil-login.top" not in page  # malicious URLs appear defanged only


def test_html_batch_has_an_index(phish):
    benign = triage_file(sample("sample_benign.eml"))
    page = html.render([phish, benign])
    assert 'href="#msg-1"' in page and 'href="#msg-2"' in page


def test_markdown_escapes_table_pipes(hostile):
    note = markdown.render(hostile)
    assert "\\| pipe" in note
    assert "- [ ] " in note


def test_csv_neutralises_formula_injection(hostile):
    rows = list(csv.DictReader(io.StringIO(csvout.render([hostile]))))
    assert rows, "hostile mail should produce indicators"
    assert all(row["subject"].startswith("'<script>") or row["subject"].startswith("'=")
               or not row["subject"].startswith(("=", "+", "-", "@")) for row in rows)
    formula = triage_bytes(build_eml(subject="=HYPERLINK(\"http://x\")",
                                     text="https://evil-login.top/verify",
                                     headers=[("Reply-To", "a@other.example")]))
    rows = list(csv.DictReader(io.StringIO(csvout.render([formula]))))
    assert rows and all(row["subject"].startswith("'=") for row in rows)


def test_html_embeds_its_fonts_and_prints_to_a4(phish):
    page = html.render([phish])
    assert "font-src data:" in page and "default-src 'none'" in page
    assert page.count("@font-face") == 2 and "data:font/woff2;base64," in page
    assert "fonts.googleapis" not in page and "fonts.gstatic" not in page  # nothing is fetched
    assert "@page{size:A4" in page
    assert ".evidence{break-before:page}" in page  # summary on page one, evidence after it
    assert ".tbl thead{display:table-header-group}" in page  # column headers repeat on every page


def _between(page, start, end):
    return page.split(start, 1)[1].split(end, 1)[0]


def _panel_of(page, title):
    """The HTML of the panel whose heading is title."""
    return page.split("<h2>%s</h2>" % title, 1)[1].split("</section>", 1)[0]


def test_html_puts_decisions_before_evidence(phish):
    from phishhawk.report.common import sorted_signals

    page = html.render([phish])
    summary, evidence = page.split('<div class="evidence stack">', 1)
    # the verdict, the top three findings and the actions come first ...
    for marker in ('class="card hero', "<h2>Top findings</h2>", "<h2>Recommended actions</h2>"):
        assert marker in summary, marker
    top = _panel_of(summary, "Top findings")
    assert all(html.escape(s.label) in top for s in sorted_signals(phish)[:3])
    assert html.escape(sorted_signals(phish)[3].label) not in top
    # ... then each part of the evidence in its own section, in this order
    order = ["Message", "Authentication", "Findings", "URLs", "Files", "MITRE ATT&amp;CK",
             "Reputation and enrichment", "Evidence and provenance", "Limitations"]
    positions = [evidence.index("<h2>%s</h2>" % title) for title in order]
    assert positions == sorted(positions)
    message_id = html.escape(phish.message_id)
    assert message_id in _panel_of(evidence, "Message") and message_id not in summary


def test_html_section_navigation_works_without_a_script(phish):
    benign = triage_file(sample("sample_benign.eml"))
    page = html.render([phish, benign])
    nav = _between(page, '<nav class="secnav" aria-label="Report sections">', "</nav>")
    for key in ("summary", "actions", "message", "auth", "findings", "urls", "files", "attack", "evidence",
                "limits"):
        assert 'href="#msg-1-%s"' % key in nav
        assert 'id="msg-1-%s"' % key in page
    assert 'id="msg-2-summary"' in page  # every message has its own anchors
    assert page.count('<nav class="secnav"') == 2
    assert ".secnav,.secmenu{display:none}" in page.split("@media print{", 1)[1]
    assert "<script" not in page


def test_html_authentication_spells_out_each_check(phish):
    from phishhawk.alignment import assess
    from phishhawk.report.common import defang_host

    page = html.render([phish])
    panel = _panel_of(page, "Authentication")
    block = assess(phish, defang_host)
    for header in ("Check", "Result", "Domain checked", "Aligned with From"):
        assert '<th scope="col">%s</th>' % header in panel
    for check in block["checks"]:
        assert 'data-label="Check"><div>%s</div>' % check["check"] in panel
    assert all(html.escape(line) in panel for line in block["explanation"])
    assert "Read from" in panel and "Authentication-Results" in panel
    assert "Fail" in panel  # results use the report's words, not raw tokens


def test_html_findings_say_why_they_matter(phish):
    page = html.render([phish])
    panel = _panel_of(page, "Findings")
    assert '<th scope="col">Why it matters</th>' in panel
    assert html.WHY_IT_MATTERS["auth"] in panel and html.WHY_IT_MATTERS["sender"] in panel


def test_html_files_section_is_there_even_without_files(phish):
    benign = triage_file(sample("sample_benign.eml"))
    assert not [f for f in benign.attachments if not f.inline]
    assert "No attachments were found." in _panel_of(html.render([benign]), "Files")


def test_html_states_completeness_reputation_and_evidence_explicitly(phish):
    import copy

    page = html.render([phish])
    hero = _between(page, 'class="card hero', "<h2>")
    assert "Analysis: <b>Complete</b>" in hero
    assert "Reputation: <b>Not checked</b>" in hero
    evidence = _panel_of(page, "Evidence and provenance")
    assert phish.evidence["sha256"] in evidence
    assert "Not recorded" in evidence and "Not verified" in evidence
    assert _panel_of(page, "URLs").count("Not checked") >= len(phish.urls)  # never "clean" by silence
    assert "does not mean an indicator is safe" in _panel_of(page, "Reputation and enrichment")
    partial = copy.deepcopy(phish)
    partial.urls_dropped = 2
    hero = _between(html.render([partial]), 'class="card hero', "<h2>")
    assert 'class="fact warn"' in hero and "Analysis: <b>Incomplete</b>" in hero


def test_html_limitations_and_footer_keep_the_report_honest(phish):
    from phishhawk.report.common import limitations

    page = html.render([phish])
    panel = _panel_of(page, "Limitations")
    assert all(html.escape(note) in panel for note in limitations(phish))
    footer = _between(page, "<footer>", "</footer>")
    assert "investigation aid" in footer and "evidence policy" in footer
    assert "Purge" not in page


def test_html_theme_follows_the_system_and_can_be_switched_without_a_script(phish):
    page = html.render([phish])
    assert "<script" not in page
    assert "@media screen and (prefers-color-scheme:dark){:root{" + html.DARK in page  # auto
    assert ":root:has(#theme-light:checked){color-scheme:light;" + html.LIGHT in page
    assert ":root:has(#theme-dark:checked){color-scheme:dark;" + html.DARK in page
    for key in ("auto", "light", "dark"):
        assert '<input type="radio" name="theme" id="theme-%s"' % key in page
        assert '<label for="theme-%s"' % key in page
    assert '<input type="radio" name="theme" id="theme-auto" checked>' in page
    # the dark tokens are screen-only, so a printout is always on paper
    assert "@media (prefers-color-scheme:dark)" not in page


def test_html_severity_is_never_colour_alone(phish):
    page = html.render([phish])
    badges = re.findall(r'<span class="badge b-(\w+)"><svg[^>]*>.*?</svg>([^<]+)</span>', page)
    assert badges and all(word.strip() for _, word in badges)
    assert {("high", "high"), ("medium", "medium"), ("low", "low")} <= set(badges)
    assert '<div class="verdict"><svg' in page and "LIKELY PHISHING" in page


def test_html_tables_keep_their_labels_on_narrow_screens(phish):
    page = html.render([phish])
    assert 'data-label="Finding"' in page and 'data-label="Domain checked"' in page


def test_html_font_files_ship_with_the_package():
    from importlib.resources import files

    folder = files("phishhawk.report").joinpath("fonts")
    for name in ("Outfit-Variable-latin.woff2", "JetBrainsMono-Variable-latin.woff2",
                 "Outfit-OFL.txt", "JetBrainsMono-OFL.txt"):
        assert folder.joinpath(name).is_file(), name


def test_html_escapes_the_authentication_source():
    # The authserv-id comes from a header, so a sender can write anything there.
    eml = build_eml(headers=[("Authentication-Results", "<script>alert`1`</script>.example; spf=pass")])
    a = triage_bytes(eml)
    assert a.auth_receiver.startswith("<script>")
    page = html.render([a])
    assert "<script>alert" not in page and "&lt;script&gt;alert`1`&lt;/script&gt;" in page
    assert "<script>alert" not in markdown.render(a)


@pytest.fixture(scope="module")
def bec():
    return triage_file(sample("sample_bec_smuggling.eml"))


def test_html_explains_how_the_score_was_calculated(bec):
    from phishhawk.report.common import sorted_signals

    page = html.render([bec])
    calc = _between(_panel_of(page, "Findings"), '<details class="calc">', "</details>")
    assert "<summary>How this score was calculated</summary>" in calc
    points = [int(n) for n in re.findall(r'data-label="Points"><div>(\d+)', calc)]
    assert len(points) == len(bec.signals) and sum(points) == bec.score
    lows = [s for s in sorted_signals(bec) if s.severity == "low"]
    assert len(lows) > 3 and ("cap of 3 reached" in calc or "same kind" in calc)  # low signals are capped
    assert html.verdict_reason(bec) in calc
    assert ".calc{display:none}" in page.split("@media print{", 1)[1]


def test_html_findings_say_what_to_check(phish):
    panel = _panel_of(html.render([phish]), "Findings")
    for family in ("auth", "sender", "link"):
        assert html.escape(html.WHAT_TO_CHECK[family]) in panel


def test_html_actions_are_a_checklist_that_needs_no_script(phish):
    page = html.render([phish])
    panel = _panel_of(page, "Recommended actions")
    actions = recommendations(phish)
    assert panel.count('<input type="checkbox"') == len(actions)
    for action in actions:
        assert '<span class="t">%s</span></label>' % html.escape(action) in panel
    assert "<script" not in page
    assert ".steps input:checked+.n" in page  # ticking needs no :has() and no script


def test_html_urls_are_cards_with_every_fact(phish):
    panel = _panel_of(html.render([phish]), "URLs")
    assert "<table" not in panel and panel.count('<li class="urlcard') == len(phish.urls)
    for ioc in phish.urls:
        assert html.escape(ioc.defanged) in panel
    for label in ("Found in", "Domain", "VirusTotal", "urlscan.io"):
        assert panel.count("<dt>%s</dt>" % label) == len(phish.urls)


def test_html_lookalikes_show_which_characters_changed(bec):
    panel = _panel_of(html.render([bec]), "Lookalike domains")
    assert "examp<mark>1</mark>e-corp[.]co[.]uk" in panel  # observed
    assert "examp<mark>l</mark>e-corp[.]co[.]uk" in panel  # imitates
    assert "not proof" in panel


def test_html_attack_groups_techniques_by_tactic(bec):
    from phishhawk.attack import ENTERPRISE_TACTICS, TACTIC_ORDER

    page = html.render([bec])
    panel = _panel_of(page, "MITRE ATT&amp;CK")
    assert len(ENTERPRISE_TACTICS) == 14 and set(TACTIC_ORDER) <= set(ENTERPRISE_TACTICS)
    strip = _between(panel, '<ol class="tactics"', "</ol>")
    assert all(html.escape(t) in strip for t in ENTERPRISE_TACTICS)
    assert strip.count("not assessed") == len(ENTERPRISE_TACTICS) - len(TACTIC_ORDER)
    assert "<h3>Defense Evasion</h3>" in panel and "<h3>Persistence</h3>" not in panel
    assert "(opens in a new tab)" in panel and "<table" not in panel


def test_html_has_no_control_characters(bec):
    # A CSS escape such as "\2197" written in a Python string turns into a
    # control character and a stray "97" on screen.
    page = html.render([bec])
    assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", page)
    assert 'content:"\\2197"' in page and 'content:"\\2713"' in page


def test_html_keeps_the_verdict_in_sight_while_scrolling(phish):
    page = html.render([phish])
    bar = _between(page, '<nav class="secnav" aria-label="Report sections">', "</nav>")
    assert '<span class="nav-verdict t-high">' in bar and "LIKELY PHISHING &middot; %d" % phish.score in bar
    # on a phone or tablet the same links fold into a menu that needs no script
    menu = _between(page, '<details class="secmenu">', "</details>")
    assert "<summary>" in menu and "LIKELY PHISHING &middot; %d" % phish.score in menu
    assert '<nav aria-label="Report sections">' in menu and 'href="#msg-1-limits"' in menu
    narrow = page.split("@media (max-width:900px){", 1)[1].split("\n}", 1)[0]
    assert ".secnav{display:none}" in narrow and ".secmenu{display:block" in narrow
    assert ".secnav,.secmenu{display:none}" in page.split("@media print{", 1)[1]


def test_html_print_pages_carry_the_verdict_time_and_page_numbers(phish):
    benign = triage_file(sample("sample_benign.eml"))
    page = html.render([phish])
    generated = re.search(r'Generated <span class="mono">([0-9TZ:-]+)</span>', page).group(1)
    assert '@bottom-left{content:"PhishHawk \\00B7  LIKELY PHISHING \\00B7  risk score %d"' % phish.score in page
    assert '@bottom-center{content:"Generated %s"' % generated in page
    assert '@bottom-right{content:"Page " counter(page) " of " counter(pages)' in page
    assert '@bottom-left{content:"PhishHawk \\00B7  2 messages"' in html.render([phish, benign])


def test_html_print_keeps_the_score_breakdown_inside_the_hero(phish):
    # an A4 page is narrower than 900px, so the tablet layout would set the
    # breakdown beside the ring, outside the narrow print column, and cut it off
    printed = html.render([phish]).split("@media print{", 1)[1].split("\n}", 1)[0]
    assert ".hero-side{grid-template-columns:minmax(0,1fr)}" in printed


def test_html_controls_are_big_enough_to_tap(phish):
    page = html.render([phish])
    assert ".chip{display:inline-flex;align-items:center;min-height:24px" in page
    assert "a[download]{display:inline-block;padding:4px 0}" in page  # the report-file links
    coarse = page.split("@media (pointer:coarse){", 1)[1].split("\n}", 1)[0]
    assert ".secmenu a{min-height:44px}" in coarse and ".secnav a{padding:10px 14px}" in coarse
