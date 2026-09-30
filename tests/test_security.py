"""PhishHawk attacked the way a bug-bounty hunter would: every test here was
an exploit against 1.2.0 that now fails. Input is attacker-controlled, and so
is anything a report shows from it."""

import base64
import os
import re
import stat
import sys
import time
from email.message import EmailMessage

import pytest

from phishhawk.cache import Cache
from phishhawk.cli import main
from phishhawk.enrich import redact_recipients
from phishhawk.lookalike import find_lookalikes
from phishhawk.parse import parse_bytes
from phishhawk.pipeline import Options, triage_bytes, triage_file
from phishhawk.report import console, csvout, html, markdown

from conftest import build_eml, sample

OSC_CLIPBOARD = "\x1b]52;c;ZWNobyBwd25lZA==\x07"
LURE = "[Pay now](https://evil-pay.top/p) ![](https://evil-pay.top/seen.png) <b>x</b>"
HOSTILE = build_eml(
    subject="Invoice %s %s" % (OSC_CLIPBOARD, LURE),
    sender='"Micro\x1b[2J\x1b]8;;https://evil.top/\x07SOFT" <billing@evil-pay.top>',
    html='<a href="https://evil-pay.top/login">https://microsoft.com</a>',
    attachments=[(b"MZ", "application", "octet-stream", "invoice‮fdp.exe")])


def own_colour_removed(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# ------------------------------------------------------------ output injection --

def test_attacker_text_cannot_drive_the_terminal():
    a = triage_bytes(HOSTILE)
    for rendered in (console.render(a, console.Palette(True), verbose=True),
                     console.render_quiet(a, console.Palette(True)),
                     console.render_batch_table([a, a], console.Palette(True))):
        assert "\x1b" not in own_colour_removed(rendered) and "\x07" not in rendered
    assert "\\x1b]52;c;" in console.render(a, console.Palette(False))  # shown, not executed


def test_a_right_to_left_override_is_named_not_obeyed():
    a = triage_bytes(HOSTILE)
    assert "invoice<U+202E>fdp.exe" in console.render(a, console.Palette(False))
    assert "invoice&lt;U+202E&gt;fdp.exe" in html.render([a])
    assert "T1036.002" in a.techniques  # the detection still sees the real name


def test_the_markdown_ticket_has_no_live_links_images_or_html():
    note = markdown.render(triage_bytes(HOSTILE))
    subject_line = next(line for line in note.splitlines() if line.startswith("| **Subject**"))
    assert "](" not in subject_line and "<b>" not in subject_line and "https://" not in subject_line
    assert "hxxps://evil-pay.top/p" in subject_line


def test_csv_cells_carry_no_control_characters():
    out = csvout.render([triage_bytes(HOSTILE)])
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)


# ------------------------------------------------------- forged authentication --

MX = ("Authentication-Results", "mx.acme-labs.example; spf=fail smtp.mailfrom=evil.top; dkim=none")
RECEIVED = ("Received", "from evil.top by mx.acme-labs.example; Tue, 29 Sep 2026 10:00:00 +0000")


def test_a_pass_forged_below_the_receivers_results_is_ignored_and_flagged():
    forged = ("Authentication-Results", "mx.acme-labs.example; spf=pass; dkim=pass; dmarc=pass")
    a = triage_bytes(build_eml(headers=[MX, RECEIVED, forged]))
    assert a.auth == {"spf": "fail", "dkim": "none"}
    labels = [(s.severity, s.label) for s in a.signals if "Authentication-Results" in s.label]
    assert labels == [("medium", "forged Authentication-Results: spf=pass, dkim=pass, dmarc=pass claimed in "
                                 "the name of mx.acme-labs.example, below that server's real results (ignored)")]


def test_an_upstream_servers_pass_is_ignored_but_only_noted():
    upstream = ("Authentication-Results", "relay.partner.example; dmarc=pass")
    a = triage_bytes(build_eml(headers=[MX, RECEIVED, upstream]))
    assert "dmarc" not in a.auth
    assert [s.severity for s in a.signals if "Authentication-Results" in s.label] == ["low"]


def test_one_header_per_check_from_the_same_server_is_read_in_full():
    proton = [("Authentication-Results", "mailin1.protonmail.ch; dkim=pass header.d=a.example"),
              ("Authentication-Results", "mailin1.protonmail.ch; dmarc=none"),
              ("Authentication-Results", "mailin1.protonmail.ch; spf=pass smtp.mailfrom=a.example"), RECEIVED]
    assert triage_bytes(build_eml(headers=proton)).auth == {"dkim": "pass", "dmarc": "none", "spf": "pass"}


def test_trusted_authserv_believes_only_your_own_server():
    forged_only = [RECEIVED, ("Authentication-Results", "mx.google.com; spf=pass; dkim=pass; dmarc=pass")]
    assert triage_bytes(build_eml(headers=forged_only)).auth["dmarc"] == "pass"  # nothing to compare with
    trusted = Options(trusted_authserv=["mx.acme-labs.example"])
    assert triage_bytes(build_eml(headers=forged_only), options=trusted).auth == {}


# ------------------------------------------------------------ unwrap evasion --

def test_a_phish_carrying_a_harmless_attached_message_is_still_caught():
    inner = EmailMessage()
    inner["From"], inner["Subject"] = "colleague@acme-labs.example", "Lunch?"
    inner.set_content("Lunch on Friday?")
    outer = EmailMessage()
    outer["From"] = '"Microsoft 365" <no-reply@micros0ft-verify.top>'
    outer["To"], outer["Subject"] = "victim@acme-labs.example", "Your password expires today"
    outer.set_content("Your password expires today. Keep it: https://micros0ft-verify.top/login")
    outer.add_attachment(inner)
    a = triage_bytes(outer.as_bytes())
    assert a.subject == "Lunch?"  # the attached message is still what is shown...
    assert a.verdict != "NO STRONG INDICATORS"  # ...but the carrier's findings count
    assert any(s.label.startswith("carrier email: ") for s in a.signals)
    assert any("micros0ft-verify.top" in u.url for u in a.urls)


def test_a_genuine_report_gains_nothing_from_the_reporters_note():
    a = triage_file(sample("sample_reported.eml"))
    assert a.reported_by and not any(s.label.startswith("carrier email") for s in a.signals)


# ---------------------------------------------------------- lookalike evasion --

@pytest.mark.parametrize("domain, method", [
    ("paypal-com.top", "combosquat"), ("www-paypal.com", "combosquat"),
    ("paypalcom.top", "combosquat"), ("micros-oft.com", "typosquat"),
])
def test_spelled_out_and_hyphen_split_names_are_found(domain, method):
    assert ("microsoft.com" if "micro" in domain else "paypal.com", method) in \
        [(h.target, h.method) for h in find_lookalikes(domain, "url", [])]


def test_a_hyphen_split_own_domain_is_found():
    hits = find_lookalikes("examplecorp.co.uk", "sender", ["example-corp.co.uk"])
    assert [(h.target, h.method) for h in hits] == [("example-corp.co.uk", "typosquat")]


# ------------------------------------------------------------ hostile files --

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_fifos_devices_and_huge_files_are_skipped_quickly(tmp_path, capsys):
    os.mkfifo(tmp_path / "fifo.eml")
    (tmp_path / "zero.eml").symlink_to("/dev/zero")
    (tmp_path / "big.eml").write_bytes(b"\0" * (2 * 1024 * 1024 + 1))
    with open(sample("sample_benign.eml"), "rb") as handle:
        (tmp_path / "ok.eml").write_bytes(handle.read())
    started = time.perf_counter()
    assert main([str(tmp_path), "--offline", "--no-color", "--quiet", "--max-size", "2"]) == 3
    assert time.perf_counter() - started < 20
    captured = capsys.readouterr()
    assert "big.eml: skipped, larger than 2 MB" in captured.err
    assert "== " in captured.out  # the regular file was still analysed
    assert main([str(tmp_path / "zero.eml"), "--offline", "--no-color"]) == 3
    assert "not a regular file" in capsys.readouterr().err


def test_a_hostile_path_is_printed_inert(tmp_path, capsys):
    main([str(tmp_path / "\x1b]52;c;cHduZWQ=\x07.eml"), "--offline", "--no-color"])
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\\x1b]52" in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_lookup_cache_is_private(tmp_path):
    path = tmp_path / "cache" / "lookups.sqlite3"
    Cache(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_a_link_flood_is_fast_and_flagged():
    flood = "".join('<a href="https://h%d.example/p">x</a>' % i for i in range(6000))
    started = time.perf_counter()
    a = triage_bytes(build_eml(html=flood))
    assert time.perf_counter() - started < 15
    assert any("distinct link hosts" in s.label for s in a.signals)


# ------------------------------------------------------------ privacy --

def test_urlscan_submissions_carry_no_recipient_addresses():
    a = parse_bytes(build_eml(to="Victim <Victim@Acme-Labs.example>"))
    b64 = base64.b64encode(b"victim@acme-labs.example").decode()
    assert redact_recipients("https://kit.top/l?e=Victim@Acme-Labs.example", a) == "https://kit.top/l?e=user@example.com"
    assert redact_recipients("https://kit.top/l?e=victim%40acme-labs.example", a).endswith("user%40example.com")
    assert b64 not in redact_recipients("https://kit.top/#" + b64, a)
    assert redact_recipients("https://kit.top/l?cc=boss@acme-labs.example", a).endswith("user@example.com")
    assert redact_recipients("https://kit.top/l?x=crook@evil.top", a).endswith("crook@evil.top")
