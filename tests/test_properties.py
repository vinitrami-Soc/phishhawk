"""Properties that must hold for any input, checked with Hypothesis. The
example counts are kept small so CI stays fast; the standalone fuzzer runs
the same targets for hours (see docs/SECURITY-REVIEW.md)."""

import contextlib
import json
import re

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import filebuild as fb  # noqa: E402
from phishhawk.extract import URL_RE, clean_url, defang_text, parse_html, usable_url  # noqa: E402
from phishhawk.formats import archives, disk, lnk, mailparts, msg  # noqa: E402
from phishhawk.formats.cfb import CompoundFile  # noqa: E402
from phishhawk.indicators import find_wallets  # noqa: E402
from phishhawk.pipeline import triage_bytes  # noqa: E402
from phishhawk.report import console, csvout, html, markdown, misp, stix  # noqa: E402
from phishhawk.report.common import printable, to_dict  # noqa: E402

from conftest import build_eml  # noqa: E402

FAST = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])

HEADER_NAMES = st.sampled_from(["Subject", "From", "To", "Cc", "Reply-To", "Content-Type", "Content-Disposition",
                                "Content-Transfer-Encoding", "Received", "Authentication-Results", "Date",
                                "Message-ID", "Return-Path", "MIME-Version", "X-Originating-IP"])
NASTY = st.sampled_from(['"', "=?", "?=", "*=", "''", ";", "<", ">", "\\", "(", ")", ",", "@", "\x00", "\xff",
                         "\r\n", "\r\n ", "--b", "boundary=b", "charset=idna", "charset=undefined",
                         "filename*=utf\x00-8''a", "multipart/mixed", "message/rfc822", "base64", "https://x.top/"])
TOKENS = st.lists(st.one_of(NASTY, st.text(max_size=12)), max_size=30).map("".join)


def _render_everything(a):
    json.dumps(to_dict(a))
    html.render([a])
    markdown.render(a)
    console.render(a, console.Palette(False), verbose=True)
    csvout.render([a])
    stix.build_bundle([a])
    misp.build([a])


@FAST
@given(st.binary(max_size=3000))
def test_any_bytes_triage_and_render_without_raising(data):
    _render_everything(triage_bytes(data))


@FAST
@given(st.lists(st.tuples(HEADER_NAMES, TOKENS), max_size=12), TOKENS)
def test_hostile_headers_and_bodies_triage_and_render(headers, body):
    raw = "".join("%s: %s\r\n" % (name, value) for name, value in headers) + "\r\n" + body
    _render_everything(triage_bytes(raw.encode("utf-8", "surrogateescape")))


SEEDS = {
    "rar": fb.rar5(["a.lnk", "b/c.txt"]), "rar4": fb.rar4([("a.exe", 4)]),
    "7z": fb.seven_zip_encoded(["a.js"], coder="lzma"), "iso": fb.iso({"a.txt": b"x"}),
    "fat": fb.fat12({"a.exe": b"MZ"}), "lnk": fb.lnk(), "tnef": fb.tnef({"a.exe": b"MZ"}, "hi"),
}
READERS = {"rar": archives.list_rar, "rar4": archives.list_rar, "7z": archives.list_7z, "iso": disk.list_iso,
           "fat": disk.list_fat, "lnk": lnk.parse_lnk, "tnef": mailparts.parse_tnef}


@st.composite
def mutated(draw):
    kind = draw(st.sampled_from(sorted(SEEDS)))
    data = bytearray(SEEDS[kind])
    for _ in range(draw(st.integers(1, 8))):
        position = draw(st.integers(0, len(data)))
        choice = draw(st.integers(0, 2))
        if choice == 0 and data:
            data[min(position, len(data) - 1)] = draw(st.integers(0, 255))
        elif choice == 1:
            del data[position:position + draw(st.integers(1, 64))]
        else:
            data[position:position] = draw(st.binary(min_size=1, max_size=16))
    return kind, bytes(data)


@FAST
@given(mutated())
def test_readers_raise_only_value_error(case):
    kind, data = case
    with contextlib.suppress(ValueError):
        READERS[kind](data)


@FAST
@given(st.binary(max_size=4096))
def test_compound_file_and_outlook_readers_raise_only_value_error(tail):
    from olebuild import build_msg

    attachment = {"name": "a.txt", "data": b"z" * 5000, "mime": "text/plain"}
    base = build_msg(subject="x", body="y", attachments=[attachment])
    data = base[:512] + tail + base[512 + len(tail):]
    for reader in (msg.msg_to_bytes, CompoundFile):
        with contextlib.suppress(ValueError):
            reader(data)


@FAST
@given(st.text(max_size=300))
def test_defanged_text_holds_no_live_link(text):
    defanged = defang_text(text)
    assert not any(usable_url(clean_url(m.group(0))) for m in URL_RE.finditer(defanged))


@FAST
@given(st.text(max_size=300))
def test_printable_text_has_no_control_or_direction_characters(text):
    shown = printable(text)
    assert not re.search(r"[\x00-\x08\x0a-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]", shown)


@FAST
@given(st.text(max_size=400))
def test_clean_url_is_bounded_and_free_of_control_characters(text):
    url = clean_url("https://a.top/" + text)
    assert len(url) <= 8192 and not re.search(r"[\x00-\x1f\x7f]", url)


@FAST
@given(st.text(max_size=500))
def test_html_and_wallet_scanners_never_raise(text):
    parse_html(text)
    find_wallets(text)


@FAST
@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
def test_any_subject_and_body_round_trip_through_every_report(text):
    a = triage_bytes(build_eml(subject=" ".join(text.split())[:150] or "x", text=text))
    _render_everything(a)
