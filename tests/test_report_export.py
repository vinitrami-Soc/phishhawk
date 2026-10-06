"""Exporting a report: one identifier in every format, file names that carry
nothing from the message, and a manifest of what a run wrote, with sizes and
SHA-256 hashes, so a copy passed along can be checked."""

import hashlib
import json
import os
import re

import pytest

from phishhawk.cli import main
from phishhawk.pipeline import triage_bytes, triage_file
from phishhawk.report import html, markdown
from phishhawk.report.common import report_id, safe_report_name, to_dict

from conftest import build_eml, sample

OFFLINE = ["--offline", "--no-color", "--quiet"]
NAME = re.compile(r"^phishhawk-(report|batch)-[0-9a-f]{12}-\d{8}\."
                  r"(html|json|md|csv|stix\.json|misp\.json|manifest\.json)$")


@pytest.fixture(scope="module")
def bec():
    return triage_file(sample("sample_bec_smuggling.eml"))


def test_one_report_id_in_every_format(bec):
    rid = report_id(bec)
    assert rid == "PH-" + bec.evidence["sha256"][:16].upper()
    assert to_dict(bec)["report_id"] == rid
    assert rid in html.render([bec]) and rid in markdown.render(bec)


def test_safe_names_carry_nothing_from_the_message(bec):
    hostile = triage_bytes(build_eml(subject="../../etc/passwd <x>.exe"), path="../evil\x00name.eml")
    for kind in ("html", "json", "md", "csv", "stix", "misp", "manifest"):
        name = safe_report_name([hostile], kind, "20261006")
        assert NAME.match(name), name
    assert safe_report_name([bec], "html", "20261006") == "phishhawk-report-%s-20261006.html" % (
        bec.evidence["sha256"][:12])
    batch = safe_report_name([bec, hostile], "json", "20261006")
    assert batch.startswith("phishhawk-batch-") and NAME.match(batch)
    assert batch == safe_report_name([hostile, bec], "json", "20261006")  # order does not matter


def test_a_directory_gets_safe_names_a_manifest_and_linked_files(bec, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    args = [sample("sample_bec_smuggling.eml"), *OFFLINE]
    for flag in ("--html", "--json", "--md", "--csv", "--manifest"):
        args += [flag, str(out)]
    assert main(args) == 1
    names = sorted(p.name for p in out.iterdir())
    assert len(names) == 5 and all(NAME.match(n) for n in names), names
    manifest_name = next(n for n in names if n.endswith(".manifest.json"))
    manifest = json.loads((out / manifest_name).read_text())
    listed = {entry["name"]: entry for entry in manifest["files"]}
    assert set(listed) == set(names) - {manifest_name}
    for name, entry in listed.items():
        data = (out / name).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest() and entry["size"] == len(data)
    assert manifest["messages"] == [{"report_id": report_id(bec), "path": sample("sample_bec_smuggling.eml"),
                                     "sha256": bec.evidence["sha256"], "size": bec.evidence["size"]}]
    # the HTML lists the files written before it, with their hashes, linked side by side
    page = (out / next(n for n in names if n.endswith(".html"))).read_text()
    panel = page.split("<h2>Report files</h2>", 1)[1].split("</section>", 1)[0]
    for name in names:
        if name.endswith((".json", ".md", ".csv")) and not name.endswith(".manifest.json"):
            assert '<a href="%s" download>%s</a>' % (name, name) in panel
            assert listed[name]["sha256"] in panel
    err = capsys.readouterr().err
    assert err.count("sha256 ") == 5  # every written file is announced with its hash


def test_a_new_directory_is_created_for_a_trailing_separator(tmp_path, capsys):
    target = str(tmp_path / "new") + os.sep
    assert main([sample("sample_benign.eml"), *OFFLINE, "--json", target]) == 0
    (name,) = os.listdir(target)
    assert NAME.match(name) and name.endswith(".json")


def test_explicit_file_names_still_work_and_are_not_linked_across_folders(tmp_path, capsys):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    page_path, json_path = tmp_path / "a" / "my report.html", tmp_path / "b" / "r.json"
    assert main([sample("sample_phish.eml"), *OFFLINE, "--json", str(json_path), "--html", str(page_path)]) == 1
    panel = page_path.read_text().split("<h2>Report files</h2>", 1)[1].split("</section>", 1)[0]
    assert "r.json" in panel and 'href="r.json"' not in panel  # another folder: named, not linked


def test_the_html_says_it_needs_no_network(bec):
    page = html.render([bec])
    assert '<span class="pill offline">' in page and "Offline report" in page
    assert "<h2>Report files</h2>" not in page  # nothing else was written
