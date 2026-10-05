"""Evidence: every report names the exact bytes it analysed, and --evidence
keeps those bytes with a hash-chained custody log that can be verified."""

import hashlib
import json
import os
import stat

import pytest

from phishhawk import evidence
from phishhawk.cli import main
from phishhawk.pipeline import triage_bytes
from phishhawk.report import console, html, markdown
from phishhawk.report.common import to_dict

from conftest import build_eml, sample

OFFLINE = ["--offline", "--no-color", "--quiet"]


def _bytes(name):
    with open(sample(name), "rb") as handle:
        return handle.read()


def test_every_report_names_the_hash_of_the_bytes_analysed():
    data = _bytes("sample_phish.eml")
    analysis = triage_bytes(data, "phish.eml")
    digest = hashlib.sha256(data).hexdigest()
    assert analysis.evidence == {"sha256": digest, "sha1": hashlib.sha1(data).hexdigest(),
                                 "md5": hashlib.md5(data).hexdigest(), "size": len(data)}
    assert to_dict(analysis)["evidence"]["sha256"] == digest
    assert digest in markdown.render(analysis)
    assert digest in html.render([analysis])
    assert digest in console.render(analysis, console.Palette(False))


def test_the_hash_is_of_the_report_as_received_not_the_unwrapped_original():
    data = _bytes("sample_reported.eml")
    analysis = triage_bytes(data, "reported.eml")
    assert analysis.reported_by  # the attached original is what was analysed...
    assert analysis.evidence["sha256"] == hashlib.sha256(data).hexdigest()  # ...but the evidence is the input


def _records(directory):
    with open(os.path.join(directory, evidence.CUSTODY), encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def test_evidence_keeps_the_message_read_only_and_records_custody(tmp_path, capsys):
    data = _bytes("sample_phish.eml")
    digest = hashlib.sha256(data).hexdigest()
    report = tmp_path / "report.json"
    assert main([sample("sample_phish.eml"), *OFFLINE, "--evidence", str(tmp_path / "ev"),
                 "--json", str(report)]) == 1
    kept = tmp_path / "ev" / (digest + ".eml")
    assert kept.read_bytes() == data
    assert not os.stat(kept).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    [record] = _records(tmp_path / "ev")
    assert record["sha256"] == digest and record["file"] == digest + ".eml"
    assert record["verdict"] == "LIKELY PHISHING" and record["source"] == sample("sample_phish.eml")
    assert record["previous"] == "" and len(record["chain"]) == 64
    # The ticket carries the custody chain value, which anchors the log.
    assert json.loads(report.read_text())["evidence"]["custody"] == record["chain"]


def test_records_chain_and_a_message_seen_twice_is_kept_once(tmp_path, capsys):
    directory = str(tmp_path / "ev")
    for _ in range(2):
        main([sample("sample_phish.eml"), *OFFLINE, "--evidence", directory])
    first, second = _records(directory)
    assert second["previous"] == first["chain"] != second["chain"]
    assert sorted(os.listdir(directory)) == sorted([evidence.CUSTODY, first["file"]])
    assert evidence.verify(directory).problems == []


def test_an_outlook_msg_is_kept_as_msg(tmp_path):
    data = bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 504
    record = evidence.keep(str(tmp_path), data, "mail.msg", triage_bytes(build_eml(), "x.eml"))
    assert record["file"].endswith(".msg")


def test_verify_accepts_an_untouched_log(tmp_path, capsys):
    directory = str(tmp_path / "ev")
    main([sample("sample_phish.eml"), sample("sample_benign.eml"), *OFFLINE, "--evidence", directory])
    result = evidence.verify(directory)
    assert result.problems == [] and result.records == 2
    assert result.head == _records(directory)[-1]["chain"]
    assert main(["evidence", "verify", directory, "--no-color"]) == 0
    assert result.head in capsys.readouterr().out


def _two_records(tmp_path):
    directory = str(tmp_path / "ev")
    main([sample("sample_phish.eml"), sample("sample_benign.eml"), *OFFLINE, "--evidence", directory])
    return directory, os.path.join(directory, evidence.CUSTODY)


def test_verify_catches_an_edited_record(tmp_path, capsys):
    directory, log = _two_records(tmp_path)
    with open(log, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    record = json.loads(lines[0])
    record["verdict"] = "NO STRONG INDICATORS"
    lines[0] = json.dumps(record)
    with open(log, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    assert any("record 1" in problem for problem in evidence.verify(directory).problems)
    assert main(["evidence", "verify", directory, "--no-color"]) == 1


def test_verify_catches_a_deleted_record(tmp_path):
    directory, log = _two_records(tmp_path)
    with open(log, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    with open(log, "w", encoding="utf-8") as handle:
        handle.write(lines[1] + "\n")
    assert any("record 1" in problem for problem in evidence.verify(directory).problems)


def test_verify_catches_a_changed_or_missing_message(tmp_path):
    directory, _ = _two_records(tmp_path)
    first, second = _records(directory)
    changed = os.path.join(directory, first["file"])
    os.chmod(changed, 0o600)
    with open(changed, "ab") as handle:
        handle.write(b"tampered")
    os.remove(os.path.join(directory, second["file"]))
    problems = evidence.verify(directory).problems
    assert any(first["file"] in p and "does not match" in p for p in problems)
    assert any(second["file"] in p and "missing" in p for p in problems)


def test_verify_reports_a_broken_line_instead_of_crashing(tmp_path):
    directory, log = _two_records(tmp_path)
    with open(log, "a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    assert any("record 3" in problem for problem in evidence.verify(directory).problems)


def test_a_planted_file_under_the_evidence_name_is_not_trusted(tmp_path, capsys):
    data = _bytes("sample_phish.eml")
    directory = tmp_path / "ev"
    directory.mkdir()
    (directory / (hashlib.sha256(data).hexdigest() + ".eml")).write_bytes(b"something else")
    assert main([sample("sample_phish.eml"), *OFFLINE, "--evidence", str(directory)]) == 3
    assert "does not match" in capsys.readouterr().err


def test_a_symlink_in_place_of_the_message_is_refused(tmp_path, capsys):
    data = _bytes("sample_phish.eml")
    directory = tmp_path / "ev"
    directory.mkdir()
    target = tmp_path / "elsewhere"
    os.symlink(target, directory / (hashlib.sha256(data).hexdigest() + ".eml"))
    assert main([sample("sample_phish.eml"), *OFFLINE, "--evidence", str(directory)]) == 3
    assert not target.exists()


def test_verify_of_a_folder_without_a_log_fails(tmp_path, capsys):
    assert main(["evidence", "verify", str(tmp_path), "--no-color"]) == 1
    assert "no custody log" in capsys.readouterr().out


def test_the_schema_describes_the_evidence_block():
    jsonschema = __import__("pytest").importorskip("jsonschema")
    schema_path = os.path.join(os.path.dirname(__file__), "..", "docs", "report.schema.json")
    with open(schema_path, encoding="utf-8") as handle:
        schema = json.load(handle)
    report = json.loads(json.dumps(to_dict(triage_bytes(_bytes("sample_phish.eml"), "phish.eml"))))
    report["evidence"].update(file="a" * 64 + ".eml", custody="b" * 64)
    jsonschema.validate(report, schema)
    report["evidence"]["sha256"] = "not a hash"
    with __import__("pytest").raises(jsonschema.ValidationError):
        jsonschema.validate(report, schema)


# ------------------------------------------------- 2.2 independent review --

def _non_utf8_folder(tmp_path):
    folder = tmp_path / "in"
    folder.mkdir()
    name = os.fsdecode(b"Rechnung_\xfc.eml")
    with open(os.path.join(str(folder), name), "wb") as handle:
        handle.write(_bytes("sample_phish.eml"))
    return folder


def test_a_file_name_that_is_not_utf8_is_kept_and_reported(tmp_path, capsys):
    folder = _non_utf8_folder(tmp_path)
    report = tmp_path / "r.json"
    code = main([str(folder), *OFFLINE, "--evidence", str(tmp_path / "ev"), "--json", str(report)])
    captured = capsys.readouterr()
    assert code == 1 and "Traceback" not in captured.err and "could not" not in captured.err
    [record] = _records(tmp_path / "ev")
    assert record["source"].endswith("Rechnung_\\xfc.eml")
    assert json.loads(report.read_text())["path"].endswith("Rechnung_\\xfc.eml")


def test_campaign_reports_name_such_files_too(tmp_path, capsys):
    folder = _non_utf8_folder(tmp_path)
    assert main(["campaign", str(folder), "--json", str(tmp_path / "c.json"), "--md", str(tmp_path / "c.md"),
                 "--csv", str(tmp_path / "c.csv"), "--no-color"]) == 0
    [message] = json.loads((tmp_path / "c.json").read_text())["unclustered"]
    assert message["path"].endswith("Rechnung_\\xfc.eml")


def _rewrite_from(directory, first, change):
    """What someone able to write the folder can do: change record `first`
    and recompute every link after it."""
    path = os.path.join(directory, evidence.CUSTODY)
    records = _records(directory)
    change(records[first])
    previous = records[first - 1]["chain"] if first else ""
    for record in records[first:]:
        record["previous"] = previous
        record["chain"] = evidence._link(previous, record)
        previous = record["chain"]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(r) + "\n" for r in records))


def test_a_head_put_in_a_ticket_exposes_a_rewritten_log(tmp_path, capsys):
    directory = str(tmp_path / "ev")
    main([sample("sample_phish.eml"), sample("sample_benign.eml"), *OFFLINE, "--evidence", directory])
    head = _records(directory)[-1]["chain"]
    assert main(["evidence", "verify", directory, "--head", head, "--no-color"]) == 0
    _rewrite_from(directory, 0, lambda r: r.update(verdict="NO STRONG INDICATORS"))
    assert evidence.verify(directory).problems == []  # consistent again: the chain alone cannot tell
    assert main(["evidence", "verify", directory, "--head", head, "--no-color"]) == 1
    assert "not in the log" in capsys.readouterr().out


def test_every_record_is_checked_against_its_message(tmp_path):
    directory = str(tmp_path / "ev")
    for _ in range(2):
        main([sample("sample_phish.eml"), *OFFLINE, "--evidence", directory])
    _rewrite_from(directory, 1, lambda r: r.update(sha256="0" * 64))
    assert any(p.startswith("record 2") and "SHA-256" in p for p in evidence.verify(directory).problems)


def test_a_record_naming_a_file_with_a_trailing_newline_is_invalid(tmp_path):
    directory = str(tmp_path / "ev")
    main([sample("sample_phish.eml"), *OFFLINE, "--evidence", directory])
    _rewrite_from(directory, 0, lambda r: r.update(file=r["file"] + "\n"))
    assert any("names no valid evidence file" in p for p in evidence.verify(directory).problems)


def test_a_write_that_fails_halfway_leaves_no_message_behind(tmp_path, monkeypatch):
    real_write = os.write

    def full_disk(fd, data):
        if len(data) > 1000:
            raise OSError(28, "No space left on device")
        return real_write(fd, data)
    monkeypatch.setattr(evidence.os, "write", full_disk)
    data = _bytes("sample_phish.eml")
    with pytest.raises(OSError):
        evidence.keep(str(tmp_path), data, "x.eml", triage_bytes(data, "x.eml"))
    assert os.listdir(tmp_path) == []
    monkeypatch.setattr(evidence.os, "write", real_write)
    evidence.keep(str(tmp_path), data, "x.eml", triage_bytes(data, "x.eml"))  # and the next run is not blocked
    assert evidence.verify(str(tmp_path)).problems == []
