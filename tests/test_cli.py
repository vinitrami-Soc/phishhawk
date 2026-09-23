import io
import json
import sys

import pytest

from phishhawk.cache import Cache
from phishhawk.cli import main, normalise_argv

from conftest import SAMPLES, sample

OFFLINE = ["--offline", "--no-color"]


def test_exit_codes_follow_the_verdict(capsys):
    assert main([sample("sample_benign.eml"), *OFFLINE, "--quiet"]) == 0
    assert main([sample("sample_phish.eml"), *OFFLINE, "--quiet"]) == 1
    assert main(["missing.eml", *OFFLINE]) == 3
    assert "file not found" in capsys.readouterr().err


def test_directory_input_and_batch_table(capsys):
    assert main([SAMPLES, *OFFLINE, "--quiet"]) == 1
    out = capsys.readouterr().out
    assert "BATCH SUMMARY (4 messages)" in out
    assert out.count("== ") == 4


def test_json_to_stdout_is_pure_json(capsys):
    main([sample("sample_phish.eml"), *OFFLINE, "--json", "-"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["verdict"] == "LIKELY PHISHING"
    assert "offline mode" in captured.err  # notices never pollute stdout


def test_every_output_format_is_written(tmp_path, capsys):
    paths = {kind: tmp_path / ("out." + kind) for kind in ("json", "html", "stix", "md", "csv")}
    args = [sample("sample_bec_smuggling.eml"), *OFFLINE, "--quiet"]
    for kind, path in paths.items():
        args += ["--" + kind, str(path)]
    assert main(args) == 1
    for path in paths.values():
        assert path.stat().st_size > 200
    assert json.loads(paths["stix"].read_text())["type"] == "bundle"
    assert paths["html"].read_text().startswith("<!doctype html>")


def test_stdin_input(monkeypatch, capsys):
    with open(sample("sample_phish.eml"), "rb") as handle:
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(handle.read())))
    assert main(["-", *OFFLINE, "--quiet"]) == 1
    assert "<stdin>" in capsys.readouterr().out


def test_protect_flag_turns_a_lookalike_into_bec(capsys):
    main([sample("sample_phish.eml"), *OFFLINE, "--no-auto-protect", "--protect", "micros0ft.com",
          "--json", "-"])
    payload = json.loads(capsys.readouterr().out)
    assert "micros0ft.com" in payload["protected_domains"]


def test_cache_command(tmp_path, capsys):
    path = str(tmp_path / "c.sqlite3")
    cache = Cache(path)
    cache.set("virustotal:url:x", {"v": 1})
    cache.set("rdap:domain:y", {"v": 2})
    cache.close()
    assert main(["cache", "stats", "--cache-path", path]) == 0
    assert "virustotal" in capsys.readouterr().out
    assert main(["cache", "clear", "--provider", "rdap", "--cache-path", path]) == 0
    assert "cleared 1 cached lookup(s) for rdap" in capsys.readouterr().out
    assert main(["cache", "path", "--cache-path", path]) == 0
    assert capsys.readouterr().out.strip() == path


def test_doctor_reports_missing_keys_as_warnings(monkeypatch, tmp_path, capsys):
    for name in ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert main(["doctor", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "WARN  VirusTotal key" in out and "OK    Python" in out
    monkeypatch.setenv("VT_API_KEY", "abcdefghijklmnop")
    main(["doctor", "--no-color"])
    assert "abcd…op (VT_API_KEY)" in capsys.readouterr().out  # never printed in full


def test_techniques_command_lists_every_technique(capsys):
    from phishhawk.attack import TECHNIQUES
    assert main(["techniques", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert {row["id"] for row in listed} == set(TECHNIQUES)
    assert all(row["evidence"] for row in listed)


def test_help_command_and_overview(capsys):
    assert main([]) == 0
    assert "commands:" in capsys.readouterr().out
    assert main(["help", "scan"]) == 0
    help_text = capsys.readouterr().out
    assert "exit codes:" in help_text and "VT_API_KEY" in help_text and "examples:" in help_text


@pytest.mark.parametrize("argv, expected", [
    (["mail.eml"], ["scan", "mail.eml"]),
    (["--offline", "mail.eml"], ["scan", "--offline", "mail.eml"]),
    (["-"], ["scan", "-"]),
    (["doctor"], ["doctor"]),
    (["--no-banner", "doctor"], ["--no-banner", "doctor"]),
    (["-h"], ["-h"]),
    ([], []),
])
def test_scan_is_the_default_command(argv, expected):
    assert normalise_argv(argv) == expected


@pytest.mark.parametrize("argv", [["scan"], ["x.eml", "--json", "-", "--csv", "-"], ["x.eml", "--html", "-"],
                                  ["scan", "--no-such-flag"]])
def test_argument_errors(argv):
    with pytest.raises(SystemExit) as error:
        main(argv + ["--offline"])
    assert error.value.code == 2
