import io
import json
import sys

import pytest

from phishtriage.cache import Cache
from phishtriage.cli import main

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


def test_clear_cache(tmp_path, capsys):
    path = str(tmp_path / "c.sqlite3")
    Cache(path).set("x", {"v": 1})
    assert main(["--clear-cache", "--cache-path", path]) == 0
    assert "cleared 1" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [[], ["x.eml", "--json", "-", "--csv", "-"], ["x.eml", "--html", "-"]])
def test_argument_errors(argv):
    with pytest.raises(SystemExit) as error:
        main(argv + ["--offline"])
    assert error.value.code == 2
