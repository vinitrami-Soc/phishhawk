"""2.1: an optional full public suffix list. Without one, PhishHawk keeps its
built-in approximation; with one, a registrable domain is what the list
says, wildcards and exceptions included. Expected values are the Public
Suffix List's own test vectors (publicsuffix.org/list/tests.txt)."""

import pytest

from phishhawk import extract
from phishhawk.cli import main
from phishhawk.pipeline import triage_bytes

from conftest import build_eml

LIST = """// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
// *.ck with an exception for www.ck
*.ck
!www.ck
cn
公司.cn
// ===BEGIN PRIVATE DOMAINS===
github.io
"""


@pytest.fixture
def psl(tmp_path):
    path = tmp_path / "public_suffix_list.dat"
    path.write_text(LIST, encoding="utf-8")
    yield path
    extract.use_public_suffixes(None)  # back to the built-in approximation for every other test


@pytest.mark.parametrize("host, registrable", [
    ("example.com", "example.com"),
    ("www.example.co.uk", "example.co.uk"),
    ("b.test.ck", "b.test.ck"),
    ("a.b.test.ck", "b.test.ck"),
    ("www.ck", "www.ck"),
    ("www.www.ck", "www.ck"),
    ("phish.github.io", "phish.github.io"),
    ("a.phish.github.io", "phish.github.io"),
    ("shop.example.xn--55qx5d.cn", "example.xn--55qx5d.cn"),
    ("shishi.公司.cn", "shishi.公司.cn"),  # a host in Unicode meets the same rule
    ("www.食狮.公司.cn", "食狮.公司.cn"),
    ("a.b.example.unknowntld", "example.unknowntld"),
])
def test_a_loaded_list_decides_the_registrable_domain(psl, host, registrable):
    assert extract.load_public_suffixes(str(psl)) == 8  # com uk co.uk *.ck !www.ck cn 公司.cn github.io
    assert extract.registrable_domain(host) == registrable


def test_without_a_list_the_built_in_approximation_stays(psl):
    assert extract.registrable_domain("a.phish.github.io") == "github.io"
    extract.load_public_suffixes(str(psl))
    extract.use_public_suffixes(None)
    assert extract.registrable_domain("a.phish.github.io") == "github.io"


def test_a_lookalike_on_shared_hosting_is_its_own_domain(psl, tmp_path, capsys):
    raw = build_eml(html='<a href="https://paypal-billing.github.io/login">Log in to PayPal</a>')
    (tmp_path / "mail.eml").write_bytes(raw)
    main(["scan", str(tmp_path / "mail.eml"), "--offline", "-q", "--no-color", "--json",
          str(tmp_path / "r.json"), "--psl", str(psl)])
    report = (tmp_path / "r.json").read_text()
    assert "paypal-billing.github.io" in report and '"combosquat"' in report


def test_the_list_can_come_from_the_config_file_or_the_environment(psl, tmp_path, monkeypatch):
    settings = tmp_path / "config.json"
    settings.write_text('{"public_suffix_list": "%s"}' % str(psl).replace("\\", "\\\\"))
    assert main(["scan", "--config", str(settings), str(tmp_path / "missing.eml"), "--offline", "-q"]) == 3
    assert extract.registrable_domain("a.phish.github.io") == "phish.github.io"
    extract.use_public_suffixes(None)
    monkeypatch.setenv("PHISHHAWK_PSL", str(psl))
    main(["scan", str(tmp_path / "missing.eml"), "--offline", "-q"])
    assert extract.registrable_domain("a.phish.github.io") == "phish.github.io"


def test_an_unreadable_list_is_a_clear_error(tmp_path, capsys):
    code = main(["scan", str(tmp_path), "--offline", "-q", "--no-color", "--psl", str(tmp_path / "nope.dat")])
    assert code == 3 and "public suffix list" in capsys.readouterr().err


def test_a_list_with_no_rules_is_refused(tmp_path):
    empty = tmp_path / "empty.dat"
    empty.write_text("// nothing here\n")
    with pytest.raises(ValueError):
        extract.load_public_suffixes(str(empty))
    assert extract.registrable_domain("a.phish.github.io") == "github.io"


def test_detection_is_unchanged_without_a_list():
    raw = build_eml(html='<a href="https://paypal-billing.github.io/login">Log in to PayPal</a>')
    methods = {hit.method for hit in triage_bytes(raw).lookalikes}
    assert "combosquat" not in methods  # github.io is one domain to the approximation


def test_doctor_checks_the_list(psl, tmp_path, monkeypatch, capsys):
    # A list named in the config file or the environment that cannot be read
    # stops every scan, so doctor says so before a scan does.
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setenv("PHISHHAWK_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("PHISHHAWK_PSL", raising=False)
    main(["doctor", "--no-color"])
    out = capsys.readouterr().out
    assert "--    Public suffixes" in out and "built-in approximation" in out
    monkeypatch.setenv("PHISHHAWK_PSL", str(psl))
    assert main(["doctor", "--no-color"]) == 0
    assert "OK    Public suffixes    %s  (8 rules)" % psl in capsys.readouterr().out
    monkeypatch.setenv("PHISHHAWK_PSL", str(tmp_path / "nope.dat"))
    assert main(["doctor", "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  Public suffixes" in out and "cannot read the public suffix list" in out


def test_a_host_of_thousands_of_labels_is_cheap(psl):
    # Every label was tried as the start of a rule, each with a join of the
    # rest: quadratic, 5 s to triage a message with five such links.
    import time

    extract.load_public_suffixes(str(psl))
    host = "a." * 20_000 + "phish.github.io"
    started = time.perf_counter()
    assert extract.registrable_domain(host) == "phish.github.io"
    assert extract.registrable_domain("x." * 20_000 + "b.test.ck") == "b.test.ck"
    assert time.perf_counter() - started < 0.5
