"""2.0 workflow features: wallet and phone indicators, MISP export, the
config file with allow and block lists, YARA rules, --fail-on, and reading
a mailbox over IMAP without changing it."""

import copy
import imaplib
import json
import sys

import pytest

from olebuild import build_msg
from phishhawk import cli, config, knowledge, lookalike
from phishhawk.indicators import find_wallets
from phishhawk.pipeline import Options, triage_bytes
from phishhawk.report import misp, stix
from phishhawk.report.common import REPORT_VERSION, to_dict

from conftest import build_eml, sample

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


@pytest.fixture(autouse=True)
def pristine_knowledge():
    """Config can add brands and lures; every test starts from the built-in lists."""
    brands, lures = copy.deepcopy(knowledge.BRANDS), copy.deepcopy(knowledge.LURES)
    yield
    knowledge.BRANDS.clear()
    knowledge.BRANDS.update(brands)
    knowledge.LURES.clear()
    knowledge.LURES.update(lures)
    knowledge.extend()


def labels(a):
    return [s.label for s in a.signals]


def raw_sample(name):
    with open(sample(name), "rb") as handle:
        return handle.read()


# ---------------------------------------------------------------- indicators --

def test_wallets_are_only_real_addresses():
    text = "Send 0.1 BTC to %s. Tracking: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb 0x%s" % (GENESIS, "0" * 40)
    assert find_wallets(text) == [{"currency": "bitcoin", "address": GENESIS}]
    assert find_wallets("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")[0]["currency"] == "bitcoin"


def test_a_sextortion_wallet_is_a_high_signal_and_an_indicator():
    a = triage_bytes(build_eml(text="I recorded you through your webcam. Pay $1500 to my bitcoin wallet %s "
                                    "within 48 hours." % GENESIS))
    assert any(label.startswith("asks for payment to a bitcoin wallet") for label in labels(a))
    assert {"type": "crypto-wallet", "value": GENESIS, "context": "bitcoin wallet in the message"} in a.iocs()


def test_the_callback_number_is_an_indicator():
    a = triage_bytes(build_eml(sender='"Geek Squad" <orders.7@gmail.com>', text=(
        "Your subscription has been renewed for USD 399.99. If you did not authorize this charge, "
        "call us at +1 (888) 555-0142 to cancel this order.")))
    assert a.phones == ["+1 (888) 555-0142"]
    assert any(i["type"] == "phone" and i["value"] == "+1 (888) 555-0142" for i in a.iocs())


# --------------------------------------------------------------------- exports --

def test_misp_event():
    a = triage_bytes(raw_sample("sample_phish.eml"))
    event = misp.build([a], "red")["Event"]
    assert {"name": "tlp:red"} in event["Tag"]
    galaxy = 'misp-galaxy:mitre-attack-pattern="'
    assert any(t["name"].startswith(galaxy) and t["name"].endswith(' - T1566.002"') for t in event["Tag"])
    kinds = {(attr["type"], attr["category"]) for attr in event["Attribute"]}
    assert ("url", "Network activity") in kinds and ("ip-src", "Network activity") in kinds
    assert ("sha256", "Payload delivery") in kinds and ("filename|sha256", "Payload delivery") in kinds
    assert event["threat_level_id"] == "2" and event["Object"][0]["name"] == "email"
    assert len({attr["uuid"] for attr in event["Attribute"]}) == len(event["Attribute"])
    assert isinstance(misp.build([a, a]), list)


def test_misp_carries_wallets_and_stix_leaves_them_out():
    a = triage_bytes(build_eml(text="I hacked your device. Pay to my btc address %s" % GENESIS))
    attributes = misp.build([a])["Event"]["Attribute"]
    assert any(attr["type"] == "btc" and attr["category"] == "Financial fraud" and attr["value"] == GENESIS
               for attr in attributes)
    patterns = [o.get("pattern", "") for o in stix.build_bundle([a])["objects"]]
    assert not any(GENESIS in p for p in patterns)


def test_ipv6_indicators():
    a = triage_bytes(build_eml(text="Sign in: http://[2001:db8::7]/owa/login"))
    assert {"type": "ipv6", "value": "2001:db8::7", "context": "url host"} in a.iocs()
    patterns = [o.get("pattern", "") for o in stix.build_bundle([a])["objects"]]
    assert any("ipv6-addr:value = '2001:db8::7'" in p for p in patterns)


def test_json_report_version_and_mail_path():
    report = to_dict(triage_bytes(raw_sample("sample_phish.eml")))
    assert report["report_version"] == REPORT_VERSION
    assert report["hops"][0]["ip"] == "185.243.115.22" and report["hops"][1]["delay_seconds"] == 3


# ---------------------------------------------------------------------- config --

def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_config_from_json_and_toml(tmp_path):
    data = {"protect": ["example-corp.co.uk"], "allow_domains": ["payroll-partner.com"], "fail_on": "likely",
            "brands": {"northbank": ["northbank.co.uk"]}, "lures": {"credential": ["verifieer uw rekening"]}}
    settings = config.load(write(tmp_path, "c.json", json.dumps(data)))
    assert settings.protect == ["example-corp.co.uk"] and settings.fail_on == "likely"
    if sys.version_info >= (3, 11):
        toml = ('protect = ["example-corp.co.uk"]\nblock_domains = ["evil.example"]\n'
                '[brands]\nnorthbank = ["northbank.co.uk"]\n')
        assert config.load(write(tmp_path, "c.toml", toml)).block_domains == ["evil.example"]


@pytest.mark.parametrize("body, message", [
    ('{"protekt": []}', "unknown setting"),
    ('{"allow_domains": ["bad domain"]}', "not a domain"),
    ('{"fail_on": "sometimes"}', "fail_on"),
    ('{"max_size": -1}', "whole number"),
    ('{"lures": {"x": ["ab"]}}', "at least 4"),
    ("[1, 2]", "table of settings"),
    ("{not json", "c.json"),
])
def test_config_mistakes_are_explained(tmp_path, body, message):
    with pytest.raises(config.ConfigError, match=message):
        config.load(write(tmp_path, "c.json", body))


def test_config_is_never_read_from_the_current_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "config.json", '{"allow_domains": ["evil.example"]}')
    write(tmp_path, "phishhawk.json", '{"allow_domains": ["evil.example"]}')
    monkeypatch.delenv("PHISHHAWK_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    assert config.load().allow_domains == []


def test_configured_brands_and_lures_are_used(tmp_path):
    settings = config.parse({"brands": {"northbank": ["northbank.co.uk"]},
                             "lures": {"credential": ["verifieer uw rekening"]}})
    config.apply_knowledge(settings)
    a = triage_bytes(build_eml(sender='"Northbank Security" <alerts@northbank-secure.top>',
                               text="Verifieer uw rekening vandaag."))
    assert any("display name claims 'northbank'" in label for label in labels(a))
    assert any("credential lure wording: verifieer uw rekening" in label for label in labels(a))
    assert lookalike.find_lookalikes("northbank-login.top", "url")


def test_allow_and_block_lists():
    raw = build_eml(sender="<payroll@examp1e-partner.com>", to="dev@example-corp.co.uk",
                    text="See https://evil-cdn.example/x and https://examp1e-partner.com/pay")
    plain = triage_bytes(raw)
    allowed = triage_bytes(raw, options=Options(allow_domains=["examp1e-partner.com"],
                                                block_domains=["evil-cdn.example"]))
    assert any("examp1e-partner" in i["value"] for i in plain.iocs()) or plain.verdict == "NO STRONG INDICATORS"
    assert not any("examp1e-partner" in i["value"] for i in allowed.iocs())
    assert any(label == "link domain evil-cdn[.]example is on your block list" for label in labels(allowed))


# ------------------------------------------------------------------------ YARA --

def test_yara_rules_run_on_files_inside_archives(tmp_path):
    pytest.importorskip("yara")
    from phishhawk import yararules

    rules = tmp_path / "rules.yar"
    rules.write_text('rule Invoice_Dropper { meta: severity = "medium" description = "dropper string" '
                     'mitre = "T1204.002, bogus" strings: $a = "WScript.Shell" condition: $a }')
    import filebuild as fb

    archive = fb.plain_zip({"run.txt": b"new ActiveXObject('WScript.Shell')"})
    a = triage_bytes(build_eml(attachments=[(archive, "application", "zip", "a.zip")]),
                     options=Options(yara=yararules.Rules(str(rules))))
    match = next(s for s in a.signals if s.label.startswith("YARA rule Invoice_Dropper matched run.txt"))
    assert match.severity == "medium" and match.techniques == ("T1204.002",)
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken {")
    with pytest.raises(yararules.YaraError):
        yararules.Rules(str(bad))


# -------------------------------------------------------------------- the CLI --

def run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_fail_on(capsys):
    phish = sample("sample_phish.eml")
    assert run(["scan", phish, "--offline", "-q", "--no-color"], capsys)[0] == 1
    assert run(["scan", phish, "--offline", "-q", "--no-color", "--fail-on", "malicious"], capsys)[0] == 0
    assert run(["scan", phish, "--offline", "-q", "--no-color", "--fail-on", "likely"], capsys)[0] == 1
    benign = sample("sample_benign.eml")
    assert run(["scan", benign, "--offline", "-q", "--no-color", "--fail-on", "suspicious"], capsys)[0] == 0


def test_misp_on_stdout_and_a_bad_config(tmp_path, capsys):
    code, out, _ = run(["scan", sample("sample_phish.eml"), "--offline", "--misp", "-"], capsys)
    assert code == 1 and json.loads(out)["Event"]["info"].startswith("Phishing: ")
    bad = write(tmp_path, "bad.json", '{"nope": 1}')
    code, _, err = run(["scan", sample("sample_phish.eml"), "--offline", "--config", bad], capsys)
    assert code == 3 and "unknown setting" in err


def test_an_outlook_file_on_the_command_line(tmp_path, capsys):
    path = tmp_path / "Invoice overdue.msg"
    path.write_bytes(build_msg(subject="Invoice overdue", sender="billing@paypa1-billing.top",
                               body="Pay at https://paypa1-billing.top/login"))
    code, out, _ = run(["scan", str(tmp_path), "--offline", "--no-color"], capsys)
    assert "Invoice overdue" in out and code == 1


# ------------------------------------------------------------------------ IMAP --

class FakeImap:
    """Records what the client asked for; serves two messages."""
    calls: list = []
    messages = {7: build_eml(subject="Unusual sign-in", sender="<alerts@m1crosoft-security.top>",
                             text="Verify your account: https://m1crosoft-security.top/login"),
                9: build_eml(subject="Lunch", text="See you at noon")}

    def __init__(self, host, port, ssl_context=None, timeout=None):
        FakeImap.calls.append(("connect", host, port, ssl_context is not None))

    def login(self, user, password):
        FakeImap.calls.append(("login", user, password))
        if password == "wrong":
            raise imaplib.IMAP4.error("AUTHENTICATIONFAILED")

    def select(self, folder, readonly=False):
        FakeImap.calls.append(("select", folder, readonly))
        return "OK", [b"2"]

    def uid(self, command, *args):
        FakeImap.calls.append(("uid", command) + args)
        if command == "SEARCH":
            return "OK", [b"7 9"]
        uid = int(args[0])
        if args[1] == "(RFC822.SIZE)":
            return "OK", [b"%d (UID %d RFC822.SIZE %d)" % (uid, uid, len(self.messages[uid]))]
        return "OK", [(b"%d (UID %d BODY[] {%d}" % (uid, uid, len(self.messages[uid])), self.messages[uid]), b")"]

    def logout(self):
        FakeImap.calls.append(("logout",))


def test_imap_reads_without_changing_anything(monkeypatch, tmp_path, capsys):
    FakeImap.calls = []
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeImap)
    monkeypatch.setenv("PHISHHAWK_IMAP_PASSWORD", "s3cret")
    out_dir = tmp_path / "reports"
    code, out, _ = run(["imap", "--host", "mail.example-corp.co.uk", "--user", "soc", "--folder",
                        "Phish reports", "--offline", "-q", "--no-color", "--out", str(out_dir)], capsys)
    assert code == 1 and "UID=7" in out and "UID=9" in out
    assert ("select", '"Phish reports"', True) in FakeImap.calls  # EXAMINE, not SELECT
    fetches = [c for c in FakeImap.calls if c[:2] == ("uid", "FETCH")]
    assert all(c[3] in ("(RFC822.SIZE)", "(BODY.PEEK[])") for c in fetches)
    assert not any(c[1] in ("STORE", "COPY", "MOVE", "EXPUNGE") for c in FakeImap.calls if c[0] == "uid")
    assert ("connect", "mail.example-corp.co.uk", 993, True) in FakeImap.calls
    written = sorted(p.name for p in out_dir.iterdir())
    assert written == ["imap-7.html", "imap-7.json", "imap-9.html", "imap-9.json"]


def test_imap_login_failure_is_an_error_not_a_crash(monkeypatch, capsys):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeImap)
    monkeypatch.setenv("PHISHHAWK_IMAP_PASSWORD", "wrong")
    code, _, err = run(["imap", "--host", "h.example", "--user", "soc", "--offline", "-q", "--no-color"], capsys)
    assert code == 3 and "login to h.example refused" in err


def test_every_sample_report_matches_the_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    import glob
    import os

    with open(os.path.join(os.path.dirname(__file__), "..", "docs", "report.schema.json")) as handle:
        schema = json.load(handle)
    jsonschema.Draft202012Validator.check_schema(schema)
    for path in sorted(glob.glob(sample("*.eml"))):
        with open(path, "rb") as handle:
            report = json.loads(json.dumps(to_dict(triage_bytes(handle.read(), path))))
        jsonschema.validate(report, schema)
