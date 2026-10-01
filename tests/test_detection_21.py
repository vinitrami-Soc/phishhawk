"""2.1 detection changes: independent evidence decides LIKELY PHISHING, weak
findings of one kind count once, and the false positives found in 2.0's
evaluation are fixed. The tests of new behaviour fail on 2.0.0; the rest
guard what the change must leave alone (a brand's own country domain, a
disguised Latin word, your own domain)."""

import json
import os
import time

import pytest

from phishhawk.models import Analysis, signal_kind
from phishhawk.pipeline import triage_bytes
from phishhawk.report.common import to_dict

from conftest import build_eml

SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "report.schema.json")


def _analysis(*signals):
    a = Analysis(path="x")
    for severity, label, family in signals:
        a.add_signal(severity, label, (), family)
    return a


# ------------------------------------------------------------------ verdicts --

def test_a_high_signal_backed_by_another_part_of_the_message_is_likely_phishing():
    a = _analysis(("high", "display name claims 'paypal' but the domain is x[.]top", "sender"),
                  ("medium", "shortened link: hxxp://bit[.]ly/x", "link"))
    assert a.score == 5 and a.corroborated and a.verdict == "LIKELY PHISHING"


def test_two_views_of_the_same_header_are_not_independent():
    a = _analysis(("high", "DMARC=fail", "auth"), ("medium", "DKIM=none", "auth"))
    assert not a.corroborated and a.verdict == "SUSPICIOUS"


def test_signals_without_a_family_never_corroborate():
    # Signals added by hand (by a plugin or an old caller) keep the 2.0 rules.
    a = _analysis(("high", "custom high", ""), ("medium", "custom medium", ""))
    assert a.verdict == "SUSPICIOUS"


def test_three_kinds_of_medium_evidence_make_likely_phishing():
    a = _analysis(("medium", "SPF=none", "auth"), ("medium", "shortened link: hxxp://bit[.]ly/x", "link"),
                  ("medium", "prize lure wording: you have won, claim your", "content"),
                  ("low", "greets the recipient by email address instead of by name", "content"))
    assert a.score == 7 and a.verdict == "SUSPICIOUS"  # below 8: still only suspicious
    a.add_signal("low", "recipient's address pasted into the subject (mail-merge lure)", (), "content")
    assert a.score == 8 and a.verdict == "LIKELY PHISHING"


def test_weak_findings_of_one_kind_count_once():
    a = _analysis(("medium", "link text/href mismatch: news[.]com shown, click[.]news[.]net real", "link"),
                  ("low", "credential-harvesting path on www[.]comics[.]com", "link"),
                  ("low", "credential-harvesting path on www[.]dilbert[.]com", "link"))
    assert signal_kind(a.signals[1].label) == signal_kind(a.signals[2].label)
    assert a.score == 3 and a.verdict == "NO STRONG INDICATORS"  # 2.0 scored 4: suspicious


def test_the_kind_of_a_huge_label_is_found_in_linear_time():
    # Labels quote the message; "\\S+[.]\\S+" over a long unbroken run is quadratic.
    started = time.perf_counter()
    kind = signal_kind("credential-harvesting path on " + "a" * 200_000)
    assert time.perf_counter() - started < 1 and kind.startswith("credential-harvesting path on")


def test_the_family_is_in_the_json_report_and_the_schema_allows_it():
    jsonschema = pytest.importorskip("jsonschema")
    raw = build_eml(sender='"PayPal" <service@paypal-billing.top>', text="Verify your account: https://bit.ly/x")
    report = json.loads(json.dumps(to_dict(triage_bytes(raw))))
    assert {s["family"] for s in report["signals"]} >= {"sender"}
    with open(SCHEMA, encoding="utf-8") as handle:
        jsonschema.validate(report, json.load(handle))


# ------------------------------------------------------------- the sender --

@pytest.mark.parametrize("sender, shown", [
    ('"Netflix" <"info@members.netflix.com">', "info@members[.]netflix[.]com"),
    ('"ADAC" <"service@adac.de">', "service@adac[.]de"),
])
def test_a_whole_address_in_quotes_with_no_domain_is_flagged(sender, shown):
    a = triage_bytes(build_eml(sender=sender))
    labels = [s.label for s in a.signals if s.severity == "high"]
    assert any("quoted name (%s) with no domain of its own" % shown in label for label in labels)


def test_a_quoted_address_in_front_of_the_real_domain_is_flagged():
    a = triage_bytes(build_eml(sender='"x" <"billing@bank.example"@evil.top>'))
    assert any("hides its real domain evil[.]top behind a quoted address" in s.label for s in a.signals)


def test_the_quoted_address_check_is_linear():
    # Two whitespace runs back to back ("\\s*(@...)?\\s*$") split a long run of
    # spaces every possible way before giving up: minutes for 50,000 spaces.
    from phishhawk.parse import _QUOTED_ADDRESS_RE

    started = time.perf_counter()
    assert _QUOTED_ADDRESS_RE.match('"a@b.example"' + " " * 50_000 + "x") is None
    assert time.perf_counter() - started < 1
    assert _QUOTED_ADDRESS_RE.match('"a@b.example" @ evil.top  ').groups() == ("a@b.example", "evil.top")
    assert _QUOTED_ADDRESS_RE.match('"a@b.example"  ').groups() == ("a@b.example", None)
    started = time.perf_counter()
    assert not list(_QUOTED_ADDRESS_RE.finditer(" " * 50_000 + "x"))  # nor wherever a search starts
    assert time.perf_counter() - started < 1


def test_an_ordinary_quoted_display_name_is_not_flagged():
    a = triage_bytes(build_eml(sender='"Smith, Jane" <jane@corp.example>'))
    assert not any("quoted" in s.label for s in a.signals)


def test_a_sender_on_free_web_hosting_is_flagged():
    a = triage_bytes(build_eml(sender="GLS <no-reply@svepdev.firebaseapp.com>"))
    assert any(s.severity == "medium" and "free web hosting (svepdev[.]firebaseapp[.]com)" in s.label
               for s in a.signals)


@pytest.mark.parametrize("sender", ['"PayPal" <service@paypal.de>', '"Amazon" <order@amazon.co.jp>',
                                    '"Lidl" <news@lidl.fr>', '"IKEA" <news@ikea.de>'])
def test_a_brand_on_its_own_country_domain_is_not_an_impersonation(sender):
    a = triage_bytes(build_eml(sender=sender))
    assert not any("display name claims" in s.label for s in a.signals)


@pytest.mark.parametrize("sender, brand", [('"PayPal" <service@paypal.top>', "paypal"),
                                           ('"PayPal" <service@paypal.co>', "paypal"),
                                           ('"Temu" <deals@promo-mail.top>', "temu"),
                                           ('"Social Security Administration" <info@cwtwebpem.com>',
                                            "socialsecurity"),
                                           ('"Banco do Brasil" <aviso@atendimento.com.br>', "bancodobrasil")])
def test_a_brand_elsewhere_is_still_an_impersonation(sender, brand):
    a = triage_bytes(build_eml(sender=sender))
    assert any("display name claims '%s'" % brand in s.label for s in a.signals)


def test_short_new_brands_do_not_match_inside_other_names():
    # "temu" is inside Temuco, a Chilean city.
    a = triage_bytes(build_eml(sender='"Turismo Temuco" <info@temuco.cl>'))
    assert not any("temu" in s.label for s in a.signals)
    assert not a.lookalikes


# ------------------------------------------- 2.0's evaluation false positives --

def test_a_foreign_name_with_one_stray_latin_letter_is_not_a_disguise():
    # 2.0 flagged a Russian display name typed with one Latin "a".
    a = triage_bytes(build_eml(sender='"Анна Атиковa" <anna@mail.example>'))
    assert not any("mixes alphabets" in s.label for s in a.signals)


@pytest.mark.parametrize("name", ["МеtaМask Support", "Ꮮеdgеr", "Оsmоѕіѕ zоnе"])
def test_latin_words_with_borrowed_letters_are_still_flagged(name):
    a = triage_bytes(build_eml(sender='"%s" <x@mail.example>' % name))
    assert any("display name mixes alphabets" in s.label for s in a.signals)


def test_a_misdecoded_subject_is_not_filter_evasion():
    # Big5 decoded as Latin-1: soft hyphens between symbols, not inside words.
    subject = "4d8119¡@(¤j ÉawÄ­Ñ±M ¤j®­»¡"
    a = triage_bytes(build_eml(subject=subject))
    assert not any("invisible characters" in s.label for s in a.signals)


def test_soft_hyphens_and_zero_width_characters_inside_words_are_still_counted():
    a = triage_bytes(build_eml(subject="Pay­Pal: con​firm your account"))
    assert any("2 invisible characters inside the subject" in s.label for s in a.signals)


@pytest.mark.parametrize("to", ["friend@yahoo.com.tw", "someone@example.net", "a@hotmail.fr"])
def test_free_mail_and_documentation_domains_are_not_guessed_as_yours(to):
    a = triage_bytes(build_eml(to=to))
    assert a.protected_domains == []


def test_your_own_domain_is_still_guessed_from_the_recipients():
    a = triage_bytes(build_eml(to="staff@example-corp.co.uk"))
    assert a.protected_domains == ["example-corp.co.uk"]


def test_a_sign_in_word_in_an_image_address_is_not_a_credential_page():
    html = '<p>Hi</p><img src="https://cdn.news.example/login/banner.gif">'
    a = triage_bytes(build_eml(html=html))
    assert not any("credential-harvesting path" in s.label for s in a.signals)
    html = '<p>Hi</p><a href="https://evil.example/login/verify">Open</a>'
    a = triage_bytes(build_eml(html=html))
    assert any("credential-harvesting path" in s.label for s in a.signals)


# -------------------------------------------------------------- lure words --

@pytest.mark.parametrize("text, category", [
    ("WICHTIG: Zustellproblem mit Ihrem Paket", "delivery"),
    ("Gefeliciteerd! Je bent geselecteerd voor een beloning", "prize"),
    ("Seu pedido está retido. Pague a taxa de entrega", "delivery"),
    ("Willkommensbonus: keine Einzahlung erforderlich", "gambling"),
])
def test_lure_wording_in_more_languages(text, category):
    a = triage_bytes(build_eml(subject=text[:40], text=text))
    assert any(s.label.startswith("%s lure wording" % category) for s in a.signals)


def test_the_html_report_states_the_rule_that_decided():
    from phishhawk.report import html

    a = _analysis(("medium", "SPF=none", "auth"), ("medium", "shortened link: hxxp://bit[.]ly/x", "link"),
                  ("medium", "prize lure wording: you have won, claim your", "content"),
                  ("low", "greets the recipient by email address instead of by name", "content"),
                  ("low", "recipient's address pasted into the subject (mail-merge lure)", "content"))
    assert a.verdict == "LIKELY PHISHING" and not any(s.severity == "high" for s in a.signals)
    page = html.render([a])
    assert "also needs a high-severity signal," not in page  # not since 2.1: three kinds of evidence do too
    assert "a high-severity signal or three independent kinds of evidence" in page
    assert "3 parts of the message" in page
