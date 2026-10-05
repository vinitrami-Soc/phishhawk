"""Authentication and alignment: which domain each check vouched for, whether
it is the sender the reader sees, and one plain verdict for the ticket."""

import json

from phishhawk.alignment import assess
from phishhawk.pipeline import triage_bytes
from phishhawk.report import console, html, markdown
from phishhawk.report.common import to_dict

from conftest import build_eml

MICROSOFT = ("mx.microsoft.com; spf=pass (sender IP is 192.0.2.7) smtp.mailfrom=bounces.mailer-esp.net; "
             "dkim=pass (signature was verified) header.d=shop.example; dmarc=pass action=none "
             "header.from=shop.example;compauth=pass reason=100")
GMAIL = ("mx.google.com; dkim=pass header.i=@news.shop.example header.s=s1 header.b=abc; "
         "spf=pass (google.com: domain of bounce@em.mailer-esp.net designates 192.0.2.7 as permitted sender) "
         "smtp.mailfrom=bounce@em.mailer-esp.net; dmarc=pass (p=REJECT sp=REJECT dis=NONE) "
         "header.from=news.shop.example")
SPOOF = ("mx.microsoft.com; spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=evil-sender.example; "
         "dkim=none (message not signed) header.d=none; dmarc=fail action=quarantine header.from=paypal.com")


def _analysis(auth, sender='"Shop" <deals@shop.example>', headers=()):
    extra = [("Authentication-Results", auth)] if auth else []
    return triage_bytes(build_eml(sender=sender, headers=extra + list(headers)), "m.eml")


def test_each_check_records_the_domain_it_vouched_for():
    a = _analysis(MICROSOFT)
    assert a.auth_checks == [
        {"method": "spf", "result": "pass", "domain": "bounces.mailer-esp.net"},
        {"method": "dkim", "result": "pass", "domain": "shop.example"},
        {"method": "dmarc", "result": "pass", "domain": "shop.example"},
    ]


def test_addresses_are_reduced_to_domains_and_comments_are_ignored():
    a = _analysis(GMAIL, sender="<deals@news.shop.example>")
    domains = {check["method"]: check["domain"] for check in a.auth_checks}
    # "domain of bounce@em.mailer-esp.net" in the comment is not what is read
    assert domains == {"dkim": "news.shop.example", "spf": "em.mailer-esp.net", "dmarc": "news.shop.example"}


def test_every_dkim_signature_is_kept():
    a = _analysis("mx.example.net; dkim=pass header.d=sendgrid.net; dkim=pass header.d=shop.example; "
                  "spf=pass smtp.mailfrom=sendgrid.net; dmarc=pass header.from=shop.example")
    assert [c["domain"] for c in a.auth_checks if c["method"] == "dkim"] == ["sendgrid.net", "shop.example"]
    dkim = assess(a)["checks"][1]
    assert dkim == {"check": "DKIM", "result": "pass", "domain": "shop.example", "aligned": True}


def test_a_claim_written_below_the_receivers_block_is_not_a_check():
    forged = ("mx.microsoft.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; "
              "dmarc=pass header.from=paypal.com")
    a = _analysis(SPOOF, sender="<service@paypal.com>", headers=[("X-Filler", "x"),
                                                                ("Authentication-Results", forged)])
    assert {c["domain"] for c in a.auth_checks} <= {"evil-sender.example", "paypal.com", ""}
    assert all(c["result"] != "pass" or c["method"] == "spf" for c in a.auth_checks)


def test_a_bulk_mailer_with_its_own_bounce_domain_still_passes():
    block = assess(_analysis(MICROSOFT))
    assert block["status"] == "pass"
    spf, dkim, dmarc = block["checks"]
    assert spf == {"check": "SPF", "result": "pass", "domain": "bounces.mailer-esp.net", "aligned": False}
    assert dkim["aligned"] is True and dmarc["result"] == "pass"
    text = " ".join(block["explanation"])
    assert "bounce address" in text and "shop.example" in text


def test_a_spoofed_brand_fails_and_says_why():
    block = assess(_analysis(SPOOF, sender='"PayPal" <service@paypal.com>'))
    assert block["status"] == "fail"
    assert block["explanation"][0].startswith("DMARC failed")
    assert "paypal.com" in block["explanation"][0]


def test_no_results_is_unknown_not_pass():
    block = assess(_analysis(""))
    assert block["status"] == "unknown"
    assert block["checks"] == []
    assert "unverified" in block["explanation"][0]


def test_without_dmarc_an_aligned_signature_decides():
    passing = assess(_analysis("mx.example.net; spf=pass smtp.mailfrom=mailer-esp.net; "
                               "dkim=pass header.d=shop.example"))
    failing = assess(_analysis("mx.example.net; spf=pass smtp.mailfrom=mailer-esp.net; "
                               "dkim=pass header.d=mailer-esp.net"))
    assert (passing["status"], failing["status"]) == ("pass", "fail")


def test_alignment_is_relaxed_to_the_organisation():
    a = _analysis("mx.example.net; dkim=pass header.d=shop.example; spf=softfail smtp.mailfrom=shop.example",
                  sender="<news@mail.news.shop.example>")
    dkim = assess(a)["checks"][1]
    assert dkim["aligned"] is True


def test_spf_without_a_domain_falls_back_to_the_return_path():
    a = _analysis("mx.example.net; spf=fail", headers=[("Return-Path", "<x@bounce.other.example>")])
    spf = assess(a)["checks"][0]
    assert spf == {"check": "SPF", "result": "fail", "domain": "bounce.other.example", "aligned": False}


def test_identities_name_a_reply_to_in_another_organisation():
    block = assess(_analysis(MICROSOFT, headers=[("Reply-To", "<pay@collect.example>")]))
    reply = [row for row in block["identities"] if row["role"] == "Reply-To"][0]
    assert reply == {"role": "Reply-To", "address": "pay@collect.example", "domain": "collect.example",
                     "same_organisation": False}
    assert any("collect.example" in sentence for sentence in block["explanation"])
    same = assess(_analysis(MICROSOFT, headers=[("Reply-To", "<help@shop.example>")]))
    assert not any("Replies" in sentence for sentence in same["explanation"])


def test_a_hostile_domain_value_is_not_kept():
    a = _analysis('mx.example.net; dkim=pass header.d=evil.example<script>alert(1)</script>; '
                  "dmarc=pass header.from=" + "a" * 400 + ".example")
    assert all(c["domain"] in ("", "evil.example") for c in a.auth_checks)


def test_every_report_shows_the_block():
    a = _analysis(SPOOF, sender='"PayPal" <service@paypal.com>')
    payload = json.loads(json.dumps(to_dict(a)))
    assert payload["authentication"]["status"] == "fail"
    assert "Authentication: FAIL" in markdown.render(a)
    assert "DMARC failed" in html.render([a])
    assert "Alignment    : FAIL" in console.render(a, console.Palette(False))


def test_the_schema_describes_the_block():
    import os

    import pytest

    jsonschema = pytest.importorskip("jsonschema")
    with open(os.path.join(os.path.dirname(__file__), "..", "docs", "report.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    payload = json.loads(json.dumps(to_dict(_analysis(MICROSOFT, headers=[("Reply-To", "<a@b.example>")]))))
    jsonschema.validate(payload, schema)
    payload["authentication"]["status"] = "maybe"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)
    payload = json.loads(json.dumps(to_dict(_analysis(MICROSOFT))))
    payload["auth_checks"][0]["result"] = 5
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)


def test_the_receivers_dmarc_failure_wins_over_relaxed_alignment():
    # A domain can demand strict alignment (aspf=s): SPF for shop.example then
    # does not cover news.shop.example, and the receiver's DMARC fails it.
    a = _analysis("mx.example.net; spf=pass smtp.mailfrom=shop.example; dkim=none; dmarc=fail "
                  "header.from=news.shop.example", sender="<deals@news.shop.example>")
    block = assess(a)
    assert block["checks"][0]["aligned"] is True
    assert block["status"] == "fail"
