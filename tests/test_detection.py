"""Detections added after evaluating against real phishing (phishing_pot)
and legitimate mail. Each test names the real-world pattern it covers."""

import base64
import time
import zlib

import pytest

from phishhawk.extract import unwrap_link, urls_from_pdf
from phishhawk.hosting import hosting_kind
from phishhawk.models import Analysis, Signal
from phishhawk.parse import parse_bytes
from phishhawk.pipeline import triage_bytes

from conftest import build_eml


def labels(a):
    return [s.label for s in a.signals]


def has(a, fragment):
    return any(fragment in label for label in labels(a))


# --------------------------------------------------------------- robustness --


def test_pathological_bodies_parse_in_linear_time():
    """A 100 KB base64 image in an HTML body once made the address regex
    quadratic: one real sample took 60 s. Attacker-shaped input must not."""
    blob = "A" * 300_000
    html = ('<img src="data:image/png;base64,%s">' % blob) + "<" * 50_000 + ("a." * 20_000)
    started = time.perf_counter()
    parse_bytes(build_eml(text=blob, html=html))
    assert time.perf_counter() - started < 3


def test_pdf_bomb_is_capped():
    bomb = b"%PDF-1.7\nstream\n" + zlib.compress(b"\0" * 60_000_000) + b"\nendstream\n"
    started = time.perf_counter()
    assert urls_from_pdf(bomb) == []
    assert time.perf_counter() - started < 3


def test_links_inside_compressed_pdf_streams_are_found():
    body = b"<< /A << /S /URI /URI (https://hidden.example/pdf-link) >> >>"
    pdf = b"%PDF-1.7\n1 0 obj << /Filter /FlateDecode >>\nstream\n" + zlib.compress(body) + b"\nendstream\n"
    assert urls_from_pdf(pdf) == ["https://hidden.example/pdf-link"]


# ------------------------------------------------------- wrappers/redirects --


@pytest.mark.parametrize(
    "wrapped, inner, kind",
    [
        (
            "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top%2Fx&data=1",
            "https://evil.top/x",
            "gateway",
        ),
        ("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.top_x&d=1", "https://evil.top/x", "gateway"),
        ("https://urldefense.com/v3/__https://evil.top/x__;!!abc", "https://evil.top/x", "gateway"),
        ("https://www.google.com/url?q=https://evil.top/x&sa=D", "https://evil.top/x", "redirect"),
        ("https://www.google.com/amp/s/evil.top/x", "https://evil.top/x", "redirect"),
        (
            "https://www.bing.com/ck/a?!&&u=a1"
            + base64.urlsafe_b64encode(b"https://evil.top/x").decode().rstrip("="),
            "https://evil.top/x",
            "redirect",
        ),
        ("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.top%2Fx", "https://evil.top/x", "redirect"),
    ],
)
def test_unwrap_link(wrapped, inner, kind):
    got = unwrap_link(wrapped)
    assert got and got[0] == inner and got[2] == kind


@pytest.mark.parametrize("url", ["https://www.google.com/search?q=cats", "https://example.com/?url=https://x.top"])
def test_ordinary_links_are_not_unwrapped(url):
    assert unwrap_link(url) is None


def test_safe_links_are_analysed_as_the_original_url():
    wrapped = "https://eur02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top%2Flogin&data=05"
    a = parse_bytes(build_eml(text="Keep your password: " + wrapped))
    assert [u.url for u in a.urls] == ["https://evil.top/login"]
    assert "via Microsoft Safe Links" in a.urls[0].sources[0]


def test_open_redirect_on_a_trusted_domain_is_flagged():
    a = triage_bytes(build_eml(text="Sign in: https://www.google.com/amp/s/m365-verify.top/login"))
    assert has(a, "Google AMP hides the real destination: m365-verify[.]top")
    assert {"www.google.com", "m365-verify.top"} <= {u.host for u in a.urls}


# ------------------------------------------------------------------ hosting --


@pytest.mark.parametrize(
    "url, kind",
    [
        ("https://secure-check.web.app/login", "free hosting"),
        ("https://x.pages.dev/", "free hosting"),
        ("https://bucket.s3.amazonaws.com/a.html", "free hosting"),
        ("https://abc.trycloudflare.com/", "tunnel or IPFS"),
        ("https://ipfs.io/ipfs/bafy123/login.html", "tunnel or IPFS"),
        ("https://drive.google.com/uc?id=1abc", "file sharing"),
        ("https://docs.google.com/forms/d/e/1/viewform", "file sharing"),
        ("https://docs.google.com/document/d/1", ""),
        ("https://www.google.com/", ""),
    ],
)
def test_hosting_kind(url, kind):
    assert hosting_kind(url) == kind


def test_file_sharing_url_is_an_ioc_but_its_domain_is_not():
    a = triage_bytes(
        build_eml(
            subject="Verify your account",
            sender='"X" <x@gmail.com>',
            text="Verify your account now: https://drive.google.com/uc?id=1abc&export=download "
            "or your account will be suspended",
        )
    )
    values = {(i["type"], i["value"]) for i in a.iocs()}
    assert ("url", "https://drive.google.com/uc?id=1abc&export=download") in values
    assert not any(t == "domain" and "google" in v for t, v in values)


# ------------------------------------------------------------------ sender --


def test_freemail_sender_with_an_organisation_name():
    a = triage_bytes(build_eml(sender='"Caixa Tem - Protocolo 1865" <ogbf@gmail.com>'))
    assert has(a, "reads as an organisation but the address is free-mail (gmail.com)")


def test_brand_hidden_by_punctuation_in_display_name():
    a = triage_bytes(build_eml(sender='"Trust-Wallet" <alerts@alquiaga.example>'))
    assert has(a, "display name claims 'trustwallet'")


def test_subject_brand_with_credential_ask_and_foreign_links_is_high():
    a = triage_bytes(
        build_eml(
            subject="Microsoft account unusual sign-in activity",
            sender="<x@notify.example>",
            text="Unusual sign-in detected. Review: https://thema214.example/track",
        )
    )
    signal = next(s for s in a.signals if "poses as a microsoft notice" in s.label)
    assert signal.severity == "high"


def test_genuine_brand_alert_from_the_brand_is_quiet():
    a = triage_bytes(
        build_eml(
            subject="Microsoft account unusual sign-in activity",
            sender='"Microsoft account team" <no-reply@microsoft.com>',
            text="If this was you, ignore this. Review: https://account.live.com/Activity",
        )
    )
    assert a.verdict == "NO STRONG INDICATORS"


def test_inline_forward_recovers_the_original_sender():
    text = (
        "Is this real?\n\n---------- Forwarded message ---------\nFrom: PayPal Security <alert@paypa1.example>\n"
        "Date: Mon, 1 Sep 2026\nSubject: Account limited\n\nVerify: https://paypa1.example/verify\n"
    )
    a = triage_bytes(build_eml(subject="Fwd: Account limited", text=text))
    assert a.forwarded_from["address"] == "alert@paypa1.example"
    assert has(a, "forwarded original: display name claims 'paypal'")


# ---------------------------------------------------------------- language --


def test_letter_spacing_obfuscation_is_seen_through():
    text = (
        "T h e I d e n t i t y o f y o u r w a l l e t h a s n o t b e e n v e r i f i e d. "
        "v e r i f y y o u r a c c o u n t"
    )
    a = triage_bytes(build_eml(text=text))
    assert has(a, "text split into single letters")
    assert has(a, "credential lure wording: verify your account")


def test_callback_phishing_without_any_link():
    text = (
        "Your subscription has been renewed for USD 399.99. If you did not authorize this charge, "
        "call us at +1 (888) 555-0142 to cancel this order."
    )
    a = triage_bytes(build_eml(sender='"Geek Squad" <orders.7@gmail.com>', text=text))
    assert has(a, "callback-phishing pattern")
    assert a.verdict != "NO STRONG INDICATORS"


def test_qr_code_lure():
    png = b"\x89PNG\r\n\x1a\nfake"
    a = triage_bytes(
        build_eml(
            text="Scan the QR code below with your phone to re-enrol MFA.",
            attachments=[(png, "image", "png", "qr.png", "inline")],
        )
    )
    assert has(a, "QR-code lure")


def test_freemail_payment_request_is_bec():
    a = triage_bytes(
        build_eml(
            sender='"Ben Carter" <ben.c19@gmail.com>', text="I need an urgent payment made today, reply asap."
        )
    )
    assert has(a, "free-mail sender asks for money")
    assert a.verdict == "SUSPICIOUS"


def test_email_address_greeting_and_subject_token():
    a = triage_bytes(
        build_eml(
            subject="Notificação - Valores a Receber - qWrUAngJaLJzBndSE",
            text="Dear rodrigo.f@hotmail.com, your funds are ready.",
        )
    )
    assert has(a, "greets the recipient by email address")
    assert has(a, "random token in subject")


def test_devanagari_joiners_are_not_obfuscation():
    a = triage_bytes(build_eml(text="क्‍ष त्र‌य"))
    assert a.zero_width_chars == 0
    assert not has(a, "zero-width") and not has(a, "single letters")


# ----------------------------------------------------------------- scoring --


def test_weak_signals_alone_never_reach_suspicious():
    a = Analysis(path="x")
    for label in ("no Authentication-Results header present", "Return-Path differs", "no URLs", "urgency", "tld"):
        a.signals.append(Signal("low", label))
    assert a.score == 3 and a.verdict == "NO STRONG INDICATORS"


def test_one_high_signal_is_suspicious_two_is_likely():
    a = Analysis(path="x", signals=[Signal("high", "a")])
    assert a.verdict == "SUSPICIOUS"
    a.signals.append(Signal("high", "b"))
    assert a.verdict == "LIKELY PHISHING"


def test_tld_swap_is_medium_not_high():
    a = triage_bytes(build_eml(sender="<ceo@example-corp.com>", to="me@example-corp.co.uk"))
    swap = next(s for s in a.signals if "tld-swap" in s.label)
    assert swap.severity == "medium"
