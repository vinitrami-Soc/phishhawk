"""Filter-evasion tricks added in 2.0, each measured on the phishing_pot
tuning set before it was scored: hidden text, look-alike letters, IP
addresses written as numbers, script links and forged brand senders."""

import pytest

from phishhawk.extract import canonical_host, domain_of_address, host_of, is_ip, parse_html, parse_ipv4, usable_url
from phishhawk.pipeline import triage_bytes

from conftest import build_eml


def labels(a):
    return [s.label for s in a.signals]


def severity(a, fragment):
    return [s.severity for s in a.signals if fragment in s.label]


# ------------------------------------------------------ IPs written as numbers --

@pytest.mark.parametrize("written", ["3232235777", "0xC0A80101", "0300.0250.1.1", "192.168.257", "0xc0.0xa8.1.1"])
def test_every_spelling_of_an_ipv4_address_is_read(written):
    assert parse_ipv4(written) == "192.168.1.1"
    assert host_of("http://%s/login" % written) == "192.168.1.1"


@pytest.mark.parametrize("host", ["example.com", "123.com", "08.1.1.1", "4294967296", "1.2.3.4.5", "a.1", ""])
def test_names_are_not_mistaken_for_addresses(host):
    assert parse_ipv4(host) == ""


def test_ipv6_hosts_are_kept():
    assert canonical_host("2001:DB8:0:0::1") == "2001:db8::1"
    assert is_ip("2001:db8::1") and usable_url("http://[2001:db8::1]/x")
    assert not is_ip("2001:db8::zz")


def test_a_disguised_ip_is_flagged_twice():
    a = triage_bytes(build_eml(text="Sign in: http://3232235777/owa/login"))
    ioc = a.urls[0]
    assert ioc.host == "192.168.1.1"
    assert any("written as 3232235777" in note for note in ioc.notes)
    assert severity(a, "disguises the IP address") == ["high"]
    assert a.verdict == "LIKELY PHISHING"


# --------------------------------------------------------------- hidden text --

def test_hidden_text_inside_words_is_seen():
    html = ('<p>Your Micro<span style="font-size:0">qz</span>soft acc<span style="display: none '
            '!important">zz</span>ount is locked</p>')
    found = parse_html(html)
    assert found.hidden_splits == 2 and found.visible_text == "Your Microsoft account is locked"
    a = triage_bytes(build_eml(html=html))
    assert severity(a, "hidden text breaks up words") == ["high"]


def test_words_broken_up_by_empty_tags():
    letters = '<span style="font-size:0px"></span>'.join("The Identity of your wallet")
    a = triage_bytes(build_eml(html="<p><strong>%s</strong></p>" % letters))
    assert severity(a, "words broken up with HTML tags") == ["medium"]
    bold = triage_bytes(build_eml(html="<p><b>W</b>elcome to our <i>n</i>ewsletter</p>"))
    assert not any("broken up" in label for label in labels(bold))


def test_hidden_filler_is_flagged_but_a_preview_line_is_not():
    filler = " ".join("recipe garden weather football holiday market %d" % i for i in range(60))
    a = triage_bytes(build_eml(html='<div style="display:none">%s</div><p>Your parcel is waiting.</p>' % filler))
    assert severity(a, "letters of hidden text") == ["medium"]

    preview = ('<div style="display:none;max-height:0;overflow:hidden">Your March statement is ready'
               + "&zwnj;&nbsp;" * 40 + "</div><p>Hello Anna, your March statement is ready.</p>")
    assert not any("hidden" in label for label in labels(triage_bytes(build_eml(html=preview))))


def test_a_hidden_responsive_copy_of_the_visible_text_is_not_filler():
    content = " ".join("Weekly roundup of product news, release notes and community events %d." % i
                       for i in range(20))
    html = '<div class="desktop">%s</div><div style="display:none" class="mobile">%s</div>' % (content, content)
    assert not any("hidden" in label for label in labels(triage_bytes(build_eml(html=html))))


def test_css_classes_that_hide_text_count():
    found = parse_html('<style>.x{display:none}</style><p>Shown</p><div class="y x">secret</div>')
    assert found.hidden_text == "secret" and found.visible_text == "Shown"


def test_a_hidden_preview_line_still_counts_for_lures():
    html = ('<div style="display:none">Your subscription has been renewed. Call us at +1 (808) 745-9684</div>'
            "<p>Thank you</p>")
    a = triage_bytes(build_eml(text="", html=html))
    assert any(label.startswith("callback-phishing") for label in labels(a))


# ------------------------------------------------------- look-alike letters --

def test_cyrillic_letters_in_the_display_name():
    a = triage_bytes(build_eml(sender='"МеtaМask Support" <help@wallet-help.example>'))
    assert severity(a, "imitates 'metamask' with look-alike characters") == ["high"]
    assert severity(a, "display name mixes alphabets") == ["high"]


def test_greek_and_cyrillic_words_on_their_own_are_fine():
    a = triage_bytes(build_eml(sender='"Αθηνά Παπαδοπούλου" <a@example.gr>', subject="Привет, как дела?"))
    assert not any("alphabets" in label for label in labels(a))


def test_a_capital_i_for_an_l_in_the_subject():
    a = triage_bytes(build_eml(subject="Scan your Iedger now"))
    assert severity(a, "subject spells 'ledger' as 'Iedger'") == ["high"]
    assert not any("spells" in label for label in labels(triage_bytes(build_eml(subject="Ledger statement"))))


def test_digits_for_letters_in_the_subject():
    a = triage_bytes(build_eml(subject="Your Amaz0n order is on hold"))
    assert any("spells 'amazon' as 'Amaz0n'" in label for label in labels(a))


def test_styled_unicode_and_invisible_characters_in_the_subject():
    styled = triage_bytes(build_eml(subject="💻 𝘾𝙊𝙉𝙂𝙍𝘼𝙏𝙐𝙇𝘼𝙏𝙄𝙊𝙉𝙎! You have won"))
    assert severity(styled, "styled Unicode letters") == ["medium"]
    hidden = triage_bytes(build_eml(subject="Fi​n​al wa​rn​ing"))
    assert severity(hidden, "invisible characters inside the subject") == ["medium"]


def test_lures_are_read_through_styled_letters():
    a = triage_bytes(build_eml(subject="𝗩𝗲𝗿𝗶𝗳𝘆 𝘆𝗼𝘂𝗿 𝗮𝗰𝗰𝗼𝘂𝗻𝘁 today"))
    assert any(label.startswith("credential lure wording: verify your account") for label in labels(a))


# ------------------------------------------------------------ script links --

def test_script_and_data_links():
    js = triage_bytes(build_eml(html='<a href="javascript:location=atob(\'aHR0cA==\')">Open</a>'))
    assert severity(js, "runs JavaScript") == ["medium"]
    data = triage_bytes(build_eml(html='<a href="data:text/html;base64,PGgxPkxvZ2luPC9oMT4=">View</a>'))
    assert severity(data, "page built into the link itself") == ["high"]
    harmless = triage_bytes(build_eml(html='<a href="javascript:void(0)">menu</a><a href="#top">top</a>'))
    assert not any("link runs" in label or "built into" in label for label in labels(harmless))


# --------------------------------------------------------- downloads, senders --

def test_links_to_files_that_run():
    a = triage_bytes(build_eml(html='<a href="https://files.example.net/Invoice_2291.exe">Invoice</a>'
                                    '<a href="https://files.example.net/photos.zip">Photos</a>'
                                    '<script src="https://cdn.example.net/app.js"></script>'))
    assert severity(a, "downloads a .exe file") == ["high"]
    assert severity(a, "downloads a .zip file") == ["medium"]
    assert not any(".js file" in label for label in labels(a))


def test_a_brand_domain_that_fails_authentication_is_forged():
    forged = triage_bytes(build_eml(sender='"Amazon" <no-reply@amazon.de>', headers=[
        ("Authentication-Results", "mx.example.net; spf=softfail; dkim=none; dmarc=fail header.from=amazon.de")]))
    assert severity(forged, "the From line is probably forged") == ["high"]
    genuine = triage_bytes(build_eml(sender='"Amazon" <no-reply@amazon.de>', headers=[
        ("Authentication-Results", "mx.example.net; spf=pass; dkim=pass; dmarc=pass header.from=amazon.de")]))
    assert not any("forged" in label for label in labels(genuine))
    unknown = triage_bytes(build_eml(sender="<no-reply@amazon.de>"))  # exported mail without the header
    assert not any("forged" in label for label in labels(unknown))


def test_quotes_around_a_bare_address_are_dropped():
    assert domain_of_address('service@adac.de"') == "adac.de"
    a = triage_bytes(build_eml(sender='"service@adac.de"'))
    assert a.from_domain == "adac.de"


# ----------------------------------------------------------- measured noise --

def test_word_brands_on_another_tld_are_low():
    a = triage_bytes(build_eml(sender="<list@slack.net>"))
    assert severity(a, "tld-swap lookalike of slack") == ["low"]
    risky = triage_bytes(build_eml(sender="<billing@slack.top>"))
    assert severity(risky, "tld-swap lookalike of slack") == ["medium"]


def test_a_brand_word_in_a_subdomain_alone_is_low():
    a = triage_bytes(build_eml(text="see https://outlook.4team.biz/news"))
    assert severity(a, "subdomain lookalike of outlook") == ["low"]


def test_a_lookalike_of_your_domain_asking_for_gift_cards_is_bec():
    a = triage_bytes(build_eml(sender='"Ben" <ben@northwind-traders.com>', to="dev@northwind-traders.co.uk",
                               text="I need you to buy 5 gift cards for a client, keep this confidential."))
    bec = [s for s in a.signals if s.label.startswith("business email compromise")]
    assert [s.severity for s in bec] == ["high"] and "T1657" in bec[0].techniques
