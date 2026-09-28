import pytest

from phishhawk.lookalike import (
    decode_idna,
    edit_distance,
    find_lookalikes,
    one_edit_apart,
    skeletons,
    strong_subdomain,
)


@pytest.mark.parametrize("domain, protected, target, method", [
    ("micros0ft-verify-support.top", [], "microsoft.com", "homoglyph"),
    ("paypa1.com", [], "paypal.com", "homoglyph"),
    ("xn--pypal-4ve.com", [], "paypal.com", "homoglyph"),          # Cyrillic 'а'
    ("micosoft-login.com", [], "microsoft.com", "typosquat"),
    ("microsoft.com.account-verify.top", [], "microsoft.com", "subdomain"),
    ("dhl-parcel-tracking.top", [], "dhl.com", "combosquat"),
    ("examp1e-corp.co.uk", ["example-corp.co.uk"], "example-corp.co.uk", "homoglyph"),
    ("exmaple-corp.co.uk", ["example-corp.co.uk"], "example-corp.co.uk", "typosquat"),
    ("example-corp.com", ["example-corp.co.uk"], "example-corp.co.uk", "tld-swap"),
    ("example-corp-payroll.com", ["example-corp.co.uk"], "example-corp.co.uk", "combosquat"),
    ("rnicrosoft.com", [], "microsoft.com", "homoglyph"),           # 'rn' reads as 'm'
    ("outlooksecure.com", [], "outlook.com", "combosquat"),         # name + lure word, no separator
    ("paypal-billing-update.com", [], "paypal.com", "combosquat"),
    ("taxascorreios756.com", [], "correios.com.br", "combosquat"),  # Portuguese lure word + digits
    ("slack.net", [], "slack.com", "tld-swap"),
    ("outlook.4team.biz", [], "outlook.com", "subdomain"),          # still reported, at medium
])
def test_lookalikes_are_found(domain, protected, target, method):
    hits = find_lookalikes(domain, "url", protected)
    assert (target, method) in [(h.target, h.method) for h in hits]


@pytest.mark.parametrize("domain, protected", [
    ("login.microsoftonline.com", []),
    ("billing.example-corp.co.uk", ["example-corp.co.uk"]),
    ("metadata-labs.io", []),        # 'meta' only matches as a whole token
    ("startups.com", []),            # 'ups' likewise
    ("cloudflare.com", []),          # 'cl'->'d' is a variant, never a rewrite
    ("groups.io", []),
    ("mail-secure-recovery.xyz", []),
    ("185.243.115.22", []),
    ("", []),
    # Seen on real legitimate mail (SpamAssassin ham): a name inside another
    # name, or a brand's own country site, is not a lookalike.
    ("linuxmafia.com", ["linux.ie"]),
    ("linux-laptop.net", ["linux.ie"]),
    ("taintedmelodies.com", ["taint.org"]),
    ("shagmail.com", []),
    ("yahoogroups.com", []),
    ("watchingmicrosoftlikeahawk.com", []),
    ("storage.googleapis.com", []),
    ("yahoo.co.uk", []),
    ("santander.com.br", []),
    ("enigmail.mozdev.org", []),
])
def test_legitimate_domains_stay_quiet(domain, protected):
    assert find_lookalikes(domain, "url", protected) == []


def test_edit_distance_counts_transpositions_as_one():
    assert edit_distance("microsoft", "micosoft") == 1
    assert edit_distance("abcd", "abdc") == 1
    assert edit_distance("short", "a-much-longer-string", limit=2) == 3


def test_idna_and_skeletons():
    assert decode_idna("xn--pypal-4ve") != "xn--pypal-4ve"
    assert "microsoft" in skeletons("micr0s0ft")


def test_one_edit_apart_matches_edit_distance():
    for a, b in (("paypal", "paypa"), ("paypal", "paypall"), ("paypal", "papyal"), ("paypal", "paypxl"),
                 ("paypal", "paypal"), ("paypal", "pyapla"), ("", "a"), ("ab", "ba"), ("abc", "cab")):
        assert one_edit_apart(a, b) == (edit_distance(a, b, 1) == 1), (a, b)


def test_brand_in_subdomain_is_only_strong_with_something_else_wrong():
    assert strong_subdomain("microsoft.com.account-verify.top", "microsoft.com")
    assert strong_subdomain("ups.usa.butss.shop", "ups.com")            # high-abuse TLD
    assert strong_subdomain("paypal.secure-login-check.com", "paypal.com")  # credential word
    assert not strong_subdomain("outlook.4team.biz", "outlook.com")
    assert not strong_subdomain("outlook.iowastate.edu", "outlook.com")  # 'owa' inside a word
    assert strong_subdomain("outlook.owa-mail.com", "outlook.com")       # 'owa' as a token
