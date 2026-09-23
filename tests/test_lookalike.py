import pytest

from phishhawk.lookalike import decode_idna, edit_distance, find_lookalikes, skeletons


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
