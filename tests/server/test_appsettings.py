"""Admin settings: providers, sealed keys, limits that override the
environment, and the trait key that never changes."""

import threading
import time

import pytest

from phishhawk.server import appsettings
from phishhawk.server.db import transaction
from phishhawk.server.models import Setting

from .serverkit import TEST_DATABASE


def test_a_fresh_install_is_offline(db, box, settings):
    with transaction(db) as s:
        options = appsettings.analysis_options(s, box, settings, offline=False)
    assert options.providers == frozenset() and options.keys == {}


def test_enabled_providers_and_keys_reach_the_analysis_unless_offline(db, box, settings):
    with transaction(db) as s:
        appsettings.set_value(s, "providers", ["virustotal", "rdap", "not-a-provider"])
        appsettings.set_secret(s, box, "key:virustotal", "vt-key-1234")
    with transaction(db) as s:
        options = appsettings.analysis_options(s, box, settings, offline=False)
        assert options.providers == frozenset({"virustotal", "rdap"})
        assert options.keys == {"virustotal": "vt-key-1234"}
        assert appsettings.analysis_options(s, box, settings, offline=True).providers == frozenset()


def test_keys_are_sealed_and_shown_masked(db, box, settings):
    with transaction(db) as s:
        appsettings.set_secret(s, box, "key:abuseipdb", "abuse-secret-9876")
    with transaction(db) as s:
        assert "abuse-secret" not in str(s.get(Setting, "secret:key:abuseipdb").value)
        assert appsettings.public_view(s, box, settings)["keys"]["abuseipdb"] == "...9876"


def test_a_limit_set_by_an_admin_wins_over_the_environment(db, settings):
    with transaction(db) as s:
        assert appsettings.limit(s, settings, "retention_days") == 30
        appsettings.set_value(s, "retention_days", 7)
        assert appsettings.limit(s, settings, "retention_days") == 7


def test_the_trait_key_is_made_once_and_kept(db, box):
    with transaction(db) as s:
        first = appsettings.trait_key(s, box)
    with transaction(db) as s:
        assert appsettings.trait_key(s, box) == first and len(first) == 32


@pytest.mark.skipif(not TEST_DATABASE, reason="two writers at once need Postgres")
def test_two_workers_making_the_trait_key_at_once_end_up_with_the_same_one(db, box):
    first, second = db(), db()
    found = {}

    def other_worker():
        try:
            found["key"] = appsettings.trait_key(second, box)
            second.commit()
        except Exception as exc:  # reported below, not lost in the thread
            found["error"] = exc

    try:
        mine = appsettings.trait_key(first, box)
        first.flush()  # stored but not committed: the other worker cannot see it yet
        thread = threading.Thread(target=other_worker)
        thread.start()
        time.sleep(1)  # it finds no key, makes its own and waits on the row this one holds
        first.commit()
        thread.join(30)
        assert found == {"key": mine}
    finally:
        first.close()
        second.close()
