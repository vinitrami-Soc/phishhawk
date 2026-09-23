from phishhawk.cache import Cache


def test_round_trip_and_ttl(tmp_path):
    now = [1000.0]
    cache = Cache(str(tmp_path / "c.sqlite3"), ttl_hours=1, clock=lambda: now[0])
    cache.set("k", {"status": "ok", "n": 1})
    assert cache.get("k") == {"status": "ok", "n": 1}
    assert cache.hits == 1
    now[0] += 3601
    assert cache.get("k") is None


def test_persists_across_instances(tmp_path):
    path = str(tmp_path / "nested" / "c.sqlite3")
    Cache(path).set("k", {"v": 1})
    assert Cache(path).get("k") == {"v": 1}


def test_purge(tmp_path):
    cache = Cache(str(tmp_path / "c.sqlite3"))
    cache.set("a", {})
    cache.set("b", {})
    assert cache.purge() == 2
    assert cache.get("a") is None


def test_unusable_path_disables_quietly(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    cache = Cache(str(blocker / "sub" / "c.sqlite3"))  # parent is a file
    assert cache.enabled is False
    cache.set("k", {"v": 1})
    assert cache.get("k") is None
    assert Cache(None).enabled is False
