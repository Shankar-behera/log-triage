import pytest
from app.cache import ResultCache


@pytest.fixture
def cache(tmp_path):
    # enabled=True overrides conftest's CACHE_ENABLED=False
    return ResultCache(db_path=str(tmp_path / "test.db"), enabled=True)


def test_hit(cache):
    key = ResultCache.make_key("log", "full", "model", 0.2)
    cache.set(key, {"summary": "ok"})
    assert cache.get(key)["summary"] == "ok"


def test_miss(cache):
    assert cache.get("unknown") is None


def test_key_depends_on_model():
    k1 = ResultCache.make_key("log", "full", "model-a", 0.2)
    k2 = ResultCache.make_key("log", "full", "model-b", 0.2)
    assert k1 != k2


def test_key_depends_on_temperature():
    k1 = ResultCache.make_key("log", "full", "model", 0.2)
    k2 = ResultCache.make_key("log", "full", "model", 0.5)
    assert k1 != k2


def test_eviction(tmp_path):
    c = ResultCache(db_path=str(tmp_path / "evict.db"), enabled=True)
    c.MAX_CACHE_ENTRIES = 3
    for i in range(5):
        c.set(ResultCache.make_key(f"log{i}", "full", "m", 0.2), {"i": i})
    assert c.stats()["entries"] <= 3


def test_recent_persists(cache):
    cache.store_recent("abc-123", {"summary": "persisted"})
    assert cache.get_recent("abc-123")["summary"] == "persisted"


def test_recent_bounded(tmp_path):
    c = ResultCache(db_path=str(tmp_path / "recent.db"), enabled=True)
    c.MAX_RECENT_RESULTS = 5
    for i in range(10):
        c.store_recent(f"id-{i}", {"i": i})
    assert c.get_recent("id-0") is None
    assert c.get_recent("id-9") is not None


def test_disabled_returns_none(tmp_path):
    """Regression: enabled=False should be a no-op for get/set."""
    c = ResultCache(db_path=str(tmp_path / "off.db"), enabled=False)
    key = ResultCache.make_key("x", "quick", "m", 0.2)
    c.set(key, {"summary": "ignored"})
    assert c.get(key) is None