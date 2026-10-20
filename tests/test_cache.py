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


def test_disabled_cache_does_not_store_or_return_recent_results(tmp_path):
    import sqlite3

    db_path = tmp_path / "disabled-cache.db"
    cache = ResultCache(db_path=str(db_path), enabled=False)

    cache.store_recent("disabled-incident", {
        "summary": "must not persist",
    })

    assert cache.get_recent("disabled-incident") is None

    with sqlite3.connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM recent_results"
        ).fetchone()[0]

    assert count == 0

def test_cache_redacts_nested_secrets_and_pii(cache):
    import json

    key = ResultCache.make_key("privacy-test", "full", "model", 0.2)
    cache.set(
        key,
        {
            "summary": "Contact alice@example.com from 192.0.2.10",
            "details": [{"message": "password=hunter2"}],
        },
    )

    # Assert on the *persisted* row, not just the read path, so this
    # catches regressions in the set() sanitize-before-write step.
    with cache._connect() as conn:
        persisted = conn.execute(
            "SELECT result_json FROM analysis_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()["result_json"]

    result = json.loads(persisted)
    serialized = json.dumps(result)

    assert "alice@example.com" not in serialized
    assert "192.0.2.10" not in serialized
    assert "hunter2" not in serialized
    assert "[REDACTED_EMAIL]" in serialized
    assert "[REDACTED_IP]" in serialized


def test_recent_results_redact_nested_secrets_and_pii(cache):
    import json

    cache.store_recent(
        "privacy-recent",
        {
            "summary": "Contact alice@example.com from 192.0.2.10",
            "details": [{"message": "token=synthetic-secret"}],
        },
    )

    with cache._connect() as conn:
        persisted = conn.execute(
            "SELECT result_json FROM recent_results WHERE analysis_id = ?",
            ("privacy-recent",),
        ).fetchone()["result_json"]

    result = json.loads(persisted)
    serialized = json.dumps(result)

    assert "alice@example.com" not in serialized
    assert "192.0.2.10" not in serialized
    assert "synthetic-secret" not in serialized
    assert "[REDACTED_EMAIL]" in serialized
    assert "[REDACTED_IP]" in serialized


def test_initialization_sanitizes_existing_cache_rows_on_disk(tmp_path):
    import json
    import sqlite3
    import time
    db_path = tmp_path / "legacy-sensitive.db"

    # Create the schema before injecting rows from an older implementation.
    ResultCache(db_path=str(db_path), enabled=True)

    legacy_payload = {
        "summary": "Contact alice@example.com from 192.0.2.10; password=hunter2",
        "details": [{"message": "token=synthetic-secret"}],
    }
    raw_json = json.dumps(legacy_payload)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analysis_cache
                (cache_key, result_json, created_at, hit_count)
            VALUES (?, ?, ?, ?)
            """,
            ("legacy-key", raw_json, time.time(), 0),
        )
        conn.execute(
            """
            INSERT INTO recent_results
                (analysis_id, result_json, created_at)
            VALUES (?, ?, ?)
            """,
            ("legacy-id", raw_json, time.time()),
        )
        conn.commit()

    # Reinitialization runs the migration against both tables.
    migrated = ResultCache(db_path=str(db_path), enabled=True)

    with sqlite3.connect(db_path) as conn:
        cache_json = conn.execute(
            "SELECT result_json FROM analysis_cache WHERE cache_key = ?",
            ("legacy-key",),
        ).fetchone()[0]
        recent_json = conn.execute(
            "SELECT result_json FROM recent_results WHERE analysis_id = ?",
            ("legacy-id",),
        ).fetchone()[0]

    for persisted_json in (cache_json, recent_json):
        assert "alice@example.com" not in persisted_json
        assert "192.0.2.10" not in persisted_json
        assert "hunter2" not in persisted_json
        assert "synthetic-secret" not in persisted_json
        assert "[REDACTED_EMAIL]" in persisted_json
        assert "[REDACTED_IP]" in persisted_json
        assert "[REDACTED]" in persisted_json

    # Confirm the migrated cache remains readable.
    assert migrated.get("legacy-key")["summary"]
    assert migrated.get_recent("legacy-id")["summary"]
def test_cache_sanitization_preserves_distinct_safe_keys(cache):
    key = ResultCache.make_key("key-compatibility", "full", "model", 0.2)

    cache.set(
        key,
        {
            "summary": "First result",
            "details": "Second result",
        },
    )

    result = cache.get(key)

    assert result is not None
    assert result["summary"] == "First result"
    assert result["details"] == "Second result"


def test_cache_sanitization_does_not_silently_drop_colliding_keys(cache):
    import json

    key = ResultCache.make_key("key-collision-test", "full", "model", 0.2)
    cache.set(
        key,
        {
            "alice@example.com": "first value",
            "bob@example.com": "second value",
        },
    )

    with cache._connect() as conn:
        persisted = conn.execute(
            "SELECT result_json FROM analysis_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()["result_json"]

    result = json.loads(persisted)

    # Both values must survive, while the original email keys stay private.
    assert len(result) == 2
    assert set(result.values()) == {"first value", "second value"}
    assert "alice@example.com" not in persisted
    assert "bob@example.com" not in persisted
    assert "[REDACTED_EMAIL]" in result
    assert "[REDACTED_EMAIL]#2" in result
