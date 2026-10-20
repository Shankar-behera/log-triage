"""On-disk cache + persistent recent-results buffer.

Cache path defaults to ~/.cache/log-triage/cache.db (XDG-aware) so the CLI
works cleanly from any directory without littering ./data/ in the CWD.
"""
import hashlib
import json
import os
import sqlite3
import time
import threading
# import stat
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import settings


class ResultCache:
    MAX_CACHE_ENTRIES = 1000
    MAX_RECENT_RESULTS = 50

    _LEGACY_PAYLOAD_KEYS = frozenset(
        {
            "events",
            "raw",
            "timeline",
            "root_cause_signals",
            "cascading_failures",
        }
    )

    def __init__(self, db_path: Optional[str] = None, enabled: Optional[bool] = None):
        """Initialize the cache.

        `enabled` overrides settings.CACHE_ENABLED when provided - tests
        use this to force-enable caching even when the global config
        disables it for other tests.
        """
        self.enabled = settings.CACHE_ENABLED if enabled is None else enabled
        self.ttl_seconds = settings.CACHE_TTL_HOURS * 3600

        if db_path:
            self.db_path = Path(db_path)
        elif settings.CACHE_DB_PATH:
            self.db_path = Path(settings.CACHE_DB_PATH)
        else:
            base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
            self.db_path = base / "log-triage" / "cache.db"

        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            try:
                os.chmod(self.db_path.parent, 0o700)
                if not self.db_path.exists():
                    fd = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(fd)
            except OSError:
                pass
        self._init_db()
        if os.name == "posix":
            try: os.chmod(self.db_path, 0o600)
            except OSError: pass
        self._purge_legacy_entries()

    @classmethod
    def _contains_legacy_payload(cls, value: Any) -> bool:
        """Return whether JSON contains a prohibited payload key."""
        if isinstance(value, dict):
            for key, child in value.items():
                if (
                    isinstance(key, str)
                    and key.casefold() in cls._LEGACY_PAYLOAD_KEYS
                ):
                    return True
                if cls._contains_legacy_payload(child):
                    return True
        elif isinstance(value, list):
            return any(
                cls._contains_legacy_payload(item) for item in value
            )

        return False

    def _purge_legacy_entries(self) -> None:
        """Remove legacy cache rows that may contain full event payloads."""
        try:
            with self._connect() as conn:
                for table in ("analysis_cache", "recent_results"):
                    rows = conn.execute(
                        f"SELECT rowid, result_json FROM {table}"
                    ).fetchall()

                    for row in rows:
                        try:
                            payload = json.loads(row["result_json"])
                        except (TypeError, ValueError):
                            # An unreadable cache payload cannot be verified safe.
                            should_delete = True
                        else:
                            should_delete = self._contains_legacy_payload(
                                payload
                            )

                        if should_delete:
                            conn.execute(
                                f"DELETE FROM {table} WHERE rowid = ?",
                                (row["rowid"],),
                            )

                conn.commit()
        except sqlite3.Error:
            # Cache cleanup remains best-effort if SQLite is unavailable.
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    cache_key TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recent_results (
                    analysis_id TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_recent_created ON recent_results(created_at DESC)"
            )
            conn.commit()

    @staticmethod
    def make_key(log_text: str, analysis_type: str, model: str, temperature: float) -> str:
        payload = f"{model}|{temperature}|{analysis_type}|{log_text}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json, created_at FROM analysis_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
            if row is None:
                return None
            if time.time() - row["created_at"] > self.ttl_seconds:
                conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (cache_key,))
                conn.commit()
                return None
            conn.execute(
                "UPDATE analysis_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                (cache_key,),
            )
            conn.commit()
            return json.loads(row["result_json"])

    def set(self, cache_key: str, result: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO analysis_cache (cache_key, result_json, created_at, hit_count)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(cache_key) DO UPDATE SET
                    result_json = excluded.result_json,
                    created_at = excluded.created_at
            """, (cache_key, json.dumps(result, default=str), time.time()))
            conn.execute("""
                DELETE FROM analysis_cache
                WHERE cache_key IN (
                    SELECT cache_key FROM analysis_cache
                    ORDER BY created_at ASC
                    LIMIT MAX(0, (SELECT COUNT(*) FROM analysis_cache) - ?)
                )
            """, (self.MAX_CACHE_ENTRIES,))
            conn.commit()

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS entries, COALESCE(SUM(hit_count), 0) AS total_hits FROM analysis_cache"
            ).fetchone()
            recent = conn.execute("SELECT COUNT(*) AS n FROM recent_results").fetchone()
            return {
                "entries": row["entries"],
                "total_cache_hits": row["total_hits"],
                "recent_results_stored": recent["n"],
                "enabled": self.enabled,
            }

    def clear(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM analysis_cache")
            conn.commit()
            return cur.rowcount

    def store_recent(self, analysis_id: str, result: Dict[str, Any]) -> None:
        # The recent-results buffer is a compact UI summary, not an event store.
        # Do not persist event lists, raw log lines, timelines, or source evidence.
        if not self.enabled:
            return
        safe_result = {
            key: value for key, value in result.items()
            if key not in {"events", "raw", "timeline", "root_cause_signals", "cascading_failures"}
        }
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO recent_results (analysis_id, result_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET result_json = excluded.result_json
            """, (analysis_id, json.dumps(safe_result, default=str), time.time()))
            conn.execute("""
                DELETE FROM recent_results
                WHERE analysis_id NOT IN (
                    SELECT analysis_id FROM recent_results
                    ORDER BY created_at DESC LIMIT ?
                )
            """, (self.MAX_RECENT_RESULTS,))
            conn.commit()

    def get_recent(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json FROM recent_results WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            return json.loads(row["result_json"]) if row else None


class _LazyResultCache:
    """Defer cache filesystem side effects until cache use."""
    def __init__(self):
        self._instance = None
        self._lock = threading.Lock()
    def _get(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = ResultCache()
        return self._instance
    def __getattr__(self, name):
        return getattr(self._get(), name)
    def _reset(self):
        with self._lock:
            self._instance = None

result_cache = _LazyResultCache()