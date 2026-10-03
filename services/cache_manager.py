"""
SQLite-backed response cache with TTL.
Prevents hammering NVD/EPSS APIs for duplicate queries.
"""
import json
import sqlite3
import time
from typing import Optional, Any
from config import Config
from utils.logger import get_logger

logger = get_logger("cache")


class CacheManager:
    """
    Thread-safe(ish) SQLite cache. Each service gets its own table prefix.
    """

    def __init__(self, db_path: str = Config.CACHE_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_cache (
                    cache_key TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_service ON api_cache(service)
            """)
            conn.commit()

    def get(self, key: str, ttl_seconds: int = Config.CACHE_TTL_SECONDS) -> Optional[Any]:
        try:
            with self._connection() as conn:
                row = conn.execute(
                    "SELECT response_json, created_at FROM api_cache WHERE cache_key = ?",
                    (key,)
                ).fetchone()
                if not row:
                    return None
                age = time.time() - row["created_at"]
                if age > ttl_seconds:
                    conn.execute("DELETE FROM api_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                    return None
                return json.loads(row["response_json"])
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
            return None

    def set(self, key: str, service: str, data: Any):
        try:
            with self._connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO api_cache
                       (cache_key, service, response_json, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (key, service, json.dumps(data), time.time())
                )
                conn.commit()
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")

    def stats(self) -> dict:
        try:
            with self._connection() as conn:
                total = conn.execute("SELECT COUNT(*) FROM api_cache").fetchone()[0]
                by_service = conn.execute(
                    "SELECT service, COUNT(*) as c FROM api_cache GROUP BY service"
                ).fetchall()
                return {
                    "total_entries": total,
                    "by_service": {r["service"]: r["c"] for r in by_service},
                }
        except Exception as e:
            logger.warning(f"Cache stats error: {e}")
            return {"total_entries": 0, "by_service": {}}
