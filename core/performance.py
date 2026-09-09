"""
r3con v6.1 - Performance Module PRO
Cache Redis optionnel + SQLite + metrics + parallel
"""
from __future__ import annotations
import json
import time
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

CACHE_DIR = Path.home() / ".r3con" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_DB = CACHE_DIR / "performance.db"

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


class PerformanceCache:
    """Cache performance avec SQLite + Redis optionnel."""

    def __init__(self, use_redis: bool = False, redis_url: str = "redis://localhost:6379/0"):
        self.use_redis = use_redis and HAS_REDIS
        self.redis_client = None
        self.sqlite_conn = None

        if self.use_redis:
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True, socket_timeout=2)
                self.redis_client.ping()
            except Exception:
                self.use_redis = False
                self.redis_client = None

        self._init_sqlite()

    def _init_sqlite(self):
        try:
            self.sqlite_conn = sqlite3.connect(str(SQLITE_DB), check_same_thread=False)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    created_at TEXT,
                    expires_at TEXT,
                    hits INTEGER DEFAULT 0
                )
            """)
            self.sqlite_conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task TEXT,
                    duration_ms INTEGER,
                    status TEXT,
                    timestamp TEXT
                )
            """)
            self.sqlite_conn.commit()
        except Exception:
            self.sqlite_conn = None

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        # Try Redis first
        if self.use_redis and self.redis_client:
            try:
                val = self.redis_client.get(f"r3con:{key}")
                if val:
                    return json.loads(val)
            except Exception:
                pass

        # SQLite fallback
        if self.sqlite_conn:
            try:
                cur = self.sqlite_conn.execute("SELECT value, expires_at, hits FROM cache_entries WHERE key=?", (key,))
                row = cur.fetchone()
                if row:
                    value, expires_at, hits = row
                    if expires_at:
                        try:
                            if datetime.fromisoformat(expires_at) < datetime.now():
                                self.sqlite_conn.execute("DELETE FROM cache_entries WHERE key=?", (key,))
                                self.sqlite_conn.commit()
                                return None
                        except Exception:
                            pass
                    self.sqlite_conn.execute("UPDATE cache_entries SET hits=hits+1 WHERE key=?", (key,))
                    self.sqlite_conn.commit()
                    return json.loads(value)
            except Exception:
                pass

        return None

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 3600):
        value_json = json.dumps(value)

        if self.use_redis and self.redis_client:
            try:
                self.redis_client.setex(f"r3con:{key}", ttl_seconds, value_json)
            except Exception:
                pass

        if self.sqlite_conn:
            try:
                expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
                self.sqlite_conn.execute(
                    "INSERT OR REPLACE INTO cache_entries (key, value, created_at, expires_at, hits) VALUES (?, ?, ?, ?, 0)",
                    (key, value_json, datetime.now().isoformat(), expires_at)
                )
                self.sqlite_conn.commit()
            except Exception:
                pass

    def record_metric(self, task: str, duration_ms: int, status: str = "ok"):
        if self.sqlite_conn:
            try:
                self.sqlite_conn.execute(
                    "INSERT INTO metrics (task, duration_ms, status, timestamp) VALUES (?, ?, ?, ?)",
                    (task, duration_ms, status, datetime.now().isoformat())
                )
                self.sqlite_conn.commit()
            except Exception:
                pass

    def get_stats(self) -> Dict[str, Any]:
        stats = {"backend": "redis" if self.use_redis else "sqlite", "redis_available": HAS_REDIS}
        if self.sqlite_conn:
            try:
                cur = self.sqlite_conn.execute("SELECT COUNT(*), SUM(hits) FROM cache_entries")
                row = cur.fetchone()
                stats["entries"] = row[0] if row else 0
                stats["total_hits"] = row[1] if row and row[1] else 0

                cur = self.sqlite_conn.execute("SELECT task, AVG(duration_ms), COUNT(*) FROM metrics GROUP BY task")
                metrics = {}
                for task, avg_dur, count in cur.fetchall():
                    metrics[task] = {"avg_ms": round(avg_dur, 1) if avg_dur else 0, "count": count}
                stats["metrics"] = metrics
            except Exception as e:
                stats["error"] = str(e)[:200]
        return stats

    def clear(self):
        if self.use_redis and self.redis_client:
            try:
                keys = self.redis_client.keys("r3con:*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass
        if self.sqlite_conn:
            try:
                self.sqlite_conn.execute("DELETE FROM cache_entries")
                self.sqlite_conn.commit()
            except Exception:
                pass


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


class ParallelExecutor:
    """Exécuteur parallèle avec metrics."""

    def __init__(self, max_workers: int = 4, cache: Optional[PerformanceCache] = None):
        self.max_workers = max_workers
        self.cache = cache or PerformanceCache()

    def execute_batch(self, tasks: List[Dict[str, Any]], func) -> List[Dict[str, Any]]:
        """Exécute batch avec cache + parallèle."""
        import concurrent.futures

        results = []
        to_execute = []
        cached_results = {}

        # Check cache
        for task in tasks:
            key = f"task:{hash_content(json.dumps(task, sort_keys=True))}"
            cached = self.cache.get(key)
            if cached:
                cached_results[task.get("id", str(task))] = cached
            else:
                to_execute.append(task)

        # Execute uncached
        if to_execute:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {executor.submit(func, t): t for t in to_execute}
                for future in concurrent.futures.as_completed(future_to_task):
                    task = future_to_task[future]
                    task_id = task.get("id", str(task))
                    start = time.time()
                    try:
                        result = future.result()
                        duration = int((time.time() - start) * 1000)
                        self.cache.record_metric(task.get("type", "unknown"), duration, "ok")
                        key = f"task:{hash_content(json.dumps(task, sort_keys=True))}"
                        self.cache.set(key, result, ttl_seconds=3600)
                        cached_results[task_id] = result
                    except Exception as e:
                        cached_results[task_id] = {"status": "error", "error": str(e)[:500]}

        # Return in original order
        for task in tasks:
            task_id = task.get("id", str(task))
            if task_id in cached_results:
                results.append(cached_results[task_id])

        return results
