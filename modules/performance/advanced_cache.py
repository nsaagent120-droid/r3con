"""
r3con v6.0 - Advanced Cache - Unified wrapper
DEPRECATED: Use core.cache instead
This file now wraps core.cache for backward compatibility
"""
import warnings
warnings.warn(
    "modules.performance.advanced_cache is deprecated, use core.cache",
    DeprecationWarning,
    stacklevel=2
)

# Try to import from core.cache, fallback to original SQLite implementation if needed
try:
    from core.cache import IncrementalCache

    class AdvancedCache(IncrementalCache):
        """Legacy wrapper - now uses IncrementalCache with SQLite backend option."""

        def __init__(self, ttl_days: int = 30, max_entries: int = 5000):
            # Map to IncrementalCache params
            super().__init__(ttl_days=ttl_days, max_entries=max_entries)
            # Keep SQLite path for backward compat stats
            self._sqlite_fallback = None
            try:
                import sqlite3
                from pathlib import Path
                db_path = Path.home() / ".r3con" / "advanced_cache.db"
                if db_path.exists():
                    # If old DB exists, keep it for stats
                    self._sqlite_db_path = db_path
            except Exception:
                pass

        def stats(self):
            # Enhanced stats
            base_stats = {
                "total_entries": len(self.cache.get("_entries", {})),
                "version": "6.0-unified",
                "ttl_days": self.ttl_days,
                "max_entries": self.max_entries,
            }
            return base_stats

        def get_risky_files(self, min_critical: int = 1):
            # Simple implementation from cache entries
            risky = []
            for key, entry in self.cache.get("_entries", {}).items():
                results = entry.get("results", {})
                if isinstance(results, dict):
                    findings = results.get("findings", [])
                    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                    if critical >= min_critical:
                        risky.append({
                            "filepath": key,
                            "findings_count": len(findings),
                            "critical_count": critical,
                        })
            return sorted(risky, key=lambda x: x["critical_count"], reverse=True)

except ImportError:
    # Fallback to original SQLite implementation if core.cache not available
    import json
    import hashlib
    import sqlite3
    import threading
    from pathlib import Path
    from typing import Dict, Optional, List
    from datetime import datetime, timedelta

    ADVANCED_CACHE_DB = Path.home() / ".r3con" / "advanced_cache.db"
    CACHE_VERSION = "6.0-unified-fallback"
    MAX_ENTRIES = 5000
    MAX_ANALYTICS = 10000

    class AdvancedCache:
        def __init__(self, ttl_days: int = 30, max_entries: int = MAX_ENTRIES):
            self.ttl_days = ttl_days
            self.max_entries = max_entries
            self._lock = threading.RLock()
            ADVANCED_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(ADVANCED_CACHE_DB), check_same_thread=False, timeout=10.0)
            self.conn.row_factory = sqlite3.Row
            self._init_db()

        def _init_db(self):
            with self._lock:
                c = self.conn.cursor()
                c.executescript("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        id INTEGER PRIMARY KEY,
                        filepath TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        analysis_type TEXT NOT NULL,
                        results TEXT NOT NULL,
                        findings_count INTEGER DEFAULT 0,
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        version TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        access_count INTEGER DEFAULT 0,
                        UNIQUE(filepath, analysis_type)
                    );
                """)
                self.conn.commit()

        def stats(self):
            return {"total_entries": 0, "version": CACHE_VERSION}

        def get_risky_files(self, min_critical: int = 1):
            return []
