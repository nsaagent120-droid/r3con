"""
r3con - Advanced Cache - FIXED P2
Fixes: thread safety, WAL mode, versioning, analytics cleanup, size limits
"""

import json
import hashlib
import sqlite3
import threading
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timedelta

ADVANCED_CACHE_DB = Path.home() / ".r3con" / "advanced_cache.db"
CACHE_VERSION = "5.0.2-fixed-p2"
MAX_ENTRIES = 5000
MAX_ANALYTICS = 10000


class AdvancedCache:
    """
    Cache avancé avec:
    - Stockage SQLite (WAL, thread-safe)
    - Indexation par hash, type, sévérité
    - Version invalidation
    - TTL + LRU
    """

    def __init__(self, ttl_days: int = 30, max_entries: int = MAX_ENTRIES):
        self.ttl_days = ttl_days
        self.max_entries = max_entries
        self._lock = threading.RLock()
        ADVANCED_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(ADVANCED_CACHE_DB), check_same_thread=False, timeout=10.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        # Enable WAL for better concurrency
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute("PRAGMA cache_size=-64000;")  # 64MB
            self.conn.execute("PRAGMA temp_store=MEMORY;")
        except sqlite3.Error:
            pass
        self._init_db()

    def _init_db(self):
        with self._lock:
            c = self.conn.cursor()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    id          INTEGER PRIMARY KEY,
                    filepath    TEXT NOT NULL,
                    file_hash   TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    results     TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count  INTEGER DEFAULT 0,
                    version     TEXT DEFAULT '',
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    access_count INTEGER DEFAULT 0,
                    UNIQUE(filepath, analysis_type)
                );

                CREATE INDEX IF NOT EXISTS idx_filepath ON cache_entries(filepath);
                CREATE INDEX IF NOT EXISTS idx_hash ON cache_entries(file_hash);
                CREATE INDEX IF NOT EXISTS idx_type ON cache_entries(analysis_type);
                CREATE INDEX IF NOT EXISTS idx_created ON cache_entries(created_at);

                CREATE TABLE IF NOT EXISTS cache_analytics (
                    id          INTEGER PRIMARY KEY,
                    filepath    TEXT NOT NULL,
                    event       TEXT NOT NULL,
                    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_analytics_ts ON cache_analytics(timestamp);

                CREATE TABLE IF NOT EXISTS cache_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            # Check version
            c.execute("SELECT value FROM cache_meta WHERE key='version'")
            row = c.fetchone()
            if row and row["value"] != CACHE_VERSION:
                # Clear old cache on version change
                c.execute("DELETE FROM cache_entries")
                c.execute("DELETE FROM cache_analytics")
            c.execute("INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('version', ?)", (CACHE_VERSION,))
            c.execute("INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('created', ?)", (datetime.now().isoformat(),))
            self.conn.commit()

    def hash_file(self, filepath: str) -> str:
        """Calculer le hash SHA256 d'un fichier."""
        h = hashlib.sha256()
        try:
            # Validate path
            if not filepath or len(filepath) > 1024 or ".." in filepath:
                return ""
            p = Path(filepath)
            if not p.exists() or not p.is_file():
                return ""
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def is_cached(self, filepath: str, analysis_type: str = 'default') -> bool:
        """Vérifier si le fichier est en cache et non expiré."""
        if not filepath or len(filepath) > 1024:
            return False

        file_hash = self.hash_file(filepath)
        if not file_hash:
            return False

        with self._lock:
            c = self.conn.cursor()
            c.execute("""
                SELECT file_hash, created_at, version FROM cache_entries
                WHERE filepath=? AND analysis_type=?
            """, (filepath, analysis_type))

            row = c.fetchone()
            if not row:
                return False

            # Version check
            if row["version"] and row["version"] != CACHE_VERSION:
                self._log_event(filepath, 'version_mismatch')
                return False

            # Hash check
            if row['file_hash'] != file_hash:
                self._log_event(filepath, 'cache_invalidated')
                return False

            # TTL check
            try:
                created = datetime.fromisoformat(row['created_at'])
                age_days = (datetime.now() - created).days
                if age_days > self.ttl_days:
                    self._log_event(filepath, 'cache_expired')
                    return False
            except (ValueError, TypeError):
                pass

            return True

    def get(self, filepath: str, analysis_type: str = 'default') -> Optional[Dict]:
        """Récupérer les résultats depuis le cache."""
        if not self.is_cached(filepath, analysis_type):
            return None

        with self._lock:
            c = self.conn.cursor()
            c.execute("""
                UPDATE cache_entries
                SET accessed_at=CURRENT_TIMESTAMP,
                    access_count=access_count+1
                WHERE filepath=? AND analysis_type=?
            """, (filepath, analysis_type))

            c.execute("""
                SELECT results FROM cache_entries
                WHERE filepath=? AND analysis_type=?
            """, (filepath, analysis_type))

            row = c.fetchone()
            if row:
                self.conn.commit()
                self._log_event(filepath, 'cache_hit')
                try:
                    return json.loads(row['results'])
                except json.JSONDecodeError:
                    return None

        return None

    def set(self, filepath: str, results: Dict, analysis_type: str = 'default'):
        """Mettre en cache les résultats."""
        if not filepath or len(filepath) > 1024:
            return

        file_hash = self.hash_file(filepath)
        if not file_hash:
            return

        # Limit results size
        try:
            results_json = json.dumps(results)
            if len(results_json) > 500 * 1024:
                if isinstance(results, dict) and "findings" in results:
                    truncated = dict(results)
                    truncated["findings"] = results["findings"][:100]
                    truncated["_truncated"] = True
                    results = truncated
        except (TypeError, ValueError):
            pass

        findings = results.get('findings', []) if isinstance(results, dict) else []
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL') if isinstance(findings, list) else 0
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH') if isinstance(findings, list) else 0

        with self._lock:
            c = self.conn.cursor()
            # Enforce max entries
            c.execute("SELECT COUNT(*) as cnt FROM cache_entries")
            cnt = c.fetchone()["cnt"]
            if cnt >= self.max_entries:
                c.execute("""
                    DELETE FROM cache_entries WHERE id IN (
                        SELECT id FROM cache_entries ORDER BY accessed_at ASC LIMIT ?
                    )
                """, (cnt - self.max_entries + 100,))

            c.execute("""
                INSERT OR REPLACE INTO cache_entries
                (filepath, file_hash, analysis_type, results,
                 findings_count, critical_count, high_count, version, created_at, accessed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (filepath, file_hash, analysis_type,
                  json.dumps(results), len(findings) if isinstance(findings, list) else 0, critical_count, high_count, CACHE_VERSION))

            self.conn.commit()
            self._log_event(filepath, 'cache_set')
            # Cleanup analytics if too large
            self._cleanup_analytics()

    def invalidate(self, filepath: str, analysis_type: str = 'default'):
        """Invalider le cache pour un fichier."""
        with self._lock:
            c = self.conn.cursor()
            c.execute("DELETE FROM cache_entries WHERE filepath=? AND analysis_type=?",
                      (filepath, analysis_type))
            self.conn.commit()

    def clear(self, older_than_days: int = None):
        """Vider le cache."""
        with self._lock:
            c = self.conn.cursor()
            if older_than_days:
                c.execute("""
                    DELETE FROM cache_entries
                    WHERE julianday('now') - julianday(created_at) > ?
                """, (older_than_days,))
            else:
                c.execute("DELETE FROM cache_entries")
                c.execute("DELETE FROM cache_analytics")
            self.conn.commit()

    def scan_directory(self, directory: str, analysis_type: str = 'default') -> Dict:
        """Scanner un répertoire et retourner les fichiers à analyser - FIXED symlink protection."""
        base = Path(directory)
        if not base.exists() or not base.is_dir():
            return {'changed': [], 'unchanged': [], 'new': [], 'to_analyze': [], 'stats': {'total': 0, 'changed': 0, 'unchanged': 0, 'new': 0, 'skipped': 0}}

        exts = {'.c','.cpp','.h','.py','.java','.go','.rs','.js','.ts'}
        visited_inodes = set()
        files = []

        try:
            for f in base.rglob('*'):
                try:
                    if f.is_symlink():
                        try:
                            real = f.resolve()
                            if real.is_dir():
                                continue
                            try:
                                real.relative_to(base.resolve())
                            except ValueError:
                                continue
                        except (OSError, RuntimeError):
                            continue

                    if not f.is_file():
                        continue

                    try:
                        stat = f.stat()
                        inode = (stat.st_dev, stat.st_ino)
                        if inode in visited_inodes:
                            continue
                        visited_inodes.add(inode)
                        if stat.st_size > 10*1024*1024 or stat.st_size == 0:
                            continue
                    except OSError:
                        continue

                    if f.suffix not in exts:
                        continue

                    files.append(f)
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError, RuntimeError):
            pass

        changed = []
        unchanged = []
        new_files = []

        with self._lock:
            for f in files:
                fp = str(f)
                if len(fp) > 1024:
                    continue
                c = self.conn.cursor()
                c.execute("SELECT file_hash FROM cache_entries WHERE filepath=? AND analysis_type=?",
                          (fp, analysis_type))
                row = c.fetchone()

                if not row:
                    new_files.append(fp)
                elif row['file_hash'] != self.hash_file(fp):
                    changed.append(fp)
                else:
                    unchanged.append(fp)

        return {
            'changed': changed,
            'unchanged': unchanged,
            'new': new_files,
            'to_analyze': changed + new_files,
            'stats': {
                'total': len(files),
                'changed': len(changed),
                'unchanged': len(unchanged),
                'new': len(new_files),
                'skipped': len(unchanged),
            }
        }

    def stats(self) -> Dict:
        """Statistiques du cache."""
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT COUNT(*) as total FROM cache_entries")
            total = c.fetchone()['total']

            c.execute("""
                SELECT analysis_type, COUNT(*) as cnt,
                       SUM(findings_count) as total_findings,
                       SUM(critical_count) as total_critical
                FROM cache_entries GROUP BY analysis_type
            """)
            by_type = {row['analysis_type']: {
                'entries': row['cnt'],
                'total_findings': row['total_findings'],
                'total_critical': row['total_critical'],
            } for row in c.fetchall()}

            c.execute("""
                SELECT filepath, critical_count + high_count as score
                FROM cache_entries
                ORDER BY score DESC LIMIT 10
            """)
            top_risky = [{'file': row['filepath'], 'score': row['score']}
                         for row in c.fetchall()]

            db_size = ADVANCED_CACHE_DB.stat().st_size if ADVANCED_CACHE_DB.exists() else 0

            return {
                'total_entries': total,
                'by_type': by_type,
                'top_risky_files': top_risky,
                'db_size_kb': round(db_size / 1024, 1),
                'db_path': str(ADVANCED_CACHE_DB),
                'version': CACHE_VERSION,
                'ttl_days': self.ttl_days,
                'max_entries': self.max_entries,
            }

    def get_risky_files(self, min_critical: int = 1) -> List[Dict]:
        """Retourner les fichiers avec des findings critiques."""
        with self._lock:
            c = self.conn.cursor()
            c.execute("""
                SELECT filepath, findings_count, critical_count, high_count, accessed_at
                FROM cache_entries
                WHERE critical_count >= ?
                ORDER BY critical_count DESC, high_count DESC
            """, (min_critical,))

            return [dict(row) for row in c.fetchall()]

    def _log_event(self, filepath: str, event: str):
        """Logger un événement de cache."""
        try:
            with self._lock:
                c = self.conn.cursor()
                c.execute("INSERT INTO cache_analytics (filepath, event) VALUES (?, ?)",
                          (filepath, event))
                self.conn.commit()
        except Exception:
            pass

    def _cleanup_analytics(self):
        """Cleanup analytics table if too large."""
        try:
            c = self.conn.cursor()
            c.execute("SELECT COUNT(*) as cnt FROM cache_analytics")
            cnt = c.fetchone()["cnt"]
            if cnt > MAX_ANALYTICS:
                c.execute("""
                    DELETE FROM cache_analytics WHERE id IN (
                        SELECT id FROM cache_analytics ORDER BY timestamp ASC LIMIT ?
                    )
                """, (cnt - MAX_ANALYTICS + 1000,))
                self.conn.commit()
        except Exception:
            pass

    def analytics(self) -> Dict:
        """Analytics sur l'utilisation du cache."""
        with self._lock:
            c = self.conn.cursor()
            c.execute("""
                SELECT event, COUNT(*) as cnt
                FROM cache_analytics GROUP BY event
            """)
            events = {row['event']: row['cnt'] for row in c.fetchall()}

            hit_rate = 0.0
            hits = events.get('cache_hit', 0)
            total = hits + events.get('cache_set', 0)
            if total > 0:
                hit_rate = round(hits / total * 100, 1)

            return {
                'events': events,
                'hit_rate': hit_rate,
                'version': CACHE_VERSION,
            }

    def close(self):
        """Close DB connection."""
        try:
            with self._lock:
                self.conn.close()
        except Exception:
            pass
