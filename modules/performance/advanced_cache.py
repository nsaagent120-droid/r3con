"""
r3con - Advanced Cache
Cache avancé avec SQLite, indexation, et analytics.
Plus rapide et plus intelligent que le cache simple.
"""

import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime


ADVANCED_CACHE_DB = Path.home() / ".r3con" / "advanced_cache.db"


class AdvancedCache:
    """
    Cache avancé avec:
    - Stockage SQLite (plus rapide que JSON)
    - Indexation par hash, type, sévérité
    - Analytics (quels fichiers changent le plus)
    - TTL (expiration automatique)
    - Compression des résultats
    """

    def __init__(self, ttl_days: int = 30):
        """
        Args:
            ttl_days: Jours avant expiration du cache
        """
        self.ttl_days = ttl_days
        ADVANCED_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(ADVANCED_CACHE_DB), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
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
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                UNIQUE(filepath, analysis_type)
            );

            CREATE INDEX IF NOT EXISTS idx_filepath
                ON cache_entries(filepath);
            CREATE INDEX IF NOT EXISTS idx_hash
                ON cache_entries(file_hash);
            CREATE INDEX IF NOT EXISTS idx_type
                ON cache_entries(analysis_type);

            CREATE TABLE IF NOT EXISTS cache_analytics (
                id          INTEGER PRIMARY KEY,
                filepath    TEXT NOT NULL,
                event       TEXT NOT NULL,
                timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.conn.commit()

    def hash_file(self, filepath: str) -> str:
        """Calculer le hash SHA256 d'un fichier."""
        h = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def is_cached(self, filepath: str, analysis_type: str = 'default') -> bool:
        """Vérifier si le fichier est en cache et non expiré."""
        file_hash = self.hash_file(filepath)
        if not file_hash:
            return False

        c = self.conn.cursor()
        c.execute("""
            SELECT file_hash, created_at FROM cache_entries
            WHERE filepath=? AND analysis_type=?
        """, (filepath, analysis_type))

        row = c.fetchone()
        if not row:
            return False

        # Vérifier le hash
        if row['file_hash'] != file_hash:
            self._log_event(filepath, 'cache_invalidated')
            return False

        # Vérifier le TTL
        created = datetime.fromisoformat(row['created_at'])
        age_days = (datetime.now() - created).days
        if age_days > self.ttl_days:
            self._log_event(filepath, 'cache_expired')
            return False

        return True

    def get(self, filepath: str, analysis_type: str = 'default') -> Optional[Dict]:
        """Récupérer les résultats depuis le cache."""
        if not self.is_cached(filepath, analysis_type):
            return None

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
            return json.loads(row['results'])

        return None

    def set(self, filepath: str, results: Dict,
            analysis_type: str = 'default'):
        """Mettre en cache les résultats."""
        file_hash = self.hash_file(filepath)
        if not file_hash:
            return

        findings       = results.get('findings', [])
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count     = sum(1 for f in findings if f.get('severity') == 'HIGH')

        c = self.conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO cache_entries
            (filepath, file_hash, analysis_type, results,
             findings_count, critical_count, high_count, created_at, accessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (filepath, file_hash, analysis_type,
              json.dumps(results), len(findings), critical_count, high_count))

        self.conn.commit()
        self._log_event(filepath, 'cache_set')

    def invalidate(self, filepath: str, analysis_type: str = 'default'):
        """Invalider le cache pour un fichier."""
        c = self.conn.cursor()
        c.execute("DELETE FROM cache_entries WHERE filepath=? AND analysis_type=?",
                  (filepath, analysis_type))
        self.conn.commit()

    def clear(self, older_than_days: int = None):
        """Vider le cache (optionnel: seulement les entrées > N jours)."""
        c = self.conn.cursor()
        if older_than_days:
            c.execute("""
                DELETE FROM cache_entries
                WHERE julianday('now') - julianday(created_at) > ?
            """, (older_than_days,))
        else:
            c.execute("DELETE FROM cache_entries")
        self.conn.commit()

    def scan_directory(self, directory: str,
                       analysis_type: str = 'default') -> Dict:
        """Scanner un répertoire et retourner les fichiers à analyser."""
        base  = Path(directory)
        exts  = {'.c','.cpp','.h','.py','.java','.go','.rs','.js','.ts'}
        files = [f for f in base.rglob('*')
                 if f.is_file() and f.suffix in exts
                 and f.stat().st_size < 10*1024*1024]

        changed   = []
        unchanged = []
        new_files = []

        for f in files:
            fp = str(f)
            c  = self.conn.cursor()
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
            'changed':    changed,
            'unchanged':  unchanged,
            'new':        new_files,
            'to_analyze': changed + new_files,
            'stats': {
                'total':     len(files),
                'changed':   len(changed),
                'unchanged': len(unchanged),
                'new':       len(new_files),
                'skipped':   len(unchanged),
            }
        }

    def stats(self) -> Dict:
        """Statistiques du cache."""
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
            'entries':        row['cnt'],
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
            'by_type':       by_type,
            'top_risky_files': top_risky,
            'db_size_kb':    round(db_size / 1024, 1),
            'db_path':       str(ADVANCED_CACHE_DB),
        }

    def get_risky_files(self, min_critical: int = 1) -> List[Dict]:
        """Retourner les fichiers avec des findings critiques."""
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
            c = self.conn.cursor()
            c.execute("INSERT INTO cache_analytics (filepath, event) VALUES (?, ?)",
                      (filepath, event))
            self.conn.commit()
        except Exception:
            pass

    def analytics(self) -> Dict:
        """Analytics sur l'utilisation du cache."""
        c = self.conn.cursor()
        c.execute("""
            SELECT event, COUNT(*) as cnt
            FROM cache_analytics GROUP BY event
        """)
        events = {row['event']: row['cnt'] for row in c.fetchall()}

        hit_rate = 0.0
        hits     = events.get('cache_hit', 0)
        total    = hits + events.get('cache_set', 0)
        if total > 0:
            hit_rate = round(hits / total * 100, 1)

        return {
            'events':   events,
            'hit_rate': hit_rate,
        }
