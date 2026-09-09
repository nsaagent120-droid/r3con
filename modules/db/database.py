"""
r3con - Database Module
SQLite-based analysis storage and querying.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

DB_PATH = Path.home() / ".r3con" / "analysis.db"


class AnalysisDB:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.conn = None
        self._lock = None
        try:
            import threading
            self._lock = threading.RLock()
        except ImportError:
            pass
        self._init_db()

    def _init_db(self):
        """Initialize database schema - FIXED WAL, timeout, thread safety."""
        self.conn = sqlite3.connect(str(DB_PATH), timeout=10.0, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute("PRAGMA cache_size=-64000;")
            self.conn.execute("PRAGMA temp_store=MEMORY;")
        except sqlite3.Error:
            pass
        c = self.conn.cursor()

        # Findings table
        c.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                analysis_id TEXT,
                severity TEXT,
                type TEXT,
                file TEXT,
                line INTEGER,
                description TEXT,
                recommendation TEXT,
                cwe TEXT,
                cve TEXT,
                created_at TIMESTAMP
            )
        ''')

        # Analysis table
        c.execute('''
            CREATE TABLE IF NOT EXISTS analysis (
                id TEXT PRIMARY KEY,
                target TEXT,
                analysis_type TEXT,
                status TEXT,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                exploit_chains INTEGER,
                created_at TIMESTAMP,
                completed_at TIMESTAMP,
                metadata TEXT
            )
        ''')

        # Exploit chains table
        c.execute('''
            CREATE TABLE IF NOT EXISTS exploit_chains (
                id TEXT PRIMARY KEY,
                analysis_id TEXT,
                chain_name TEXT,
                description TEXT,
                steps TEXT,
                impact TEXT,
                confidence REAL,
                finding_ids TEXT,
                created_at TIMESTAMP
            )
        ''')

        # Taint flow table
        c.execute('''
            CREATE TABLE IF NOT EXISTS taint_flows (
                id INTEGER PRIMARY KEY,
                analysis_id TEXT,
                source_file TEXT,
                source_line INTEGER,
                sink_file TEXT,
                sink_line INTEGER,
                path TEXT,
                vulnerability_type TEXT,
                exploitable INTEGER
            )
        ''')

        self.conn.commit()

    def _execute_locked(self, func):
        """Execute with lock if available."""
        if self._lock:
            with self._lock:
                return func()
        else:
            return func()

    def add_analysis(self, analysis_id: str, target: str, analysis_type: str, metadata: dict = None) -> None:
        """Create a new analysis record - FIXED validation, locking."""
        if not analysis_id or len(analysis_id) > 256 or "\x00" in analysis_id:
            raise ValueError("Invalid analysis_id")
        if not target or len(target) > 1024:
            raise ValueError("Invalid target")

        def _do():
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO analysis (id, target, analysis_type, status, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (analysis_id, target[:1024], analysis_type[:100], "in_progress", datetime.now().isoformat(),
                  json.dumps(metadata or {})[:10000]))
            self.conn.commit()

        self._execute_locked(_do)

    def add_finding(self, analysis_id: str, finding: dict) -> None:
        """Add a finding to the analysis - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return

        def _do():
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO findings 
                (analysis_id, severity, type, file, line, description, recommendation, cwe, cve, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (analysis_id, str(finding.get("severity","INFO"))[:20], str(finding.get("type",""))[:200],
                  str(finding.get("file",""))[:500], finding.get("line"), str(finding.get("description",""))[:1000],
                  str(finding.get("recommendation",""))[:1000], str(finding.get("cwe",""))[:20], str(finding.get("cve",""))[:20],
                  datetime.now().isoformat()))
            self.conn.commit()

        self._execute_locked(_do)

    def add_exploit_chain(self, analysis_id: str, chain: dict) -> None:
        """Record an exploit chain - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return

        def _do():
            c = self.conn.cursor()
            chain_id = f"{analysis_id}_chain_{datetime.now().timestamp()}"
            c.execute('''
                INSERT INTO exploit_chains 
                (id, analysis_id, chain_name, description, steps, impact, confidence, finding_ids, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (chain_id, analysis_id, str(chain.get("name",""))[:200], str(chain.get("description",""))[:1000],
                  json.dumps(chain.get("steps", []))[:10000], str(chain.get("impact",""))[:200], chain.get("confidence"),
                  json.dumps(chain.get("finding_ids", []))[:5000], datetime.now().isoformat()))
            self.conn.commit()

        self._execute_locked(_do)

    def add_taint_flow(self, analysis_id: str, taint: dict) -> None:
        """Record a taint flow from source to sink - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return

        def _do():
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO taint_flows 
                (analysis_id, source_file, source_line, sink_file, sink_line, path, vulnerability_type, exploitable)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (analysis_id, str(taint.get("source_file",""))[:500], taint.get("source_line"),
                  str(taint.get("sink_file",""))[:500], taint.get("sink_line"), json.dumps(taint.get("path", []))[:10000],
                  str(taint.get("vulnerability_type",""))[:100], int(taint.get("exploitable", False))))
            self.conn.commit()

        self._execute_locked(_do)

    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Retrieve analysis record - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return None

        def _do():
            c = self.conn.cursor()
            c.execute('SELECT * FROM analysis WHERE id = ?', (analysis_id,))
            row = c.fetchone()
            return dict(row) if row else None

        return self._execute_locked(_do)

    def get_findings(self, analysis_id: str) -> List[Dict]:
        """Get all findings for an analysis - FIXED limit."""
        if not analysis_id or len(analysis_id) > 256:
            return []

        def _do():
            c = self.conn.cursor()
            c.execute('SELECT * FROM findings WHERE analysis_id = ? ORDER BY severity DESC LIMIT 1000', (analysis_id,))
            return [dict(row) for row in c.fetchall()]

        return self._execute_locked(_do)

    def get_exploit_chains(self, analysis_id: str) -> List[Dict]:
        """Get all exploit chains for an analysis - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return []

        def _do():
            c = self.conn.cursor()
            c.execute('SELECT * FROM exploit_chains WHERE analysis_id = ? LIMIT 100', (analysis_id,))
            chains = []
            for row in c.fetchall():
                chain = dict(row)
                try:
                    chain['steps'] = json.loads(chain['steps'])
                except (json.JSONDecodeError, TypeError):
                    chain['steps'] = []
                try:
                    chain['finding_ids'] = json.loads(chain['finding_ids'])
                except (json.JSONDecodeError, TypeError):
                    chain['finding_ids'] = []
                chains.append(chain)
            return chains

        return self._execute_locked(_do)

    def get_taint_flows(self, analysis_id: str) -> List[Dict]:
        """Get all taint flows for an analysis - FIXED."""
        if not analysis_id or len(analysis_id) > 256:
            return []

        def _do():
            c = self.conn.cursor()
            c.execute('SELECT * FROM taint_flows WHERE analysis_id = ? LIMIT 200', (analysis_id,))
            flows = []
            for row in c.fetchall():
                flow = dict(row)
                try:
                    flow['path'] = json.loads(flow['path'])
                except (json.JSONDecodeError, TypeError):
                    flow['path'] = []
                flows.append(flow)
            return flows

        return self._execute_locked(_do)

    def update_analysis(self, analysis_id: str, updates: dict) -> None:
        """Update analysis record."""
        allowed = {"target", "status", "profile", "started_at", "completed_at", "duration_ms", "error", "metadata"}
        unknown = set(updates) - allowed
        if unknown:
            raise ValueError("unsupported analysis fields: " + ", ".join(sorted(unknown)))
        if not updates:
            return
        fields = ', '.join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [analysis_id]
        # fields est limité à la liste blanche ci-dessus ; les valeurs restent paramétrées.
        self.conn.cursor().execute(f"UPDATE analysis SET {fields} WHERE id = ?", values)  # nosec B608
        self.conn.commit()

    def get_stats(self, analysis_id: str) -> Dict:
        """Get statistics for an analysis."""
        findings = self.get_findings(analysis_id)
        chains = self.get_exploit_chains(analysis_id)
        flows = self.get_taint_flows(analysis_id)

        severity_counts = {}
        for f in findings:
            s = f['severity']
            severity_counts[s] = severity_counts.get(s, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "exploit_chains": len(chains),
            "taint_flows": len(flows),
            "exploitable_flows": sum(1 for f in flows if f['exploitable'])
        }

    def close(self):
        if self.conn:
            self.conn.close()
