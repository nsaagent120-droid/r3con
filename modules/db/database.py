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
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        self.conn = sqlite3.connect(str(DB_PATH))
        self.conn.row_factory = sqlite3.Row
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

    def add_analysis(self, analysis_id: str, target: str, analysis_type: str, metadata: dict = None) -> None:
        """Create a new analysis record."""
        c = self.conn.cursor()
        c.execute('''
            INSERT INTO analysis (id, target, analysis_type, status, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (analysis_id, target, analysis_type, "in_progress", datetime.now().isoformat(),
              json.dumps(metadata or {})))
        self.conn.commit()

    def add_finding(self, analysis_id: str, finding: dict) -> None:
        """Add a finding to the analysis."""
        c = self.conn.cursor()
        c.execute('''
            INSERT INTO findings 
            (analysis_id, severity, type, file, line, description, recommendation, cwe, cve, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (analysis_id, finding.get("severity"), finding.get("type"),
              finding.get("file"), finding.get("line"), finding.get("description"),
              finding.get("recommendation"), finding.get("cwe"), finding.get("cve"),
              datetime.now().isoformat()))
        self.conn.commit()

    def add_exploit_chain(self, analysis_id: str, chain: dict) -> None:
        """Record an exploit chain."""
        c = self.conn.cursor()
        chain_id = f"{analysis_id}_chain_{datetime.now().timestamp()}"
        c.execute('''
            INSERT INTO exploit_chains 
            (id, analysis_id, chain_name, description, steps, impact, confidence, finding_ids, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (chain_id, analysis_id, chain.get("name"), chain.get("description"),
              json.dumps(chain.get("steps", [])), chain.get("impact"), chain.get("confidence"),
              json.dumps(chain.get("finding_ids", [])), datetime.now().isoformat()))
        self.conn.commit()

    def add_taint_flow(self, analysis_id: str, taint: dict) -> None:
        """Record a taint flow from source to sink."""
        c = self.conn.cursor()
        c.execute('''
            INSERT INTO taint_flows 
            (analysis_id, source_file, source_line, sink_file, sink_line, path, vulnerability_type, exploitable)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (analysis_id, taint.get("source_file"), taint.get("source_line"),
              taint.get("sink_file"), taint.get("sink_line"), json.dumps(taint.get("path", [])),
              taint.get("vulnerability_type"), int(taint.get("exploitable", False))))
        self.conn.commit()

    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Retrieve analysis record."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM analysis WHERE id = ?', (analysis_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_findings(self, analysis_id: str) -> List[Dict]:
        """Get all findings for an analysis."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM findings WHERE analysis_id = ? ORDER BY severity DESC', (analysis_id,))
        return [dict(row) for row in c.fetchall()]

    def get_exploit_chains(self, analysis_id: str) -> List[Dict]:
        """Get all exploit chains for an analysis."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM exploit_chains WHERE analysis_id = ?', (analysis_id,))
        chains = []
        for row in c.fetchall():
            chain = dict(row)
            chain['steps'] = json.loads(chain['steps'])
            chain['finding_ids'] = json.loads(chain['finding_ids'])
            chains.append(chain)
        return chains

    def get_taint_flows(self, analysis_id: str) -> List[Dict]:
        """Get all taint flows for an analysis."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM taint_flows WHERE analysis_id = ?', (analysis_id,))
        flows = []
        for row in c.fetchall():
            flow = dict(row)
            flow['path'] = json.loads(flow['path'])
            flows.append(flow)
        return flows

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
        self.conn.cursor().execute(f"UPDATE analysis SET {fields} WHERE id = ?", values)
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
