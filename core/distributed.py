"""
r3con v7.0 - Distributed Performance PRO
Task queue, Elasticsearch, PostgreSQL backends for large-scale analysis
"""
from __future__ import annotations
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import time
import hashlib
from datetime import datetime

class TaskQueue:
    """Simple task queue for distributed analysis (fallback without Celery)."""

    def __init__(self, backend: str = "memory"):
        self.backend = backend
        self.tasks: List[Dict[str, Any]] = []
        self.results: Dict[str, Any] = {}

    def enqueue(self, task_name: str, target_path: str, profile: str = "full", priority: int = 0) -> str:
        task_id = hashlib.md5(f"{task_name}:{target_path}:{time.time()}".encode()).hexdigest()[:12]
        task = {
            "id": task_id,
            "name": task_name,
            "target": target_path,
            "profile": profile,
            "priority": priority,
            "status": "queued",
            "created_at": datetime.now().isoformat(),
        }
        self.tasks.append(task)
        return task_id

    def dequeue(self) -> Optional[Dict[str, Any]]:
        if not self.tasks:
            return None
        # Sort by priority
        self.tasks.sort(key=lambda x: x.get("priority", 0))
        task = self.tasks.pop(0)
        task["status"] = "running"
        task["started_at"] = datetime.now().isoformat()
        return task

    def complete(self, task_id: str, result: Dict[str, Any]):
        self.results[task_id] = {
            "result": result,
            "completed_at": datetime.now().isoformat(),
            "status": "completed",
        }
        # Update task status
        for task in self.tasks:
            if task["id"] == task_id:
                task["status"] = "completed"

    def get_status(self, task_id: str) -> Dict[str, Any]:
        for task in self.tasks:
            if task["id"] == task_id:
                return task
        if task_id in self.results:
            return self.results[task_id]
        return {"status": "not_found", "id": task_id}

    def list_tasks(self) -> List[Dict[str, Any]]:
        return self.tasks

    def stats(self) -> Dict[str, Any]:
        return {
            "queued": len([t for t in self.tasks if t["status"] == "queued"]),
            "running": len([t for t in self.tasks if t["status"] == "running"]),
            "completed": len(self.results),
            "total": len(self.tasks) + len(self.results),
        }

class ElasticsearchBackend:
    """Elasticsearch backend for findings storage."""

    def __init__(self, es_url: str = "http://localhost:9200", index: str = "r3con-findings"):
        self.es_url = es_url
        self.index = index
        self.available = False
        try:
            import requests
            resp = requests.get(es_url, timeout=2)
            if resp.status_code == 200:
                self.available = True
        except Exception:
            pass

    def index_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not self.available:
            return {"status": "skipped", "reason": "elasticsearch_not_available"}

        try:
            import requests
            url = f"{self.es_url}/{self.index}/_doc"
            # Add timestamp
            doc = {**finding, "@timestamp": datetime.now().isoformat()}
            resp = requests.post(url, json=doc, timeout=5)
            if resp.status_code in (200, 201):
                return {"status": "ok", "id": resp.json().get("_id")}
            else:
                return {"status": "error", "code": resp.status_code, "error": resp.text[:500]}
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def search(self, query: str, size: int = 20) -> Dict[str, Any]:
        if not self.available:
            return {"status": "skipped", "reason": "elasticsearch_not_available", "results": []}

        try:
            import requests
            url = f"{self.es_url}/{self.index}/_search"
            body = {
                "query": {"multi_match": {"query": query, "fields": ["type", "description", "severity"]}},
                "size": size,
            }
            resp = requests.post(url, json=body, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                return {"status": "ok", "total": data.get("hits", {}).get("total", {}).get("value", 0), "results": [h.get("_source", {}) for h in hits]}
            else:
                return {"status": "error", "code": resp.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def stats(self) -> Dict[str, Any]:
        return {"available": self.available, "url": self.es_url, "index": self.index}

class PostgresBackend:
    """PostgreSQL backend for findings."""

    def __init__(self, dsn: str = "postgresql://r3con:r3con@localhost/r3con"):
        self.dsn = dsn
        self.available = False
        try:
            import psycopg2
            conn = psycopg2.connect(dsn, connect_timeout=2)
            conn.close()
            self.available = True
        except Exception:
            pass

    def save_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not self.available:
            return {"status": "skipped", "reason": "postgres_not_available"}

        try:
            import psycopg2
            conn = psycopg2.connect(self.dsn)
            cur = conn.cursor()
            # Create table if not exists
            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id SERIAL PRIMARY KEY,
                    type TEXT,
                    severity TEXT,
                    description TEXT,
                    file_path TEXT,
                    line_num INTEGER,
                    cwe TEXT,
                    data JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            cur.execute("""
                INSERT INTO findings (type, severity, description, file_path, line_num, cwe, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                finding.get("type", ""),
                finding.get("severity", ""),
                finding.get("description", ""),
                finding.get("file", ""),
                finding.get("line", 0),
                finding.get("cwe", ""),
                json.dumps(finding),
            ))
            conn.commit()
            cur.close()
            conn.close()
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def stats(self) -> Dict[str, Any]:
        return {"available": self.available, "dsn": self.dsn[:50] + "..."}

class PerformanceManager:
    """Performance manager PRO - coordinates caching, queue, backends."""

    def __init__(self):
        from core.performance import PerformanceCache
        self.cache = PerformanceCache()
        self.queue = TaskQueue()
        self.es = ElasticsearchBackend()
        self.pg = PostgresBackend()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "cache": self.cache.get_stats(),
            "queue": self.queue.stats(),
            "elasticsearch": self.es.stats(),
            "postgres": self.pg.stats(),
        }
