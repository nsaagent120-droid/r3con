"""
r3con - Session Manager
Persistent analysis history across runs.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path

SESSION_DIR = Path.home() / ".r3con" / "sessions"


class SessionManager:
    def __init__(self):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self.index_file = SESSION_DIR / "index.json"
        self.index = self._load_index()

    def _load_index(self) -> list:
        if self.index_file.exists():
            try:
                return json.loads(self.index_file.read_text())
            except Exception:
                return []
        return []

    def _save_index(self):
        self.index_file.write_text(json.dumps(self.index, indent=2))

    def save(self, type_: str, target: str, output: str) -> str:
        sid   = str(uuid.uuid4())[:8]
        entry = {"id": sid, "type": type_, "target": target,
                 "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                 "file": f"{sid}.json"}
        (SESSION_DIR / f"{sid}.json").write_text(
            json.dumps({**entry, "output": output}, indent=2))
        self.index.insert(0, entry)
        if len(self.index) > 200:
            old = self.index.pop()
            (SESSION_DIR / old["file"]).unlink(missing_ok=True)
        self._save_index()
        return sid

    def get(self, sid: str) -> dict:
        f = SESSION_DIR / f"{sid}.json"
        return json.loads(f.read_text()) if f.exists() else None

    def list_sessions(self) -> list:
        return self.index[:50]

    def clear(self):
        for f in SESSION_DIR.glob("*.json"):
            f.unlink()
        self.index = []
        self._save_index()
