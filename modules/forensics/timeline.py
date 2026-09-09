"""
r3con v6.2 - Forensics Timeline PRO
Timeline analysis from filesystem, logs, etc.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import re

class TimelineAnalyzer:
    """Timeline analyzer PRO."""

    def __init__(self):
        pass

    def analyze_directory(self, dir_path: str) -> Dict[str, Any]:
        base = Path(dir_path)
        if not base.is_dir():
            return {"status": "error", "error": "not_a_directory"}

        files = []
        try:
            for f in base.rglob("*"):
                if f.is_file():
                    try:
                        stat = f.stat()
                        files.append({
                            "path": str(f),
                            "size": stat.st_size,
                            "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "ctime": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            "atime": datetime.fromtimestamp(stat.st_atime).isoformat(),
                        })
                    except Exception:
                        continue
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        # Sort by mtime
        files_sorted = sorted(files, key=lambda x: x["mtime"])

        # Detect suspicious patterns
        findings = []
        # Recently modified executables
        for f in files_sorted[-20:]:
            if f["path"].endswith((".exe", ".dll", ".so", ".sh")) and f["size"] > 1024:
                findings.append({
                    "type": "Recently Modified Executable",
                    "severity": "MEDIUM",
                    "description": f"Executable {f['path']} modified at {f['mtime']}",
                    "file": f["path"],
                })

        return {
            "status": "ok",
            "engine": "timeline",
            "total_files": len(files),
            "files": files_sorted[-100:],
            "findings": findings[:50],
            "time_range": {
                "earliest": files_sorted[0]["mtime"] if files_sorted else None,
                "latest": files_sorted[-1]["mtime"] if files_sorted else None,
            }
        }
