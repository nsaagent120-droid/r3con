"""
r3con v7.0 - Nuclei Wrapper PRO
Integration Nuclei templates pour web scanning
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

def _run(cmd: List[str], timeout: int = 60) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=min(timeout, 300))
        output = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else ""
        if not output and result.stderr.strip():
            output = result.stderr.strip()
        return output[:2*1024*1024] if output else None
    except Exception:
        return None

class NucleiWrapper:
    """Nuclei wrapper PRO."""

    def __init__(self, target: str = None, timeout: int = 120):
        self.target = target
        self.timeout = timeout
        self.bin = shutil.which("nuclei")

    def scan(self, target: str = None, templates: List[str] = None, severity: str = None) -> Dict[str, Any]:
        tgt = target or self.target
        if not tgt:
            return {"status": "error", "error": "no_target"}

        if not self.bin:
            return {"status": "unsupported", "tool": "nuclei", "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

        cmd = [self.bin, "-u", tgt, "-j", "-silent"]

        if templates:
            for tmpl in templates[:10]:
                cmd.extend(["-t", tmpl])

        if severity:
            cmd.extend(["-severity", severity])

        out = _run(cmd, timeout=self.timeout)
        if out:
            findings = []
            for line in out.splitlines()[:1000]:
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": f"Nuclei: {data.get('template-id','unknown')}",
                        "severity": data.get("info", {}).get("severity", "MEDIUM").upper(),
                        "description": f"{data.get('info', {}).get('name','')} - {data.get('matched-at','')}",
                        "template": data.get("template-id", ""),
                        "matched_at": data.get("matched-at", ""),
                        "info": data.get("info", {}),
                    })
                except json.JSONDecodeError:
                    continue

            return {
                "status": "ok",
                "tool": "nuclei",
                "target": tgt,
                "findings": findings[:100],
                "count": len(findings),
            }

        return {"status": "error", "tool": "nuclei", "target": tgt}

    def detect(self) -> Dict[str, Any]:
        return {"available": self.bin is not None, "binary": self.bin}
