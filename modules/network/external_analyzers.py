"""Adaptateurs optionnels TShark/Zeek pour captures locales uniquement."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict


class ExternalNetworkAnalyzer:
    def __init__(self, pcap_path: str, timeout: int = 120, max_output: int = 8_000_000):
        self.pcap = Path(pcap_path)
        self.timeout = timeout
        self.max_output = max_output

    def status(self) -> Dict:
        return {"tshark": shutil.which("tshark"), "zeek": shutil.which("zeek")}

    def tshark_fields(self, fields: list[str]) -> Dict:
        exe = shutil.which("tshark")
        if not exe:
            return {"status": "unsupported", "tool": "tshark"}
        if not self.pcap.is_file():
            return {"status": "invalid", "error": "pcap_not_found"}
        safe_fields = [f for f in fields if f.replace("_", "").replace(".", "").isalnum()]
        if not safe_fields:
            return {"status": "invalid", "error": "no_safe_fields"}
        cmd = [exe, "-n", "-r", str(self.pcap), "-T", "json"]
        for field in safe_fields[:64]:
            cmd.extend(["-e", field])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "tool": "tshark"}
        output = (proc.stdout or "")[: self.max_output]
        if proc.returncode != 0:
            return {"status": "error", "tool": "tshark", "returncode": proc.returncode, "stderr": (proc.stderr or "")[-2000:]}
        try:
            return {"status": "ok", "tool": "tshark", "records": json.loads(output)}
        except json.JSONDecodeError:
            return {"status": "partial", "tool": "tshark", "raw": output}

    def zeek_offline(self) -> Dict:
        exe = shutil.which("zeek")
        if not exe:
            return {"status": "unsupported", "tool": "zeek"}
        if not self.pcap.is_file():
            return {"status": "invalid", "error": "pcap_not_found"}
        with tempfile.TemporaryDirectory(prefix="r3con-zeek-") as outdir:
            cmd = [exe, "-C", "-r", str(self.pcap)]
            try:
                proc = subprocess.run(cmd, cwd=outdir, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "tool": "zeek"}
            logs = {}
            for path in Path(outdir).glob("*.log"):
                logs[path.name] = path.read_text(errors="replace")[: self.max_output]
            if proc.returncode != 0:
                return {"status": "error", "tool": "zeek", "returncode": proc.returncode, "stderr": (proc.stderr or "")[-2000:], "logs": logs}
            return {"status": "ok", "tool": "zeek", "logs": logs}
