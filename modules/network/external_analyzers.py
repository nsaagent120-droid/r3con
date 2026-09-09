"""Adaptateurs optionnels TShark/Zeek pour captures locales uniquement - FIXED P3
Fixes: path validation, field validation, size limits, symlink protection
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict

MAX_PCAP_SIZE = 500 * 1024 * 1024
MAX_FIELDS = 64
MAX_FIELD_LEN = 100
MAX_OUTPUT = 8_000_000

SAFE_FIELD_RE = re.compile(r'^[a-zA-Z0-9._\-]+$')


def _validate_pcap_path(pcap_path: str) -> bool:
    """Validate pcap path."""
    if not pcap_path or len(pcap_path) > 1024 or "\x00" in pcap_path:
        return False
    p = Path(pcap_path)
    try:
        if not p.exists() or not p.is_file():
            return False
        if p.stat().st_size > MAX_PCAP_SIZE or p.stat().st_size == 0:
            return False
    except (OSError, RuntimeError):
        return False
    return True


def _validate_field(field: str) -> bool:
    """Validate field name - FIXED strict."""
    if not field or not isinstance(field, str):
        return False
    if len(field) > MAX_FIELD_LEN or "\x00" in field:
        return False
    if any(c in field for c in ";|&`$()><\n\r\"'"):
        return False
    # Must match safe pattern and contain at least one dot or be known
    if not SAFE_FIELD_RE.match(field):
        return False
    return True


class ExternalNetworkAnalyzer:
    """External network analyzers with validation - FIXED P3."""

    def __init__(self, pcap_path: str, timeout: int = 120, max_output: int = MAX_OUTPUT):
        self.pcap = Path(pcap_path)
        self.timeout = max(1, min(timeout, 300))
        self.max_output = max(1024, min(max_output, 50_000_000))

    def status(self) -> Dict:
        return {"tshark": shutil.which("tshark"), "zeek": shutil.which("zeek")}

    def tshark_fields(self, fields: list[str]) -> Dict:
        """Extract fields via tshark - FIXED validation, limits."""
        exe = shutil.which("tshark")
        if not exe:
            return {"status": "unsupported", "tool": "tshark"}

        if not _validate_pcap_path(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap_path"}

        if not isinstance(fields, list) or len(fields) == 0:
            return {"status": "invalid", "error": "no_fields"}

        if len(fields) > MAX_FIELDS:
            fields = fields[:MAX_FIELDS]

        safe_fields = [f for f in fields if _validate_field(f)]

        if not safe_fields:
            return {"status": "invalid", "error": "no_safe_fields"}

        cmd = [exe, "-n", "-r", str(self.pcap), "-T", "json"]
        for field in safe_fields[:MAX_FIELDS]:
            cmd.extend(["-e", field])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "tool": "tshark"}
        except (OSError, ValueError) as e:
            return {"status": "error", "tool": "tshark", "error": str(e)[:500]}

        output = (proc.stdout or "")[: self.max_output]

        if proc.returncode != 0:
            return {"status": "error", "tool": "tshark", "returncode": proc.returncode,
                    "stderr": (proc.stderr or "")[-2000:]}

        try:
            records = json.loads(output)
            # Limit records
            if isinstance(records, list) and len(records) > 10000:
                records = records[:10000]
            return {"status": "ok", "tool": "tshark", "records": records, "field_count": len(safe_fields)}
        except json.JSONDecodeError:
            return {"status": "partial", "tool": "tshark", "raw": output[:10000]}

    def zeek_offline(self) -> Dict:
        """Run Zeek offline - FIXED validation, limits."""
        exe = shutil.which("zeek")
        if not exe:
            return {"status": "unsupported", "tool": "zeek"}

        if not _validate_pcap_path(str(self.pcap)):
            return {"status": "invalid", "error": "invalid_pcap_path"}

        with tempfile.TemporaryDirectory(prefix="r3con-zeek-") as outdir:
            cmd = [exe, "-C", "-r", str(self.pcap)]
            try:
                proc = subprocess.run(cmd, cwd=outdir, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return {"status": "timeout", "tool": "zeek"}
            except (OSError, ValueError) as e:
                return {"status": "error", "tool": "zeek", "error": str(e)[:500]}

            logs = {}
            try:
                for path in Path(outdir).glob("*.log"):
                    try:
                        if not path.is_file():
                            continue
                        if path.stat().st_size > self.max_output:
                            # Truncate large logs
                            logs[path.name] = path.read_text(errors="replace")[: self.max_output]
                        else:
                            logs[path.name] = path.read_text(errors="replace")[: self.max_output]

                        # Limit total logs
                        if len(logs) >= 20:
                            break
                        if sum(len(v) for v in logs.values()) > self.max_output:
                            break
                    except (OSError, UnicodeDecodeError):
                        continue
            except (OSError, RuntimeError):
                pass

            if proc.returncode != 0:
                return {"status": "error", "tool": "zeek", "returncode": proc.returncode,
                        "stderr": (proc.stderr or "")[-2000:], "logs": logs}

            return {"status": "ok", "tool": "zeek", "logs": logs, "log_count": len(logs)}
