"""Gestion sûre et explicite des outils externes.

Par défaut, ce module ne télécharge rien et n’installe rien. Il détecte les
outils présents, prépare un plan d’installation et exige un appel explicite
pour toute installation système.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path


@dataclass(frozen=True)
class ToolSpec:
    key: str
    executable: str
    purpose: str
    packages: Dict[str, str]
    version_args: tuple[str, ...] = ("--version",)


SPECS = (
    ToolSpec("tshark", "tshark", "protocol decoding from offline PCAP", {"apt": "tshark", "dnf": "wireshark-cli", "brew": "wireshark"}),
    ToolSpec("zeek", "zeek", "offline session and protocol logs", {"apt": "zeek", "dnf": "zeek", "brew": "zeek"}),
    ToolSpec("radare2", "r2", "binary analysis and function discovery", {"apt": "radare2", "brew": "radare2"}, version_args=("-v",)),
    ToolSpec("gdb", "gdb", "dynamic debugging", {"apt": "gdb", "dnf": "gdb", "brew": "gdb"}),
    ToolSpec("pwndbg", "pwndbg", "GDB enhancement plugin", {}),
    ToolSpec("ghidra", "analyzeHeadless", "headless decompilation and reverse engineering", {}),
    ToolSpec("binwalk", "binwalk", "firmware extraction", {"apt": "binwalk", "pip": "binwalk"}, version_args=("--help",)),
)


class ToolManager:
    def __init__(self, specs=SPECS):
        self.specs = tuple(specs)
        self.by_key = {s.key: s for s in self.specs}

    def inspect(self) -> List[Dict]:
        rows = []
        for spec in self.specs:
            path = shutil.which(spec.executable)
            if spec.key == "pwndbg":
                configured = os.environ.get("PWNDBG_HOME", "")
                candidates = [
                    Path(configured) / "gdbinit.py" if configured else Path("/nonexistent/gdbinit.py"),
                    Path.home() / "tools" / "pwndbg" / "gdbinit.py",
                    Path.home() / "pwndbg" / "gdbinit.py",
                    Path("/home/pentagone/pwndbg/gdbinit.py"),
                    Path("/opt/pwndbg/gdbinit.py"),
                ]
                candidate = next((p for p in candidates if p.is_file()), None)
                path = str(candidate) if candidate else path
            if spec.key == "ghidra":
                candidates = [Path(os.environ.get("GHIDRA_HOME", "")) / "support" / "analyzeHeadless", Path("/opt/ghidra/support/analyzeHeadless"), Path("/usr/local/ghidra/support/analyzeHeadless")]
                path = next((str(p) for p in candidates if p.is_file()), path)
            version = None
            error = None
            if path:
                try:
                    if spec.key in ("pwndbg", "ghidra"):
                        version = "installed (plugin/config)" if spec.key == "pwndbg" else "installed (headless)"
                        proc = None
                    else:
                        proc = subprocess.run([path, *spec.version_args], capture_output=True, text=True, timeout=4)
                    if proc is not None:
                        version = (proc.stdout or proc.stderr).strip().splitlines()[0][:240] if (proc.stdout or proc.stderr) else "unknown"
                except (OSError, subprocess.TimeoutExpired) as exc:
                    error = type(exc).__name__
            rows.append({"key": spec.key, "executable": spec.executable, "present": bool(path), "path": path, "version": version, "error": error, "purpose": spec.purpose})
        return rows

    def install_plan(self, keys: Optional[List[str]] = None) -> List[Dict]:
        family = self._package_family()
        selected = keys or [s.key for s in self.specs]
        plan = []
        for key in selected:
            if key not in self.by_key:
                plan.append({"key": key, "status": "unknown_tool"})
                continue
            spec = self.by_key[key]
            if shutil.which(spec.executable):
                plan.append({"key": key, "status": "already_present"})
                continue
            package = spec.packages.get(family) or spec.packages.get("apt")
            if package:
                plan.append({"key": key, "status": "available", "manager": family if family in spec.packages else "apt", "package": package, "command": self._command(family, package)})
            else:
                plan.append({"key": key, "status": "manual", "message": "No safe package recipe configured; install from the official project documentation."})
        return plan

    def install(self, keys: List[str], apply: bool = False) -> Dict:
        plan = self.install_plan(keys)
        if not apply:
            return {"status": "plan_only", "plan": plan, "message": "No installation performed. Re-run with explicit apply=True after reviewing the plan."}
        if os.geteuid() != 0:
            return {"status": "refused", "error": "system_install_requires_root_or_user_confirmation"}
        results = []
        for item in plan:
            if item.get("status") != "available":
                results.append(item)
                continue
            command = item["command"]
            proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
            results.append({**item, "status": "installed" if proc.returncode == 0 else "failed", "returncode": proc.returncode, "stderr": proc.stderr[-1000:]})
        return {"status": "completed", "results": results}

    @staticmethod
    def _package_family() -> str:
        if shutil.which("apt-get"):
            return "apt"
        if shutil.which("dnf"):
            return "dnf"
        if shutil.which("brew"):
            return "brew"
        if shutil.which("pip"):
            return "pip"
        return "unknown"

    @staticmethod
    def _command(family: str, package: str) -> List[str]:
        if family == "apt":
            return ["sudo", "apt-get", "install", "-y", package]
        if family == "dnf":
            return ["sudo", "dnf", "install", "-y", package]
        if family == "brew":
            return ["brew", "install", package]
        return ["python", "-m", "pip", "install", package]
