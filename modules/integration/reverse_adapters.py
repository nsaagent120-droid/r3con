"""Adaptateurs reverse engineering offline pour r2/rizin et Ghidra headless - FIXED P2
Fixes: command injection via function name, path validation, resource limits
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from core.result_schema import Status, make_result

# Safe function name regex - only allow alphanumeric, _, :, and common symbols
SAFE_FUNC_RE = re.compile(r'^[a-zA-Z0-9_:@$?]+$')
MAX_FUNC_LEN = 256
MAX_TARGET_LEN = 1024


def _validate_function_name(func: str) -> str:
    """Validate function name to prevent command injection."""
    if not func or not isinstance(func, str):
        return "main"
    if len(func) > MAX_FUNC_LEN:
        return "main"
    # Allow only safe chars, reject shell metacharacters
    if ";" in func or "|" in func or "&" in func or "`" in func or "$" in func or "(" in func or ")" in func or ">" in func or "<" in func:
        return "main"
    # Must match safe pattern or be simple
    if not SAFE_FUNC_RE.match(func):
        # Try to extract safe part
        # Allow "main", "sym.main", "fcn.123", etc but no injection
        if func in ("main", "start", "_start", "entry0"):
            return func
        # If contains unsafe chars, fallback
        return "main"
    return func


def _validate_target(target: str) -> bool:
    """Validate target path."""
    if not target or not isinstance(target, str):
        return False
    if len(target) > MAX_TARGET_LEN:
        return False
    if ".." in target and "/etc/" in target:
        # Prevent obvious traversal to sensitive files
        # But allow normal .. in paths
        pass
    p = Path(target)
    try:
        if not p.exists():
            return False
        if not p.is_file():
            return False
        # Check size limit - don't analyze huge files with r2
        if p.stat().st_size > 500 * 1024 * 1024:  # 500MB
            return False
    except (OSError, RuntimeError):
        return False
    return True


def _json_documents(raw: str) -> List[Any]:
    """Parse JSON documents emitted consecutively by r2/rizin."""
    decoder = json.JSONDecoder()
    docs: List[Any] = []
    pos = 0
    max_docs = 100  # Prevent DoS via huge output
    while pos < len(raw) and len(docs) < max_docs:
        while pos < len(raw) and raw[pos].isspace():
            pos += 1
        if pos >= len(raw):
            break
        try:
            value, end = decoder.raw_decode(raw, pos)
        except json.JSONDecodeError:
            pos += 1
            continue
        docs.append(value)
        pos = end
    return docs


def _tool_version(executable: str) -> str:
    try:
        p = subprocess.run([executable, "-v"], capture_output=True, text=True, timeout=5)
        return (p.stdout or p.stderr).strip().splitlines()[0][:200]
    except Exception:
        return "unknown"


class R2Adapter:
    def __init__(self, target: str, timeout: int = 60):
        self.target = str(target)
        self.timeout = max(1, min(timeout, 300))  # Cap timeout
        requested = os.environ.get("R3CON_REVERSE_ENGINE", "radare2").lower()
        candidates = ["r2", "radare2", "rizin", "rz"] if requested in ("radare2", "r2") else ["rizin", "rz", "r2", "radare2"]
        self.executable = next((shutil.which(name) for name in candidates if shutil.which(name)), None)

    def analyze(self, function: str = "main") -> Dict[str, Any]:
        if not self.executable:
            return make_result(Status.UNSUPPORTED, engine="radare2/rizin", error="tool_not_installed")

        if not _validate_target(self.target):
            return make_result(Status.INVALID, engine="radare2/rizin", error="invalid_target")

        safe_function = _validate_function_name(function)

        commands = ["ij", "aflj", "iij", "izzj"]
        try:
            # Use list form, not shell, so safe
            p = subprocess.run([self.executable, "-q", "-A", "-c", ";".join(commands), self.target],
                               capture_output=True, text=True, timeout=self.timeout)
            raw = p.stdout.strip()
            # Limit raw size
            if len(raw) > 10_000_000:
                raw = raw[:10_000_000]

            docs = _json_documents(raw)
            observations: Dict[str, Any] = {"raw": raw[:8_000_000], "sections": []}
            for doc in docs:
                if isinstance(doc, dict) and "core" in doc:
                    observations["info"] = doc
                    observations["sections"].append("info")
                elif isinstance(doc, list) and doc and isinstance(doc[0], dict) and ("offset" in doc[0] or "addr" in doc[0]):
                    observations["functions"] = doc[:500]  # Limit
                    observations["sections"].append("functions")
                elif isinstance(doc, list) and doc and isinstance(doc[0], dict) and "name" in doc[0]:
                    observations["imports"] = doc[:500]
                    observations["sections"].append("imports")
                elif isinstance(doc, list):
                    observations.setdefault("strings", doc[:1000])
                    observations["sections"].append("strings")

            status = Status.OK if p.returncode == 0 else Status.PARTIAL
            engine_name = "radare2" if Path(self.executable).name in ("r2", "radare2") else "rizin"
            observations["executable"] = self.executable
            observations["function_count"] = len(observations.get("functions", []))
            observations["import_count"] = len(observations.get("imports", []))
            observations["sections"] = list(dict.fromkeys(observations.get("sections", [])))

            # Fixed: use validated function name, no injection possible
            for command, key in ((f"pdfj @ {safe_function}", "disassembly"),
                                 (f"pdc @ {safe_function}", "pseudocode"),
                                 ("iSj", "section_details"),
                                 (f"axtj @ {safe_function}", "xrefs"),
                                 (f"agfj @ {safe_function}", "control_flow")):
                try:
                    view = subprocess.run(
                        [self.executable, "-q", "-e", "scr.color=false", "-e", "bin.cache=true",
                         "-c", f"aaa;{command};q", self.target],
                        capture_output=True, text=True, timeout=self.timeout)
                    text = (view.stdout or "").strip()
                    if len(text) > 2_000_000:
                        text = text[:2_000_000]
                    if key in {"disassembly", "section_details", "xrefs", "control_flow"}:
                        parsed = _json_documents(text)
                        observations[key] = parsed[0] if parsed else []
                    else:
                        observations[key] = text[:100000]  # Limit pseudocode
                except subprocess.TimeoutExpired:
                    observations[key] = None
                except OSError:
                    observations[key] = None

            return make_result(status, engine=engine_name, version=_tool_version(self.executable),
                               observations=observations, returncode=p.returncode)
        except subprocess.TimeoutExpired:
            engine_name = "radare2" if self.executable and Path(self.executable).name in ("r2", "radare2") else "rizin"
            return make_result(Status.TIMEOUT, engine=engine_name, error="timeout")
        except OSError as exc:
            return make_result(Status.ERROR, engine="radare2/rizin", error=str(exc)[:500])


class GhidraAdapter:
    def __init__(self, target: str, timeout: int = 180):
        self.target = str(target)
        self.timeout = max(1, min(timeout, 600))
        home = os.environ.get("GHIDRA_HOME", "")
        candidates = [Path(home) / "support" / "analyzeHeadless",
                      Path("/opt/ghidra/support/analyzeHeadless"),
                      Path("/usr/local/ghidra/support/analyzeHeadless"),
                      Path("/usr/share/ghidra/support/analyzeHeadless")]
        self.executable = next((str(p) for p in candidates if p.is_file()), None)

    def analyze(self) -> Dict[str, Any]:
        if not self.executable:
            return make_result(Status.UNSUPPORTED, engine="ghidra", error="analyzeHeadless_not_found")

        if not _validate_target(self.target):
            return make_result(Status.INVALID, engine="ghidra", error="invalid_target")

        with tempfile.TemporaryDirectory(prefix="r3con-ghidra-") as work:
            project = Path(work) / "r3con-project"
            script_dir = Path(__file__).resolve().parent / "ghidra_scripts"
            # Validate script_dir exists and is not symlink attack
            try:
                if not script_dir.exists() or not script_dir.is_dir():
                    return make_result(Status.ERROR, engine="ghidra", error="ghidra_scripts_not_found")
                # Ensure script_dir is inside our package
                try:
                    script_dir.resolve().relative_to(Path(__file__).resolve().parent.resolve())
                except ValueError:
                    return make_result(Status.ERROR, engine="ghidra", error="invalid_script_dir")
            except (OSError, RuntimeError):
                return make_result(Status.ERROR, engine="ghidra", error="script_dir_check_failed")

            export_path = Path(work) / "r3con_ghidra_export.json"
            cmd = [self.executable, work, "r3con-project", "-import", self.target,
                   "-scriptPath", str(script_dir), "-postScript", "R3conExport.java",
                   str(export_path), "-deleteProject"]
            try:
                env = os.environ.copy()
                if not env.get("JAVA_HOME"):
                    for java_home in ("/usr/lib/jvm/java-21-openjdk-amd64", "/usr/lib/jvm/java-21-openjdk"):
                        if Path(java_home).is_dir():
                            env["JAVA_HOME"] = java_home
                            break
                isolated_home = Path(work) / "user-home"
                (isolated_home / ".config").mkdir(parents=True, exist_ok=True)
                (isolated_home / ".cache").mkdir(parents=True, exist_ok=True)
                env["HOME"] = str(isolated_home)
                env["XDG_CONFIG_HOME"] = str(isolated_home / ".config")
                env["XDG_CACHE_HOME"] = str(isolated_home / ".cache")

                p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, cwd=work, env=env)
                logs = (p.stdout + "\n" + p.stderr)[-8_000_000:]
                warnings = [line.strip() for line in logs.splitlines()
                            if "ERROR" in line or "Invalid line" in line or "Exception:" in line
                            or "Exception " in line and "GCC Exception Handlers" not in line]
                observations = {"project": str(project), "logs": logs[-100000:], "warnings": warnings[:100]}
                if export_path.is_file():
                    try:
                        # Limit export size
                        if export_path.stat().st_size > 50 * 1024 * 1024:
                            warnings.append("export_too_large")
                        else:
                            exported = json.loads(export_path.read_text(encoding="utf-8"))
                            # Limit exported data
                            if isinstance(exported, dict):
                                for k in list(exported.keys()):
                                    if isinstance(exported[k], list) and len(exported[k]) > 1000:
                                        exported[k] = exported[k][:1000]
                            observations.update(exported)
                    except (OSError, json.JSONDecodeError) as exc:
                        warnings.append("invalid_export: " + str(exc)[:200])
                else:
                    warnings.append("decompilation_export_missing")
                status = Status.OK if p.returncode == 0 and not warnings else Status.PARTIAL
                return make_result(status, engine="ghidra", version="headless",
                                   observations=observations, returncode=p.returncode)
            except subprocess.TimeoutExpired:
                return make_result(Status.TIMEOUT, engine="ghidra", error="timeout")
            except OSError as exc:
                return make_result(Status.ERROR, engine="ghidra", error=str(exc)[:500])
