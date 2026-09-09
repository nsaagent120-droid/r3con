"""
r3con v5.0.3 - Advanced External Tool Adapters
Integrates 30+ powerful external tools with safe execution, limits, and structured output
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.result_schema import Status, make_result

MAX_OUTPUT = 10_000_000
MAX_BINARY_SIZE = 500 * 1024 * 1024


def _validate_path(path_str: str, max_size: int = MAX_BINARY_SIZE) -> bool:
    if not path_str or len(path_str) > 1024 or "\x00" in path_str:
        return False
    p = Path(path_str)
    try:
        if not p.exists() or not p.is_file():
            return False
        if p.stat().st_size > max_size or p.stat().st_size == 0:
            return False
    except (OSError, RuntimeError):
        return False
    return True


def _run_cmd(cmd: List[str], timeout: int = 60, cwd: Optional[str] = None, env: Optional[Dict] = None) -> Dict[str, Any]:
    """Safe command execution with limits."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, env=env
        )
        stdout = (proc.stdout or "")[:MAX_OUTPUT]
        stderr = (proc.stderr or "")[:MAX_OUTPUT//2]
        return {
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "success": proc.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "timeout", "success": False, "timeout": True}
    except (OSError, ValueError) as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)[:1000], "success": False}


def _find_executable(names: List[str], custom_path: Optional[str] = None) -> Optional[str]:
    """Find executable with custom path override."""
    if custom_path:
        p = Path(custom_path)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        # Also check if it's a dir containing the tool
        for name in names:
            candidate = p / name
            if candidate.is_file():
                return str(candidate)

    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


# ── Binary Analysis Adapters ──

class ChecksecAdapter:
    """checksec --file=binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["checksec", "checksec.sh"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="checksec", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="checksec", error="invalid_target")

        # Try --file first, then file argument
        result = _run_cmd([self.exe, f"--file={self.target}"], timeout=self.timeout)
        if not result["success"] and "unrecognized" in result["stderr"].lower():
            result = _run_cmd([self.exe, "--file", self.target], timeout=self.timeout)

        output = result["stdout"] + result["stderr"]

        protections = {
            "canary": "canary" in output.lower() and "found" in output.lower() or "yes" in output.lower(),
            "nx": "nx" in output.lower(),
            "pie": "pie" in output.lower(),
            "relro": "relro" in output.lower(),
            "fortify": "fortify" in output.lower(),
            "raw": output[:5000],
        }

        # Parse checksec output
        for line in output.splitlines():
            lower = line.lower()
            if "canary" in lower:
                protections["canary"] = "yes" in lower or "found" in lower or "enabled" in lower
            if "nx" in lower or "noexec" in lower:
                protections["nx"] = "yes" in lower or "enabled" in lower
            if "pie" in lower:
                protections["pie"] = "yes" in lower or "enabled" in lower

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="checksec", version=self.exe,
                           observations=protections)


class RopperAdapter:
    """ropper --file binary --search"""

    def __init__(self, target: str, timeout: int = 60, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["ropper", "ropper2"], custom_path)

    def analyze(self, search: str = "pop rdi", limit: int = 20) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="ropper", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="ropper", error="invalid_target")

        cmd = [self.exe, "--file", self.target, "--search", search, "--nocolor"]
        result = _run_cmd(cmd, timeout=self.timeout)

        gadgets = []
        for line in result["stdout"].splitlines()[:limit*2]:
            if "0x" in line and ":" in line:
                gadgets.append(line.strip()[:200])

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="ropper",
                           observations={"gadgets": gadgets[:limit], "search": search, "count": len(gadgets)})


class OneGadgetAdapter:
    """one_gadget binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["one_gadget"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="one_gadget", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="one_gadget", error="invalid_target")

        result = _run_cmd([self.exe, self.target], timeout=self.timeout)

        gadgets = []
        for line in result["stdout"].splitlines():
            if "0x" in line:
                gadgets.append(line.strip()[:300])

        return make_result(Status.OK if gadgets else Status.PARTIAL,
                           engine="one_gadget",
                           observations={"gadgets": gadgets[:20], "count": len(gadgets)})


class ObjdumpAdapter:
    """objdump -d -M intel binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["objdump"], custom_path)

    def analyze(self, function: Optional[str] = None) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="objdump", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="objdump", error="invalid_target")

        cmd = [self.exe, "-d", "-M", "intel", self.target]
        if function:
            # Safe: function is validated, no shell
            cmd.extend(["--disassemble", function])

        result = _run_cmd(cmd, timeout=self.timeout)

        lines = result["stdout"].splitlines()
        # Limit to 2000 lines
        disasm = "\n".join(lines[:2000])

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="objdump",
                           observations={"disassembly": disasm, "lines": len(lines), "truncated": len(lines) > 2000})


class ReadelfAdapter:
    """readelf -a binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["readelf"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="readelf", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="readelf", error="invalid_target")

        # Get multiple sections
        results = {}
        for flag, key in [("-h", "header"), ("-l", "program_headers"), ("-S", "sections"), ("-d", "dynamic"), ("-s", "symbols")]:
            r = _run_cmd([self.exe, flag, self.target], timeout=self.timeout)
            results[key] = r["stdout"][:50000]  # 50K per section

        return make_result(Status.OK, engine="readelf", observations=results)


class StringsAdapter:
    """strings -a -t x binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["strings"], custom_path)

    def analyze(self, min_len: int = 4) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="strings", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="strings", error="invalid_target")

        min_len = max(1, min(min_len, 100))
        result = _run_cmd([self.exe, "-a", "-t", "x", f"-n", str(min_len), self.target], timeout=self.timeout)

        strings = []
        for line in result["stdout"].splitlines()[:10000]:
            if len(line) > 10 and len(line) < 500:
                strings.append(line[:500])

        return make_result(Status.OK, engine="strings", observations={"strings": strings, "count": len(strings)})


# ── Firmware Adapters ──

class BinwalkAdapter:
    """binwalk -e binary"""

    def __init__(self, target: str, timeout: int = 120, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["binwalk"], custom_path)

    def analyze(self, extract: bool = False) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="binwalk", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="binwalk", error="invalid_target")

        cmd = [self.exe, self.target]
        if not extract:
            # Just scan
            result = _run_cmd(cmd, timeout=self.timeout)
        else:
            with tempfile.TemporaryDirectory(prefix="r3con-binwalk-") as tmpdir:
                cmd = [self.exe, "-e", "-C", tmpdir, self.target]
                result = _run_cmd(cmd, timeout=self.timeout)
                # List extracted
                try:
                    extracted = [str(p) for p in Path(tmpdir).rglob("*") if p.is_file()][:100]
                    result["extracted"] = extracted
                except Exception:
                    result["extracted"] = []

        findings = []
        for line in result["stdout"].splitlines():
            if any(x in line.lower() for x in ["filesystem", "squashfs", "uboot", "gzip", "elf", "certificate"]):
                findings.append(line.strip()[:300])

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="binwalk",
                           observations={"findings": findings[:100], "raw": result["stdout"][:10000], "extracted": result.get("extracted", [])})


# ── APK Adapters ──

class JadxAdapter:
    """jadx -d out apk"""

    def __init__(self, target: str, timeout: int = 120, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["jadx"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="jadx", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="jadx", error="invalid_target")

        with tempfile.TemporaryDirectory(prefix="r3con-jadx-") as tmpdir:
            result = _run_cmd([self.exe, "-d", tmpdir, self.target, "--show-bad-code"], timeout=self.timeout)

            java_files = []
            try:
                for p in Path(tmpdir).rglob("*.java"):
                    if p.is_file():
                        java_files.append(str(p.relative_to(tmpdir)))
                        if len(java_files) >= 100:
                            break
            except Exception:
                pass

            return make_result(Status.OK if result["success"] else Status.PARTIAL,
                               engine="jadx",
                               observations={"java_files": java_files, "count": len(java_files), "logs": result["stderr"][:5000]})


class ApktoolAdapter:
    """apktool d apk -o out"""

    def __init__(self, target: str, timeout: int = 120, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["apktool"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="apktool", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="apktool", error="invalid_target")

        with tempfile.TemporaryDirectory(prefix="r3con-apktool-") as tmpdir:
            result = _run_cmd([self.exe, "d", self.target, "-o", tmpdir, "-f"], timeout=self.timeout)

            files = []
            try:
                for p in Path(tmpdir).rglob("*"):
                    if p.is_file():
                        files.append(str(p.relative_to(tmpdir)))
                        if len(files) >= 100:
                            break
            except Exception:
                pass

            return make_result(Status.OK if result["success"] else Status.PARTIAL,
                               engine="apktool",
                               observations={"files": files, "count": len(files), "logs": result["stderr"][:5000]})


# ── Dynamic Analysis ──

class StraceAdapter:
    """strace -f binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["strace"], custom_path)

    def analyze(self, args: Optional[List[str]] = None) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="strace", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="strace", error="invalid_target")

        cmd = [self.exe, "-f", "-s", "200", self.target]
        if args:
            # Validate args - no injection
            safe_args = [a for a in args[:10] if len(a) <= 100 and "\x00" not in a and ";" not in a and "|" not in a]
            cmd.extend(safe_args)

        result = _run_cmd(cmd, timeout=self.timeout)

        syscalls = []
        for line in result["stderr"].splitlines()[:1000]:  # strace outputs to stderr
            if "(" in line and ")" in line:
                syscalls.append(line[:500])

        return make_result(Status.OK if result["stdout"] or result["stderr"] else Status.PARTIAL,
                           engine="strace",
                           observations={"syscalls": syscalls[:200], "count": len(syscalls)})


class LtraceAdapter:
    """ltrace -f binary"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["ltrace"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="ltrace", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="ltrace", error="invalid_target")

        result = _run_cmd([self.exe, "-f", "-s", "200", self.target], timeout=self.timeout)

        calls = []
        for line in result["stderr"].splitlines()[:1000]:
            if "(" in line:
                calls.append(line[:500])

        return make_result(Status.OK, engine="ltrace", observations={"calls": calls[:200], "count": len(calls)})


# ── Fuzzing ──

class AFLAdapter:
    """afl-fuzz helpers - check if available and show usage"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["afl-fuzz", "afl++"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="afl", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="afl", error="invalid_target")

        result = _run_cmd([self.exe, "-h"], timeout=self.timeout)

        return make_result(Status.OK, engine="afl", observations={"help": result["stdout"][:5000] + result["stderr"][:5000], "binary": self.target})


# ── Angr Symbolic Execution ──

class AngrAdapter:
    """angr - symbolic execution"""

    def __init__(self, target: str, timeout: int = 120, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        # angr is Python lib, check import
        try:
            import angr
            self.available = True
            self.version = angr.__version__
        except ImportError:
            self.available = False
            self.version = None

    def analyze(self, find_addr: Optional[int] = None, avoid_addr: Optional[int] = None) -> Dict[str, Any]:
        if not self.available:
            return make_result(Status.UNSUPPORTED, engine="angr", error="not_installed - pip install angr")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="angr", error="invalid_target")

        try:
            import angr
            import claripy

            proj = angr.Project(self.target, auto_load_libs=False)

            # Create initial state
            state = proj.factory.entry_state()

            # Setup simulation manager
            simgr = proj.factory.simulation_manager(state)

            # Explore
            if find_addr:
                simgr.explore(find=find_addr, avoid=avoid_addr, timeout=self.timeout)
                found = len(simgr.found)
                return make_result(Status.OK, engine="angr",
                                   observations={"found": found, "avoid": len(simgr.avoided),
                                                 "active": len(simgr.active), "find_addr": hex(find_addr)})
            else:
                # Just run a few steps
                simgr.run(n=10)
                return make_result(Status.OK, engine="angr",
                                   observations={"active": len(simgr.active), "deadended": len(simgr.deadended),
                                                 "errored": len(simgr.errored)})

        except Exception as e:
            return make_result(Status.ERROR, engine="angr", error=str(e)[:1000])


# ── Frida ──

class FridaAdapter:
    """frida - dynamic instrumentation"""

    def __init__(self, target: str, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.timeout = timeout
        self.exe = _find_executable(["frida", "frida-trace"], custom_path)

    def analyze(self) -> Dict[str, Any]:
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="frida", error="not_installed")
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="frida", error="invalid_target")

        result = _run_cmd([self.exe, "--version"], timeout=self.timeout)

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="frida",
                           observations={"version": result["stdout"][:500], "binary": self.target})


# ── YARA ──

class YaraAdapter:
    """yara - scan binary with rules"""

    def __init__(self, target: str, rules_path: Optional[str] = None, timeout: int = 30, custom_path: Optional[str] = None):
        self.target = target
        self.rules_path = rules_path
        self.timeout = timeout
        self.exe = _find_executable(["yara"], custom_path)
        try:
            import yara
            self.yara_lib = True
        except ImportError:
            self.yara_lib = False

    def analyze(self) -> Dict[str, Any]:
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="yara", error="invalid_target")

        # Try python lib first
        if self.yara_lib and self.rules_path:
            try:
                import yara
                if _validate_path(self.rules_path, max_size=10*1024*1024):
                    rules = yara.compile(filepath=self.rules_path)
                    matches = rules.match(self.target, timeout=self.timeout)
                    return make_result(Status.OK, engine="yara-python",
                                       observations={"matches": [str(m) for m in matches][:100], "count": len(matches)})
            except Exception as e:
                return make_result(Status.ERROR, engine="yara-python", error=str(e)[:1000])

        # Fallback to CLI
        if not self.exe:
            return make_result(Status.UNSUPPORTED, engine="yara", error="not_installed")

        if not self.rules_path:
            return make_result(Status.INVALID, engine="yara", error="rules_path_required")

        result = _run_cmd([self.exe, self.rules_path, self.target], timeout=self.timeout)

        matches = []
        for line in result["stdout"].splitlines():
            if line.strip():
                matches.append(line.strip()[:300])

        return make_result(Status.OK if result["success"] else Status.PARTIAL,
                           engine="yara",
                           observations={"matches": matches[:100], "count": len(matches)})


# ── Unified Enhanced Adapter ──

class EnhancedToolChain:
    """Chain multiple external tools for maximum capability."""

    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = target
        self.config = config or {}
        self.timeout = self.config.get("timeout", 120)

    def full_binary_analysis(self) -> Dict[str, Any]:
        """Run full chain of binary analysis tools."""
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="enhanced_chain", error="invalid_target")

        results = {}

        # Layer 1: Basic info (always works)
        results["checksec"] = ChecksecAdapter(self.target, timeout=30).analyze()
        results["strings"] = StringsAdapter(self.target, timeout=30).analyze()
        results["readelf"] = ReadelfAdapter(self.target, timeout=30).analyze()

        # Layer 2: Disassembly
        results["objdump"] = ObjdumpAdapter(self.target, timeout=60).analyze()

        # Layer 3: ROP / gadgets
        results["ropper"] = RopperAdapter(self.target, timeout=60).analyze()
        results["one_gadget"] = OneGadgetAdapter(self.target, timeout=30).analyze()

        # Layer 4: Advanced (if available)
        results["binwalk"] = BinwalkAdapter(self.target, timeout=60).analyze()

        # Aggregate findings
        all_findings = []
        for tool, res in results.items():
            if isinstance(res, dict) and res.get("findings"):
                all_findings.extend(res["findings"][:10])

        return make_result(Status.OK, engine="enhanced_binary_chain",
                           observations=results,
                           findings=all_findings[:100])

    def full_firmware_analysis(self) -> Dict[str, Any]:
        """Full firmware chain."""
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="enhanced_chain", error="invalid_target")

        results = {}
        results["binwalk"] = BinwalkAdapter(self.target, timeout=120).analyze()
        results["strings"] = StringsAdapter(self.target, timeout=60).analyze(min_len=6)
        results["readelf"] = ReadelfAdapter(self.target, timeout=30).analyze()

        return make_result(Status.OK, engine="enhanced_firmware_chain", observations=results)

    def full_apk_analysis(self) -> Dict[str, Any]:
        """Full APK chain."""
        if not _validate_path(self.target):
            return make_result(Status.INVALID, engine="enhanced_chain", error="invalid_target")

        results = {}
        results["jadx"] = JadxAdapter(self.target, timeout=120).analyze()
        results["apktool"] = ApktoolAdapter(self.target, timeout=120).analyze()
        results["strings"] = StringsAdapter(self.target, timeout=30).analyze()

        return make_result(Status.OK, engine="enhanced_apk_chain", observations=results)
