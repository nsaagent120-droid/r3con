"""Gestion sûre et explicite des outils externes - v5.0.3 PRO
Support 35+ outils, détection avancée, capacités, et chaîne d'outils
Par défaut, ne télécharge rien et n'installe rien.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass(frozen=True)
class ToolSpec:
    key: str
    executables: tuple[str, ...]  # Multiple possible names
    purpose: str
    category: str  # binary, firmware, apk, network, dynamic, fuzzing, misc
    packages: Dict[str, str] = field(default_factory=dict)
    version_args: tuple[str, ...] = ("--version",)
    check_args: Optional[tuple[str, ...]] = None
    requires_root: bool = False
    python_lib: Optional[str] = None  # Alternative python lib
    capabilities: tuple[str, ...] = ()


# 35+ tools organized by category
SPECS = (
    # ── Binary analysis (12 tools) ──
    ToolSpec("r2", ("r2", "radare2"), "binary analysis and disassembly", "binary",
             {"apt": "radare2", "brew": "radare2", "dnf": "radare2"}, ("-v",),
             capabilities=("disasm", "decompile", "functions", "strings", "imports")),
    ToolSpec("rizin", ("rizin", "rz"), "modern binary analysis", "binary",
             {"apt": "rizin", "brew": "rizin"}, ("-v",),
             capabilities=("disasm", "decompile", "functions")),
    ToolSpec("ghidra", ("analyzeHeadless",), "headless decompilation", "binary",
             {}, ("-h",), capabilities=("decompile", "functions", "decompiler"),
             python_lib=None),
    ToolSpec("checksec", ("checksec", "checksec.sh"), "binary protections", "binary",
             {"apt": "checksec", "pip": "checksec.py", "brew": "checksec"}, ("--help",),
             capabilities=("protections", "canary", "nx", "pie")),
    ToolSpec("ropper", ("ropper", "ropper2"), "ROP gadgets finder", "binary",
             {"pip": "ropper", "apt": "ropper"}, ("--help",),
             capabilities=("rop", "gadgets", "jop")),
    ToolSpec("one_gadget", ("one_gadget",), "one gadget RCE finder", "binary",
             {"gem": "one_gadget", "pip": "one_gadget"}, ("--help",),
             capabilities=("rop", "one_gadget", "execve")),
    ToolSpec("objdump", ("objdump", "gobjdump"), "disassembly via binutils", "binary",
             {"apt": "binutils", "brew": "binutils"}, ("--version",),
             capabilities=("disasm", "sections")),
    ToolSpec("readelf", ("readelf", "greadelf"), "ELF parser", "binary",
             {"apt": "binutils"}, ("--version",),
             capabilities=("elf", "headers", "sections", "symbols")),
    ToolSpec("nm", ("nm", "gnm"), "symbol lister", "binary",
             {"apt": "binutils"}, ("--version",),
             capabilities=("symbols", "imports")),
    ToolSpec("strings", ("strings", "gstrings"), "string extractor", "binary",
             {"apt": "binutils"}, ("--version",),
             capabilities=("strings", "secrets")),
    ToolSpec("file", ("file", "gfile"), "file type detector", "binary",
             {"apt": "file"}, ("--version",),
             capabilities=("magic", "type")),
    ToolSpec("angr", ("angr",), "symbolic execution", "binary",
             {"pip": "angr"}, (), capabilities=("symbolic", "exploration"),
             python_lib="angr"),

    # ── Firmware (5 tools) ──
    ToolSpec("binwalk", ("binwalk",), "firmware extraction", "firmware",
             {"apt": "binwalk", "pip": "binwalk", "brew": "binwalk"}, ("--help",),
             capabilities=("extract", "entropy", "filesystem")),
    ToolSpec("firmwalker", ("firmwalker", "firmwalker.sh"), "firmware secrets", "firmware",
             {}, ("--help",), capabilities=("secrets", "creds", "keys")),
    ToolSpec("sasquatch", ("sasquatch",), "squashfs extractor", "firmware",
             {"apt": "sasquatch"}, ("--help",), capabilities=("squashfs", "extract")),
    ToolSpec("ubi_reader", ("ubireader_extract_images",), "UBI extractor", "firmware",
             {"pip": "ubi_reader"}, ("--help",), capabilities=("ubi", "extract")),
    ToolSpec("jefferson", ("jefferson",), "JFFS2 extractor", "firmware",
             {"pip": "jefferson"}, ("--help",), capabilities=("jffs2", "extract")),

    # ── APK / Mobile (5 tools) ──
    ToolSpec("jadx", ("jadx",), "DEX to Java decompiler", "apk",
             {"apt": "jadx", "brew": "jadx"}, ("--version",),
             capabilities=("decompile", "java", "dex")),
    ToolSpec("apktool", ("apktool",), "APK disassembly", "apk",
             {"apt": "apktool", "brew": "apktool"}, ("--version",),
             capabilities=("manifest", "smali", "resources")),
    ToolSpec("dex2jar", ("d2j-dex2jar", "dex2jar"), "DEX to JAR", "apk",
             {"apt": "dex2jar"}, ("--help",),
             capabilities=("dex", "jar")),
    ToolSpec("apksigner", ("apksigner",), "APK signature verifier", "apk",
             {"apt": "apksigner"}, ("--version",),
             capabilities=("signature", "cert")),
    ToolSpec("zipalign", ("zipalign",), "APK alignment checker", "apk",
             {"apt": "zipalign"}, ("--help",),
             capabilities=("alignment",)),

    # ── Network (5 tools) ──
    ToolSpec("tshark", ("tshark",), "protocol decoding", "network",
             {"apt": "tshark", "dnf": "wireshark-cli", "brew": "wireshark"}, ("--version",),
             capabilities=("pcap", "protocols", "iocs")),
    ToolSpec("zeek", ("zeek", "bro"), "network logs", "network",
             {"apt": "zeek", "brew": "zeek"}, ("--version",),
             capabilities=("logs", "flows", "protocols")),
    ToolSpec("tcpdump", ("tcpdump",), "packet capture", "network",
             {"apt": "tcpdump"}, ("--version",),
             capabilities=("capture", "pcap"), requires_root=True),
    ToolSpec("wireshark", ("wireshark",), "GUI analyzer (for tshark)", "network",
             {"apt": "wireshark"}, ("--version",),
             capabilities=("pcap",)),
    ToolSpec("capinfos", ("capinfos",), "PCAP info", "network",
             {"apt": "tshark"}, ("--help",),
             capabilities=("pcap", "info")),

    # ── Dynamic (8 tools) ──
    ToolSpec("gdb", ("gdb", "ggdb"), "debugger", "dynamic",
             {"apt": "gdb", "brew": "gdb"}, ("--version",),
             capabilities=("debug", "breakpoint", "memory")),
    ToolSpec("pwndbg", ("pwndbg",), "GDB plugin", "dynamic",
             {}, (), capabilities=("heap", "exploit")),
    ToolSpec("gef", ("gef",), "GDB Enhanced Features", "dynamic",
             {}, (), capabilities=("heap", "exploit")),
    ToolSpec("qemu", ("qemu-x86_64", "qemu-arm", "qemu-mips", "qemu"), "emulation", "dynamic",
             {"apt": "qemu-user", "brew": "qemu"}, ("--version",),
             capabilities=("emulate", "arch")),
    ToolSpec("frida", ("frida", "frida-trace"), "dynamic instrumentation", "dynamic",
             {"pip": "frida-tools", "npm": "frida"}, ("--version",),
             capabilities=("hook", "trace", "instrument")),
    ToolSpec("strace", ("strace",), "syscall tracer", "dynamic",
             {"apt": "strace"}, ("--version",),
             capabilities=("syscall", "trace")),
    ToolSpec("ltrace", ("ltrace",), "library call tracer", "dynamic",
             {"apt": "ltrace"}, ("--version",),
             capabilities=("library", "trace")),
    ToolSpec("valgrind", ("valgrind",), "memory checker", "dynamic",
             {"apt": "valgrind", "brew": "valgrind"}, ("--version",),
             capabilities=("memcheck", "leak", "heap")),

    # ── Fuzzing (3 tools) ──
    ToolSpec("afl", ("afl-fuzz", "afl++"), "fuzzer", "fuzzing",
             {"apt": "afl++", "brew": "afl++"}, ("-h",),
             capabilities=("fuzz", "coverage")),
    ToolSpec("honggfuzz", ("honggfuzz",), "fuzzer", "fuzzing",
             {"apt": "honggfuzz"}, ("--help",),
             capabilities=("fuzz",)),
    ToolSpec("radamsa", ("radamsa",), "fuzz case generator", "fuzzing",
             {"apt": "radamsa", "brew": "radamsa"}, ("--version",),
             capabilities=("mutate",)),

    # ── Misc / Security (7 tools) ──
    ToolSpec("yara", ("yara",), "pattern matching", "misc",
             {"apt": "yara", "pip": "yara-python", "brew": "yara"}, ("--version",),
             capabilities=("scan", "malware"), python_lib="yara"),
    ToolSpec("clamav", ("clamscan", "clamdscan"), "AV scanner", "misc",
             {"apt": "clamav"}, ("--version",),
             capabilities=("malware", "virus")),
    ToolSpec("ssdeep", ("ssdeep",), "fuzzy hashing", "misc",
             {"apt": "ssdeep"}, ("--help",),
             capabilities=("fuzzy", "hash")),
    ToolSpec("binwalk", ("binwalk",), "firmware analysis", "misc",
             {"apt": "binwalk", "pip": "binwalk"}, ("--help",),
             capabilities=("firmware",)),  # Duplicate for misc category
)


class ToolManager:
    def __init__(self, specs=SPECS, config: Optional[Dict] = None):
        self.specs = tuple(specs)
        self.by_key = {s.key: s for s in self.specs}
        self.config = config or {}
        # Custom paths from config: external_tools.paths
        self.custom_paths = self.config.get("external_tools", {}).get("paths", {}) if isinstance(self.config, dict) else {}

    def _find_tool_path(self, spec: ToolSpec) -> Optional[str]:
        # Check custom path first
        custom = self.custom_paths.get(spec.key)
        if custom:
            p = Path(custom)
            if p.is_file():
                return str(p)
            # If custom is dir, look inside
            for exe in spec.executables:
                candidate = p / exe
                if candidate.is_file():
                    return str(candidate)
            # If custom path itself is executable name override
            found = shutil.which(custom)
            if found:
                return found

        # Check env var R3CON_TOOL_<KEY>
        env_key = f"R3CON_TOOL_{spec.key.upper()}"
        env_path = os.environ.get(env_key)
        if env_path:
            p = Path(env_path)
            if p.is_file():
                return str(p)
            found = shutil.which(env_path)
            if found:
                return found

        # Standard which
        for exe in spec.executables:
            found = shutil.which(exe)
            if found:
                return found

        # Special cases
        if spec.key == "pwndbg":
            candidates = [
                Path.home() / "tools" / "pwndbg" / "gdbinit.py",
                Path.home() / "pwndbg" / "gdbinit.py",
                Path("/opt/pwndbg/gdbinit.py"),
                Path("/usr/share/pwndbg/gdbinit.py"),
            ]
            for c in candidates:
                if c.is_file():
                    return str(c)

        if spec.key == "gef":
            candidates = [
                Path.home() / ".gef.py",
                Path.home() / ".config" / "gef" / "gef.py",
                Path("/opt/gef/gef.py"),
            ]
            for c in candidates:
                if c.is_file():
                    return str(c)

        if spec.key == "ghidra":
            candidates = [
                Path(os.environ.get("GHIDRA_HOME", "")) / "support" / "analyzeHeadless",
                Path("/opt/ghidra/support/analyzeHeadless"),
                Path("/usr/local/ghidra/support/analyzeHeadless"),
                Path("/usr/share/ghidra/support/analyzeHeadless"),
                Path.home() / "tools" / "ghidra" / "support" / "analyzeHeadless",
            ]
            for c in candidates:
                if c.is_file():
                    return str(c)

        # Check python lib as fallback
        if spec.python_lib:
            try:
                __import__(spec.python_lib)
                return f"python:{spec.python_lib}"
            except ImportError:
                pass

        return None

    def inspect(self) -> List[Dict]:
        rows = []
        for spec in self.specs:
            # Deduplicate by key (keep first)
            if any(r["key"] == spec.key for r in rows):
                continue

            path = self._find_tool_path(spec)
            version = None
            error = None
            capabilities = list(spec.capabilities)

            if path:
                if path.startswith("python:"):
                    version = f"python lib {spec.python_lib}"
                else:
                    try:
                        if spec.key in ("pwndbg", "gef", "ghidra"):
                            version = "installed (plugin/config)"
                        else:
                            proc = subprocess.run(
                                [path, *spec.version_args],
                                capture_output=True, text=True, timeout=4
                            )
                            raw = (proc.stdout or proc.stderr).strip()
                            if raw:
                                version = raw.splitlines()[0][:240]
                            else:
                                version = "installed"
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        error = type(exc).__name__
                        version = "error"

            rows.append({
                "key": spec.key,
                "executables": spec.executables,
                "present": bool(path),
                "path": path,
                "version": version,
                "error": error,
                "purpose": spec.purpose,
                "category": spec.category,
                "capabilities": capabilities,
                "requires_root": spec.requires_root,
                "python_lib": spec.python_lib,
            })
        return sorted(rows, key=lambda x: (x["category"], x["key"]))

    def get_by_category(self, category: str) -> List[Dict]:
        return [t for t in self.inspect() if t["category"] == category]

    def get_available(self) -> List[Dict]:
        return [t for t in self.inspect() if t["present"]]

    def get_missing(self) -> List[Dict]:
        return [t for t in self.inspect() if not t["present"]]

    def is_available(self, key: str) -> bool:
        spec = self.by_key.get(key)
        if not spec:
            return False
        return bool(self._find_tool_path(spec))

    def get_capabilities(self, capability: str) -> List[Dict]:
        """Get all tools that provide a capability, e.g. 'disasm'."""
        return [t for t in self.inspect() if capability in t["capabilities"] and t["present"]]

    def install_plan(self, keys: Optional[List[str]] = None) -> List[Dict]:
        family = self._package_family()
        selected = keys or [s.key for s in self.specs]
        plan = []
        seen = set()
        for key in selected:
            if key in seen:
                continue
            seen.add(key)
            if key not in self.by_key:
                plan.append({"key": key, "status": "unknown_tool"})
                continue
            spec = self.by_key[key]
            path = self._find_tool_path(spec)
            if path:
                plan.append({"key": key, "status": "already_present", "path": path})
                continue
            package = spec.packages.get(family) or spec.packages.get("apt") or spec.packages.get("pip")
            if package:
                plan.append({
                    "key": key,
                    "status": "available",
                    "manager": family if family in spec.packages else "apt",
                    "package": package,
                    "command": self._command(family, package, spec),
                    "category": spec.category,
                })
            else:
                plan.append({
                    "key": key,
                    "status": "manual",
                    "message": "No safe package recipe configured; install from official project documentation.",
                    "category": spec.category,
                })
        return plan

    def install(self, keys: List[str], apply: bool = False) -> Dict:
        plan = self.install_plan(keys)
        if not apply:
            return {
                "status": "plan_only",
                "plan": plan,
                "message": "No installation performed. Re-run with apply=True after reviewing the plan. Use --dry-run to see plan."
            }
        if os.geteuid() != 0:
            return {"status": "refused", "error": "system_install_requires_root_or_user_confirmation"}
        results = []
        for item in plan:
            if item.get("status") != "available":
                results.append(item)
                continue
            command = item["command"]
            proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
            results.append({
                **item,
                "status": "installed" if proc.returncode == 0 else "failed",
                "returncode": proc.returncode,
                "stderr": proc.stderr[-1000:]
            })
        return {"status": "completed", "results": results}

    def summary(self) -> Dict:
        all_tools = self.inspect()
        by_cat = {}
        for t in all_tools:
            cat = t["category"]
            if cat not in by_cat:
                by_cat[cat] = {"total": 0, "present": 0, "tools": []}
            by_cat[cat]["total"] += 1
            if t["present"]:
                by_cat[cat]["present"] += 1
            by_cat[cat]["tools"].append(t["key"])

        return {
            "total": len(all_tools),
            "present": len([t for t in all_tools if t["present"]]),
            "missing": len([t for t in all_tools if not t["present"]]),
            "by_category": by_cat,
            "capabilities": {
                "disasm": len(self.get_capabilities("disasm")),
                "decompile": len(self.get_capabilities("decompile")),
                "rop": len(self.get_capabilities("rop")),
                "firmware": len(self.get_capabilities("firmware")),
            }
        }

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
    def _command(family: str, package: str, spec: ToolSpec) -> List[str]:
        if family == "apt":
            return ["sudo", "apt-get", "install", "-y", package]
        if family == "dnf":
            return ["sudo", "dnf", "install", "-y", package]
        if family == "brew":
            return ["brew", "install", package]
        if "pip" in spec.packages:
            return ["python", "-m", "pip", "install", package]
        if "gem" in spec.packages:
            return ["gem", "install", package]
        return ["python", "-m", "pip", "install", package]
