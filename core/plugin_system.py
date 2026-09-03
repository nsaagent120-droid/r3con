"""Fondation des plugins et workflows r3con.

Les plugins sont des adaptateurs autour d'outils locaux spécialisés. Ils
n'installent rien, n'utilisent jamais un shell implicite et renvoient des
observations avec provenance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List
import hashlib
import json
import shutil
import subprocess
import time

from core.result_schema import Finding, deduplicate_findings


@dataclass(frozen=True)
class PluginSpec:
    name: str
    description: str
    executable: str
    capabilities: List[str]
    parser: str = "text"
    network: bool = False


class Plugin:
    spec: PluginSpec

    def available(self) -> bool:
        return shutil.which(self.spec.executable) is not None

    def run(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        raise NotImplementedError


class CommandPlugin(Plugin):
    """Safe adapter for an executable and a fixed argument builder."""

    def __init__(self, spec: PluginSpec, args_builder: Callable[[str], List[str]]):
        self.spec = spec
        self._args_builder = args_builder

    def run(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        started = time.monotonic()
        command = self._args_builder(str(Path(target).resolve()))
        if not command or command[0] != self.spec.executable:
            raise ValueError("plugin command does not match declared executable")
        if not self.available():
            return {"status": "skipped", "reason": f"{self.spec.executable} not installed", "findings": []}
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=max(1, timeout), check=False)
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            finding = Finding(finding_type="tool_observation", target=str(Path(target).resolve()),
                              tool=self.spec.name, tool_version="unknown",
                              evidence={"excerpt": output[:2000]},
                              provenance={"command": command,
                                          "duration_seconds": round(time.monotonic() - started, 3),
                                          "network": self.spec.network})
            return {"status": "ok" if proc.returncode == 0 else "error",
                    "returncode": proc.returncode, "output": output[:200000],
                    "findings": [finding.to_dict()], "provenance": finding.provenance}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "findings": [],
                    "provenance": {"command": command, "network": self.spec.network}}


class AdapterPlugin(Plugin):
    """Expose an existing adapter through the common plugin registry."""

    def __init__(self, spec: PluginSpec, factory: Callable[[str, int], Any], method: str = "analyze"):
        self.spec, self._factory, self._method = spec, factory, method

    def available(self) -> bool:
        adapter = self._factory("", 1)
        return bool(getattr(adapter, "executable", None))

    def run(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        adapter = self._factory(target, timeout)
        if not self.available():
            return {"status": "skipped", "reason": f"{self.spec.name} not installed", "findings": []}
        result = getattr(adapter, self._method)()
        if isinstance(result, dict):
            result.setdefault("findings", [])
            return result
        return {"status": "ok", "observations": result, "findings": []}


class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        if plugin.spec.name in self._plugins:
            raise ValueError(f"plugin already registered: {plugin.spec.name}")
        self._plugins[plugin.spec.name] = plugin

    def get(self, name: str) -> Plugin:
        return self._plugins[name]

    def list(self) -> List[Dict[str, Any]]:
        return [{**asdict(plugin.spec), "available": plugin.available()} for plugin in self._plugins.values()]

    def run(self, names: Iterable[str], target: str, timeout: int = 60) -> Dict[str, Any]:
        results = []
        resolved = str(Path(target).resolve())
        for name in names:
            result = self.get(name).run(resolved, timeout=timeout)
            result.update({"plugin": name, "target": resolved})
            results.append(result)
        findings = deduplicate_findings([f for r in results for f in r.get("findings", [])])
        return {"schema_version": "2.0", "target": resolved, "plugins": results, "findings": findings}


def default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(CommandPlugin(PluginSpec("file", "Identify local file format", "file", ["identify"]), lambda t: ["file", "-b", t]))
    registry.register(CommandPlugin(PluginSpec("strings", "Extract printable strings", "strings", ["identify"]), lambda t: ["strings", "-a", "-n", "6", t]))
    registry.register(CommandPlugin(PluginSpec("readelf", "Inspect ELF headers and symbols", "readelf", ["elf"]), lambda t: ["readelf", "-h", "-s", t]))
    registry.register(CommandPlugin(PluginSpec("semgrep", "Structural source analysis", "semgrep", ["source", "sast"]), lambda t: ["semgrep", "--json", "--config", "auto", t]))
    registry.register(CommandPlugin(PluginSpec("yara", "Native YARA rule scanning", "yara", ["malware", "patterns"]), lambda t: ["yara", "--print-meta", "-r", "rules", t]))
    from modules.integration.reverse_adapters import R2Adapter, GhidraAdapter
    registry.register(AdapterPlugin(PluginSpec("radare2", "Radare2/Rizin reverse analysis", "r2", ["reverse", "binary"], parser="json"), R2Adapter))
    registry.register(AdapterPlugin(PluginSpec("ghidra", "Ghidra headless reverse analysis", "analyzeHeadless", ["reverse", "decompile"], parser="json"), GhidraAdapter))
    registry.register(CommandPlugin(PluginSpec("binwalk", "Firmware extraction and signature scan", "binwalk", ["firmware", "extraction"]), lambda t: ["binwalk", "--json", t]))
    from modules.dynamic.gdb_analyzer import DynamicAnalyzer
    registry.register(AdapterPlugin(PluginSpec("gdb", "GDB dynamic binary analysis", "gdb", ["dynamic", "debug"]), lambda t, timeout: DynamicAnalyzer(t)))
    return registry


def result_fingerprint(finding: Dict[str, Any]) -> str:
    key = "|".join(str(finding.get(k, "")) for k in ("target_hash", "target", "finding_type", "source_ref", "evidence"))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def save_run(result: Dict[str, Any], output_dir: str = "./r3con-runs") -> str:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    output = path / f"run-{stamp}.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(output)
