"""Orchestrateur central r3con, local et défensif.

Il coordonne les analyseurs internes et les adaptateurs externes sans shell,
avec détection de type, budgets, statuts, provenance et rapport unifié.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from core.result_schema import Status, make_result, deduplicate_findings, normalize_findings
from modules.disasm.binary_parser import BinaryParser
from modules.disasm.capstone_engine import DisasmEngine
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.integration.tool_manager import ToolManager
from modules.network.external_analyzers import ExternalNetworkAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer
from modules.audit.static_analyzer import StaticAnalyzer
from modules.integration.reverse_adapters import R2Adapter, GhidraAdapter


class Orchestrator:
    def __init__(self, target: str, profile: str = "auto", timeout: int = 120,
                 max_mb: int = 256, max_workers: int = 3,
                 reverse_engine: str | None = None, with_ghidra: bool | None = None,
                 cache: bool = True, cache_dir: str | None = None):
        self.path = Path(target)
        self.profile = profile
        self.timeout = max(1, timeout)
        self.max_bytes = max(1, max_mb) * 1024 * 1024
        self.max_workers = max(1, min(max_workers, 8))
        self.reverse_engine = (reverse_engine or os.environ.get("R3CON_REVERSE_ENGINE", "radare2")).lower()
        if self.reverse_engine not in {"radare2", "r2", "rizin"}:
            self.reverse_engine = "radare2"
        env_ghidra = os.environ.get("R3CON_ENABLE_GHIDRA", "0").lower() in {"1", "true", "yes", "on"}
        self.with_ghidra = env_ghidra if with_ghidra is None else bool(with_ghidra)
        self.cache_enabled = bool(cache) and os.environ.get("R3CON_NO_CACHE", "0").lower() not in {"1", "true", "yes", "on"}
        self.cache_dir = Path(cache_dir or os.environ.get("R3CON_CACHE_DIR", str(Path.home() / ".cache" / "r3con")))
        self.target_hash = None
        self.started = time.time()

    def run(self) -> Dict[str, Any]:
        if not self.path.is_file():
            return make_result(Status.INVALID, target=str(self.path), error="target_not_found")
        if self.path.stat().st_size > self.max_bytes:
            return make_result(Status.INVALID, target=str(self.path), error="target_too_large", max_bytes=self.max_bytes)
        target = self._target_info()
        self.target_hash = target.get("sha256")
        run_id = f"{self.target_hash[:12]}-{int(time.time())}"
        self.artifact_dir = Path(os.environ.get("R3CON_ARTIFACT_DIR", str(self.cache_dir / "runs"))) / run_id
        try:
            self.artifact_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.artifact_dir = None
        profile = self._select_profile()
        plan = self._build_plan(profile)
        results = self._execute_plan(plan)
        findings = self._collect_findings(results)
        artifact_files = []
        if self.artifact_dir is not None:
            for task, result in results.items():
                try:
                    artifact = self.artifact_dir / f"{task}.json"
                    artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                    artifact_files.append(str(artifact))
                except (OSError, TypeError):
                    pass
            try:
                (self.artifact_dir / "manifest.json").write_text(json.dumps({"run_id": run_id, "target": target, "plan": plan, "files": artifact_files}, ensure_ascii=False, indent=2), encoding="utf-8")
                artifact_files.append(str(self.artifact_dir / "manifest.json"))
            except OSError:
                pass
        statuses = [x.get("status") for x in results.values() if isinstance(x, dict)]
        status = Status.OK.value if statuses and all(s == Status.OK.value for s in statuses) else Status.PARTIAL.value
        if any(s == Status.ERROR.value for s in statuses) and all(s in (Status.ERROR.value, Status.INVALID.value) for s in statuses):
            status = Status.ERROR.value
        return make_result(status, target=target, profile=profile, plan=plan,
                           results=results, findings=findings,
                           tool_inventory=ToolManager().inspect(),
                           execution={"run_id": run_id, "cache_enabled": self.cache_enabled, "artifact_dir": str(self.artifact_dir) if self.artifact_dir else None},
                           artifacts={"directory": str(self.artifact_dir) if self.artifact_dir else None, "files": artifact_files},
                           duration_ms=round((time.time() - self.started) * 1000))

    def _target_info(self) -> Dict[str, Any]:
        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        magic = self.path.read_bytes()[:8]
        if magic.startswith(b"\x7fELF"):
            # Un firmware peut contenir une signature ELF tronquée ou invalide.
            # On ne classe en binaire que les classes/architectures ELF connues.
            data = self.path.read_bytes()[:32]
            machine = int.from_bytes(data[18:20], "little") if len(data) >= 20 else 0
            known_machines = {3, 8, 40, 62, 183, 243}
            kind = "binary" if len(data) >= 20 and data[4] in (1, 2) and data[5] in (1, 2) and machine in known_machines else "firmware"
        elif magic.startswith(b"PK\x03\x04"):
            kind = "apk_or_zip"
        elif magic.startswith((b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            kind = "binary"
        elif magic[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
            kind = "network"
        else:
            source_suffixes = {".c", ".h", ".cc", ".cpp", ".py", ".go", ".rs", ".java", ".js", ".ts", ".php", ".rb"}
            sample = self.path.read_bytes()[:8192]
            printable_ratio = sum((b in (9, 10, 13) or 32 <= b < 127) for b in sample) / max(1, len(sample))
            kind = "source" if self.path.suffix.lower() in source_suffixes or printable_ratio > 0.92 else "firmware"
        return {"path": str(self.path), "sha256": h.hexdigest(), "size": self.path.stat().st_size, "kind": kind}

    def _select_profile(self) -> str:
        if self.profile != "auto":
            return self.profile
        kind = self._target_info()["kind"]
        return {"binary": "binary", "network": "network", "apk_or_zip": "apk", "source": "source", "source_or_firmware": "firmware", "firmware": "firmware"}.get(kind, "binary")

    def _build_plan(self, profile: str) -> List[str]:
        plans = {
            "quick": ["identify", "strings"],
            "binary": ["identify", "strings", "imports"],
            "network": ["network_internal", "network_external"],
            "firmware": ["firmware_identify", "firmware_strings", "firmware_entropy"],
            "source": ["source_audit"],
            "apk": ["apk_identify"],
            "dynamic": ["identify", "gdb_status", "gdb_info", "gdb_crash"],
        }
        if profile == "full":
            kind = self._target_info()["kind"]
            full_by_kind = {
                "binary": ["identify", "strings", "imports"],
                "network": ["network_internal", "network_external"],
                "firmware": ["identify", "firmware_identify", "firmware_strings", "firmware_entropy"],
                "source": ["source_audit"],
                "apk_or_zip": ["identify", "apk_identify"],
            }
            plan = list(full_by_kind.get(kind, ["identify", "strings"]))
        else:
            plan = list(plans.get(profile, plans["quick"]))
        if profile in ("binary", "full"):
            r2 = R2Adapter(str(self.path), timeout=self.timeout)
            if r2.executable:
                # External r2/rizin owns disassembly and pseudo-decompilation.
                plan.append("radare2")
            elif not self.with_ghidra or not GhidraAdapter(str(self.path), timeout=self.timeout).executable:
                # Controlled fallback only when no external reverse engine exists.
                plan.append("disassembly")
            # Ghidra is opt-in; an explicit request is kept in the plan so a
            # missing installation is reported as unsupported instead of hidden.
            if self.with_ghidra:
                plan.append("ghidra")
        return plan

    def _execute_plan(self, plan: List[str]) -> Dict[str, Any]:
        independent = [x for x in plan if x not in {"identify", "network_external", "gdb_crash"}]
        results: Dict[str, Any] = {}
        if "identify" in plan:
            started = time.time()
            results["identify"] = self._identify()
            if isinstance(results["identify"], dict):
                results["identify"] = dict(results["identify"], task="identify", duration_ms=round((time.time() - started) * 1000))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._cached_task, task): task for task in independent}
            for future in concurrent.futures.as_completed(futures):
                task = futures[future]
                try:
                    results[task] = future.result()
                except Exception as exc:
                    results[task] = make_result(Status.ERROR, engine=task, error=str(exc))
        if "network_external" in plan:
            results["network_external"] = self._network_external()
        if "gdb_crash" in plan:
            results["gdb_crash"] = self._gdb_crash()
        return {key: results[key] for key in plan if key in results}

    def _cached_task(self, task: str) -> Dict[str, Any]:
        cacheable = self.cache_enabled and task not in {"gdb_status", "gdb_info", "gdb_crash", "network_external"}
        cache_file = None
        if cacheable and self.target_hash:
            key = hashlib.sha256(json.dumps({"sha256": self.target_hash, "profile": self.profile, "task": task, "engine": self.reverse_engine, "ghidra": self.with_ghidra}, sort_keys=True).encode()).hexdigest()
            cache_file = self.cache_dir / key[:2] / (key + ".json")
            try:
                if cache_file.is_file():
                    cached = json.loads(cache_file.read_text(encoding="utf-8"))
                    cached["cache"] = "hit"
                    cached["task"] = task
                    return cached
            except (OSError, ValueError, TypeError):
                pass
        started = time.time()
        result = self._task(task)
        if isinstance(result, dict):
            result = dict(result, task=task, duration_ms=round((time.time() - started) * 1000))
        if cache_file is not None and isinstance(result, dict):
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
                result = dict(result)
                result["cache"] = "miss"
            except OSError:
                pass
        return result

    def _task(self, task: str) -> Dict[str, Any]:
        if task == "strings":
            parser = BinaryParser(str(self.path))
            return make_result(Status.OK, engine="r3con.binary_parser", observations=parser.extract_strings()[:2000])
        if task == "imports":
            parser = BinaryParser(str(self.path))
            return make_result(Status.OK, engine="r3con.binary_parser", observations=parser.get_imports()[:2000])
        if task == "disassembly":
            engine = DisasmEngine(str(self.path), max_instructions=2000)
            available = getattr(engine, "_cs", None) is not None
            if not available:
                return make_result(Status.UNSUPPORTED, engine="r3con.capstone", observations={"asm": [], "truncated": False})
            asm = engine.disasm_main()
            stats = engine.get_statistics()
            import re
            match = re.search(r"Total:\s+(\d+)\s+instructions", asm)
            observations = {
                "asm": asm,
                "statistics": stats,
                "instruction_count": int(match.group(1)) if match else None,
                "sections_analyzed": [s.get("name") for s in stats.get("sections", []) if s.get("name")],
                "truncated": "LIMITE ATTEINTE" in asm,
            }
            return make_result(Status.OK, engine="r3con.capstone", observations=observations)
        if task == "network_internal":
            return ProtocolAnalyzer(str(self.path), max_bytes=self.max_bytes).analyze()
        if task == "firmware_identify" or task == "firmware_strings" or task == "firmware_entropy":
            fw = FirmwareAnalyzer(str(self.path))
            if not fw.load():
                return make_result(Status.ERROR, engine="r3con.firmware", error="load_failed")
            if task == "firmware_identify":
                return make_result(Status.OK, engine="r3con.firmware", observations=fw.identify())
            if task == "firmware_strings":
                return make_result(Status.OK, engine="r3con.firmware", observations=fw.extract_strings()[:5000])
            return make_result(Status.OK, engine="r3con.firmware", observations=fw.entropy_map()[:5000])
        if task == "radare2":
            adapter = R2Adapter(str(self.path), timeout=self.timeout)
            return adapter.analyze()
        if task == "gdb_status":
            from modules.dynamic.gdb_analyzer import DynamicAnalyzer
            return make_result(Status.OK if DynamicAnalyzer(str(self.path)).available else Status.UNSUPPORTED,
                               engine="gdb", observations=DynamicAnalyzer(str(self.path)).status())
        if task == "gdb_info":
            from modules.dynamic.gdb_analyzer import DynamicAnalyzer
            info = DynamicAnalyzer(str(self.path)).get_binary_info()
            return make_result(Status.OK if info.get("raw_output") else Status.PARTIAL,
                               engine="gdb", observations=info)
        if task == "ghidra":
            return GhidraAdapter(str(self.path), timeout=max(self.timeout, 180)).analyze()
        if task == "source_audit":
            try:
                code = self.path.read_text(encoding="utf-8", errors="replace")
                findings = StaticAnalyzer().analyze(code)
                return make_result(Status.OK, engine="r3con.static_analyzer", findings=findings, observations={"lines": len(code.splitlines())})
            except OSError as exc:
                return make_result(Status.ERROR, engine="r3con.static_analyzer", error=str(exc))
        if task == "apk_identify":
            return make_result(Status.UNSUPPORTED, engine="r3con.apk", error="use_apk_profile_command", target=str(self.path))
        return make_result(Status.UNSUPPORTED, engine=task, error="task_not_implemented")

    def _identify(self) -> Dict[str, Any]:
        try:
            info = BinaryParser(str(self.path)).parse()
            if info.get("format") == "unknown":
                return make_result(Status.OK, engine="r3con.binary_parser", observations=info)
            return make_result(Status.OK, engine="r3con.binary_parser", observations=info)
        except Exception as exc:
            return make_result(Status.ERROR, engine="r3con.binary_parser", error=str(exc))

    def _network_external(self) -> Dict[str, Any]:
        analyzer = ExternalNetworkAnalyzer(str(self.path), timeout=self.timeout)
        engines = {"tshark": analyzer.tshark_fields(["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "dns.qry.name", "http.host"]), "zeek": analyzer.zeek_offline()}
        statuses = [v.get("status", "error") for v in engines.values() if isinstance(v, dict)]
        overall = "ok" if any(s == "ok" for s in statuses) else ("unsupported" if statuses and all(s == "unsupported" for s in statuses) else "partial")
        return make_result(overall, engine="external_network", observations=engines)

    def _gdb_crash(self) -> Dict[str, Any]:
        from modules.dynamic.gdb_analyzer import DynamicAnalyzer
        analyzer = DynamicAnalyzer(str(self.path))
        if not analyzer.available:
            return make_result(Status.UNSUPPORTED, engine="gdb", error="gdb_not_installed")
        observations = analyzer.analyze_crash("A" * 128, timeout=self.timeout)
        raw = observations.get("raw_output") or ""
        if raw == "[TIMEOUT]":
            status = Status.TIMEOUT
        elif raw.startswith("[ERROR]"):
            status = Status.ERROR
        else:
            status = Status.OK
        return make_result(status, engine="gdb", observations=observations)

    def _collect_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for task, result in results.items():
            if not isinstance(result, dict):
                continue
            task_findings = result.get("findings", [])
            findings.extend(normalize_findings(
                task_findings,
                target=str(self.path),
                target_hash=self.target_hash or "",
                tool=str(result.get("engine", task)),
                tool_version=str(result.get("version", "unknown")),
                source_task=task,
                provenance=result.get("provenance", {}),
            ))
            for key in ("tshark", "zeek"):
                nested = result.get(key)
                if isinstance(nested, dict) and nested.get("status") not in ("ok", "unsupported"):
                    findings.append({"type": "external_engine_issue", "severity": "INFO",
                                     "source_task": task, "engine": key,
                                     "status": nested.get("status"), "target": str(self.path),
                                     "target_hash": self.target_hash or ""})
        return deduplicate_findings(findings)[:10000]


def run_analysis(target: str, profile: str = "auto", **kwargs) -> Dict[str, Any]:
    return Orchestrator(target, profile=profile, **kwargs).run()
