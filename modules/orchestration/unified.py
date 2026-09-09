"""
r3con v5.1.0 PRO - Unified Orchestrator
Fusion de classic + enhanced + pipeline en un seul orchestrateur efficace et utile
Remplace orchestrator.py, enhanced_orchestrator.py, et r3con_core.py
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.result_schema import Status, make_result, deduplicate_findings, normalize_findings
from core.config_manager import ConfigManager, get_config
from core.pipeline import Pipeline, create_unified_pipeline, create_binary_pipeline, create_firmware_pipeline

from modules.disasm.binary_parser import BinaryParser
from modules.integration.tool_manager import ToolManager


class UnifiedOrchestrator:
    """
    Orchestrateur unifié PRO - efficace et utile
    - Utilise pipeline avec graphe de dépendances
    - Config puissante avec profils
    - 35+ outils externes avec chaining
    - Cache intelligent version-aware
    - Détection cible avancée
    """

    def __init__(self,
                 target: str,
                 profile: str = "auto",
                 config_path: Optional[str] = None,
                 config: Optional[ConfigManager] = None,
                 use_pipeline: bool = True,
                 **overrides):

        self.path = Path(target)
        self.profile = profile
        self.use_pipeline = use_pipeline
        self.overrides = overrides

        # Config puissante
        if config:
            self.config = config
        else:
            self.config = get_config(config_path=config_path, profile=profile, force_reload=True)

        # Apply CLI overrides
        for k, v in overrides.items():
            if v is not None and "." in k:
                parts = k.split(".")
                current = self.config.config
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = v

        # Extract core config
        self.timeout = self.config.get_int("analysis.timeout", 120)
        self.max_bytes = self.config.get_int("analysis.max_file_size_mb", 500) * 1024 * 1024
        self.max_workers = max(1, min(self.config.get_int("analysis.max_workers", 4), 16))
        self.cache_enabled = self.config.get_bool("analysis.cache_enabled", True)
        self.cache_dir = Path(self.config.get("analysis.cache_dir", str(Path.home() / ".cache" / "r3con")))
        self.chaining = self.config.get_bool("external_tools.chaining.enabled", True)

        self.tool_manager = ToolManager(config=self.config.to_dict())
        self.target_hash = None
        self.started = time.time()

    def run(self) -> Dict[str, Any]:
        """Run unifié - efficace avec pipeline ou fallback classic."""

        # Validation
        if not self.path.is_file():
            return make_result(Status.INVALID, target=str(self.path), error="target_not_found")

        if self.path.stat().st_size > self.max_bytes:
            return make_result(Status.INVALID, target=str(self.path),
                               error="target_too_large", max_bytes=self.max_bytes)

        # Target info avancé
        target_info = self._target_info()
        self.target_hash = target_info.get("sha256")
        run_id = f"{self.target_hash[:12]}-{int(time.time())}"

        # Artifacts
        artifact_dir = Path(os.environ.get("R3CON_ARTIFACT_DIR", str(self.cache_dir / "runs"))) / run_id
        try:
            artifact_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            artifact_dir = None

        # Profile selection
        profile = self._select_profile(target_info)
        plan = self._build_plan(profile, target_info)

        # Execute via pipeline (efficace) ou classic
        if self.use_pipeline:
            results = self._execute_via_pipeline(plan, target_info)
        else:
            results = self._execute_classic(plan, target_info)

        # Findings
        findings = self._collect_findings(results)

        # Save artifacts
        artifact_files = []
        if artifact_dir:
            for task, result in results.items():
                try:
                    (artifact_dir / f"{task}.json").write_text(
                        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    artifact_files.append(str(artifact_dir / f"{task}.json"))
                except (OSError, TypeError):
                    pass

        # Status
        statuses = [x.get("status") for x in results.values() if isinstance(x, dict)]
        if statuses and all(s == Status.OK.value for s in statuses):
            overall = Status.OK.value
        elif statuses and all(s in (Status.ERROR.value, Status.INVALID.value) for s in statuses):
            overall = Status.ERROR.value
        else:
            overall = Status.PARTIAL.value

        return make_result(
            overall,
            target=target_info,
            profile=profile,
            plan=plan,
            results=results,
            findings=findings,
            tool_inventory=self.tool_manager.inspect(),
            tool_summary=self.tool_manager.summary(),
            config_snapshot={
                "profile": profile,
                "timeout": self.timeout,
                "max_workers": self.max_workers,
                "max_file_mb": self.max_bytes // (1024*1024),
                "chaining": self.chaining,
                "cache": self.cache_enabled,
                "limits": {
                    "max_strings": self.config.get_int("limits.max_strings"),
                    "max_findings": self.config.get_int("limits.max_findings"),
                    "max_functions": self.config.get_int("limits.max_functions"),
                }
            },
            execution={
                "run_id": run_id,
                "use_pipeline": self.use_pipeline,
                "artifact_dir": str(artifact_dir) if artifact_dir else None,
                "duration_ms": round((time.time() - self.started) * 1000),
            },
            artifacts={
                "directory": str(artifact_dir) if artifact_dir else None,
                "files": artifact_files,
            },
            duration_ms=round((time.time() - self.started) * 1000)
        )

    def _target_info(self) -> Dict[str, Any]:
        """Détection cible avancée et efficace."""

        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)

        try:
            file_data = self.path.read_bytes()[:8192]
            full_size = self.path.stat().st_size
        except Exception:
            file_data = b""
            full_size = 0

        magic = file_data[:16]
        kind = "unknown"
        confidence = 0.0
        details = {"size": full_size}

        # ELF
        if magic.startswith(b"\x7fELF"):
            data = file_data[:32]
            machine = int.from_bytes(data[18:20], "little") if len(data) >= 20 else 0
            if len(data) >= 20 and data[4] in (1, 2) and data[5] in (1, 2) and machine in {3, 8, 20, 21, 40, 62, 183, 243}:
                kind = "binary"
                confidence = 0.95
                details["elf_machine"] = machine
            else:
                kind = "firmware"
                confidence = 0.6

        # ELF embedded
        elif b"\x7fELF" in file_data and full_size > 1024:
            kind = "firmware"
            confidence = 0.8
            details["elf_embedded"] = True

        # APK
        elif magic.startswith(b"PK\x03\x04"):
            if b"AndroidManifest.xml" in file_data or b"classes.dex" in file_data:
                kind = "apk"
                confidence = 0.95
            else:
                kind = "archive"
                confidence = 0.6

        # PE/MachO
        elif magic.startswith(b"MZ") or magic.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            kind = "binary"
            confidence = 0.9

        # PCAP
        elif magic[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or magic[:4] == b"\x0a\x0d\x0d\x0a":
            kind = "network"
            confidence = 0.95

        # Source
        elif self.path.suffix.lower() in {".c", ".h", ".cpp", ".py", ".go", ".rs", ".java", ".js", ".php"}:
            kind = "source"
            confidence = 0.9

        # Firmware fallback
        elif any(ind in file_data.lower() for ind in [b"squashfs", b"uboot", b"busybox", b"jffs2"]):
            kind = "firmware"
            confidence = 0.75

        else:
            kind = "firmware" if full_size > 1024*1024 else "binary"
            confidence = 0.4

        return {
            "path": str(self.path),
            "sha256": h.hexdigest(),
            "size": full_size,
            "size_human": self._human_size(full_size),
            "kind": kind,
            "confidence": confidence,
            "details": details,
        }

    def _select_profile(self, target_info: Dict) -> str:
        if self.profile != "auto":
            return self.profile
        return {
            "binary": "binary",
            "firmware": "firmware",
            "apk": "apk",
            "network": "network",
            "source": "source",
            "archive": "firmware",
        }.get(target_info.get("kind", "unknown"), "deep")

    def _build_plan(self, profile: str, target_info: Dict) -> List[str]:
        """Plan intelligent basé sur profil + config + outils."""

        base_plans = {
            "quick": ["identify", "strings"],
            "deep": ["identify", "strings", "imports", "protections"],
            "full": ["identify", "strings", "imports", "protections", "disassembly", "rop", "secrets"],
            "binary": ["identify", "strings", "imports", "protections", "checksec", "ropper", "disassembly", "r2"],
            "firmware": ["identify", "firmware_identify", "firmware_strings", "firmware_entropy", "binwalk", "secrets"],
            "apk": ["identify", "apk_identify", "apk_strings", "apk_permissions"],
            "network": ["network_internal", "tshark", "zeek"],
            "source": ["source_audit"],
            "bugbounty": ["identify", "strings", "secrets", "protections"],
            "exploit": ["identify", "protections", "checksec", "ropper", "one_gadget", "r2"],
            "stealth": ["identify", "strings", "imports"],
        }

        plan = base_plans.get(profile, base_plans["deep"])

        # Filter by enabled tools and chaining
        if not self.chaining:
            # Only core tasks if no chaining
            core_only = {"identify", "strings", "imports", "protections", "source_audit", "firmware_identify", "network_internal"}
            plan = [t for t in plan if t in core_only]

        # Filter by tool availability from config
        filtered = []
        for task in plan:
            # Map task to tool key
            tool_map = {
                "checksec": "checksec",
                "ropper": "ropper",
                "one_gadget": "one_gadget",
                "r2": "r2",
                "ghidra": "ghidra",
                "binwalk": "binwalk",
                "jadx": "jadx",
                "apktool": "apktool",
                "tshark": "tshark",
                "zeek": "zeek",
            }
            tool_key = tool_map.get(task)
            if tool_key:
                if not self.config.is_tool_enabled(tool_key):
                    continue
            filtered.append(task)

        # Deduplicate preserve order
        seen = set()
        deduped = []
        for t in filtered:
            if t not in seen:
                seen.add(t)
                deduped.append(t)

        return deduped

    def _execute_via_pipeline(self, plan: List[str], target_info: Dict) -> Dict[str, Any]:
        """Exécution via pipeline efficace."""

        target_path = str(self.path)
        pipeline = create_unified_pipeline(self.config, target_path, self.profile, target_info.get("kind", "binary"))

        # Add custom tasks not in default pipeline
        from core.pipeline import Task, TaskPriority

        # Add missing tasks from plan
        for task_name in plan:
            if task_name not in pipeline.tasks:
                # Create generic task that calls _task
                def make_func(name):
                    def func(ctx, prev):
                        return self._task(name, target_info)
                    return func

                pipeline.add_task(Task(
                    name=task_name,
                    func=make_func(task_name),
                    dependencies=["identify"] if task_name != "identify" else [],
                    priority=TaskPriority.MEDIUM,
                    cacheable=True,
                    timeout=self.timeout,
                    category="dynamic"
                ))

        context = {"target_path": target_path, "target_info": target_info, "config": self.config}
        return pipeline.execute(plan, context, max_workers=self.max_workers)

    def _execute_classic(self, plan: List[str], target_info: Dict) -> Dict[str, Any]:
        """Fallback classic execution."""

        results = {}
        if "identify" in plan:
            results["identify"] = self._task("identify", target_info)

        import concurrent.futures
        independent = [t for t in plan if t != "identify"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._task, task, target_info): task for task in independent}
            for future in concurrent.futures.as_completed(futures):
                task = futures[future]
                try:
                    results[task] = future.result()
                except Exception as exc:
                    results[task] = make_result(Status.ERROR, engine=task, error=str(exc)[:500])

        return {k: results[k] for k in plan if k in results}

    def _task(self, task: str, target_info: Dict) -> Dict[str, Any]:
        """Single task execution with advanced adapters."""

        # Core
        if task == "identify":
            try:
                info = BinaryParser(str(self.path)).parse()
                return make_result(Status.OK, engine="binary_parser", observations=info)
            except Exception as e:
                return make_result(Status.ERROR, engine="binary_parser", error=str(e)[:500])

        if task == "strings":
            try:
                parser = BinaryParser(str(self.path))
                max_s = self.config.get_int("limits.max_strings", 10000)
                strings = parser.extract_strings()[:max_s]
                return make_result(Status.OK, engine="strings", observations=strings, count=len(strings))
            except Exception as e:
                return make_result(Status.ERROR, engine="strings", error=str(e)[:500])

        if task == "imports":
            try:
                parser = BinaryParser(str(self.path))
                imports = parser.get_imports()[:5000]
                return make_result(Status.OK, engine="imports", observations=imports)
            except Exception as e:
                return make_result(Status.ERROR, engine="imports", error=str(e)[:500])

        if task == "protections":
            try:
                info = BinaryParser(str(self.path)).parse()
                return make_result(Status.OK, engine="protections", observations=info.get("protections", {}))
            except Exception as e:
                return make_result(Status.ERROR, engine="protections", error=str(e)[:500])

        # Advanced tools
        try:
            from modules.integration.advanced_adapters import (
                ChecksecAdapter, RopperAdapter, OneGadgetAdapter,
                BinwalkAdapter, EnhancedToolChain
            )

            if task == "checksec":
                return ChecksecAdapter(str(self.path), timeout=self.config.get_tool_timeout("checksec")).analyze()
            if task == "ropper":
                return RopperAdapter(str(self.path), timeout=self.config.get_tool_timeout("ropper")).analyze()
            if task == "one_gadget":
                return OneGadgetAdapter(str(self.path), timeout=self.config.get_tool_timeout("one_gadget")).analyze()
            if task == "binwalk":
                return BinwalkAdapter(str(self.path), timeout=self.config.get_tool_timeout("binwalk")).analyze(
                    extract=self.config.get_bool("firmware.extract", False)
                )
            if task == "rop":
                return EnhancedToolChain(str(self.path), config=self.config.to_dict()).full_binary_analysis()

        except ImportError:
            pass

        # Reverse
        if task == "r2":
            try:
                from modules.integration.reverse_adapters import R2Adapter
                return R2Adapter(str(self.path), timeout=self.timeout).analyze()
            except Exception as e:
                return make_result(Status.ERROR, engine="r2", error=str(e)[:500])

        if task == "ghidra":
            try:
                from modules.integration.reverse_adapters import GhidraAdapter
                return GhidraAdapter(str(self.path), timeout=max(self.timeout, 180)).analyze()
            except Exception as e:
                return make_result(Status.ERROR, engine="ghidra", error=str(e)[:500])

        # Firmware
        if task.startswith("firmware_"):
            try:
                from modules.firmware.firmware_analyzer import FirmwareAnalyzer
                fw = FirmwareAnalyzer(str(self.path))
                if not fw.load():
                    return make_result(Status.ERROR, engine="firmware", error="load_failed")
                if task == "firmware_identify":
                    return make_result(Status.OK, engine="firmware", observations=fw.identify())
                if task == "firmware_strings":
                    return make_result(Status.OK, engine="firmware", observations=fw.extract_strings()[:10000])
                if task == "firmware_entropy":
                    return make_result(Status.OK, engine="firmware", observations=fw.entropy_map()[:5000])
            except Exception as e:
                return make_result(Status.ERROR, engine="firmware", error=str(e)[:500])

        # Network
        if task == "network_internal":
            try:
                from modules.network.protocol_analyzer import ProtocolAnalyzer
                max_b = self.config.get_int("network.max_bytes", 256*1024*1024)
                return ProtocolAnalyzer(str(self.path), max_bytes=max_b).analyze()
            except Exception as e:
                return make_result(Status.ERROR, engine="network", error=str(e)[:500])

        if task in ("tshark", "zeek"):
            try:
                from modules.network.external_analyzers import ExternalNetworkAnalyzer
                analyzer = ExternalNetworkAnalyzer(str(self.path), timeout=self.timeout)
                if task == "tshark":
                    return analyzer.tshark_fields(["frame.number", "ip.src", "ip.dst"])
                return analyzer.zeek_offline()
            except Exception as e:
                return make_result(Status.ERROR, engine=task, error=str(e)[:500])

        # Source
        if task == "source_audit":
            try:
                from modules.audit.static_analyzer import StaticAnalyzer
                code = self.path.read_text(encoding="utf-8", errors="replace")
                max_kb = self.config.get_int("audit.max_file_size_kb", 2048) * 1024
                if len(code) > max_kb:
                    code = code[:max_kb]
                findings = StaticAnalyzer().analyze(code)
                return make_result(Status.OK, engine="static_analyzer", findings=findings)
            except Exception as e:
                return make_result(Status.ERROR, engine="static_analyzer", error=str(e)[:500])

        return make_result(Status.UNSUPPORTED, engine=task, error="not_implemented")

    def _collect_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for task, result in results.items():
            if not isinstance(result, dict):
                continue
            findings.extend(normalize_findings(
                result.get("findings", []),
                target=str(self.path),
                target_hash=self.target_hash or "",
                tool=str(result.get("engine", task)),
                tool_version=str(result.get("version", "unknown")),
                source_task=task,
            ))

        max_findings = self.config.get_int("limits.max_findings", 10000)
        return deduplicate_findings(findings)[:max_findings]

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"


def run_unified_analysis(target: str, profile: str = "auto", **kwargs) -> Dict[str, Any]:
    return UnifiedOrchestrator(target, profile=profile, **kwargs).run()
