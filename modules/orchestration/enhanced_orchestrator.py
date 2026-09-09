"""
r3con v5.0.3 PRO - Enhanced Orchestrator
Orchestrateur puissant avec config, chaînage d'outils externes, et profils
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.result_schema import Status, make_result, deduplicate_findings, normalize_findings
from core.config_manager import get_config, ConfigManager

# Core analyzers
from modules.disasm.binary_parser import BinaryParser
from modules.disasm.capstone_engine import DisasmEngine
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer
from modules.audit.static_analyzer import StaticAnalyzer
from modules.integration.tool_manager import ToolManager
from modules.integration.reverse_adapters import R2Adapter, GhidraAdapter

# Advanced adapters (35+ tools)
try:
    from modules.integration.advanced_adapters import (
        ChecksecAdapter, RopperAdapter, OneGadgetAdapter,
        ObjdumpAdapter, ReadelfAdapter, StringsAdapter,
        BinwalkAdapter, JadxAdapter, ApktoolAdapter,
        StraceAdapter, LtraceAdapter, AngrAdapter,
        YaraAdapter, EnhancedToolChain
    )
    ADVANCED_AVAILABLE = True
except ImportError:
    ADVANCED_AVAILABLE = False


class EnhancedOrchestrator:
    """Orchestrateur PRO avec config puissante, chaînage, et profils."""

    def __init__(self,
                 target: str,
                 profile: str = "auto",
                 config_path: Optional[str] = None,
                 config: Optional[ConfigManager] = None,
                 **overrides):
        self.path = Path(target)
        self.profile = profile
        self.overrides = overrides

        # Load powerful config
        if config:
            self.config = config
        else:
            self.config = get_config(config_path=config_path, profile=profile, force_reload=True)

        # Apply overrides from CLI
        for k, v in overrides.items():
            if v is not None:
                # Support dot notation in overrides
                if "." in k:
                    parts = k.split(".")
                    current = self.config.config
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = v
                else:
                    # Top-level override
                    self.config.config[k] = v

        # Extract config values with limits
        self.timeout = self.config.get_int("analysis.timeout", 120)
        self.max_bytes = self.config.get_int("analysis.max_file_size_mb", 500) * 1024 * 1024
        self.max_workers = self.config.get_int("analysis.max_workers", 4)
        self.max_workers = max(1, min(self.max_workers, 16))
        self.cache_enabled = self.config.get_bool("analysis.cache_enabled", True)
        self.cache_dir = Path(self.config.get("analysis.cache_dir", str(Path.home() / ".cache" / "r3con")))

        # External tools config
        self.tool_manager = ToolManager(config=self.config.to_dict())
        self.prefer_disasm = self.config.get("external_tools.prefer.disasm", "auto")
        self.chaining_enabled = self.config.get_bool("external_tools.chaining.enabled", True)

        self.target_hash = None
        self.started = time.time()

    def run(self) -> Dict[str, Any]:
        if not self.path.is_file():
            return make_result(Status.INVALID, target=str(self.path), error="target_not_found")

        if self.path.stat().st_size > self.max_bytes:
            return make_result(Status.INVALID, target=str(self.path),
                               error="target_too_large", max_bytes=self.max_bytes,
                               actual_size=self.path.stat().st_size)

        target_info = self._target_info()
        self.target_hash = target_info.get("sha256")
        run_id = f"{self.target_hash[:12]}-{int(time.time())}"

        # Setup artifacts
        artifact_dir = Path(os.environ.get("R3CON_ARTIFACT_DIR", str(self.cache_dir / "runs"))) / run_id
        try:
            artifact_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            artifact_dir = None

        # Select profile based on target kind if auto
        profile = self._select_profile(target_info)
        plan = self._build_enhanced_plan(profile, target_info)

        # Execute plan
        results = self._execute_enhanced_plan(plan, target_info)

        # Collect findings
        findings = self._collect_findings(results)

        # Save artifacts
        artifact_files = []
        if artifact_dir:
            for task, result in results.items():
                try:
                    artifact = artifact_dir / f"{task}.json"
                    artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                    artifact_files.append(str(artifact))
                except (OSError, TypeError):
                    pass

        # Status aggregation
        statuses = [x.get("status") for x in results.values() if isinstance(x, dict)]
        if statuses and all(s == Status.OK.value for s in statuses):
            overall_status = Status.OK.value
        elif any(s == Status.ERROR.value for s in statuses) and all(s in (Status.ERROR.value, Status.INVALID.value) for s in statuses):
            overall_status = Status.ERROR.value
        else:
            overall_status = Status.PARTIAL.value

        return make_result(
            overall_status,
            target=target_info,
            profile=profile,
            plan=plan,
            results=results,
            findings=findings,
            tool_inventory=self.tool_manager.inspect(),
            tool_summary=self.tool_manager.summary(),
            config={
                "profile": profile,
                "timeout": self.timeout,
                "max_workers": self.max_workers,
                "prefer": {
                    "disasm": self.prefer_disasm,
                    "decompiler": self.config.get("external_tools.prefer.decompiler"),
                },
                "chaining": self.chaining_enabled,
                "limits": {
                    "max_strings": self.config.get_int("limits.max_strings"),
                    "max_findings": self.config.get_int("limits.max_findings"),
                }
            },
            execution={
                "run_id": run_id,
                "cache_enabled": self.cache_enabled,
                "artifact_dir": str(artifact_dir) if artifact_dir else None,
                "advanced_adapters": ADVANCED_AVAILABLE,
            },
            artifacts={
                "directory": str(artifact_dir) if artifact_dir else None,
                "files": artifact_files,
            },
            duration_ms=round((time.time() - self.started) * 1000)
        )

    def _target_info(self) -> Dict[str, Any]:
        """Enhanced target detection with more heuristics."""
        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)

        try:
            file_data = self.path.read_bytes()[:8192]  # First 8K for detection
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
            known_machines = {3, 8, 20, 21, 40, 62, 183, 243}
            if len(data) >= 20 and data[4] in (1, 2) and data[5] in (1, 2) and machine in known_machines:
                kind = "binary"
                confidence = 0.95
                details["elf_machine"] = machine
                details["elf_bits"] = data[4]
            else:
                kind = "firmware"
                confidence = 0.6

        # Check for ELF embedded in firmware
        elif b"\x7fELF" in file_data and full_size > 1024:
            kind = "firmware"
            confidence = 0.8
            details["elf_embedded"] = True

        # APK / ZIP
        if kind == "unknown" and magic.startswith(b"PK\x03\x04"):
            if b"AndroidManifest.xml" in file_data or b"classes.dex" in file_data:
                kind = "apk"
                confidence = 0.95
                details["apk"] = True
            else:
                # Check file extension
                if self.path.suffix.lower() in (".apk", ".zip", ".jar"):
                    kind = "apk" if self.path.suffix.lower() == ".apk" else "archive"
                    confidence = 0.8
                else:
                    kind = "archive"
                    confidence = 0.6

        # PE
        if kind == "unknown" and magic.startswith(b"MZ"):
            kind = "binary"
            confidence = 0.9
            details["pe"] = True

        # MachO
        if kind == "unknown" and magic.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe")):
            kind = "binary"
            confidence = 0.9
            details["macho"] = True

        # PCAP
        if kind == "unknown" and magic[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") or magic[:4] == b"\x0a\x0d\x0d\x0a":
            kind = "network"
            confidence = 0.95
            details["pcap"] = True

        # Source code
        if kind == "unknown":
            source_exts = {".c", ".h", ".cc", ".cpp", ".py", ".go", ".rs", ".java", ".js", ".ts", ".php", ".rb", ".sh"}
            if self.path.suffix.lower() in source_exts:
                kind = "source"
                confidence = 0.9
                details["source_ext"] = self.path.suffix
            else:
                # Check printable ratio
                if file_data:
                    printable = sum((b in (9, 10, 13) or 32 <= b < 127) for b in file_data) / len(file_data)
                    details["printable_ratio"] = printable
                    if printable > 0.85 and full_size < 5*1024*1024:
                        # Check for source indicators
                        source_indicators = [b"#include", b"def ", b"function", b"class ", b"import ", b"package "]
                        if any(ind in file_data for ind in source_indicators):
                            kind = "source"
                            confidence = 0.7

        # Firmware fallback
        if kind == "unknown":
            firmware_indicators = [b"squashfs", b"uboot", b"u-boot", b"Linux version", b"busybox", b"JFFS2", b"CRAMFS", b"filesystem"]
            found = [ind.decode() for ind in firmware_indicators if ind.lower() in file_data.lower()]
            if found:
                kind = "firmware"
                confidence = 0.75
                details["firmware_indicators"] = found
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

        kind = target_info.get("kind", "unknown")
        mapping = {
            "binary": "binary",
            "firmware": "firmware",
            "apk": "apk",
            "network": "network",
            "source": "source",
            "archive": "firmware",
        }
        return mapping.get(kind, "deep")

    def _build_enhanced_plan(self, profile: str, target_info: Dict) -> List[str]:
        """Build enhanced plan with external tools chaining."""

        # Base plans per profile
        base_plans = {
            "quick": ["identify", "strings"],
            "deep": ["identify", "strings", "imports", "protections"],
            "full": ["identify", "strings", "imports", "protections", "disassembly", "rop", "firmware_check"],
            "binary": ["identify", "strings", "imports", "protections", "disassembly", "rop"],
            "firmware": ["identify", "firmware_identify", "firmware_strings", "firmware_entropy", "binwalk"],
            "apk": ["identify", "apk_identify", "apk_strings"],
            "network": ["network_internal", "network_external"],
            "source": ["source_audit"],
            "bugbounty": ["identify", "strings", "secrets", "imports", "protections"],
        }

        plan = base_plans.get(profile, base_plans["deep"])

        # Enhance based on available tools and config
        if ADVANCED_AVAILABLE and self.chaining_enabled:
            kind = target_info.get("kind")

            if kind == "binary":
                # Add advanced binary tools if enabled
                if self.config.is_tool_enabled("checksec"):
                    if "protections" not in plan:
                        plan.append("checksec")
                if self.config.is_tool_enabled("ropper") and "rop" not in plan:
                    plan.append("ropper")
                if self.config.is_tool_enabled("one_gadget"):
                    plan.append("one_gadget")
                if self.config.is_tool_enabled("objdump") and self.prefer_disasm == "objdump":
                    plan.append("objdump")
                if self.config.is_tool_enabled("readelf"):
                    plan.append("readelf")

                # External reverse engineering
                if self.config.is_tool_enabled("r2") or self.config.is_tool_enabled("rizin"):
                    plan.append("radare2")
                if self.config.is_tool_enabled("ghidra") and self.config.get_bool("external_tools.enabled.ghidra"):
                    plan.append("ghidra")
                if self.config.is_tool_enabled("angr") and self.config.get_bool("external_tools.enabled.angr"):
                    plan.append("angr")

            elif kind == "firmware":
                if self.config.is_tool_enabled("binwalk"):
                    if "binwalk" not in plan:
                        plan.append("binwalk")

            elif kind == "apk":
                if self.config.is_tool_enabled("jadx") and self.config.get_bool("external_tools.enabled.jadx"):
                    plan.append("jadx")
                if self.config.is_tool_enabled("apktool") and self.config.get_bool("external_tools.enabled.apktool"):
                    plan.append("apktool")

            elif kind == "network":
                if self.config.is_tool_enabled("tshark"):
                    plan.append("tshark")
                if self.config.is_tool_enabled("zeek"):
                    plan.append("zeek")

        # Deduplicate but preserve order
        seen = set()
        deduped = []
        for task in plan:
            if task not in seen:
                seen.add(task)
                deduped.append(task)

        return deduped

    def _execute_enhanced_plan(self, plan: List[str], target_info: Dict) -> Dict[str, Any]:
        """Execute plan with parallelization and caching."""

        results = {}

        # Phase 1: Always run identify first
        if "identify" in plan:
            results["identify"] = self._task("identify", target_info)

        # Phase 2: Parallel independent tasks
        independent = [t for t in plan if t not in ("identify", "network_external", "tshark", "zeek")]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._cached_task, task, target_info): task for task in independent}
            for future in concurrent.futures.as_completed(futures):
                task = futures[future]
                try:
                    results[task] = future.result()
                except Exception as exc:
                    results[task] = make_result(Status.ERROR, engine=task, error=str(exc)[:500])

        # Phase 3: Network external (sequential)
        if "network_external" in plan:
            results["network_external"] = self._network_external()
        if "tshark" in plan:
            results["tshark"] = self._task("tshark", target_info)
        if "zeek" in plan:
            results["zeek"] = self._task("zeek", target_info)

        # Return in plan order
        return {k: results[k] for k in plan if k in results}

    def _cached_task(self, task: str, target_info: Dict) -> Dict[str, Any]:
        """Cached task with version-aware invalidation."""
        cacheable = self.cache_enabled and task not in ("tshark", "zeek", "network_external", "strace", "ltrace")
        cache_file = None

        if cacheable and self.target_hash:
            version_info = {
                "r3con": "5.0.3",
                "task": task,
                "profile": self.profile,
                "config_hash": hashlib.sha256(json.dumps(self.config.to_dict(), sort_keys=True).encode()).hexdigest()[:12],
            }
            key_data = {"sha256": self.target_hash, **version_info}
            key = hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
            cache_file = self.cache_dir / key[:2] / (key + ".json")

            try:
                if cache_file.is_file():
                    # Check TTL
                    age = time.time() - cache_file.stat().st_mtime
                    ttl = self.config.get_int("analysis.cache_ttl_days", 7) * 24 * 3600
                    if age > ttl:
                        cache_file.unlink(missing_ok=True)
                    else:
                        cached = json.loads(cache_file.read_text(encoding="utf-8"))
                        cached["cache"] = "hit"
                        cached["task"] = task
                        return cached
            except (OSError, ValueError):
                pass

        started = time.time()
        result = self._task(task, target_info)
        if isinstance(result, dict):
            result = dict(result, task=task, duration_ms=round((time.time() - started) * 1000))

        if cache_file and isinstance(result, dict):
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
                result["cache"] = "miss"
            except OSError:
                pass

        return result

    def _task(self, task: str, target_info: Dict) -> Dict[str, Any]:
        """Execute single task with advanced adapters."""

        # ── Basic tasks ──
        if task == "identify":
            try:
                info = BinaryParser(str(self.path)).parse()
                return make_result(Status.OK, engine="r3con.binary_parser", observations=info)
            except Exception as exc:
                return make_result(Status.ERROR, engine="r3con.binary_parser", error=str(exc)[:500])

        if task == "strings":
            max_strings = self.config.get_int("limits.max_strings", 10000)
            try:
                parser = BinaryParser(str(self.path))
                strings = parser.extract_strings()[:max_strings]
                return make_result(Status.OK, engine="r3con.binary_parser",
                                   observations=strings, count=len(strings))
            except Exception as exc:
                # Fallback to external strings tool
                if ADVANCED_AVAILABLE and self.config.is_tool_enabled("strings"):
                    return StringsAdapter(str(self.path), timeout=self.timeout).analyze()
                return make_result(Status.ERROR, engine="strings", error=str(exc)[:500])

        if task == "imports":
            max_imports = self.config.get_int("limits.max_imports", 5000)
            try:
                parser = BinaryParser(str(self.path))
                imports = parser.get_imports()[:max_imports]
                return make_result(Status.OK, engine="r3con.binary_parser",
                                   observations=imports, count=len(imports))
            except Exception as exc:
                return make_result(Status.ERROR, engine="imports", error=str(exc)[:500])

        if task == "protections":
            try:
                parser = BinaryParser(str(self.path))
                info = parser.parse()
                protections = info.get("protections", {})
                return make_result(Status.OK, engine="r3con.binary_parser", observations=protections)
            except Exception as exc:
                return make_result(Status.ERROR, engine="protections", error=str(exc)[:500])

        # ── Advanced external tools ──
        if ADVANCED_AVAILABLE:

            if task == "checksec":
                return ChecksecAdapter(str(self.path), timeout=self.config.get_tool_timeout("checksec")).analyze()

            if task == "ropper":
                return RopperAdapter(str(self.path), timeout=self.config.get_tool_timeout("ropper")).analyze()

            if task == "one_gadget":
                return OneGadgetAdapter(str(self.path), timeout=self.config.get_tool_timeout("one_gadget")).analyze()

            if task == "objdump":
                return ObjdumpAdapter(str(self.path), timeout=self.config.get_tool_timeout("objdump")).analyze()

            if task == "readelf":
                return ReadelfAdapter(str(self.path), timeout=self.config.get_tool_timeout("readelf")).analyze()

            if task == "binwalk":
                extract = self.config.get_bool("firmware.extract", False)
                return BinwalkAdapter(str(self.path), timeout=self.config.get_tool_timeout("binwalk")).analyze(extract=extract)

            if task == "jadx":
                return JadxAdapter(str(self.path), timeout=self.config.get_tool_timeout("jadx")).analyze()

            if task == "apktool":
                return ApktoolAdapter(str(self.path), timeout=self.config.get_tool_timeout("apktool")).analyze()

            if task == "rop":
                # Full ROP chain
                chain = EnhancedToolChain(str(self.path), config=self.config.to_dict())
                return chain.full_binary_analysis()

        # ── Reverse engineering ──
        if task == "disassembly":
            max_ins = self.config.get_int("disasm.max_instructions", 5000)
            try:
                engine = DisasmEngine(str(self.path), max_instructions=max_ins)
                if getattr(engine, "_cs", None) is None:
                    return make_result(Status.UNSUPPORTED, engine="r3con.capstone", error="capstone_not_available")
                asm = engine.disasm_main()
                stats = engine.get_statistics()
                return make_result(Status.OK, engine="r3con.capstone",
                                   observations={"asm": asm[:100000], "stats": stats})
            except Exception as exc:
                return make_result(Status.ERROR, engine="capstone", error=str(exc)[:500])

        if task == "radare2":
            adapter = R2Adapter(str(self.path), timeout=self.timeout)
            return adapter.analyze()

        if task == "ghidra":
            return GhidraAdapter(str(self.path), timeout=max(self.timeout, 180)).analyze()

        if task == "angr" and ADVANCED_AVAILABLE:
            return AngrAdapter(str(self.path), timeout=self.config.get_tool_timeout("angr")).analyze()

        # ── Firmware ──
        if task in ("firmware_identify", "firmware_strings", "firmware_entropy"):
            try:
                fw = FirmwareAnalyzer(str(self.path))
                if not fw.load():
                    return make_result(Status.ERROR, engine="r3con.firmware", error="load_failed")
                if task == "firmware_identify":
                    return make_result(Status.OK, engine="r3con.firmware", observations=fw.identify())
                if task == "firmware_strings":
                    max_s = self.config.get_int("firmware.max_strings", 10000)
                    return make_result(Status.OK, engine="r3con.firmware", observations=fw.extract_strings()[:max_s])
                return make_result(Status.OK, engine="r3con.firmware", observations=fw.entropy_map()[:5000])
            except Exception as exc:
                return make_result(Status.ERROR, engine="r3con.firmware", error=str(exc)[:500])

        # ── Network ──
        if task == "network_internal":
            max_bytes = self.config.get_int("network.max_bytes", 256*1024*1024)
            return ProtocolAnalyzer(str(self.path), max_bytes=max_bytes).analyze()

        if task in ("tshark", "zeek"):
            from modules.network.external_analyzers import ExternalNetworkAnalyzer
            analyzer = ExternalNetworkAnalyzer(str(self.path), timeout=self.timeout)
            if task == "tshark":
                return analyzer.tshark_fields(["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "dns.qry.name", "http.host"])
            return analyzer.zeek_offline()

        # ── Source audit ──
        if task == "source_audit":
            try:
                code = self.path.read_text(encoding="utf-8", errors="replace")
                max_size = self.config.get_int("audit.max_file_size_kb", 2048) * 1024
                if len(code) > max_size:
                    code = code[:max_size]
                findings = StaticAnalyzer().analyze(code)
                return make_result(Status.OK, engine="r3con.static_analyzer",
                                   findings=findings, observations={"lines": len(code.splitlines())})
            except OSError as exc:
                return make_result(Status.ERROR, engine="r3con.static_analyzer", error=str(exc)[:500])

        # ── Secrets ──
        if task == "secrets":
            try:
                parser = BinaryParser(str(self.path))
                strings = parser.extract_strings()
                # Simple secret detection
                secrets = []
                for s in strings[:5000]:
                    val = s.get("value", "") if isinstance(s, dict) else str(s)
                    if any(p in val.lower() for p in ["password", "api_key", "secret", "token", "passwd"]):
                        if len(val) > 8 and len(val) < 200:
                            secrets.append({"value": val[:200], "offset": s.get("offset", 0) if isinstance(s, dict) else 0})
                return make_result(Status.OK, engine="r3con.secrets", observations=secrets[:100], count=len(secrets))
            except Exception as exc:
                return make_result(Status.ERROR, engine="secrets", error=str(exc)[:500])

        return make_result(Status.UNSUPPORTED, engine=task, error="task_not_implemented")

    def _network_external(self) -> Dict[str, Any]:
        from modules.network.external_analyzers import ExternalNetworkAnalyzer
        analyzer = ExternalNetworkAnalyzer(str(self.path), timeout=self.timeout)
        engines = {
            "tshark": analyzer.tshark_fields(["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "dns.qry.name", "http.host"]),
            "zeek": analyzer.zeek_offline()
        }
        statuses = [v.get("status", "error") for v in engines.values() if isinstance(v, dict)]
        overall = "ok" if any(s == "ok" for s in statuses) else ("unsupported" if all(s == "unsupported" for s in statuses) else "partial")
        return make_result(overall, engine="external_network", observations=engines)

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

        # Deduplicate and limit
        max_findings = self.config.get_int("limits.max_findings", 10000)
        deduped = deduplicate_findings(findings)
        return deduped[:max_findings]

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"


def run_enhanced_analysis(target: str, profile: str = "auto", config_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    return EnhancedOrchestrator(target, profile=profile, config_path=config_path, **kwargs).run()
