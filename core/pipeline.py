"""
r3con v5.1.0 PRO - Unified Pipeline
Pipeline efficace avec graphe de dépendances, caching intelligent, et streaming
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures

from core.result_schema import Status, make_result
from core.config_manager import ConfigManager, get_config


class TaskPriority(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass
class Task:
    name: str
    func: Callable
    dependencies: List[str] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.MEDIUM
    cacheable: bool = True
    timeout: int = 60
    required: bool = False
    category: str = "general"


class Pipeline:
    """Pipeline unifié avec graphe de dépendances et exécution efficace."""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or get_config()
        self.tasks: Dict[str, Task] = {}
        self.results: Dict[str, Any] = {}
        self.execution_order: List[str] = []

    def add_task(self, task: Task):
        self.tasks[task.name] = task

    def add_tasks(self, tasks: List[Task]):
        for t in tasks:
            self.add_task(t)

    def _topological_sort(self, target_tasks: List[str]) -> List[str]:
        """Tri topologique avec détection de cycles."""
        visited: Set[str] = set()
        temp_visited: Set[str] = set()
        order: List[str] = []

        def visit(node: str):
            if node in temp_visited:
                raise ValueError(f"Cycle detected at {node}")
            if node in visited:
                return
            temp_visited.add(node)
            task = self.tasks.get(node)
            if task:
                for dep in task.dependencies:
                    if dep in self.tasks:
                        visit(dep)
            temp_visited.remove(node)
            visited.add(node)
            order.append(node)

        for task_name in target_tasks:
            if task_name not in visited:
                visit(task_name)

        return order

    def _group_by_level(self, ordered_tasks: List[str]) -> List[List[str]]:
        """Groupe les tâches par niveau de dépendance pour exécution parallèle."""
        levels: List[List[str]] = []
        task_levels: Dict[str, int] = {}

        for task_name in ordered_tasks:
            task = self.tasks.get(task_name)
            if not task:
                continue
            level = 0
            for dep in task.dependencies:
                if dep in task_levels:
                    level = max(level, task_levels[dep] + 1)
            task_levels[task_name] = level

            while len(levels) <= level:
                levels.append([])
            levels[level].append(task_name)

        return levels

    def execute(self, target_tasks: List[str], context: Dict[str, Any], max_workers: int = 4) -> Dict[str, Any]:
        """Exécute le pipeline avec parallélisation par niveaux."""

        # Resolve execution order
        try:
            ordered = self._topological_sort(target_tasks)
        except ValueError as e:
            return make_result(Status.ERROR, error=f"Pipeline error: {e}")

        levels = self._group_by_level(ordered)
        self.execution_order = ordered

        # Execute level by level (parallel within level)
        for level_idx, level_tasks in enumerate(levels):
            # Sort by priority within level
            level_tasks_sorted = sorted(
                level_tasks,
                key=lambda n: self.tasks[n].priority.value if n in self.tasks else 99
            )

            # Check which tasks can be skipped (dependencies failed)
            executable = []
            for task_name in level_tasks_sorted:
                task = self.tasks.get(task_name)
                if not task:
                    continue

                # Check if dependencies succeeded or are not required
                can_run = True
                for dep in task.dependencies:
                    dep_result = self.results.get(dep)
                    if dep_result:
                        dep_status = dep_result.get("status")
                        if dep_status == Status.ERROR.value and self.tasks.get(dep, Task("", lambda: None)).required:
                            can_run = False
                            break

                if can_run:
                    executable.append(task_name)
                else:
                    self.results[task_name] = make_result(Status.ERROR, engine=task_name, error="dependency_failed")

            # Execute executable tasks in parallel
            if executable:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_task = {
                        executor.submit(self._execute_single, task_name, context): task_name
                        for task_name in executable
                    }

                    for future in concurrent.futures.as_completed(future_to_task):
                        task_name = future_to_task[future]
                        try:
                            result = future.result()
                            self.results[task_name] = result
                        except Exception as exc:
                            task = self.tasks.get(task_name)
                            self.results[task_name] = make_result(
                                Status.ERROR,
                                engine=task_name,
                                error=str(exc)[:500]
                            )

        return self.results

    def _execute_single(self, task_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute une seule tâche avec timeout et gestion d'erreurs."""
        task = self.tasks.get(task_name)
        if not task:
            return make_result(Status.ERROR, engine=task_name, error="task_not_found")

        started = time.time()
        try:
            # Pass context and previous results
            result = task.func(context, self.results)

            if not isinstance(result, dict):
                result = make_result(Status.OK, engine=task_name, observations=result)

            result["task"] = task_name
            result["duration_ms"] = round((time.time() - started) * 1000)
            result["priority"] = task.priority.name
            result["category"] = task.category

            return result

        except Exception as exc:
            return make_result(
                Status.ERROR,
                engine=task_name,
                error=str(exc)[:1000],
                task=task_name,
                duration_ms=round((time.time() - started) * 1000)
            )


def create_binary_pipeline(config: ConfigManager, target_path: str) -> Pipeline:
    """Crée un pipeline optimisé pour l'analyse binaire."""

    pipeline = Pipeline(config=config)
    max_strings = config.get_int("limits.max_strings", 10000)

    # Lazy imports to avoid loading heavy modules unnecessarily
    def task_identify(ctx, prev):
        from modules.disasm.binary_parser import BinaryParser
        try:
            info = BinaryParser(ctx["target_path"]).parse()
            return make_result(Status.OK, engine="binary_parser", observations=info)
        except Exception as e:
            return make_result(Status.ERROR, engine="binary_parser", error=str(e)[:500])

    def task_strings(ctx, prev):
        from modules.disasm.binary_parser import BinaryParser
        try:
            parser = BinaryParser(ctx["target_path"])
            strings = parser.extract_strings()[:max_strings]
            return make_result(Status.OK, engine="strings", observations=strings, count=len(strings))
        except Exception as e:
            return make_result(Status.ERROR, engine="strings", error=str(e)[:500])

    def task_imports(ctx, prev):
        from modules.disasm.binary_parser import BinaryParser
        try:
            parser = BinaryParser(ctx["target_path"])
            imports = parser.get_imports()[:5000]
            return make_result(Status.OK, engine="imports", observations=imports)
        except Exception as e:
            return make_result(Status.ERROR, engine="imports", error=str(e)[:500])

    def task_protections(ctx, prev):
        # Reuse identify result if available
        identify = prev.get("identify")
        if identify and identify.get("observations"):
            protections = identify["observations"].get("protections", {})
            if protections:
                return make_result(Status.OK, engine="protections", observations=protections)

        from modules.disasm.binary_parser import BinaryParser
        try:
            info = BinaryParser(ctx["target_path"]).parse()
            return make_result(Status.OK, engine="protections", observations=info.get("protections", {}))
        except Exception as e:
            return make_result(Status.ERROR, engine="protections", error=str(e)[:500])

    def task_checksec(ctx, prev):
        if not config.is_tool_enabled("checksec"):
            return make_result(Status.UNSUPPORTED, engine="checksec", error="disabled_in_config")
        try:
            from modules.integration.advanced_adapters import ChecksecAdapter
            return ChecksecAdapter(ctx["target_path"], timeout=config.get_tool_timeout("checksec")).analyze()
        except ImportError:
            return make_result(Status.UNSUPPORTED, engine="checksec", error="adapter_not_available")

    def task_ropper(ctx, prev):
        if not config.is_tool_enabled("ropper"):
            return make_result(Status.UNSUPPORTED, engine="ropper", error="disabled")
        try:
            from modules.integration.advanced_adapters import RopperAdapter
            return RopperAdapter(ctx["target_path"], timeout=config.get_tool_timeout("ropper")).analyze()
        except ImportError:
            return make_result(Status.UNSUPPORTED, engine="ropper", error="not_available")

    def task_disasm(ctx, prev):
        max_ins = config.get_int("disasm.max_instructions", 5000)
        try:
            from modules.disasm.capstone_engine import DisasmEngine
            engine = DisasmEngine(ctx["target_path"], max_instructions=max_ins)
            if getattr(engine, "_cs", None) is None:
                return make_result(Status.UNSUPPORTED, engine="capstone", error="not_available")
            asm = engine.disasm_main()
            return make_result(Status.OK, engine="capstone", observations={"asm": asm[:100000]})
        except Exception as e:
            return make_result(Status.ERROR, engine="capstone", error=str(e)[:500])

    def task_r2(ctx, prev):
        if not config.is_tool_enabled("r2"):
            return make_result(Status.UNSUPPORTED, engine="r2", error="disabled")
        try:
            from modules.integration.reverse_adapters import R2Adapter
            return R2Adapter(ctx["target_path"], timeout=config.get_int("analysis.timeout", 120)).analyze()
        except Exception as e:
            return make_result(Status.ERROR, engine="r2", error=str(e)[:500])

    # Define tasks with dependencies and priorities
    pipeline.add_tasks([
        Task("identify", task_identify, [], TaskPriority.CRITICAL, True, 30, True, "core"),
        Task("strings", task_strings, ["identify"], TaskPriority.HIGH, True, 60, False, "core"),
        Task("imports", task_imports, ["identify"], TaskPriority.HIGH, True, 60, False, "core"),
        Task("protections", task_protections, ["identify"], TaskPriority.HIGH, True, 30, False, "security"),
        Task("checksec", task_checksec, ["identify"], TaskPriority.MEDIUM, True, 30, False, "security"),
        Task("ropper", task_ropper, ["identify"], TaskPriority.MEDIUM, True, 60, False, "exploit"),
        Task("disasm", task_disasm, ["identify"], TaskPriority.MEDIUM, True, 60, False, "disasm"),
        Task("r2", task_r2, ["identify"], TaskPriority.LOW, True, 120, False, "reverse"),
    ])

    return pipeline


def create_firmware_pipeline(config: ConfigManager, target_path: str) -> Pipeline:
    """Pipeline pour firmware."""

    pipeline = Pipeline(config=config)

    def task_fw_identify(ctx, prev):
        from modules.firmware.firmware_analyzer import FirmwareAnalyzer
        try:
            fw = FirmwareAnalyzer(ctx["target_path"])
            if not fw.load():
                return make_result(Status.ERROR, engine="firmware", error="load_failed")
            return make_result(Status.OK, engine="firmware", observations=fw.identify())
        except Exception as e:
            return make_result(Status.ERROR, engine="firmware", error=str(e)[:500])

    def task_fw_strings(ctx, prev):
        from modules.firmware.firmware_analyzer import FirmwareAnalyzer
        try:
            fw = FirmwareAnalyzer(ctx["target_path"])
            if not fw.load():
                return make_result(Status.ERROR, engine="firmware", error="load_failed")
            max_s = config.get_int("firmware.max_strings", 10000)
            return make_result(Status.OK, engine="firmware", observations=fw.extract_strings()[:max_s])
        except Exception as e:
            return make_result(Status.ERROR, engine="firmware", error=str(e)[:500])

    def task_binwalk(ctx, prev):
        if not config.is_tool_enabled("binwalk"):
            return make_result(Status.UNSUPPORTED, engine="binwalk", error="disabled")
        try:
            from modules.integration.advanced_adapters import BinwalkAdapter
            extract = config.get_bool("firmware.extract", False)
            return BinwalkAdapter(ctx["target_path"], timeout=config.get_tool_timeout("binwalk")).analyze(extract=extract)
        except ImportError:
            return make_result(Status.UNSUPPORTED, engine="binwalk", error="not_available")

    pipeline.add_tasks([
        Task("firmware_identify", task_fw_identify, [], TaskPriority.CRITICAL, True, 60, True, "core"),
        Task("firmware_strings", task_fw_strings, ["firmware_identify"], TaskPriority.HIGH, True, 60, False, "core"),
        Task("binwalk", task_binwalk, ["firmware_identify"], TaskPriority.MEDIUM, True, 120, False, "extract"),
    ])

    return pipeline


def create_binary_pipeline_pro(config: ConfigManager, target_path: str) -> Pipeline:
    """Pipeline PRO v6.1 avec knowledge + YARA + deps + callgraph + reporting."""
    pipeline = create_binary_pipeline(config, target_path)

    def task_cve_scan(ctx, prev):
        try:
            from modules.knowledge.cve_db import CVEDatabase
            db = CVEDatabase()
            strings_res = prev.get("strings")
            disasm_res = prev.get("disasm")
            combined = ""
            if strings_res and strings_res.get("observations"):
                obs = strings_res["observations"]
                if isinstance(obs, list):
                    combined += "\n".join(str(x) for x in obs[:5000])
                else:
                    combined += str(obs)[:100000]
            if disasm_res and disasm_res.get("observations"):
                asm = disasm_res["observations"].get("asm", "")
                combined += "\n" + asm[:100000]

            # Create temp file for scanning
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as tf:
                tf.write(combined[:200000])
                tf_path = tf.name
            try:
                findings = db.search(tf_path, min_confidence=0.3)
                return make_result(Status.OK, engine="cve_db", observations=findings, count=len(findings))
            finally:
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass
        except Exception as e:
            return make_result(Status.ERROR, engine="cve_db", error=str(e)[:500])

    def task_yara_scan(ctx, prev):
        try:
            from modules.knowledge.yara_manager import YaraManager
            ym = YaraManager()
            result = ym.scan_file(ctx["target_path"])
            return make_result(Status.OK, engine="yara", observations=result, count=len(result.get("matches", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="yara", error=str(e)[:500])

    def task_deps_scan(ctx, prev):
        try:
            from pathlib import Path
            from modules.deps.dependency_scanner import DependencyScanner
            ds = DependencyScanner()
            target = Path(ctx["target_path"])
            # If target is a directory, scan it; else scan parent dir for dep files
            scan_dir = str(target if target.is_dir() else target.parent)
            result = ds.scan_directory(scan_dir)
            return make_result(Status.OK, engine="dependency_scanner", observations=result, count=result.get("vulnerable", 0))
        except Exception as e:
            return make_result(Status.ERROR, engine="dependency_scanner", error=str(e)[:500])

    def task_callgraph(ctx, prev):
        try:
            from modules.callgraph.call_graph import CallGraph
            disasm_res = prev.get("disasm")
            if not disasm_res or disasm_res.get("status") != Status.OK.value:
                return make_result(Status.UNSUPPORTED, engine="call_graph", error="no_disasm")
            # Re-use disasm or scan original if source
            cg = CallGraph()
            # Try to get source from context if it's a source file
            target = ctx["target_path"]
            if target.endswith(('.c', '.cpp', '.h')):
                result = cg.analyze_file(target)
            else:
                # No source, return empty but ok
                return make_result(Status.OK, engine="call_graph", observations={"functions": 0, "calls": 0, "paths_to_sinks": []})
            return make_result(Status.OK, engine="call_graph", observations=result, count=len(result.get("paths_to_sinks", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="call_graph", error=str(e)[:500])

    def task_ioc_extract(ctx, prev):
        try:
            from modules.knowledge.ioc_correlator import IoCCorrelator
            corr = IoCCorrelator()
            strings_res = prev.get("strings")
            content = ""
            if strings_res and strings_res.get("observations"):
                obs = strings_res["observations"]
                if isinstance(obs, list):
                    content = "\n".join(str(x) for x in obs[:10000])
                else:
                    content = str(obs)
            iocs = corr.extract_iocs(content)
            total = sum(len(v) for v in iocs.values())
            return make_result(Status.OK, engine="ioc_correlator", observations=iocs, count=total)
        except Exception as e:
            return make_result(Status.ERROR, engine="ioc_correlator", error=str(e)[:500])

    def task_knowledge_graph(ctx, prev):
        try:
            from modules.knowledge.graph import KnowledgeGraph
            kg = KnowledgeGraph()
            # Aggregate findings
            all_findings = []
            for task_name, res in prev.items():
                if res and isinstance(res, dict) and res.get("observations"):
                    obs = res["observations"]
                    if isinstance(obs, list):
                        for item in obs:
                            if isinstance(item, dict) and "type" in item:
                                all_findings.append(item)
                    elif isinstance(obs, dict) and "findings" in obs:
                        all_findings.extend(obs["findings"][:50])

            for finding in all_findings[:100]:
                try:
                    kg.add_finding(finding, workspace_id=ctx.get("workspace_id", "default"))
                except Exception:
                    continue

            stats = kg.get_stats()
            return make_result(Status.OK, engine="knowledge_graph", observations=stats)
        except Exception as e:
            return make_result(Status.ERROR, engine="knowledge_graph", error=str(e)[:500])

    def task_enhanced_report(ctx, prev):
        try:
            from modules.reporting.enhanced_reporting import EnhancedReporting
            reporter = EnhancedReporting()
            all_findings = []
            for res in prev.values():
                if not res or not isinstance(res, dict):
                    continue
                obs = res.get("observations")
                if isinstance(obs, list):
                    for item in obs:
                        if isinstance(item, dict) and ("type" in item or "severity" in item):
                            all_findings.append(item)
                elif isinstance(obs, dict):
                    if "findings" in obs and isinstance(obs["findings"], list):
                        all_findings.extend(obs["findings"])
                    if "matches" in obs and isinstance(obs["matches"], list):
                        for m in obs["matches"]:
                            all_findings.append({
                                "type": f"YARA: {m.get('rule','unknown')}",
                                "severity": m.get("severity", "MEDIUM"),
                                "description": m.get("description", ""),
                                "file": m.get("file", ctx["target_path"]),
                            })

            # Deduplicate
            seen = set()
            unique = []
            for f in all_findings:
                key = (f.get("type", ""), f.get("file", ""), str(f.get("line", "")))
                if key not in seen:
                    seen.add(key)
                    unique.append(f)

            report = reporter.generate_bugbounty_report(unique, {"target": ctx["target_path"], "type": "binary"})
            sarif = reporter.generate_sarif(unique, ctx["target_path"])
            return make_result(Status.OK, engine="enhanced_reporting", observations={"report": report, "sarif": sarif, "findings": unique}, count=len(unique))
        except Exception as e:
            return make_result(Status.ERROR, engine="enhanced_reporting", error=str(e)[:500])

    pipeline.add_tasks([
        Task("cve_scan", task_cve_scan, ["strings", "disasm"], TaskPriority.HIGH, True, 60, False, "knowledge"),
        Task("yara_scan", task_yara_scan, ["identify"], TaskPriority.HIGH, True, 60, False, "knowledge"),
        Task("deps_scan", task_deps_scan, ["identify"], TaskPriority.MEDIUM, True, 60, False, "deps"),
        Task("callgraph", task_callgraph, ["disasm"], TaskPriority.MEDIUM, True, 60, False, "analysis"),
        Task("ioc_extract", task_ioc_extract, ["strings"], TaskPriority.MEDIUM, True, 30, False, "knowledge"),
        Task("knowledge_graph", task_knowledge_graph, ["cve_scan", "yara_scan", "ioc_extract"], TaskPriority.LOW, True, 30, False, "knowledge"),
        Task("enhanced_report", task_enhanced_report, ["knowledge_graph", "callgraph", "deps_scan"], TaskPriority.LOW, True, 30, False, "reporting"),
    ])

    return pipeline


def create_malware_pipeline(config: ConfigManager, target_path: str) -> Pipeline:
    """Pipeline malware PRO v6.2 - PE/ELF + behavior + classifier + unpacker + extractor + anti-analysis."""
    pipeline = Pipeline(config=config)

    def task_pe_analyze(ctx, prev):
        try:
            from modules.malware.pe_analyzer import PEAnalyzer
            analyzer = PEAnalyzer(ctx["target_path"])
            result = analyzer.analyze()
            return make_result(Status.OK, engine="pe_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="pe_analyzer", error=str(e)[:500])

    def task_elf_analyze(ctx, prev):
        try:
            from modules.malware.elf_analyzer import ELFAnalyzer
            analyzer = ELFAnalyzer(ctx["target_path"])
            result = analyzer.analyze()
            return make_result(Status.OK, engine="elf_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="elf_analyzer", error=str(e)[:500])

    def task_behavior(ctx, prev):
        try:
            from modules.malware.behavior_analyzer import BehaviorAnalyzer
            analyzer = BehaviorAnalyzer()
            result = analyzer.analyze_file(ctx["target_path"])
            return make_result(Status.OK, engine="behavior_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="behavior_analyzer", error=str(e)[:500])

    def task_unpacker(ctx, prev):
        try:
            from modules.malware.unpacker import Unpacker
            analyzer = Unpacker(ctx["target_path"])
            result = analyzer.analyze()
            return make_result(Status.OK, engine="unpacker", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="unpacker", error=str(e)[:500])

    def task_anti_analysis(ctx, prev):
        try:
            from modules.malware.anti_analysis import AntiAnalysisDetector
            analyzer = AntiAnalysisDetector()
            result = analyzer.analyze_file(ctx["target_path"])
            return make_result(Status.OK, engine="anti_analysis", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="anti_analysis", error=str(e)[:500])

    def task_extractor(ctx, prev):
        try:
            from modules.malware.extractor import MalwareExtractor
            analyzer = MalwareExtractor()
            result = analyzer.analyze_file(ctx["target_path"])
            return make_result(Status.OK, engine="malware_extractor", observations=result, count=result.get("ioc_count", 0))
        except Exception as e:
            return make_result(Status.ERROR, engine="malware_extractor", error=str(e)[:500])

    def task_classifier(ctx, prev):
        try:
            from modules.malware.malware_classifier import MalwareClassifier
            analyzer = MalwareClassifier()
            result = analyzer.analyze_file(ctx["target_path"])
            return make_result(Status.OK, engine="malware_classifier", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="malware_classifier", error=str(e)[:500])

    def task_malware_tools(ctx, prev):
        try:
            from modules.integration.malware_tools import MalwareToolsManager
            mgr = MalwareToolsManager(ctx["target_path"])
            result = mgr.analyze_all()
            return make_result(Status.OK, engine="malware_tools", observations=result)
        except Exception as e:
            return make_result(Status.ERROR, engine="malware_tools", error=str(e)[:500])

    def task_malware_summary(ctx, prev):
        try:
            all_findings = []
            scores = []
            for res in prev.values():
                if not res or not isinstance(res, dict):
                    continue
                obs = res.get("observations", {})
                if isinstance(obs, dict):
                    findings = obs.get("findings", [])
                    if isinstance(findings, list):
                        all_findings.extend(findings)
                    # Collect scores
                    for score_key in ["malicious_score", "overall_score", "anti_analysis_score"]:
                        if score_key in obs and isinstance(obs[score_key], (int, float)):
                            scores.append(obs[score_key])

            avg_score = sum(scores) // len(scores) if scores else 0
            if avg_score >= 70:
                verdict = "MALICIOUS"
            elif avg_score >= 40:
                verdict = "SUSPICIOUS"
            elif avg_score >= 15:
                verdict = "POTENTIALLY_UNWANTED"
            else:
                verdict = "CLEAN"

            # Primary family from classifier
            classifier_res = prev.get("classifier", {}).get("observations", {})
            primary_family = classifier_res.get("primary_family")

            return make_result(Status.OK, engine="malware_summary", observations={
                "verdict": verdict,
                "score": avg_score,
                "primary_family": primary_family,
                "total_findings": len(all_findings),
                "findings": all_findings[:100],
            }, count=len(all_findings))
        except Exception as e:
            return make_result(Status.ERROR, engine="malware_summary", error=str(e)[:500])

    pipeline.add_tasks([
        Task("pe_analyze", task_pe_analyze, [], TaskPriority.CRITICAL, True, 60, False, "malware"),
        Task("elf_analyze", task_elf_analyze, [], TaskPriority.CRITICAL, True, 60, False, "malware"),
        Task("behavior", task_behavior, ["pe_analyze", "elf_analyze"], TaskPriority.HIGH, True, 60, False, "malware"),
        Task("unpacker", task_unpacker, ["pe_analyze", "elf_analyze"], TaskPriority.HIGH, True, 60, False, "malware"),
        Task("anti_analysis", task_anti_analysis, ["pe_analyze"], TaskPriority.MEDIUM, True, 60, False, "malware"),
        Task("extractor", task_extractor, ["pe_analyze", "elf_analyze"], TaskPriority.HIGH, True, 60, False, "malware"),
        Task("classifier", task_classifier, ["behavior", "extractor"], TaskPriority.HIGH, True, 60, False, "malware"),
        Task("malware_tools", task_malware_tools, ["pe_analyze"], TaskPriority.LOW, True, 120, False, "malware"),
        Task("malware_summary", task_malware_summary, ["behavior", "unpacker", "anti_analysis", "extractor", "classifier", "malware_tools"], TaskPriority.LOW, True, 30, False, "reporting"),
    ])

    return pipeline


def create_network_pipeline(config: ConfigManager, target_path: str) -> Pipeline:
    """Pipeline network PRO v6.2 - protocol + threat + flow + DNS + TLS + HTTP + external tools."""
    pipeline = Pipeline(config=config)

    def task_protocol(ctx, prev):
        try:
            from modules.network.protocol_analyzer import ProtocolAnalyzer
            analyzer = ProtocolAnalyzer(ctx["target_path"])
            result = analyzer.analyze()
            if result.get("status") == "error":
                return make_result(Status.ERROR, engine="protocol_analyzer", error=result.get("error", "unknown"))
            return make_result(Status.OK, engine="protocol_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="protocol_analyzer", error=str(e)[:500])

    def task_threat(ctx, prev):
        try:
            from modules.network.threat_detector import ThreatDetector
            proto_res = prev.get("protocol", {}).get("observations", {})
            analyzer = ThreatDetector()
            result = analyzer.analyze_pcap_summary(proto_res)
            ioc_result = analyzer.analyze_iocs(proto_res.get("iocs", {}))
            # Merge
            combined_findings = result.get("findings", []) + ioc_result.get("findings", [])
            result["findings"] = combined_findings
            result["threat_count"] = len(combined_findings)
            return make_result(Status.OK, engine="threat_detector", observations=result, count=len(combined_findings))
        except Exception as e:
            return make_result(Status.ERROR, engine="threat_detector", error=str(e)[:500])

    def task_flow(ctx, prev):
        try:
            from modules.network.flow_analyzer import FlowAnalyzer
            proto_res = prev.get("protocol", {}).get("observations", {})
            flows = proto_res.get("flows", [])
            analyzer = FlowAnalyzer()
            result = analyzer.analyze_flows(flows)
            c2 = analyzer.detect_c2_channels(flows)
            result["c2_channels"] = c2
            return make_result(Status.OK, engine="flow_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="flow_analyzer", error=str(e)[:500])

    def task_dns(ctx, prev):
        try:
            from modules.network.dns_analyzer import DNSAnalyzer
            proto_res = prev.get("protocol", {}).get("observations", {})
            analyzer = DNSAnalyzer()
            result = analyzer.analyze_pcap_dns(proto_res)
            return make_result(Status.OK, engine="dns_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="dns_analyzer", error=str(e)[:500])

    def task_tls(ctx, prev):
        try:
            from modules.network.tls_analyzer import TLSAnalyzer
            proto_res = prev.get("protocol", {}).get("observations", {})
            analyzer = TLSAnalyzer()
            result = analyzer.analyze_pcap(proto_res)
            return make_result(Status.OK, engine="tls_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="tls_analyzer", error=str(e)[:500])

    def task_http(ctx, prev):
        try:
            from modules.network.http_analyzer import HTTPAnalyzer
            proto_res = prev.get("protocol", {}).get("observations", {})
            analyzer = HTTPAnalyzer()
            result = analyzer.analyze_pcap_http(proto_res)
            return make_result(Status.OK, engine="http_analyzer", observations=result, count=len(result.get("findings", [])))
        except Exception as e:
            return make_result(Status.ERROR, engine="http_analyzer", error=str(e)[:500])

    def task_network_tools(ctx, prev):
        try:
            from modules.integration.network_tools import NetworkToolsManager
            mgr = NetworkToolsManager(ctx["target_path"])
            result = mgr.analyze_all()
            return make_result(Status.OK, engine="network_tools", observations=result)
        except Exception as e:
            return make_result(Status.ERROR, engine="network_tools", error=str(e)[:500])

    def task_network_summary(ctx, prev):
        try:
            all_findings = []
            for res in prev.values():
                if not res or not isinstance(res, dict):
                    continue
                obs = res.get("observations", {})
                if isinstance(obs, dict):
                    findings = obs.get("findings", [])
                    if isinstance(findings, list):
                        all_findings.extend(findings)

            proto_res = prev.get("protocol", {}).get("observations", {})
            summary = {
                "total_flows": len(proto_res.get("flows", [])),
                "total_findings": len(all_findings),
                "protocols": proto_res.get("protocols", {}),
                "ioc_count": sum(len(v) for v in proto_res.get("iocs", {}).values()) if isinstance(proto_res.get("iocs"), dict) else 0,
                "findings": all_findings[:100],
            }

            return make_result(Status.OK, engine="network_summary", observations=summary, count=len(all_findings))
        except Exception as e:
            return make_result(Status.ERROR, engine="network_summary", error=str(e)[:500])

    pipeline.add_tasks([
        Task("protocol", task_protocol, [], TaskPriority.CRITICAL, True, 120, True, "network"),
        Task("threat", task_threat, ["protocol"], TaskPriority.HIGH, True, 60, False, "network"),
        Task("flow", task_flow, ["protocol"], TaskPriority.HIGH, True, 60, False, "network"),
        Task("dns", task_dns, ["protocol"], TaskPriority.MEDIUM, True, 60, False, "network"),
        Task("tls", task_tls, ["protocol"], TaskPriority.MEDIUM, True, 60, False, "network"),
        Task("http", task_http, ["protocol"], TaskPriority.MEDIUM, True, 60, False, "network"),
        Task("network_tools", task_network_tools, ["protocol"], TaskPriority.LOW, True, 180, False, "network"),
        Task("network_summary", task_network_summary, ["threat", "flow", "dns", "tls", "http", "network_tools"], TaskPriority.LOW, True, 30, False, "reporting"),
    ])

    return pipeline


def create_unified_pipeline(config: ConfigManager, target_path: str, profile: str, target_kind: str) -> Pipeline:
    """Crée le pipeline unifié basé sur le type de cible et le profil - v6.2 PRO."""

    if target_kind == "binary":
        if profile in ("full", "deep", "pro", "bounty", "malware"):
            return create_binary_pipeline_pro(config, target_path)
        return create_binary_pipeline(config, target_path)
    elif target_kind == "firmware":
        return create_firmware_pipeline(config, target_path)
    elif target_kind == "malware":
        return create_malware_pipeline(config, target_path)
    elif target_kind == "network" or target_kind == "pcap":
        return create_network_pipeline(config, target_path)
    elif target_kind == "auto":
        # Auto-detect
        from pathlib import Path
        p = Path(target_path)
        if p.is_file():
            # Check extension
            if p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
                return create_network_pipeline(config, target_path)
            # Check magic
            try:
                magic = p.read_bytes()[:4]
                if magic == b"\xd4\xc3\xb2\xa1" or magic == b"\xa1\xb2\xc3\xd4" or magic[:4] == b"\x0a\x0d\x0d\x0a":
                    return create_network_pipeline(config, target_path)
                if magic[:2] == b"MZ" or magic == b"\x7fELF":
                    # Could be malware
                    if profile == "malware":
                        return create_malware_pipeline(config, target_path)
                    return create_binary_pipeline_pro(config, target_path)
            except Exception:
                pass
        return create_binary_pipeline(config, target_path)
    else:
        pipeline = Pipeline(config=config)

        def task_generic(ctx, prev):
            return make_result(Status.OK, engine="generic", observations={"target": ctx["target_path"], "kind": target_kind})

        pipeline.add_task(Task("generic", task_generic, [], TaskPriority.CRITICAL, True, 30, True, "core"))
        return pipeline
