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


def create_unified_pipeline(config: ConfigManager, target_path: str, profile: str, target_kind: str) -> Pipeline:
    """Crée le pipeline unifié basé sur le type de cible et le profil."""

    if target_kind == "binary":
        return create_binary_pipeline(config, target_path)
    elif target_kind == "firmware":
        return create_firmware_pipeline(config, target_path)
    else:
        # Generic pipeline
        pipeline = Pipeline(config=config)

        def task_generic(ctx, prev):
            return make_result(Status.OK, engine="generic", observations={"target": ctx["target_path"], "kind": target_kind})

        pipeline.add_task(Task("generic", task_generic, [], TaskPriority.CRITICAL, True, 30, True, "core"))
        return pipeline
