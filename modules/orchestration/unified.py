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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.result_schema import (
    SCHEMA_VERSION,
    Status,
    make_result,
    deduplicate_findings,
    normalize_findings,
)
from core.config_manager import ConfigManager, get_config
from core.pipeline import Pipeline, create_unified_pipeline, create_binary_pipeline, create_firmware_pipeline

from modules.disasm.binary_parser import BinaryParser
from modules.integration.tool_manager import ToolManager

# Tâches externes -> (outil requis, repli interne éventuel). Sert au
# pré-vérificateur de disponibilité et à l'explication du plan.
EXTERNAL_TASKS = {
    "checksec": {"tool": "checksec", "fallback": "protections",
                 "reason": "protections binaires (outil spécialisé)"},
    "ropper": {"tool": "ropper", "fallback": None,
               "reason": "gadgets ROP via ropper"},
    "one_gadget": {"tool": "one_gadget", "fallback": None,
                   "reason": "one-gadget RCE"},
    "r2": {"tool": "r2", "fallback": None, "reason": "désassemblage/analyse radare2"},
    "ghidra": {"tool": "ghidra", "fallback": None, "reason": "décompilation Ghidra"},
    "binwalk": {"tool": "binwalk", "fallback": "firmware_identify",
                "reason": "extraction/signature firmware via binwalk"},
    "jadx": {"tool": "jadx", "fallback": None, "reason": "désassemblage DEX"},
    "apktool": {"tool": "apktool", "fallback": None, "reason": "décodage manifeste APK"},
    "tshark": {"tool": "tshark", "fallback": "network_internal",
               "reason": "décodage protocol via tshark"},
    "zeek": {"tool": "zeek", "fallback": None, "reason": "logs réseau Zeek"},
}


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
                 explain_only: bool = False,
                 resume_dir: Optional[str] = None,
                 **overrides):

        self.path = Path(target)
        self.profile = profile
        self.use_pipeline = use_pipeline
        self.explain_only = explain_only
        self.resume_dir = Path(resume_dir) if resume_dir else None
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
        self._cache_error: Optional[str] = None
        self._plan_completed: Dict[str, bool] = {}
        self._tools_fp: Optional[str] = None

    def run(self) -> Dict[str, Any]:
        """Run unifié - efficace avec pipeline ou fallback classic."""

        # Validation
        if not self.path.is_file():
            return make_result(Status.INVALID, target=str(self.path), error="target_not_found")

        if self.path.stat().st_size > self.max_bytes:
            return make_result(Status.INVALID, target=str(self.path),
                               error="target_too_large", max_bytes=self.max_bytes)

        # Target info avancé — une cible illisible (permission, IO) produit
        # un résultat structuré, jamais une exception.
        try:
            target_info = self._target_info()
        except PermissionError as exc:
            return make_result(Status.ERROR, target=str(self.path),
                               error="permission_denied", detail=str(exc)[:200])
        except OSError as exc:
            return make_result(Status.ERROR, target=str(self.path),
                               error=f"read_failed: {type(exc).__name__}", detail=str(exc)[:200])
        self.target_hash = target_info.get("sha256")
        run_id = f"{self.target_hash[:12]}-{int(time.time())}"

        # Artifacts
        artifact_dir = self.resume_dir or Path(os.environ.get(
            "R3CON_ARTIFACT_DIR", str(self.cache_dir / "runs"))) / run_id
        try:
            artifact_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            artifact_dir = None

        # Profile selection
        profile = self._select_profile(target_info)
        full_plan = self._build_plan(profile, target_info)
        plan_details, unavailable = self._explain_plan(full_plan, profile, target_info)
        plan = list(full_plan)

        # Mode explication uniquement : aucun module n'est exécuté.
        if self.explain_only:
            return make_result(
                Status.OK, target=target_info, profile=profile, plan=plan,
                plan_details=plan_details, explain_only=True,
                warnings=unavailable, tool_inventory=self.tool_manager.inspect(),
                tool_summary=self.tool_manager.summary(),
                schema=SCHEMA_VERSION,
            )

        # Reprise : réutiliser les résultats des tâches déjà terminées.
        results: Dict[str, Any] = {}
        if self.resume_dir:
            results = self._load_resume_state(self.resume_dir, plan)
            plan = [t for t in plan if t not in results]
        self._plan_completed = dict.fromkeys(results, True)

        # Cache versionné (hash cible + profil + config + versions d'outils).
        task_cache = None
        if self.cache_enabled and self.resume_dir is None:
            try:
                from core.cache import TaskCache
                task_cache = TaskCache(cache_dir=self.cache_dir / "tasks")
                fp_config = self._config_fingerprint(profile)
                fp_tools = self._tools_fingerprint()
                cached_results: Dict[str, Any] = {}
                for task in plan:
                    key = TaskCache.fingerprint(self.target_hash, task, profile, fp_config, fp_tools)
                    cached = task_cache.get(key)
                    if isinstance(cached, dict):
                        cached = dict(cached)
                        cached["cache"] = {"hit": True, "key": key[:16]}
                        cached_results[task] = cached
                cached_tasks = set(cached_results)
                results.update(cached_results)
                plan = [t for t in plan if t not in cached_tasks]
            except Exception as exc:  # noqa: BLE001 - le cache ne doit jamais casser l'analyse
                self._cache_error = str(exc)[:300]
                task_cache = None

        # Les tâches dont l'outil externe est absent SANS repli interne sont
        # marquées unsupported AVANT exécution (aucune erreur tardive) ; celles
        # avec repli sont exécutées puis, en cas d'échec, remplacées par le
        # résultat du moteur interne local (résultat explicitement marqué
        # « fallback »).
        fallback_for = {d["task"]: d["fallback"] for d in plan_details if d.get("fallback")}
        executed_plan = [t for t in plan if t not in unavailable]
        for task in unavailable:
            if task in results:  # déjà fourni par reprise/cache : on n'écrase pas
                continue
            entry = next((d for d in plan_details if d["task"] == task), None)
            results[task] = make_result(
                Status.UNSUPPORTED, engine=task, error="tool_unavailable",
                tool=(entry or {}).get("tool"),
                install_hint=(entry or {}).get("install_hint"),
                reason="outil externe absent et aucun repli interne disponible",
            )

        # Exécution via pipeline (efficace) ou classic — une tâche qui
        # échoue n'interrompt jamais les autres.
        if executed_plan:
            try:
                if self.use_pipeline:
                    exec_results = self._execute_via_pipeline(executed_plan, target_info)
                else:
                    exec_results = self._execute_classic(executed_plan, target_info)
            except Exception as exc:  # noqa: BLE001 - l'orchestrateur survit à tout
                exec_results = {task: make_result(Status.ERROR, engine=task,
                                                   error=f"orchestrator_failure: {exc}"[:500])
                                for task in executed_plan}
            for task in executed_plan:
                result = exec_results.get(task) or make_result(
                    Status.ERROR, engine=task, error="task_produced_no_result")
                if isinstance(result, dict) and result.get("status") in (
                        Status.ERROR.value, Status.UNSUPPORTED.value, Status.TIMEOUT.value
                ) and fallback_for.get(task):
                    fb = fallback_for[task]
                    fb_result = self._task(fb, target_info)
                    if isinstance(fb_result, dict) and fb_result.get("status") == Status.OK.value:
                        fb_result = dict(fb_result)
                        fb_result["fallback"] = True
                        prov = dict(fb_result.get("provenance") or {})
                        prov.update({"fallback": True, "fallback_of": task,
                                     "missing_tool": EXTERNAL_TASKS.get(task, {}).get("tool", task)})
                        fb_result["provenance"] = prov
                        fb_result["fallback_reason"] = f"outil '{task}' indisponible ; repli interne '{fb}'"
                        result = fb_result
                results[task] = result

        # Alimentation du cache + persistance de l'état pour la reprise.
        if task_cache is not None:
            fp_config = self._config_fingerprint(profile)
            fp_tools = self._tools_fingerprint()
            for task, result in results.items():
                if isinstance(result, dict) and result.get("status") in (Status.OK.value, Status.PARTIAL.value) \
                        and not result.get("cache"):
                    key = TaskCache.fingerprint(self.target_hash, task, profile, fp_config, fp_tools)
                    task_cache.set(key, result)
        if artifact_dir:
            try:
                state = {"run_id": run_id, "target": str(self.path), "profile": profile,
                         "target_hash": self.target_hash, "plan": list(results),
                         "completed": sorted(t for t, r in results.items()
                                             if isinstance(r, dict) and r.get("status") == Status.OK.value),
                         "finished_utc": datetime.now(timezone.utc).isoformat()}
                (artifact_dir / "state.json").write_text(
                    json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass

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

        # Status — les sauts « tool_unavailable » sont des limites documentées,
        # pas des échecs : ils n'empêchent pas un statut global « ok ».
        statuses = [x.get("status") for x in results.values() if isinstance(x, dict)
                    and not (x.get("status") == Status.UNSUPPORTED.value
                             and x.get("error") == "tool_unavailable")]
        if statuses and all(s == Status.OK.value for s in statuses):
            overall = Status.OK.value
        elif statuses and all(s in (Status.ERROR.value, Status.INVALID.value) for s in statuses):
            overall = Status.ERROR.value
        else:
            overall = Status.PARTIAL.value

        fallbacks_used = sorted(
            task for task, result in results.items()
            if isinstance(result, dict) and (result.get("fallback")
                                             or (result.get("provenance") or {}).get("fallback_of"))
        )
        warnings = list(unavailable) if isinstance(unavailable, list) else []
        cache_hits = sorted(t for t, r in results.items() if isinstance(r, dict) and r.get("cache"))

        return make_result(
            overall,
            target=target_info,
            profile=profile,
            plan=full_plan,
            executed_plan=plan,
            plan_details=plan_details,
            results=results,
            findings=findings,
            fallbacks_used=fallbacks_used,
            cache_stats={**({"hits": len(cache_hits), "hit_tasks": cache_hits,
                             "error": getattr(self, "_cache_error", None)} if task_cache else
                            {"hits": 0, "enabled": False})},
            resumed_tasks=sorted(self._plan_completed) if self.resume_dir else [],
            warnings=warnings,
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
        """Détection cible via le classifieur unifié (offline, stdlib)."""

        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)

        from core.target_types import detect_target, human_description

        detected = detect_target(self.path)
        full_size = self.path.stat().st_size
        return {
            "path": str(self.path),
            "sha256": h.hexdigest(),
            "size": full_size,
            "size_human": self._human_size(full_size),
            "kind": detected.kind,
            "types": detected.types,
            "confidence": detected.confidence,
            "indicators": detected.indicators,
            "description": human_description(detected),
            "details": detected.details,
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
            "container": "firmware",
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

    # ── Explication du plan, pré-vérification des outils ────────────

    def _explain_plan(self, plan: List[str], profile: str,
                      target_info: Dict[str, Any]) -> "tuple[List[Dict[str, Any]], List[str]]":
        """Construit un plan explicable et la liste des tâches à sauter.

        Chaque entrée explique POURQUOI la tâche est là, l'outil utilisé, sa
        disponibilité et le repli interne éventuel. Les tâches dont l'outil
        externe est absent et sans repli reviennent dans ``unavailable``.
        """
        from core.target_types import KIND_BINARY

        details: List[Dict[str, Any]] = []
        unavailable: List[str] = []
        detected = ", ".join(target_info.get("types") or [target_info.get("kind", "unknown")])
        for task in plan:
            spec = EXTERNAL_TASKS.get(task)
            entry: Dict[str, Any] = {
                "task": task,
                "reason": spec["reason"] if spec else "analyse interne r3con",
                "tool": spec["tool"] if spec else "r3con",
                "tool_available": True,
                "fallback": None,
                "profile": profile,
                "target_types": detected,
                "timeout": self.timeout,
            }
            if spec:
                present = self.tool_manager.is_available(spec["tool"])
                entry["tool_available"] = bool(present)
                entry["install_hint"] = self._install_hint(spec["tool"])
                if not present:
                    if spec["fallback"] and spec["fallback"] in plan:
                        entry["fallback"] = spec["fallback"]
                        entry["note"] = (f"outil '{spec['tool']}' absent : repli interne "
                                         f"'{spec['fallback']}' utilisé si l'adaptateur échoue")
                    else:
                        unavailable.append(task)
                        entry["skipped"] = True
                        entry["note"] = f"outil '{spec['tool']}' absent et sans repli : tâche ignorée"
            if task == "checksec" and target_info.get("kind") != KIND_BINARY:
                entry["note"] = (entry.get("note", "") + " ; cible non-ELF/PE : checksec peu pertinent").strip(" ;")
            details.append(entry)
        return details, unavailable

    def _install_hint(self, tool_key: str) -> str:
        try:
            spec = self.tool_manager.by_key.get(tool_key)
            packages = getattr(spec, "packages", None) if spec is not None else None
            if packages:
                mgr, pkg = sorted(packages.items())[0]
                return f"installez via {mgr}: {pkg} (optionnel ; r3con reste fonctionnel sans)"
        except Exception:  # noqa: BLE001
            pass
        return f"outil optionnel '{tool_key}' absent ; installez-le pour enrichir l'analyse"

    def _config_fingerprint(self, profile: str) -> str:
        """Empreinte stable des options qui influencent les résultats."""
        cfg = self.config.to_dict() if hasattr(self.config, "to_dict") else {}
        relevant = {
            "profile": profile,
            "timeout": self.timeout,
            "workers": self.max_workers,
            "max_file_mb": self.max_bytes // (1024 * 1024),
            "limits": (cfg.get("limits") or {}),
            "analysis": (cfg.get("analysis") or {}),
            "enabled_tools": sorted((cfg.get("external_tools") or {}).get("enabled", {}).items()
                                    if isinstance((cfg.get("external_tools") or {}).get("enabled"), dict) else []),
        }
        blob = json.dumps(relevant, sort_keys=True, default=str, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def _tools_fingerprint(self) -> str:
        try:
            rows = self.tool_manager.inspect()
            pairs = sorted((f"{r.get('key')}={r.get('version') or 'present' if r.get('present') else '-'}"
                            for r in rows if isinstance(r, dict)))
            blob = json.dumps(pairs, ensure_ascii=False)
            return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
        except Exception:  # noqa: BLE001 - inspect peut échouer sur config exotique
            return "unknown"

    def _load_resume_state(self, resume_dir: Path, plan: List[str]) -> Dict[str, Any]:
        """Reprend une exécution interrompue depuis les artifacts d'un run."""
        reused: Dict[str, Any] = {}
        for task in plan:
            candidate = resume_dir / f"{task}.json"
            if not candidate.is_file():
                continue
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(payload, dict) and payload.get("status") in (Status.OK.value, Status.PARTIAL.value):
                payload = dict(payload)
                payload["resumed"] = True
                reused[task] = payload
        return reused


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
