"""
r3con v6.0 Titan-Omega - Autonomous Agent PRO
Agent autonome qui enchaîne outils, décide next steps, génère hypothèses, auto-exploit

Features:
- Analyse cible → décide plan → exécute pipeline → évalue findings → next steps
- Boucle autonome: observe, orient, decide, act
- Intégration workspaces fédérés + fuzzing
- Génération auto d'hypothèses 0day
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from core.workspace_manager import WorkspaceManager
from core.fuzzing_manager import FuzzingManager
from modules.orchestration.unified import UnifiedOrchestrator
from core.config_manager import get_config


class AutonomousAgent:
    """Agent autonome PRO - boucle OODA."""

    def __init__(self, workspace: Optional[str] = None, profile: str = "auto", max_iterations: int = 5):
        self.workspace_name = workspace
        self.profile = profile
        self.max_iterations = max_iterations
        self.history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []

        self.ws_manager = WorkspaceManager() if workspace else None
        self.fuzz_manager = FuzzingManager()
        self.config = get_config(profile=profile)

        self.workspace_obj = None
        if workspace:
            try:
                self.workspace_obj = self.ws_manager.get_workspace(workspace)
            except Exception:
                pass

    def _log(self, action: str, result: Any, reasoning: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iteration": len(self.history) + 1,
            "action": action,
            "reasoning": reasoning,
            "result_summary": str(result)[:500] if isinstance(result, (dict, list)) else str(result)[:500],
        }
        self.history.append(entry)

    def observe(self, target: str) -> Dict[str, Any]:
        """Phase observe: analyse initiale cible."""
        reasoning = f"Observation initiale de {target} avec profil {self.profile}"
        result = UnifiedOrchestrator(target, profile="quick", use_pipeline=True).run()

        self._log("observe", result.get("status"), reasoning)
        self.findings.extend(result.get("findings", []))

        return {
            "target_info": result.get("target", {}),
            "profile_detected": result.get("profile", self.profile),
            "initial_findings": len(result.get("findings", [])),
            "results": result.get("results", {}),
        }

    def orient(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Phase orient: évalue findings, décide axes."""
        target_info = observation.get("target_info", {})
        kind = target_info.get("kind", "binary") if isinstance(target_info, dict) else "binary"

        # Simple heuristic for next steps
        next_actions = []

        # Based on kind
        if kind == "binary":
            next_actions.append({"action": "deep_binary", "profile": "binary", "reason": "Binaire détecté, analyse approfondie avec checksec/ropper/r2"})
            # If has findings with BOF, suggest exploit + fuzzing
            has_bof = any("BOF" in str(f) or "overflow" in str(f).lower() for f in self.findings)
            if has_bof:
                next_actions.append({"action": "fuzzing", "profile": "exploit", "reason": "BOF détecté, fuzzing recommandé"})
                next_actions.append({"action": "exploit", "profile": "exploit", "reason": "BOF détecté, génération ROP chain"})
        elif kind == "firmware":
            next_actions.append({"action": "deep_firmware", "profile": "firmware", "reason": "Firmware détecté, analyse binwalk + strings + entropy"})
        elif kind == "apk":
            next_actions.append({"action": "deep_apk", "profile": "apk", "reason": "APK détecté, analyse manifest + smali + jadx"})
        elif kind == "network":
            next_actions.append({"action": "deep_network", "profile": "network", "reason": "PCAP détecté, analyse tshark/zeek"})

        # Always suggest full if quick was used
        if observation.get("profile_detected") == "quick":
            next_actions.append({"action": "full_analysis", "profile": "full", "reason": "Analyse quick initiale, passage en full pour couverture complète"})

        reasoning = f"Orientation basée sur kind={kind}, findings={len(self.findings)}, actions proposées={len(next_actions)}"
        self._log("orient", next_actions, reasoning)

        return {
            "kind": kind,
            "findings_count": len(self.findings),
            "next_actions": next_actions,
            "reasoning": reasoning,
        }

    def decide(self, orientation: Dict[str, Any]) -> Dict[str, Any]:
        """Phase decide: choisit prochaine action."""
        next_actions = orientation.get("next_actions", [])

        if not next_actions:
            return {"action": "finish", "reason": "Aucune action supplémentaire nécessaire"}

        # Pick highest priority action not yet done
        done_actions = {h["action"] for h in self.history}

        for candidate in next_actions:
            if candidate["action"] not in done_actions:
                self._log("decide", candidate, f"Choix action {candidate['action']}: {candidate['reason']}")
                return candidate

        return {"action": "finish", "reason": "Toutes actions proposées déjà effectuées"}

    def act(self, decision: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Phase act: exécute action décidée."""
        action = decision.get("action", "finish")
        profile = decision.get("profile", self.profile)

        if action == "finish":
            self._log("act", "finished", decision.get("reason", ""))
            return {"status": "finished", "findings": self.findings}

        reasoning = decision.get("reason", f"Exécution {action} avec profil {profile}")

        try:
            if action in ("deep_binary", "deep_firmware", "deep_apk", "deep_network", "full_analysis"):
                result = UnifiedOrchestrator(target, profile=profile, use_pipeline=True).run()
                self.findings.extend(result.get("findings", []))
                self._log("act", result.get("status"), f"{reasoning} → {result.get('status')}")

                # Save to workspace if exists
                if self.workspace_obj:
                    try:
                        self.workspace_obj.add_findings(result.get("findings", []), source=f"agent:{action}")
                        artifact_path = self.workspace_obj.artifacts_dir / f"agent_{action}_{int(time.time())}.json"
                        artifact_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
                    except Exception:
                        pass

                return {
                    "action": action,
                    "profile": profile,
                    "status": result.get("status"),
                    "findings_added": len(result.get("findings", [])),
                    "total_findings": len(self.findings),
                    "results": result.get("results", {}),
                }

            elif action == "fuzzing":
                # Create fuzzing campaign
                try:
                    camp_name = f"agent_fuzz_{Path(target).stem}_{int(time.time())}"
                    campaign = self.fuzz_manager.create_campaign(
                        name=camp_name,
                        target=target,
                        engine="afl",
                        workspace=self.workspace_name,
                        tags=["agent", "auto"],
                    )
                    self._log("act", f"fuzzing campaign {camp_name} created", reasoning)
                    return {
                        "action": "fuzzing",
                        "campaign": camp_name,
                        "output_dir": campaign.output_dir,
                        "status": "created",
                        "reason": "Campagne créée, lancer manuellement: afl-fuzz -i corpus -o output -- target @@",
                    }
                except Exception as e:
                    self._log("act", f"fuzzing failed: {e}", reasoning)
                    return {"action": "fuzzing", "status": "error", "error": str(e)}

            elif action == "exploit":
                # Try to generate ROP chain if binary
                try:
                    from modules.exploitation.rop_generator import ROPChainGenerator
                    gen = ROPChainGenerator(target)
                    result = gen.generate()
                    self._log("act", result.get("status"), reasoning)
                    return {
                        "action": "exploit",
                        "status": result.get("status"),
                        "rop_chain": result.get("rop_chain", []),
                        "gadgets": result.get("gadgets_count", 0),
                    }
                except Exception as e:
                    self._log("act", f"exploit failed: {e}", reasoning)
                    return {"action": "exploit", "status": "error", "error": str(e)}

        except Exception as e:
            self._log("act", f"error: {e}", reasoning)
            return {"action": action, "status": "error", "error": str(e)}

        self._log("act", "unknown action", reasoning)
        return {"action": action, "status": "unknown"}

    def run(self, target: str) -> Dict[str, Any]:
        """Boucle autonome complète OODA jusqu'à max_iterations ou finish."""
        start = time.time()
        iteration = 0

        observation = self.observe(target)

        while iteration < self.max_iterations:
            iteration += 1

            orientation = self.orient(observation)
            decision = self.decide(orientation)

            if decision.get("action") == "finish":
                break

            result = self.act(decision, target)

            # Update observation for next loop (simulate new findings)
            observation = {
                "target_info": observation.get("target_info", {}),
                "profile_detected": decision.get("profile", self.profile),
                "initial_findings": len(self.findings),
                "results": result.get("results", {}),
            }

        duration = round((time.time() - start) * 1000)

        # Save agent history to workspace if exists
        if self.workspace_obj:
            try:
                agent_report = {
                    "target": target,
                    "workspace": self.workspace_name,
                    "iterations": iteration,
                    "duration_ms": duration,
                    "history": self.history,
                    "findings": self.findings,
                    "total_findings": len(self.findings),
                }
                artifact_path = self.workspace_obj.artifacts_dir / f"agent_report_{int(time.time())}.json"
                artifact_path.write_text(json.dumps(agent_report, indent=2, ensure_ascii=False), encoding="utf-8")
                self.workspace_obj.add_findings(self.findings, source="agent_final")
            except Exception:
                pass

        return {
            "target": target,
            "workspace": self.workspace_name,
            "iterations": iteration,
            "duration_ms": duration,
            "history": self.history,
            "findings": self.findings,
            "total_findings": len(self.findings),
            "status": "finished",
        }
