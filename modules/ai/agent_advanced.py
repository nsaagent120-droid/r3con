"""
r3con v7.0 - Advanced AI Agent PRO
OODA loop (Observe, Orient, Decide, Act) with tool chaining + autonomous analysis
"""
from __future__ import annotations
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import time

class AdvancedAgent:
    """Advanced Agent PRO - autonomous analysis with OODA."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.history: List[Dict[str, Any]] = []
        self.max_iterations = self.config.get("max_iterations", 10)

    def observe(self, target_path: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Observe phase - gather initial info."""
        path = Path(target_path)
        observation: Dict[str, Any] = {
            "target": str(path),
            "exists": path.exists(),
            "is_file": path.is_file() if path.exists() else False,
            "is_dir": path.is_dir() if path.exists() else False,
            "size": path.stat().st_size if path.exists() and path.is_file() else 0,
        }

        if observation["is_file"]:
            # Detect file type
            try:
                magic = path.read_bytes()[:20]
                if magic[:2] == b"MZ":
                    observation["file_type"] = "PE"
                    observation["suggested_pipeline"] = "malware"
                elif magic[:4] == b"\x7fELF":
                    observation["file_type"] = "ELF"
                    observation["suggested_pipeline"] = "malware"
                elif magic[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or path.suffix in (".pcap", ".pcapng"):
                    observation["file_type"] = "PCAP"
                    observation["suggested_pipeline"] = "network"
                elif path.suffix in (".c", ".cpp", ".h", ".py", ".js", ".java"):
                    observation["file_type"] = "source"
                    observation["suggested_pipeline"] = "binary"
                elif path.suffix in (".yaml", ".yml") and "docker-compose" in path.name.lower() or "Dockerfile" in path.name:
                    observation["file_type"] = "container"
                    observation["suggested_pipeline"] = "container"
                elif path.suffix == ".tf":
                    observation["file_type"] = "terraform"
                    observation["suggested_pipeline"] = "cloud"
                else:
                    observation["file_type"] = "unknown"
                    observation["suggested_pipeline"] = "binary"
            except Exception:
                observation["file_type"] = "unknown"
                observation["suggested_pipeline"] = "binary"

        self.history.append({"phase": "observe", "observation": observation, "timestamp": time.time()})
        return observation

    def orient(self, observation: Dict[str, Any], previous_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Orient phase - decide what tools to use based on observation."""
        orientation: Dict[str, Any] = {
            "file_type": observation.get("file_type", "unknown"),
            "suggested_pipeline": observation.get("suggested_pipeline", "binary"),
            "tools": [],
            "priority": "full",
        }

        file_type = observation.get("file_type", "unknown")

        if file_type == "PE":
            orientation["tools"] = ["pe_analyze", "behavior", "classifier", "extractor", "unpacker", "anti_analysis", "cve_scan", "yara_scan"]
            orientation["reasoning"] = "PE file - run malware analysis + CVE/YARA"
        elif file_type == "ELF":
            orientation["tools"] = ["elf_analyze", "behavior", "classifier", "extractor", "cve_scan", "yara_scan"]
            orientation["reasoning"] = "ELF file - run malware analysis"
        elif file_type == "PCAP":
            orientation["tools"] = ["protocol", "threat", "flow", "dns", "tls", "http", "network_tools"]
            orientation["reasoning"] = "PCAP - run full network analysis"
        elif file_type == "source":
            orientation["tools"] = ["strings", "cve_scan", "yara_scan", "callgraph", "web_analyzer"]
            orientation["reasoning"] = "Source file - run SAST + web checks"
        elif file_type == "container":
            orientation["tools"] = ["docker_analyzer", "container_scanner", "secret_scan"]
            orientation["reasoning"] = "Container config - run cloud/container analysis"
        elif file_type == "terraform":
            orientation["tools"] = ["terraform_analyzer", "secret_scan"]
            orientation["reasoning"] = "Terraform - run cloud misconfig analysis"
        else:
            orientation["tools"] = ["identify", "strings", "cve_scan", "yara_scan"]
            orientation["reasoning"] = "Unknown - run basic analysis"

        # Adjust based on previous results
        if previous_results:
            findings = previous_results.get("findings", [])
            if len(findings) > 20:
                orientation["priority"] = "deep"
                orientation["tools"].append("enhanced_report")
            # If malware detected, add dynamic analysis
            if any("malware" in str(f).lower() or f.get("severity") == "CRITICAL" for f in findings[:10]):
                orientation["tools"].extend(["sandbox", "capa", "threat_intel"])
                orientation["reasoning"] += " + dynamic analysis due to critical findings"

        self.history.append({"phase": "orient", "orientation": orientation, "timestamp": time.time()})
        return orientation

    def decide(self, orientation: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
        """Decide phase - create execution plan."""
        decision: Dict[str, Any] = {
            "pipeline": orientation.get("suggested_pipeline", "binary"),
            "tools": orientation.get("tools", []),
            "target": observation.get("target", ""),
            "plan": [],
        }

        # Create plan with dependencies
        pipeline = decision["pipeline"]
        tools = decision["tools"]

        if pipeline == "malware":
            decision["plan"] = [
                {"task": "pe_analyze or elf_analyze", "depends": [], "priority": "CRITICAL"},
                {"task": "extractor", "depends": ["pe_analyze"], "priority": "HIGH"},
                {"task": "behavior", "depends": ["pe_analyze"], "priority": "HIGH"},
                {"task": "classifier", "depends": ["behavior", "extractor"], "priority": "HIGH"},
                {"task": "unpacker", "depends": ["pe_analyze"], "priority": "MEDIUM"},
                {"task": "sandbox", "depends": ["classifier"], "priority": "MEDIUM"},
                {"task": "threat_intel", "depends": ["extractor"], "priority": "LOW"},
            ]
        elif pipeline == "network":
            decision["plan"] = [
                {"task": "protocol", "depends": [], "priority": "CRITICAL"},
                {"task": "threat", "depends": ["protocol"], "priority": "HIGH"},
                {"task": "flow", "depends": ["protocol"], "priority": "HIGH"},
                {"task": "dns", "depends": ["protocol"], "priority": "MEDIUM"},
                {"task": "http", "depends": ["protocol"], "priority": "MEDIUM"},
                {"task": "tls", "depends": ["protocol"], "priority": "MEDIUM"},
            ]
        else:
            decision["plan"] = [{"task": t, "depends": [], "priority": "MEDIUM"} for t in tools]

        self.history.append({"phase": "decide", "decision": decision, "timestamp": time.time()})
        return decision

    def act(self, decision: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Act phase - execute the plan."""
        from core.config_manager import get_config
        from core.pipeline import create_unified_pipeline

        target = decision.get("target", "")
        pipeline_type = decision.get("pipeline", "binary")
        profile = "full"

        config = get_config()
        pipeline = create_unified_pipeline(config, target, profile, pipeline_type)

        # Get all tasks for this pipeline
        tasks = list(pipeline.tasks.keys())

        ctx = {"target_path": target, "workspace_id": context.get("workspace_id", "default") if context else "default"}

        # Execute
        results = pipeline.execute(tasks, ctx, max_workers=4)

        self.history.append({"phase": "act", "results": {"tasks": tasks, "count": len(results)}, "timestamp": time.time()})

        return {
            "status": "ok",
            "engine": "advanced_agent",
            "pipeline": pipeline_type,
            "target": target,
            "tasks_executed": tasks,
            "results": results,
            "history": self.history[-10:],
        }

    def run_autonomous(self, target_path: str, max_iterations: int = 3) -> Dict[str, Any]:
        """Run full OODA loop autonomously."""
        all_results = {}
        previous_results = None

        for iteration in range(max_iterations):
            # Observe
            observation = self.observe(target_path, previous_results)

            # Orient
            orientation = self.orient(observation, previous_results)

            # Decide
            decision = self.decide(orientation, observation)

            # Act
            action_result = self.act(decision, {"workspace_id": f"agent_iter_{iteration}"})

            all_results[f"iteration_{iteration}"] = {
                "observation": observation,
                "orientation": orientation,
                "decision": decision,
                "action": action_result,
            }

            # Check if we need another iteration
            results = action_result.get("results", {})
            findings = []
            for res in results.values():
                if isinstance(res, dict):
                    obs = res.get("observations", {})
                    if isinstance(obs, dict) and "findings" in obs:
                        findings.extend(obs["findings"])
                    elif isinstance(obs, list):
                        findings.extend([f for f in obs if isinstance(f, dict) and "type" in f])

            previous_results = {"findings": findings}

            # Stop if no critical findings or low score
            critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
            if critical_count == 0 and iteration >= 1:
                break

        # Final summary
        final_findings = previous_results.get("findings", []) if previous_results else []

        return {
            "status": "ok",
            "engine": "advanced_agent_autonomous",
            "target": target_path,
            "iterations": len(all_results),
            "all_results": all_results,
            "final_findings": final_findings[:100],
            "final_summary": {
                "total_findings": len(final_findings),
                "critical": len([f for f in final_findings if f.get("severity") == "CRITICAL"]),
                "high": len([f for f in final_findings if f.get("severity") == "HIGH"]),
            },
            "history": self.history,
        }
