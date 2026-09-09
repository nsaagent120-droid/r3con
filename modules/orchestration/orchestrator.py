"""
r3con v6.0 Titan-Omega - Orchestrator Classic (Legacy wrapper)
Maintained for backward compatibility, now delegates to UnifiedOrchestrator
"""
from __future__ import annotations
import warnings
from typing import Any, Dict

warnings.warn(
    "modules.orchestration.orchestrator.Orchestrator is legacy, use modules.orchestration.unified.UnifiedOrchestrator",
    DeprecationWarning,
    stacklevel=2
)

try:
    from modules.orchestration.unified import UnifiedOrchestrator

    class Orchestrator(UnifiedOrchestrator):
        """Legacy wrapper - delegates to UnifiedOrchestrator with classic behavior."""

        def __init__(self, target: str, profile: str = "auto", timeout: int = 120,
                     max_mb: int = 256, max_workers: int = 3,
                     reverse_engine: str | None = None, with_ghidra: bool | None = None,
                     cache: bool = True, cache_dir: str | None = None):
            # Map old params to new
            overrides = {}
            if timeout:
                overrides["analysis.timeout"] = timeout
            if max_mb:
                overrides["analysis.max_file_size_mb"] = max_mb
            if max_workers:
                overrides["analysis.max_workers"] = max_workers
            if with_ghidra:
                overrides["external_tools.enabled.ghidra"] = True

            super().__init__(
                target=target,
                profile=profile,
                use_pipeline=False,  # Classic uses sequential for backward compat
                cache_enabled=cache,
                cache_dir=cache_dir,
                **overrides
            )
            # Keep old attributes for compat
            self.reverse_engine = reverse_engine or "radare2"
            self.with_ghidra = with_ghidra or False

        def run(self) -> Dict[str, Any]:
            # Use parent run but ensure classic plan
            return super().run()

    def run_analysis(target: str, profile: str = "auto", **kwargs) -> Dict[str, Any]:
        return Orchestrator(target, profile=profile, **kwargs).run()

except ImportError:
    # Fallback to original implementation if unified not available
    import concurrent.futures
    import hashlib
    import json
    import os
    import time
    from pathlib import Path
    from typing import List

    from core.result_schema import Status, make_result, deduplicate_findings, normalize_findings
    from modules.disasm.binary_parser import BinaryParser
    from modules.integration.tool_manager import ToolManager

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
            self.cache_enabled = cache
            self.cache_dir = Path(cache_dir or str(Path.home() / ".cache" / "r3con"))
            self.target_hash = None
            self.started = time.time()

        def run(self) -> Dict[str, Any]:
            if not self.path.is_file():
                return make_result(Status.INVALID, target=str(self.path), error="target_not_found")
            # Minimal fallback
            try:
                info = BinaryParser(str(self.path)).parse()
                return make_result(Status.OK, target=str(self.path), profile=self.profile,
                                   results={"identify": {"status": "ok", "engine": "binary_parser", "observations": info}},
                                   findings=[], duration_ms=0)
            except Exception as e:
                return make_result(Status.ERROR, target=str(self.path), error=str(e))

    def run_analysis(target: str, profile: str = "auto", **kwargs) -> Dict[str, Any]:
        return Orchestrator(target, profile=profile, **kwargs).run()
