"""
r3con 7.3.0 — Enhanced Orchestrator (legacy wrapper, silent by default)
Delegates to UnifiedOrchestrator. Warning only if R3CON_WARN_DEPRECATED=1.
"""
from __future__ import annotations
import os
import warnings
from typing import Any, Dict, Optional

if os.environ.get("R3CON_WARN_DEPRECATED", "").lower() in {"1", "true", "yes"}:
    warnings.warn(
        "modules.orchestration.enhanced_orchestrator.EnhancedOrchestrator is legacy, use modules.orchestration.unified.UnifiedOrchestrator",
        DeprecationWarning,
        stacklevel=2,
    )

try:
    from modules.orchestration.unified import UnifiedOrchestrator

    class EnhancedOrchestrator(UnifiedOrchestrator):
        """Legacy wrapper - delegates to UnifiedOrchestrator with PRO behavior."""

        def __init__(self, target: str, profile: str = "auto", config_path: Optional[str] = None, config=None, **overrides):
            super().__init__(
                target=target,
                profile=profile,
                config_path=config_path,
                config=config,
                use_pipeline=True,
                **overrides
            )

    def run_enhanced_analysis(target: str, profile: str = "auto", config_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return EnhancedOrchestrator(target, profile=profile, config_path=config_path, **kwargs).run()

except ImportError:
    from pathlib import Path
    from core.result_schema import Status, make_result
    from modules.disasm.binary_parser import BinaryParser

    class EnhancedOrchestrator:
        def __init__(self, target: str, profile: str = "auto", config_path: Optional[str] = None, config=None, **overrides):
            self.path = Path(target)
            self.profile = profile

        def run(self) -> Dict[str, Any]:
            try:
                info = BinaryParser(str(self.path)).parse()
                return make_result(Status.OK, target=str(self.path), profile=self.profile,
                                   results={"identify": {"status": "ok", "engine": "binary_parser", "observations": info}},
                                   findings=[], duration_ms=0)
            except Exception as e:
                return make_result(Status.ERROR, target=str(self.path), error=str(e))

    def run_enhanced_analysis(target: str, profile: str = "auto", config_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return EnhancedOrchestrator(target, profile=profile, config_path=config_path, **kwargs).run()
