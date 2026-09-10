"""Adaptive orchestration for local r3con analyses — stable unified backend."""

from .unified import UnifiedOrchestrator as Orchestrator

def run_analysis(target: str, profile: str = "auto", **kwargs):
    """Run analysis via unified orchestrator (stable API)."""
    return Orchestrator(target, profile=profile, **kwargs).run()

__all__ = ["Orchestrator", "run_analysis", "UnifiedOrchestrator"]
