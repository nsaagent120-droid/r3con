"""
r3con 7.3.0 — Symbolic Execution wrapper (silent by default)
DEPRECATED: Use modules.analysis_deep.symbolic_exec instead.
Warning only if R3CON_WARN_DEPRECATED=1.
"""
import os
import warnings

if os.environ.get("R3CON_WARN_DEPRECATED", "").lower() in {"1", "true", "yes"}:
    warnings.warn(
        "modules.analysis.symbolic_exec is deprecated, use modules.analysis_deep.symbolic_exec",
        DeprecationWarning,
        stacklevel=2,
    )

from modules.analysis_deep.symbolic_exec import (
    SymbolicExecutor,
    SymbolicValue,
    ExecutionPath,
    MAX_CODE_SIZE,
    MAX_FUNCTIONS,
    MAX_PATHS,
)

SymbolicVar = SymbolicValue
PathCondition = ExecutionPath

__all__ = ["SymbolicExecutor", "SymbolicValue", "ExecutionPath", "SymbolicVar", "PathCondition"]
