"""
r3con - Symbolic Execution - Unified wrapper
DEPRECATED: Use modules.analysis_deep.symbolic_exec instead
This file now imports from analysis_deep for backward compatibility
"""
import warnings
warnings.warn(
    "modules.analysis.symbolic_exec is deprecated, use modules.analysis_deep.symbolic_exec",
    DeprecationWarning,
    stacklevel=2
)

# Import from deep (the fixed, validated version)
from modules.analysis_deep.symbolic_exec import (
    SymbolicExecutor,
    SymbolicValue,
    ExecutionPath,
    MAX_CODE_SIZE,
    MAX_FUNCTIONS,
    MAX_PATHS,
)

# Keep old names for backward compat
SymbolicVar = SymbolicValue
PathCondition = ExecutionPath

__all__ = ["SymbolicExecutor", "SymbolicValue", "ExecutionPath", "SymbolicVar", "PathCondition"]
