"""Comparaison statique légère de deux binaires locaux via radare2 et le parseur interne - FIXED P3
Fixes: path validation, size limits, function limits, error handling
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.result_schema import Status, make_result
from modules.integration.reverse_adapters import R2Adapter
from modules.disasm.binary_parser import BinaryParser

MAX_BINARY_SIZE = 500 * 1024 * 1024
MAX_FUNCTIONS = 1000
MAX_CHANGED = 200


def _validate_binary_path(path_str: str) -> bool:
    """Validate binary path."""
    if not path_str or len(path_str) > 1024 or "\x00" in path_str:
        return False
    p = Path(path_str)
    try:
        if not p.exists() or not p.is_file():
            return False
        size = p.stat().st_size
        if size > MAX_BINARY_SIZE or size == 0:
            return False
    except (OSError, RuntimeError):
        return False
    return True


def _functions(path: str) -> Dict[str, Dict[str, Any]]:
    """Get functions with limits."""
    if not _validate_binary_path(path):
        return {}

    try:
        result = R2Adapter(path).analyze(function="main")
        funcs = result.get("observations", {}).get("functions", []) if isinstance(result, dict) else []
        output: Dict[str, Dict[str, Any]] = {}

        for item in funcs[:MAX_FUNCTIONS]:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("realname")
            if name and isinstance(name, str) and len(name) <= 200:
                # Validate name
                if any(c in name for c in ";|&`$()><\n\r"):
                    continue
                output[str(name)] = {
                    "name": name[:200],
                    "offset": item.get("offset", item.get("addr")),
                    "size": item.get("size"),
                    "nargs": item.get("nargs"),
                }

        return output
    except Exception:
        return {}


def compare_binaries(old_path: str, new_path: str) -> Dict[str, Any]:
    """Compare two binaries - FIXED validation, limits."""
    if not _validate_binary_path(old_path) or not _validate_binary_path(new_path):
        return make_result(Status.INVALID, engine="r3con.binary_diff", error="invalid_target_path")

    old = Path(old_path)
    new = Path(new_path)

    try:
        old_functions = _functions(str(old))
        new_functions = _functions(str(new))

        old_names, new_names = set(old_functions), set(new_functions)

        added = sorted(list(new_names - old_names))[:MAX_FUNCTIONS]
        removed = sorted(list(old_names - new_names))[:MAX_FUNCTIONS]

        changed = []
        for name in sorted(old_names & new_names):
            if len(changed) >= MAX_CHANGED:
                break
            before, after = old_functions[name], new_functions[name]
            if before.get("size") != after.get("size") or before.get("offset") != after.get("offset"):
                changed.append({"name": name[:200], "before": before, "after": after})

        # Parse protections with error handling
        try:
            old_info = BinaryParser(str(old)).parse()
        except Exception:
            old_info = {}

        try:
            new_info = BinaryParser(str(new)).parse()
        except Exception:
            new_info = {}

        protections = {
            "before": old_info.get("protections", {}) if isinstance(old_info, dict) else {},
            "after": new_info.get("protections", {}) if isinstance(new_info, dict) else {},
        }

        # Check if protections changed (security regression)
        security_regression = False
        try:
            before_prot = protections["before"]
            after_prot = protections["after"]
            # If before had protections and after doesn't, regression
            for prot in ["canary", "nx", "pie", "relro", "fortify"]:
                if before_prot.get(prot) and not after_prot.get(prot):
                    security_regression = True
                    break
        except Exception:
            pass

        return make_result(Status.OK, engine="r3con.binary_diff", observations={
            "old": {"path": str(old)[:500], "function_count": len(old_functions)},
            "new": {"path": str(new)[:500], "function_count": len(new_functions)},
            "functions": {"added": added, "removed": removed, "changed": changed},
            "protections": protections,
            "security_regression": security_regression,
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "changed_count": len(changed),
            }
        })

    except Exception as exc:
        return make_result(Status.ERROR, engine="r3con.binary_diff", error=str(exc)[:500])
