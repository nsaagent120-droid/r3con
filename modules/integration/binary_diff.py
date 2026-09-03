"""Comparaison statique légère de deux binaires locaux via radare2 et le parseur interne."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.result_schema import Status, make_result
from modules.integration.reverse_adapters import R2Adapter
from modules.disasm.binary_parser import BinaryParser


def _functions(path: str) -> Dict[str, Dict[str, Any]]:
    result = R2Adapter(path).analyze(function="main")
    funcs = result.get("observations", {}).get("functions", []) if isinstance(result, dict) else []
    output: Dict[str, Dict[str, Any]] = {}
    for item in funcs:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("realname")
        if name:
            output[str(name)] = {
                "name": name,
                "offset": item.get("offset", item.get("addr")),
                "size": item.get("size"),
                "nargs": item.get("nargs"),
            }
    return output


def compare_binaries(old_path: str, new_path: str) -> Dict[str, Any]:
    old = Path(old_path)
    new = Path(new_path)
    if not old.is_file() or not new.is_file():
        return make_result(Status.INVALID, engine="r3con.binary_diff", error="target_not_found")
    try:
        old_functions = _functions(str(old))
        new_functions = _functions(str(new))
        old_names, new_names = set(old_functions), set(new_functions)
        added = sorted(new_names - old_names)
        removed = sorted(old_names - new_names)
        changed = []
        for name in sorted(old_names & new_names):
            before, after = old_functions[name], new_functions[name]
            if before.get("size") != after.get("size") or before.get("offset") != after.get("offset"):
                changed.append({"name": name, "before": before, "after": after})
        old_info = BinaryParser(str(old)).parse()
        new_info = BinaryParser(str(new)).parse()
        protections = {
            "before": old_info.get("protections", {}),
            "after": new_info.get("protections", {}),
        }
        return make_result(Status.OK, engine="r3con.binary_diff", observations={
            "old": {"path": str(old), "function_count": len(old_functions)},
            "new": {"path": str(new), "function_count": len(new_functions)},
            "functions": {"added": added, "removed": removed, "changed": changed},
            "protections": protections,
        })
    except Exception as exc:
        return make_result(Status.ERROR, engine="r3con.binary_diff", error=str(exc))
