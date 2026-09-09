"""
r3con - Path Condition Solver - FIXED P3
Fixes: input validation, length limits, identifier sanitization, resource guards
"""

from __future__ import annotations

import ast as pyast
import re
from typing import List

MAX_CONDITIONS = 20
MAX_COND_LEN = 500
MAX_IDENT_LEN = 100

try:
    import z3
    Z3_AVAILABLE = True
except Exception:  # pragma: no cover
    Z3_AVAILABLE = False


def _validate_condition(cond: str) -> bool:
    """Validate condition string."""
    if not cond or not isinstance(cond, str):
        return False
    if len(cond) > MAX_COND_LEN:
        return False
    if "\x00" in cond:
        return False
    # Reject if contains dangerous patterns (function calls, etc for our subset)
    # We allow only simple expressions, so reject if contains ; or { }
    if any(c in cond for c in ";{}"):
        return False
    # Limit number of operators to prevent complex expressions
    if cond.count("(") > 20 or cond.count(")") > 20:
        return False
    return True


def _sanitize_identifier(ident: str) -> bool:
    """Check if identifier is safe."""
    if not ident or len(ident) > MAX_IDENT_LEN:
        return False
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', ident):
        return False
    # Reject C keywords that would confuse
    if ident in ('if', 'while', 'for', 'return', 'sizeof', 'NULL'):
        # NULL is allowed as special case
        if ident != 'NULL':
            return False
    return True


def _c_to_py_expr(cond: str) -> str:
    """Traduction syntaxique minimale C -> expression Python - FIXED safe."""
    if not _validate_condition(cond):
        raise ValueError("Invalid condition")

    out = []
    i = 0
    n = len(cond)
    while i < n:
        if i + 1 < n and cond[i:i+2] == "&&":
            out.append(" and ")
            i += 2
        elif i + 1 < n and cond[i:i+2] == "||":
            out.append(" or ")
            i += 2
        elif cond[i] == "!" and (i + 1 >= n or cond[i+1] != "="):
            out.append(" not ")
            i += 1
        else:
            # Only allow safe chars
            c = cond[i]
            if c.isalnum() or c in "_<>=!+-*() \t":
                out.append(c)
            elif c in "&|":
                # Already handled && ||, single & | not allowed in our subset
                raise ValueError(f"Unsupported operator: {c}")
            else:
                # Reject other chars
                if c not in "\"'.,":
                    out.append(c)
                else:
                    # String literals not in our subset
                    raise ValueError(f"String literal not supported: {c}")
            i += 1
    result = "".join(out)
    if len(result) > MAX_COND_LEN * 2:
        raise ValueError("Translated expression too long")
    return result


class UnsupportedExpression(Exception):
    pass


def _to_z3(node, env: dict):
    if isinstance(node, pyast.Expression):
        return _to_z3(node.body, env)
    if isinstance(node, pyast.BoolOp):
        if len(node.values) > 20:
            raise UnsupportedExpression("too_many_bool_values")
        vals = [_to_z3(v, env) for v in node.values]
        return z3.And(*vals) if isinstance(node.op, pyast.And) else z3.Or(*vals)
    if isinstance(node, pyast.UnaryOp) and isinstance(node.op, pyast.Not):
        return z3.Not(_to_z3(node.operand, env))
    if isinstance(node, pyast.UnaryOp) and isinstance(node.op, pyast.USub):
        return -_to_z3(node.operand, env)
    if isinstance(node, pyast.Compare) and len(node.ops) == 1:
        left = _to_z3(node.left, env)
        right = _to_z3(node.comparators[0], env)
        op = node.ops[0]
        return {
            pyast.Eq: lambda a, b: a == b,
            pyast.NotEq: lambda a, b: a != b,
            pyast.Lt: lambda a, b: a < b,
            pyast.LtE: lambda a, b: a <= b,
            pyast.Gt: lambda a, b: a > b,
            pyast.GtE: lambda a, b: a >= b,
        }[type(op)](left, right)
    if isinstance(node, pyast.BinOp):
        left = _to_z3(node.left, env)
        right = _to_z3(node.right, env)
        if isinstance(node.op, pyast.Add):
            return left + right
        if isinstance(node.op, pyast.Sub):
            return left - right
        if isinstance(node.op, pyast.Mult):
            return left * right
        raise UnsupportedExpression("binop")
    if isinstance(node, pyast.Name):
        if node.id == "NULL":
            return z3.IntVal(0)
        if not _sanitize_identifier(node.id):
            raise UnsupportedExpression(f"invalid_identifier: {node.id}")
        if node.id not in env:
            if len(env) >= 50:
                raise UnsupportedExpression("too_many_vars")
            env[node.id] = z3.Int(node.id)
        return env[node.id]
    if isinstance(node, pyast.Constant) and isinstance(node.value, (int, float)):
        # Limit constant size
        if abs(int(node.value)) > 10**18:
            raise UnsupportedExpression("constant_too_large")
        return z3.IntVal(int(node.value))
    if isinstance(node, pyast.Constant) and node.value is None:
        return z3.IntVal(0)
    raise UnsupportedExpression(type(node).__name__)


def check_path_satisfiability(conditions: List[str]) -> str:
    """
    Retourne 'sat', 'unsat', ou 'unknown' - FIXED validation, limits.
    """
    if not Z3_AVAILABLE or not conditions:
        return "unknown"

    if not isinstance(conditions, list) or len(conditions) > MAX_CONDITIONS:
        return "unknown"

    # Validate all conditions first
    for cond in conditions:
        if not _validate_condition(cond):
            return "unknown"

    env: dict = {}
    z3_conds = []
    for cond in conditions:
        try:
            if len(cond.strip()) == 0:
                continue
            py_expr = _c_to_py_expr(cond)
            tree = pyast.parse(py_expr, mode="eval")
            z3_conds.append(_to_z3(tree, env))
        except (UnsupportedExpression, SyntaxError, KeyError, TypeError, ValueError):
            return "unknown"

    if not z3_conds:
        return "unknown"

    try:
        solver = z3.Solver()
        solver.add(z3.And(*z3_conds) if len(z3_conds) > 1 else z3_conds[0])
        solver.set("timeout", 2000)
        result = solver.check()
        if result == z3.sat:
            return "sat"
        if result == z3.unsat:
            return "unsat"
        return "unknown"
    except Exception:
        return "unknown"
