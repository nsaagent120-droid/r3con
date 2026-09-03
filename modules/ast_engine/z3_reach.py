"""
r3con - Path Condition Solver
Vérifie la satisfiabilité RÉELLE (via le solveur SMT z3) d'une conjonction
de conditions `if(...)` extraites de l'AST, sur le sous-ensemble sûr :
expressions entières/relationnelles/booléennes sur identifiants et
littéraux (==, !=, <, <=, >, >=, &&, ||, !, +, -, *, parenthèses).

Ce module NE PRÉTEND PAS faire de l'exécution symbolique complète : pas de
modèle mémoire, pas de pointeurs, pas d'appels de fonction interprétés. Dès
qu'une condition sort de ce sous-ensemble (appel de fonction, déréférence,
accès tableau...), le résultat est explicitement "unknown" plutôt qu'une
fausse réponse — c'est le compromis assumé entre honnêteté et utilité.
"""
from __future__ import annotations

import ast as pyast
from typing import List

try:
    import z3
    Z3_AVAILABLE = True
except Exception:  # pragma: no cover
    Z3_AVAILABLE = False


def _c_to_py_expr(cond: str) -> str:
    """Traduction syntaxique minimale C -> expression Python évaluable
    par `ast.parse` (pas d'évaluation réelle, juste pour obtenir un AST
    Python que l'on retraduit ensuite en contraintes z3)."""
    out = []
    i = 0
    n = len(cond)
    while i < n:
        if cond[i:i+2] == "&&":
            out.append(" and "); i += 2
        elif cond[i:i+2] == "||":
            out.append(" or "); i += 2
        elif cond[i] == "!" and cond[i:i+2] != "!=":
            out.append(" not "); i += 1
        else:
            out.append(cond[i]); i += 1
    return "".join(out)


class UnsupportedExpression(Exception):
    pass


def _to_z3(node, env: dict):
    if isinstance(node, pyast.Expression):
        return _to_z3(node.body, env)
    if isinstance(node, pyast.BoolOp):
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
        if node.id not in env:
            env[node.id] = z3.Int(node.id)
        return env[node.id]
    if isinstance(node, pyast.Constant) and isinstance(node.value, (int, float)):
        return z3.IntVal(int(node.value))
    if isinstance(node, pyast.Constant) and node.value is None:
        return z3.IntVal(0)
    raise UnsupportedExpression(type(node).__name__)


def check_path_satisfiability(conditions: List[str]) -> str:
    """
    Retourne 'sat', 'unsat', ou 'unknown' pour la conjonction des
    conditions données (chaque condition supposée vraie sur le chemin,
    même simplification que le reste du module — pas de suivi des
    branches then/else). 'unknown' couvre : z3 absent, expression hors
    du sous-ensemble supporté, ou liste vide.
    """
    if not Z3_AVAILABLE or not conditions:
        return "unknown"
    env: dict = {}
    z3_conds = []
    for cond in conditions:
        try:
            py_expr = _c_to_py_expr(cond)
            tree = pyast.parse(py_expr, mode="eval")
            z3_conds.append(_to_z3(tree, env))
        except (UnsupportedExpression, SyntaxError, KeyError, TypeError):
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
