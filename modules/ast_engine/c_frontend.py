"""
r3con - AST Frontend (C)
Parseur AST réel pour C via tree-sitter, avec repli automatique si
tree-sitter / tree-sitter-c ne sont pas installés (le reste du pipeline
continue de fonctionner en mode regex, comme pour lief/capstone).

Ce module ne fait AUCUNE analyse de sécurité : il expose uniquement des
primitives structurelles fiables (vrais sites d'appel, vraies bornes de
fonction, vraies affectations, vraies conditions de branchement) que les
modules d'analyse (static_analyzer, taint_analysis, interprocedural,
symbolic_exec) utilisent pour arrêter de matcher du texte brut.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language, Parser
    _LANGUAGE = Language(_tsc.language())
    _PARSER = Parser(_LANGUAGE)
    AST_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when the dep is absent
    AST_AVAILABLE = False
    _PARSER = None


@dataclass
class CallSite:
    function_name: str
    line: int                 # 1-indexed
    start_byte: int
    end_byte: int
    arg_text: str
    enclosing_function: Optional[str] = None


@dataclass
class Assignment:
    var_name: str
    line: int
    rhs_text: str


@dataclass
class BranchCondition:
    text: str
    line: int
    node: "object" = field(repr=False, default=None)


@dataclass
class FunctionDef:
    name: str
    start_line: int
    end_line: int
    calls: List[CallSite] = field(default_factory=list)
    assignments: List[Assignment] = field(default_factory=list)
    conditions: List[BranchCondition] = field(default_factory=list)
    param_names: List[str] = field(default_factory=list)
    param_is_pointer: Dict[str, bool] = field(default_factory=dict)


def _line_of(src: bytes, byte_offset: int) -> int:
    return src.count(b"\n", 0, byte_offset) + 1


def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def parse_functions(code: str) -> Dict[str, FunctionDef]:
    """
    Parse du code C et retourne les fonctions réellement définies, avec
    pour chacune : les vrais sites d'appel (call_expression), les vraies
    affectations (assignment_expression / init_declarator) et les vraies
    conditions de branchement (if_statement), tous extraits de l'AST —
    donc jamais depuis un commentaire, une chaîne, ou du code désactivé
    par #if 0 (tree-sitter ne descend pas dans ces zones comme du code).

    Retourne {} si tree-sitter/tree-sitter-c ne sont pas disponibles :
    les appelants doivent alors se rabattre sur leur chemin regex existant.
    """
    if not AST_AVAILABLE or not code.strip():
        return {}

    src = code.encode("utf-8", "replace")
    tree = _PARSER.parse(src)
    functions: Dict[str, FunctionDef] = {}

    def find_call_name(call_node) -> Optional[str]:
        fn = call_node.child_by_field_name("function")
        if fn is None:
            return None
        # Appels directs foo(...) ; on ignore volontairement les appels
        # indirects via pointeur de fonction (pas de faux sens de sécurité).
        if fn.type == "identifier":
            return _text(src, fn)
        return None

    def collect(func_node, fdef: FunctionDef):
        stack = [func_node]
        while stack:
            n = stack.pop()
            if n is func_node:
                pass
            elif n.type == "function_definition":
                # Ne pas descendre dans une fonction imbriquée (rare en C,
                # mais évite d'attribuer ses appels à la fonction englobante).
                continue
            if n.type == "call_expression":
                name = find_call_name(n)
                if name:
                    args = n.child_by_field_name("arguments")
                    fdef.calls.append(CallSite(
                        function_name=name,
                        line=_line_of(src, n.start_byte),
                        start_byte=n.start_byte,
                        end_byte=n.end_byte,
                        arg_text=_text(src, args) if args else "()",
                        enclosing_function=fdef.name,
                    ))
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and left.type == "identifier":
                    fdef.assignments.append(Assignment(
                        var_name=_text(src, left),
                        line=_line_of(src, n.start_byte),
                        rhs_text=_text(src, right) if right else "",
                    ))
            elif n.type == "init_declarator":
                declarator = n.child_by_field_name("declarator")
                value = n.child_by_field_name("value")
                # `char *ptr = raw;` -> declarator est un pointer_declarator
                # enveloppant l'identifiant ; on descend jusqu'à lui plutôt
                # que d'ignorer toute déclaration avec initialiseur pointeur.
                ident = declarator
                while ident is not None and ident.type != "identifier":
                    ident = ident.child_by_field_name("declarator")
                if ident is not None:
                    fdef.assignments.append(Assignment(
                        var_name=_text(src, ident),
                        line=_line_of(src, n.start_byte),
                        rhs_text=_text(src, value) if value else "",
                    ))
            elif n.type == "if_statement":
                cond = n.child_by_field_name("condition")
                if cond is not None:
                    fdef.conditions.append(BranchCondition(
                        text=_text(src, cond).strip("()"),
                        line=_line_of(src, cond.start_byte),
                        node=cond,
                    ))
            for c in n.children:
                stack.append(c)

    root = tree.root_node
    todo = [root]
    while todo:
        node = todo.pop()
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            # Le déclarateur peut être enveloppé (ex: `char *foo(...)` ->
            # pointer_declarator -> function_declarator). On descend
            # jusqu'au premier function_declarator réel plutôt que de
            # ramasser le premier identifiant croisé (qui peut être un
            # paramètre selon l'ordre d'itération), ce qui produisait un
            # nom de fonction incorrect.
            func_declarator = declarator
            while func_declarator is not None and func_declarator.type != "function_declarator":
                nxt = func_declarator.child_by_field_name("declarator")
                if nxt is None:
                    func_declarator = None
                    break
                func_declarator = nxt

            name = None
            params = []
            is_ptr: Dict[str, bool] = {}
            if func_declarator is not None:
                name_node = func_declarator.child_by_field_name("declarator")
                if name_node is not None and name_node.type == "identifier":
                    name = _text(src, name_node)
                param_list = func_declarator.child_by_field_name("parameters")
                if param_list is not None:
                    for p in param_list.children:
                        if p.type != "parameter_declaration":
                            continue
                        pd = p.child_by_field_name("declarator")
                        saw_pointer = False
                        search = [pd] if pd else []
                        while search:
                            cur = search.pop()
                            if cur is None:
                                continue
                            if cur.type == "pointer_declarator":
                                saw_pointer = True
                            if cur.type == "identifier":
                                params.append(_text(src, cur))
                                is_ptr[_text(src, cur)] = saw_pointer
                                break
                            search.extend(cur.children)
            if name:
                fdef = FunctionDef(
                    name=name,
                    start_line=_line_of(src, node.start_byte),
                    end_line=_line_of(src, node.end_byte),
                    param_names=params,
                    param_is_pointer=is_ptr,
                )
                collect(node, fdef)
                functions[name] = fdef
            continue
        todo.extend(node.children)

    return functions
