import os
import shutil
import pytest

from modules.orchestration.orchestrator import Orchestrator

# Avant : chemin personnel en dur (/home/ubuntu/re-lab/build/protected-check)
# absent de l'archive, avec un `raise SystemExit` au niveau du module —
# ça faisait planter la COLLECTION ENTIERE de `pytest tests/`, pas
# seulement ce fichier. Corrige : on prend un binaire ELF deja present sur
# a peu pres n'importe quel systeme Linux, et on `pytest.skip` proprement
# (au niveau du test, pas du module) si rien d'exploitable n'est trouve.
_CANDIDATES = ["/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat"]


def _pick_target():
    for c in _CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def test_r2_default_and_ghidra_optin():
    if shutil.which("r2") is None and shutil.which("rizin") is None:
        pytest.skip("radare2/rizin non installe sur cette machine")

    target = _pick_target()
    if target is None:
        pytest.skip("aucun binaire ELF de test disponible (ls/cat introuvables)")

    os.environ.pop("R3CON_ENABLE_GHIDRA", None)
    default = Orchestrator(target, profile="binary", timeout=30).run()
    assert "radare2" in default["plan"]
    assert "ghidra" not in default["plan"]
    assert default["results"]["radare2"]["status"] in {"ok", "partial"}
    assert default["results"]["radare2"]["observations"].get("function_count", 0) > 0

    opt_in = Orchestrator(target, profile="binary", timeout=120, with_ghidra=True).run()
    assert "radare2" in opt_in["plan"]
    assert "ghidra" in opt_in["plan"]
    assert opt_in["results"]["ghidra"]["status"] in {"ok", "partial", "timeout", "unsupported"}
