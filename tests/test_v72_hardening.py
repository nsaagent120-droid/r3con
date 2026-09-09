from pathlib import Path

import pytest

from modules.disasm.capstone_engine import DisasmEngine

dashboard_v2 = pytest.importorskip("modules.web.dashboard_v2")


def test_elf_disassembly_uses_only_executable_sections():
    binary = Path("/bin/ls")
    if not binary.exists():
        return

    engine = DisasmEngine(str(binary))
    sections = engine._load_all_sections()

    assert sections
    names = {name for name, _, _ in sections}
    assert ".rela.plt" not in names
    assert ".rodata" not in names
    assert ".text" in names


def test_dashboard_secret_is_not_predictable(monkeypatch):
    assert dashboard_v2.app.config["SECRET_KEY"] != "r3con-v7.2-secret-key"

    monkeypatch.setenv("R3CON_DASHBOARD_SECRET", "test-stable-secret")
    import importlib

    reloaded = importlib.reload(dashboard_v2)
    assert reloaded.app.config["SECRET_KEY"] == "test-stable-secret"
    monkeypatch.delenv("R3CON_DASHBOARD_SECRET", raising=False)
    importlib.reload(dashboard_v2)


def test_cache_version_matches_release():
    from core.cache import CACHE_VERSION
    from core.__version__ import __version__

    assert CACHE_VERSION == __version__
