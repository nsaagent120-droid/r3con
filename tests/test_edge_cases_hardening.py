"""Cas limites imposés par le cahier des charges : outil absent avec repli,
fichier sans permission, sortie d'outil invalide, cible vide/corrompue,
CLI scan avec plan/faille de sévérité."""
import json
import os
import struct

import pytest
from click.testing import CliRunner

from cli.main import cli
from modules.orchestration.unified import UnifiedOrchestrator


def make_elf() -> bytes:
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    return e_ident + struct.pack("<HHI", 2, 62, 1) + b"\x00" * 40


def test_fallback_used_when_external_tool_missing(tmp_path):
    # La machine de test n'a pas checksec installé : le moteur interne
    # 'protections' doit prendre le relais et le résultat doit être marqué.
    o = UnifiedOrchestrator(str(tmp_path / "p"), profile="binary",
                            **{"analysis.cache_enabled": False})
    o.path.write_bytes(make_elf())
    from modules.integration.tool_manager import ToolManager
    if ToolManager().is_available("checksec"):
        pytest.skip("checksec présent : scénario fallback non reproductible")
    result = o.run()
    checksec_result = result["results"].get("checksec")
    assert checksec_result, "la tâche checksec doit rester au plan via repli"
    assert checksec_result.get("fallback") is True
    assert checksec_result["provenance"]["fallback_of"] == "checksec"
    assert "checksec" in result["fallbacks_used"]
    assert result["status"] in {"ok", "partial"}


def test_permission_denied_target_is_graceful(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignore les permissions unix")
    target = tmp_path / "locked"
    target.write_bytes(make_elf())
    target.chmod(0o000)
    try:
        o = UnifiedOrchestrator(str(target), profile="quick")
        result = o.run()
        assert result["status"] in {"invalid", "partial", "error", "ok"}
        assert isinstance(result.get("findings", []), list)
    finally:
        target.chmod(0o644)


def test_corrupted_binary_does_not_raise(tmp_path):
    for blob in (b"\x7fELF" + b"garbage" * 100, b"MZ" + b"\xff" * 5000, b"PK\x03\x04" + b"\x00" * 30):
        f = tmp_path / "corrupt"
        f.write_bytes(blob)
        o = UnifiedOrchestrator(str(f), profile="binary",
                                **{"analysis.cache_enabled": False})
        result = o.run()
        assert result["status"] in {"ok", "partial", "error"}


def test_tool_unsupported_status_shape(tmp_path):
    o = UnifiedOrchestrator(str(tmp_path / "x"), profile="binary",
                            **{"analysis.cache_enabled": False})
    o.path.write_bytes(make_elf())
    result = o.run()
    for entry in result["plan_details"]:
        if entry.get("skipped"):
            task_result = result["results"][entry["task"]]
            assert task_result["status"] == "unsupported"
            assert task_result["error"] == "tool_unavailable"
            assert "install_hint" in task_result


def test_cli_scan_with_plan_and_fail_on(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("R3CON_")}
    env["HOME"] = str(tmp_path)
    target = tmp_path / "vuln.c"
    target.write_text(
        "#include <string.h>\n"
        "void f(char* in){ char b[8]; strcpy(b, in); }\n"
        "char* key = \"AKIAABCDEFGHIJKLMNOP\";\n"
    )
    runner = CliRunner(env=env)
    r = runner.invoke(cli, ["--no-banner", "scan", str(target), "--profile", "source",
                            "--explain-plan", "--plan-only", "--no-cache"],
                      catch_exceptions=False)
    assert r.exit_code == 0
    assert "Profil" in r.output or "profil" in r.output
    assert "Aucun module exécuté" in r.output

    out = tmp_path / "report.json"
    r2 = runner.invoke(cli, ["--no-banner", "scan", str(target), "--profile", "source",
                             "--no-cache", "--json-output", str(out)],
                       catch_exceptions=False)
    assert r2.exit_code == 0, r2.output
    payload = json.loads(out.read_text())
    assert payload["report_meta"]["r3con_version"]
    assert payload["report_meta"]["generated_utc"]
    assert "scan_meta" in payload

    r3 = runner.invoke(cli, ["--no-banner", "scan", str(target), "--profile", "source",
                             "--no-cache", "--fail-on", "critical"], catch_exceptions=False)
    assert r3.exit_code in (0, 2)


def test_cli_scan_directory_resume_flow(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("R3CON_")}
    env["HOME"] = str(tmp_path)
    d = tmp_path / "src"
    d.mkdir()
    (d / "a.c").write_text("int main(){char b[2]; __builtin_memcpy(b, \"AAAA\", 4);}\n")
    (d / "b.c").write_text("int add(int x,int y){return x+y;}\n")
    runner = CliRunner(env=env)
    out = tmp_path / "dir-report.json"
    r = runner.invoke(cli, ["--no-banner", "scan", str(d), "--profile", "source",
                            "--no-cache", "--json-output", str(out)], catch_exceptions=False)
    assert r.exit_code == 0
    payload = json.loads(out.read_text())
    assert payload["scan_meta"]["targets_count"] == 2


def test_cache_invalidation_on_tool_versions_change(tmp_path):
    from core.cache import TaskCache
    key1 = TaskCache.fingerprint("h", "strings", "quick", "cfg", "tools-a")
    key2 = TaskCache.fingerprint("h", "strings", "quick", "cfg", "tools-b")
    assert key1 != key2
    key_schema = TaskCache.fingerprint("h", "strings", "quick", "cfg", "tools-a")
    assert key1 == key_schema  # déterminisme

    cache = TaskCache(cache_dir=tmp_path / "tc")
    assert cache.get(key1) is None
    assert cache.set(key1, {"status": "ok", "payload": 1})
    got = cache.get(key1)
    assert got == {"status": "ok", "payload": 1}
    assert cache.stats()["hits"] == 1 and cache.stats()["misses"] == 1


def test_task_cache_oversized_result_skipped(tmp_path):
    from core.cache import TaskCache
    cache = TaskCache(cache_dir=tmp_path / "tc")
    assert cache.set("k" * 32, {"blob": "x" * 3_000_000}) is False


def test_offline_killswitch_blocks_remote_lookups(tmp_path, monkeypatch):
    import urllib.request
    monkeypatch.setenv("R3CON_OFFLINE", "1")

    def _boom(*a, **k):
        raise AssertionError("requête réseau tentée en mode offline")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    from modules.malware.dynamic.virustotal import ThreatIntelManager
    from modules.research.research import CVEMatcher
    target = tmp_path / "x.bin"
    target.write_bytes(b"MZ\x90\x00" + b"A" * 100)
    ti = ThreatIntelManager(vt_api_key="cle-factice")
    res = ti.check_file_hash(str(target))
    assert res["status"] == "ok"
    assert res["sources"]["virustotal"]["reason"] == "offline_mode"
    assert res["sources"]["malwarebazaar"]["reason"] == "offline_mode"
    assert res["remote"] == "disabled_offline"
    assert res["sources"]["local_heuristic"]["status"]
    assert CVEMatcher().fetch_cve_nvd("CVE-2021-44228")["reason"] == "offline_mode"
