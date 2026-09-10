"""Durcissement de l'orchestrateur : plan explicable, pré-vérification des
outils, replis marqués, cache versionné, reprise après interruption, robustesse."""
import json
import pathlib
import struct

from modules.orchestration.unified import UnifiedOrchestrator


def make_elf() -> bytes:
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    return e_ident + struct.pack("<HHI", 2, 62, 1) + b"\x00" * 40


def orch_for(tmp_path, binary, **extra):
    target = tmp_path / "prog"
    target.write_bytes(binary)
    profile = extra.pop("profile", "quick")
    kwargs = {"analysis.cache_dir": str(tmp_path / "cache"), "analysis.timeout": 5}
    kwargs.update(extra)
    return UnifiedOrchestrator(str(target), profile=profile, **kwargs)


def test_run_detects_target_and_builds_explainable_plan(tmp_path):
    o = orch_for(tmp_path, make_elf())
    result = o.run()
    assert result["status"] == "ok"
    target_info = result["target"]
    assert "elf64" in target_info["types"]
    assert target_info["sha256"]
    assert result["plan_details"], "le plan doit être explicable"
    entry = result["plan_details"][0]
    assert {"task", "reason", "tool", "tool_available"} <= set(entry)


def test_profile_auto_selects_by_target_type(tmp_path):
    o = orch_for(tmp_path, make_elf())
    o.profile = "auto"
    result = o.run()
    assert result["profile"] == "binary"


def test_unavailable_external_tools_are_skipped_not_fatal(tmp_path):
    o = orch_for(tmp_path, make_elf(), profile="binary")
    result = o.run()
    skipped = [d for d in result["plan_details"] if d.get("skipped")]
    for entry in skipped:
        res = result["results"][entry["task"]]
        assert res["status"] == "unsupported"
        assert res["error"] == "tool_unavailable"
        assert res["install_hint"]
    # Une ou plusieurs tâches internes réussissent -> statut global non bloquant.
    assert result["status"] in {"ok", "partial"}


def test_explain_only_does_not_execute_modules(tmp_path):
    o = orch_for(tmp_path, make_elf())
    o.explain_only = True
    result = o.run()
    assert result["explain_only"] is True
    assert "results" not in result
    assert result["plan"]


def test_cache_is_versioned_and_hit_on_second_run(tmp_path):
    o = orch_for(tmp_path, make_elf())
    first = o.run()
    assert first["cache_stats"]["hits"] == 0
    o2 = orch_for(tmp_path, make_elf())
    second = o2.run()
    assert second["cache_stats"]["hits"] >= 1
    # Modifier la cible invalide le cache ; pas de faux partage entre hash.
    o3 = orch_for(tmp_path, make_elf() + b"extra-padding")
    third = o3.run()
    assert third["cache_stats"]["hits"] == 0
    # Les clés sont stables et dépendent du profil : profil différent -> cache différent.
    from core.cache import TaskCache
    key_a = TaskCache.fingerprint("hash", "strings", "quick", "cfg", "tools")
    key_b = TaskCache.fingerprint("hash", "strings", "binary", "cfg", "tools")
    assert key_a != key_b


def test_corrupted_and_empty_targets_do_not_raise(tmp_path):
    o = orch_for(tmp_path, b"\xff" * 1024)
    result = o.run()
    assert result["status"] in {"ok", "partial", "error"}
    assert "results" in result

    o2 = orch_for(tmp_path, b"")
    res2 = o2.run()
    assert res2["status"] in {"ok", "partial", "error"}


def test_missing_target_is_invalid_result(tmp_path):
    o = UnifiedOrchestrator(str(tmp_path / "nope"), profile="quick")
    result = o.run()
    assert result["status"] == "invalid"
    assert result["error"] == "target_not_found"


def test_oversized_target_rejected(tmp_path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 4096)
    o = UnifiedOrchestrator(str(target), profile="quick", **{"analysis.max_file_size_mb": 0})
    o.max_bytes = 1024  # forcer après init: la config normalise au minimum 1MB
    result = o.run()
    assert result["status"] == "invalid"
    assert result["error"] == "target_too_large"


def test_resume_reuses_completed_task_artifacts(tmp_path):
    o = orch_for(tmp_path, make_elf())
    first = o.run()
    artifact_dir = first["execution"]["artifact_dir"]
    assert artifact_dir and (json.loads(open(f"{artifact_dir}/state.json").read()))["completed"]

    # Simuler une exécution interrompue : reprendre depuis le run terminé.
    o2 = orch_for(tmp_path, make_elf())
    o2.resume_dir = pathlib.Path(artifact_dir)
    o2.cache_enabled = False  # forcer le chemin de reprise, pas le cache
    second = o2.run()
    resumed = [r for r in second["results"].values() if isinstance(r, dict) and r.get("resumed")]
    assert resumed, "la reprise doit réutiliser les tâches déjà terminées"
    assert second["resumed_tasks"]


def test_finding_payloads_keep_v21_contract(tmp_path):
    o = orch_for(tmp_path, make_elf())
    src = tmp_path / "prog"
    # Un fichier source avec un secret pour produire des findings réels.
    src.write_text('password = "hunter2secret"\nimport os\nos.system("ls " + x)\n')
    o = UnifiedOrchestrator(str(src), profile="source",
                            **{"analysis.cache_dir": str(tmp_path / "cache")})
    result = o.run()
    for finding in result["findings"]:
        assert finding["id"]
        assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert 0.0 <= finding["confidence"] <= 1.0
        assert "references" in finding and "exploitability" in finding
        assert finding["target_hash"] == result["target"]["sha256"]


def test_single_task_failure_does_not_kill_run(tmp_path, monkeypatch):
    o = orch_for(tmp_path, make_elf())

    original = o._task

    def explode(task, target_info):
        if task == "strings":
            raise RuntimeError("outil externe corrompu simulé")
        return original(task, target_info)

    monkeypatch.setattr(o, "_task", explode)
    result = o.run()
    assert result["status"] in {"partial", "ok"}
    assert result["results"]["identify"]["status"] == "ok"
