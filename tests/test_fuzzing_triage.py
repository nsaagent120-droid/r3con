"""Triage de fuzzing : clustering de crashs, minimisation non destructive,
stats, reprise détectée, export vers findings et plan d'exécution borné."""
import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli
from core.fuzzing_manager import FuzzingManager
from core.result_schema import SCHEMA_VERSION
from modules.fuzzing.adapters import AFLAdapter, HonggfuzzAdapter
from modules.fuzzing.triage import (
    cluster_crashes,
    crashes_to_findings,
    detect_resume,
    minimize_corpus,
    parse_fuzzer_stats,
)


def make_crashes(root):
    (root / "crashes").mkdir(parents=True, exist_ok=True)
    # Deux occurrences du même bug + un bug distinct.
    (root / "crashes" / "id:000001,sig:11,src:000000").write_bytes(b"AAAA" * 4)
    (root / "crashes" / "id:000002,sig:11,src:000000").write_bytes(b"AAAA" * 4)
    (root / "crashes" / "id:000003,sig:06,src:000001").write_bytes(b"BBBBB")


def test_cluster_crashes_groups_identical_bugs(tmp_path):
    make_crashes(tmp_path)
    clusters = cluster_crashes(tmp_path / "crashes")
    assert len(clusters) == 2
    big = clusters[0]  # trié par occurrences décroissantes
    assert big["occurrences"] == 2 and big["signal"] == "SIGSEGV"
    assert big["severity"] == "HIGH"


def test_minimize_corpus_is_nondestructive(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a").write_bytes(b"x" * 10)
    (corpus / "b").write_bytes(b"x" * 10)   # doublon
    (corpus / "c").write_bytes(b"y" * 20)
    result = minimize_corpus(corpus)
    assert result["unique_kept"] == 2 and result["skipped"] == 1
    assert len(list(corpus.iterdir())) == 3, "le corpus d'origine ne doit pas être modifié"
    assert result["output"].endswith("corpus.min")


def test_fuzzer_stats_and_resume(tmp_path):
    make_crashes(tmp_path)
    (tmp_path / "fuzzer_stats").write_text(
        "afl_version  : 4.09c\nexecs_done    : 123456\nexecs_per_sec : 850.5\nunique_crashes : 2\n")
    stats = parse_fuzzer_stats(tmp_path)
    assert stats["execs_done"] == 123456
    assert stats["execs_per_sec"] == 850.5
    resume = detect_resume(tmp_path)
    assert resume["resumable"] is True
    assert detect_resume(tmp_path / "nope")["resumable"] is False


def test_crashes_to_findings_contract(tmp_path):
    make_crashes(tmp_path)
    clusters = cluster_crashes(tmp_path / "crashes")
    findings = crashes_to_findings(clusters, "/bin/victim")
    assert findings
    for f in findings:
        assert f["schema_version"] == SCHEMA_VERSION
        assert f["status"] == "observation"
        assert f["exploitability"] == "unknown"
        assert f["id"]
        assert f["tags"]
    assert any("occurrence" in f["description"] for f in findings)


def test_afl_adapter_limits_and_resume(tmp_path, monkeypatch):
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/" + name if name == "afl-fuzz" else None)
    make_crashes(tmp_path)
    (tmp_path / "fuzzer_stats").write_text("afl_version : 4.09c\n")
    plan = AFLAdapter("/bin/victim").fuzz(str(tmp_path / "corpus"), str(tmp_path),
                                          timeout_ms=1500, memory_mb=128,
                                          max_runtime_s=3600, resume=True)
    assert plan["status"] == "ready"
    joined = " ".join(plan["argv"])
    assert "-t 1500+" in joined and "-m 128" in joined and "-V 3600" in joined
    assert "-S resume0" in joined
    assert plan["resumable"] is True

    # outil absent -> pas d'exécution, statut d'erreur + conseil
    monkeypatch.setattr(_shutil, "which", lambda name: None)
    missing = AFLAdapter("/bin/victim").fuzz("in", "out")
    assert missing["status"] == "error"
    assert "fallback" in missing


def test_honggfuzz_adapter_limits(monkeypatch):
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/honggfuzz" if name == "honggfuzz" else None)
    plan = HonggfuzzAdapter("/bin/victim").fuzz("in", "out", timeout_ms=2000, memory_mb=64, max_runtime_s=60)
    joined = " ".join(plan["argv"])
    assert "--timeout 2" in joined and "--memlimit 64" in joined and "--run 60" in joined


def test_manager_export_findings(tmp_path):
    mgr = FuzzingManager(base_dir=tmp_path / "fw")
    victim = tmp_path / "victim"
    victim.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)
    campaign = mgr.create_campaign("camp1", str(victim), engine="radamsa")
    camp_dir = Path(campaign.output_dir)
    make_crashes(camp_dir)
    result = mgr.export_findings("camp1")
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["clusters"] == 2
    assert result["findings"]
    assert (camp_dir / "findings.json").is_file()
    json.loads((camp_dir / "findings.json").read_text())


def test_cli_fuzzing_export_findings_and_plan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env = {"HOME": str(tmp_path)}
    import os as _os
    for k in list(_os.environ):
        if k.startswith("R3CON_"):
            env[k] = _os.environ[k]
    victim = tmp_path / "victim"
    victim.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)
    r = CliRunner(env=env).invoke(cli, ["--no-banner", "fuzzing", "create", "clicamp",
                                        str(victim), "--engine", "afl"],
                                  catch_exceptions=False)
    assert r.exit_code == 0, r.output
    camp_dir = next(tmp_path.rglob("clicamp"))
    make_crashes(camp_dir)
    r2 = CliRunner(env=env).invoke(cli, ["--no-banner", "fuzzing", "export-findings", "clicamp",
                                          "--json-output"], catch_exceptions=False)
    assert r2.exit_code == 0, r2.output
    payload = json.loads(r2.output)
    assert payload["findings"] and payload["schema_version"] == SCHEMA_VERSION
    r3 = CliRunner(env=env).invoke(cli, ["--no-banner", "fuzzing", "plan", "clicamp",
                                         "--max-runtime", "60"], catch_exceptions=False)
    assert r3.exit_code == 0
    assert "afl-fuzz" in r3.output or "not found" in r3.output
