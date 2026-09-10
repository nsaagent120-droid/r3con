"""Runner dynamique isolé : plan sans exécution, limites réelles, capture,
crash, timeout, refus strict si le réseau n'est pas isolable."""
import json
import os
import sys

import pytest
from click.testing import CliRunner

from cli.main import cli
from modules.dynamic.sandboxed_runner import SandboxedRunner, SandboxLimits

PY = sys.executable


def test_plan_never_executes(tmp_path, monkeypatch):
    calls = []
    import subprocess as sp
    real_popen = sp.Popen

    def spy_popen(*a, **k):
        calls.append(("popen", a[0]))
        return real_popen(*a, **k)

    monkeypatch.setattr(sp, "Popen", spy_popen)
    runner = SandboxedRunner(PY, ["-c", "print(1)"], limits=SandboxLimits())
    plan = runner.plan()
    assert plan["mode"] == "plan" and plan["executed"] is False
    assert plan["argv"][-1] == "print(1)"
    assert plan["resource_limits"]["cpu_seconds"] == 5
    assert "PATH" in plan["env_whitelist"]
    # aucune des exécutions capturées ne doit concerner LA CIBLE (le probe
    # unshare interne est légitime en mode plan, pas l'argv de la cible).
    assert not any("print(1)" in " ".join(c[1]) for c in calls)


def test_execute_basic_run_and_private_workdir(tmp_path):
    runner = SandboxedRunner(
        PY, ["-c", "import os; print('hi', os.getcwd()); open('out.txt','w').write('data')"],
        limits=SandboxLimits(allow_network=True), workdir_parent=tmp_path)
    result = runner.execute()
    assert result["status"] == "ok"
    assert result["returncode"] == 0
    assert "hi" in result["stdout_tail"]
    assert "out.txt" in result["files_created"]
    assert result["files_created"]["out.txt"]["size"] == 4
    sbx_dirs = list(tmp_path.glob("r3con-sbx-*"))
    assert not sbx_dirs, "le workdir privé doit être nettoyé"


def test_execute_captures_crash_signal(tmp_path):
    runner = SandboxedRunner(PY, ["-c", "import os; os.abort()"],
                             limits=SandboxLimits(allow_network=True), workdir_parent=tmp_path)
    result = runner.execute()
    assert result["crash_signal"] == "SIGABRT"
    crash = [f for f in result["findings"] if f.get("type") == "runtime-crash"]
    assert crash and crash[0]["status"] == "observation"
    assert crash[0]["exploitability"] in {"unknown", "theoretical"}


def test_execute_timeout_kills_process_tree(tmp_path):
    runner = SandboxedRunner(PY, ["-c", "import time; time.sleep(30)"],
                             limits=SandboxLimits(wall_timeout_s=1, allow_network=True),
                             workdir_parent=tmp_path)
    result = runner.execute()
    assert result["timed_out"] is True
    assert result["status"] == "timeout"
    assert any(f.get("type") == "runtime-timeout" for f in result["findings"])


@pytest.mark.skipif(os.geteuid() == 0, reason="rlimits enfants non testés en root")
def test_rlimit_as_is_applied(tmp_path):
    # 16 MB de RAM virtuelle max : une allocation de 512 MB doit échouer dans le fils.
    code = "b = bytearray(512*1024*1024); print('allocated')"
    runner = SandboxedRunner(PY, ["-c", code],
                             limits=SandboxLimits(memory_mb=16, allow_network=True),
                             workdir_parent=tmp_path)
    result = runner.execute()
    assert "allocated" not in result["stdout_tail"]
    assert result["returncode"] != 0 or result["crash_signal"]


def test_strict_network_refuses_without_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr(SandboxedRunner, "network_isolation_available",
                        staticmethod(lambda: (False, "test : unshare indisponible")))
    runner = SandboxedRunner(PY, ["-c", "print(1)"], limits=SandboxLimits(), workdir_parent=tmp_path)
    result = runner.execute()
    assert result["status"] == "invalid"
    assert result["error"] == "network_isolation_unavailable"
    # en mode permissif assumé, l'exécution a lieu avec avertissement
    lenient = SandboxedRunner(PY, ["-c", "print('ok')"],
                              limits=SandboxLimits(strict_network=False), workdir_parent=tmp_path)
    r2 = lenient.execute()
    assert r2["status"] == "ok"
    assert any("Réseau non isolable" in w for w in r2["warnings"])


def test_input_file_and_stdin(tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_text("payload")
    runner = SandboxedRunner(PY, ["-c", "import sys; print(sys.stdin.read().upper())"],
                             input_file=inp, limits=SandboxLimits(allow_network=True),
                             workdir_parent=tmp_path)
    assert "PAYLOAD" in runner.execute()["stdout_tail"]
    runner2 = SandboxedRunner(PY, ["-c", "import sys; print(sys.stdin.read().upper())"],
                              stdin_data=b"abc", limits=SandboxLimits(allow_network=True),
                              workdir_parent=tmp_path)
    assert "ABC" in runner2.execute()["stdout_tail"]


def test_missing_target_invalid(tmp_path):
    result = SandboxedRunner(tmp_path / "nope").execute()
    assert result["status"] == "invalid"


def test_cli_dynamic_sandbox_defaults_to_plan(tmp_path):
    target = tmp_path / "sample"
    target.write_text("#!/bin/sh\necho ran\n")
    target.chmod(0o755)
    r = CliRunner().invoke(cli, ["--no-banner", "dynamic", "sandbox", str(target)],
                           catch_exceptions=False)
    assert r.exit_code == 0
    assert "Mode simulation" in r.output
    payload = json.loads(r.output[r.output.index("{"):])
    assert payload["mode"] == "plan" and payload["executed"] is False


def test_cli_dynamic_sandbox_execute(tmp_path):
    target = tmp_path / "echo.sh"
    target.write_text("#!/bin/sh\necho sandboxed-$1\n")
    target.chmod(0o755)
    r = CliRunner().invoke(cli, ["--no-banner", "dynamic", "sandbox", str(target),
                                 "--arg", "ok", "--allow-network", "--execute"],
                           catch_exceptions=False)
    assert r.exit_code == 0
    payload = json.loads(r.output[r.output.index("{"):])
    assert payload["mode"] == "executed"
    assert "sandboxed-ok" in payload["stdout_tail"]
