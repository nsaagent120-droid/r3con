import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.integration.execution_workspace import ExecutionWorkspace, WorkspaceLimits


def test_workspace_runs_argv_without_shell(tmp_path):
    with ExecutionWorkspace(tmp_path, limits=WorkspaceLimits(allow_network=True)) as workspace:
        job_id = workspace.start([sys.executable, "-c", "print('ok')"])
        result = workspace.status(job_id)
        for _ in range(50):
            if result["status"] != "running":
                break
            time.sleep(0.01)
            result = workspace.status(job_id)
        assert result["status"] == "ok"
        assert result["stdout"].strip() == "ok"


def test_workspace_rejects_shell_metacharacters_as_single_command(tmp_path):
    with ExecutionWorkspace(tmp_path, limits=WorkspaceLimits(allow_network=True)) as workspace:
        job_id = workspace.start([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(echo no-shell)"])
        for _ in range(50):
            result = workspace.status(job_id)
            if result["status"] != "running":
                break
            time.sleep(0.01)
        assert result["status"] == "ok"
        assert "$(echo no-shell)" in result["stdout"]


def test_workspace_rejects_unapproved_environment(tmp_path):
    with ExecutionWorkspace(tmp_path, limits=WorkspaceLimits(allow_network=True)) as workspace:
        with pytest.raises(ValueError, match="non autorisée"):
            workspace.start(["true"], extra_env={"SECRET": "should-not-pass"})


def test_workspace_timeout_stops_job(tmp_path):
    limits = WorkspaceLimits(wall_timeout_s=1, allow_network=True)
    with ExecutionWorkspace(tmp_path, limits=limits) as workspace:
        job_id = workspace.start([sys.executable, "-c", "import time; time.sleep(10)"])
        for _ in range(150):
            result = workspace.status(job_id)
            if result["status"] != "running":
                break
            time.sleep(0.02)
        assert result["status"] == "timeout"
        assert result["timed_out"] is True


def test_tool_inventory_has_one_binwalk_entry():
    from modules.integration.tool_manager import ToolManager

    rows = ToolManager().inspect()
    assert sum(row["key"] == "binwalk" for row in rows) == 1
