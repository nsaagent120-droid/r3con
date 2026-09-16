import json
import sys
import time
from pathlib import Path

from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
import sys as _sys
_sys.path.insert(0, str(ROOT))

from cli.main import cli
from modules.integration.execution_workspace import ExecutionWorkspace, WorkspaceLimits


def test_cache_commands_are_registered():
    runner = CliRunner()
    status = runner.invoke(cli, ["--no-banner", "cache", "status", "--json-output"])
    assert status.exit_code == 0, status.output
    payload = json.loads(status.output)
    assert "file_cache" in payload
    assert "task_cache" in payload


def test_job_metadata_is_persisted(tmp_path, monkeypatch):
    import modules.integration.execution_workspace as module
    store = tmp_path / "jobs"
    monkeypatch.setattr(module, "JOB_STORE_DIR", store)
    with ExecutionWorkspace(tmp_path / "work", limits=WorkspaceLimits(allow_network=True)) as workspace:
        job_id = workspace.start([sys.executable, "-c", "print('persisted')"])
        result = workspace.status(job_id)
        for _ in range(100):
            if result["status"] != "running":
                break
            time.sleep(0.01)
            result = workspace.status(job_id)
        assert result["status"] == "ok"
    saved = ExecutionWorkspace.get_persisted(job_id)
    assert saved is not None
    assert saved["status"] == "ok"
    assert "persisted" in saved["stdout"]
