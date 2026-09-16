import json
import sys
from pathlib import Path

from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cli.main import cli
from scripts.benchmark import build_fixture, run_once


def test_benchmark_returns_valid_measurements(tmp_path):
    targets = build_fixture(tmp_path, 2)
    result = run_once(targets, workers=1, use_cache=False)
    assert result["status"] == "ok"
    assert result["duration_ms"] >= 0
    assert result["peak_tracemalloc_mb"] >= 0
    assert result["cache_stats"]["runs"] == 2


def test_scan_exposes_progress_switch():
    result = CliRunner().invoke(cli, ["--no-banner", "scan", "--help"])
    assert result.exit_code == 0
    assert "--progress" in result.output
    assert "--no-progress" in result.output
