from modules.dynamic import gdb_analyzer
from modules.dynamic.gdb_analyzer import DynamicAnalyzer, build_cyclic_payload


def _analyzer():
    analyzer = DynamicAnalyzer("/bin/true")
    analyzer.available = True
    return analyzer


def test_crash_requires_explicit_input_or_arguments(monkeypatch):
    analyzer = _analyzer()
    result = analyzer.analyze_crash()
    assert result["status"] == "input_required"
    assert result["executed"] is False


def test_crash_builds_safe_gdb_plan_for_arguments(monkeypatch):
    analyzer = _analyzer()
    captured = {}

    def fake_run(script, binary=None, timeout=30):
        captured["script"] = script
        return "Program received signal SIGSEGV, Segmentation fault."

    monkeypatch.setattr(gdb_analyzer, "_run_gdb", fake_run)
    result = analyzer.analyze_crash(
        None,
        args=["--name", "demo"],
        breakpoint="main",
        breakpoint_address=None,
    )

    assert result["executed"] is True
    assert "set args --name demo" in captured["script"]
    assert "break main" in captured["script"]
    assert "commands\n silent\n continue\nend" in captured["script"]
    assert "run <" not in captured["script"]


def test_cyclic_plan_can_target_argument_position():
    analyzer = _analyzer()
    result = analyzer.find_bof_offset(
        max_length=64,
        prefix_length=8,
        args=["before", "after"],
        input_mode="argument",
        pattern_arg_index=1,
        breakpoint="parse_input",
        execute=False,
    )

    assert result["status"] == "planned"
    assert result["executed"] is False
    assert result["input_mode"] == "argument"
    assert result["arguments"][0] == "before"
    assert result["arguments"][2] == "after"
    assert len(bytes.fromhex(result["payload_hex"])) == 64
    assert result["breakpoint"] == "parse_input"


def test_cyclic_payload_respects_prefix_and_limit():
    payload = build_cyclic_payload(32, prefix_length=8)
    assert len(payload) == 32
    assert payload[:8] == b"A" * 8
