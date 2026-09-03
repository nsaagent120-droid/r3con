import json
import tempfile
from pathlib import Path

import pytest

from modules.orchestration.orchestrator import Orchestrator

# Avant : fixtures attendues dans /home/ubuntu/r3con_audit/ (non fournies
# dans l'archive), avec les assertions executees au niveau du MODULE plutot
# que dans une fonction de test. Corrige : les fixtures sont generees dans
# un repertoire temporaire au moment du test, donc portable partout.

FIXTURES = {
    "fixture_sample.c": (
        "source",
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        "    char buf[64];\n"
        "    if (argc > 1) { strcpy(buf, argv[1]); }\n"
        "    printf(\"%s\\n\", buf);\n"
        "    return 0;\n"
        "}\n",
    ),
    "fixture_firmware.bin": ("firmware", bytes([0x7F, 0x45, 0x4C, 0x46]) + b"\x00" * 60),
    "sample.pcap": ("network", bytes.fromhex("d4c3b2a1") + b"\x00" * 20),
}


@pytest.fixture()
def fixture_dir():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, (_, content) in FIXTURES.items():
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(root / name, mode) as f:
                f.write(content)
        yield root


def test_orchestrator_profile_detection(fixture_dir):
    for name, (expected_profile, _) in FIXTURES.items():
        target = fixture_dir / name
        result = Orchestrator(str(target), profile="auto", timeout=20).run()
        assert result.get("profile") == expected_profile, f"{name}: profile={result.get('profile')}"
        assert result.get("plan"), f"{name}: empty plan"
        assert json.dumps(result) is not None, f"{name}: not JSON-serializable"


def test_orchestrator_missing_target_is_invalid(fixture_dir):
    missing = Orchestrator(str(fixture_dir / "does-not-exist"), profile="auto").run()
    assert missing.get("status") == "invalid"
