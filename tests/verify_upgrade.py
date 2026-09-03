from pathlib import Path
from tempfile import TemporaryDirectory

from modules.orchestration.orchestrator import run_analysis


def main():
    with TemporaryDirectory() as directory:
        target = Path(directory) / "sample.c"
        target.write_text("#include <string.h>\nvoid f(char *x) { char b[8]; strcpy(b, x); }\n", encoding="utf-8")
        result = run_analysis(str(target), profile="source", cache=False)
        assert result["status"] in {"ok", "partial"}
        assert result["findings"]
        first = result["findings"][0]
        assert first["id"] and first["target_hash"] and first["finding_type"]
        assert 0 <= first["confidence"] <= 1
        print(result["status"], len(result["findings"]), first["finding_type"])


if __name__ == "__main__":
    main()
