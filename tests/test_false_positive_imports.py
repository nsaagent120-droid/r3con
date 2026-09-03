from click.testing import CliRunner
import cli.main as main


class FakeParser:
    def __init__(self, path):
        self.path = path

    def get_imports(self):
        return [
            {"library": "libc.so.6", "name": "fgets"},
            {"library": "libc.so.6", "name": "gets"},
        ]


def test_fgets_is_not_gets():
    original = main.BinaryParser
    main.BinaryParser = FakeParser
    try:
        with CliRunner().isolated_filesystem():
            with open("dummy.elf", "wb") as fh:
                fh.write(b"fixture")
            result = CliRunner().invoke(
                main.cli,
                ["--no-banner", "disasm", "imports", "dummy.elf", "--vuln-check"],
            )
    finally:
        main.BinaryParser = original
    if result.exit_code != 0:
        raise AssertionError(f"exit={result.exit_code} output={result.output!r} exception={result.exception!r}")
    fgets_line = next(line for line in result.output.splitlines() if "fgets" in line)
    gets_line = next(line for line in result.output.splitlines() if "gets" in line and "fgets" not in line)
    assert "CRITICAL" not in fgets_line and "BOF" not in fgets_line
    assert "CRITICAL" in gets_line and "BOF" in gets_line


if __name__ == "__main__":
    test_fgets_is_not_gets()
    print("false positive import tests passed")
