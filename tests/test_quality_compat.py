import struct
import tempfile
from modules.disasm.binary_parser import BinaryParser
from modules.audit.static_analyzer import StaticAnalyzer


def test_big_endian_elf_header():
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 2
    struct.pack_into(">H", data, 18, 0x3E)
    struct.pack_into(">Q", data, 24, 0x1122334455667788)
    with tempfile.NamedTemporaryFile() as fh:
        fh.write(data); fh.flush()
        info = BinaryParser(fh.name).parse()
    assert info["format"] == "ELF"
    assert info["arch"] == "x86_64"
    assert info["endian"] == "big"
    assert info["entry"] == 0x1122334455667788


def test_source_evidence():
    findings = StaticAnalyzer("c").analyze("void f(){\n gets(buf);\n}")
    assert findings[0]["evidence"]["file_line"] == 2
    assert 0.0 <= findings[0]["confidence"] <= 1.0


if __name__ == "__main__":
    test_big_endian_elf_header(); test_source_evidence(); print("quality compatibility tests passed")
