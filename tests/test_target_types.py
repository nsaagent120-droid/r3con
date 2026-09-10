"""Détection unifiée des types de cibles avec fixtures minimales."""
import struct
import zipfile

from core.target_types import (
    KIND_APK,
    KIND_ARCHIVE,
    KIND_BINARY,
    KIND_CONTAINER,
    KIND_FIRMWARE,
    KIND_NETWORK,
    KIND_SOURCE,
    detect_target,
    human_description,
)


def make_elf(bits: int = 64, etype: int = 2, machine: int = 62) -> bytes:
    e_ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + b"\x00" * 8
    return e_ident + struct.pack("<HHI", etype, machine, 1) + b"\x00" * 40


def make_pe() -> bytes:
    dos = b"MZ" + b"\x90" * 58 + struct.pack("<I", 64)
    return dos + b"PE\x00\x00" + b"\x00" * 192


def make_macho_64() -> bytes:
    return struct.pack("<IIIIIIII", 0xFEEDFACF, 7, 0, 2, 0, 0, 0, 0) + b"\x00" * 200


def make_macho_fat(narchs: int = 2) -> bytes:
    return struct.pack(">II", 0xCAFEBABE, narchs) + b"\x00" * 100


def make_pcap() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def make_zip(tmp_path, names):
    p = tmp_path / "art.zip"
    with zipfile.ZipFile(p, "w") as zf:
        for name, data in names.items():
            zf.writestr(name, data)
    return p


def test_detect_elf_executable(tmp_path):
    f = tmp_path / "prog"
    f.write_bytes(make_elf())
    t = detect_target(f)
    assert t.kind == KIND_BINARY and "elf64" in t.types and t.confidence > 0.85
    assert t.details["elf_machine_name"] == "x86-64"


def test_detect_elf_shared_object(tmp_path):
    f = tmp_path / "lib.so"
    f.write_bytes(make_elf(etype=3))
    assert detect_target(f).kind == KIND_BINARY


def test_detect_elf_odd_type_is_firmware_suspect(tmp_path):
    f = tmp_path / "odd"
    f.write_bytes(make_elf(etype=1))
    t = detect_target(f)
    assert t.kind == KIND_FIRMWARE and t.confidence <= 0.65


def test_detect_pe(tmp_path):
    f = tmp_path / "app.exe"
    f.write_bytes(make_pe())
    t = detect_target(f)
    assert t.kind == KIND_BINARY and "pe" in t.types


def test_detect_pe_without_pe_table_is_untrusted(tmp_path):
    f = tmp_path / "blob"
    f.write_bytes(b"MZ" + b"\x00" * 400)
    assert detect_target(f).kind == KIND_FIRMWARE


def test_detect_macho_and_fat(tmp_path):
    m = tmp_path / "macho"
    m.write_bytes(make_macho_64())
    assert detect_target(m).kind == KIND_BINARY and "mach-o" in detect_target(m).types
    fat = tmp_path / "fat"
    fat.write_bytes(make_macho_fat())
    t = detect_target(fat)
    assert t.kind == KIND_BINARY and "universal" in t.types and t.details["narchs"] == 2


def test_detect_pcap_and_pcapng(tmp_path):
    p = tmp_path / "cap.pcap"
    p.write_bytes(make_pcap())
    assert detect_target(p).kind == KIND_NETWORK
    q = tmp_path / "cap.pcapng"
    q.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 100)
    assert "pcapng" in detect_target(q).types


def test_detect_apk_zip(tmp_path):
    apk = make_zip(tmp_path, {"AndroidManifest.xml": "bin", "classes.dex": "dex",
                              "lib/x86_64/libnative.so": "so"})
    t = detect_target(apk)
    assert t.kind == KIND_APK and t.confidence > 0.9 and "native-libs" in t.types
    assert t.details["native_libs"] == 1


def test_detect_plain_zip_is_archive(tmp_path):
    z = make_zip(tmp_path, {"README.md": "hello"})
    assert detect_target(z).kind == KIND_ARCHIVE


def test_detect_container_image_zip(tmp_path):
    img = make_zip(tmp_path, {"manifest.json": '[{"Config":"c.json","Layers":["l.tar"]}]',
                              "c.json": "{}", "l.tar": "layer"})
    assert detect_target(img).kind == KIND_CONTAINER


def test_detect_dex(tmp_path):
    d = tmp_path / "classes.dex"
    d.write_bytes(b"dex\n035\x00" + b"\x00" * 100)
    assert detect_target(d).kind == KIND_APK


def test_detect_firmware_squashfs_and_jffs2(tmp_path):
    sq = tmp_path / "fw.bin"
    sq.write_bytes(b"hsqs" + b"\x00" * 400)
    assert "squashfs" in detect_target(sq).types
    jj = tmp_path / "fw2.bin"
    jj.write_bytes(b"\x85\x19\x03\x20" + b"\x00" * 300)
    assert detect_target(jj).kind == KIND_FIRMWARE


def test_detect_source_by_extension_and_shebang(tmp_path):
    src = tmp_path / "main.c"
    src.write_text("#include <stdio.h>\nint main(){return 0;}\n")
    assert detect_target(src).kind == KIND_SOURCE
    sh = tmp_path / "run.sh"
    sh.write_bytes(b"#!/bin/sh\necho hi\n")
    assert detect_target(sh).kind == KIND_SOURCE
    bare = tmp_path / "runner"
    bare.write_bytes(b"#!/usr/bin/env python3\nprint(1)\n")
    assert "script" in detect_target(bare).types


def test_detect_empty_and_missing(tmp_path):
    e = tmp_path / "empty"
    e.write_bytes(b"")
    assert detect_target(e).kind == "unknown"
    t = detect_target(tmp_path / "nope")
    assert t.kind == "unknown"


def test_detect_directory(tmp_path):
    assert detect_target(tmp_path).kind == "directory"


def test_textual_heuristic_and_size_fallback(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x01\x02\x03\x04" * 50)
    assert detect_target(blob).kind == KIND_BINARY
    big = tmp_path / "big.img"
    big.write_bytes(b"\xff\xfe" * (1024 * 1024 + 256))
    assert detect_target(big).kind == KIND_FIRMWARE


def test_human_description_is_explainable(tmp_path):
    f = tmp_path / "prog"
    f.write_bytes(make_elf())
    desc = human_description(detect_target(f))
    assert "binary" in desc and "confiance" in desc and "ELF" in desc


def test_corrupted_zip_does_not_raise(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04garbage" * 50)
    t = detect_target(bad)
    assert t.kind in {KIND_ARCHIVE, KIND_APK}  # dégradé mais jamais d'exception
