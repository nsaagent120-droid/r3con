import json
from pathlib import Path

from click.testing import CliRunner

from cli.groups.power import _profile_for, _target_kind, reports_group


def test_target_kind_and_auto_profile(tmp_path: Path):
    # v7.3 : la détection est unifiée via core.target_types. Un en-tête ELF
    # VALIDE est requis pour la classe « elf » ; un ELF aux champs e_ident
    # invalides est traité comme un suspect firmware (ancien comportement
    # de l'orchestrateur unifié).
    import struct
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    binary = tmp_path / "sample"
    binary.write_bytes(e_ident + struct.pack("<HHI", 2, 62, 1) + b"\x00" * 40)
    assert _target_kind(binary) == "elf"
    assert _profile_for(binary, "auto") == "binary"
    bogus = tmp_path / "bogus"
    bogus.write_bytes(b"\x7fELF" + b"\x00" * 32)
    assert _target_kind(bogus) == "firmware"
    assert _profile_for(bogus, "auto") == "firmware"


def test_compare_reports_detects_added_and_removed(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"findings": [{"id": "same"}, {"id": "removed"}]}))
    new.write_text(json.dumps({"findings": [{"id": "same"}, {"id": "added"}]}))
    result = CliRunner().invoke(reports_group, ["compare", str(old), str(new)])
    assert result.exit_code == 0, result.output
    assert "Ajoutés : 1" in result.output
    assert "Supprimés : 1" in result.output


def test_compare_reports_writes_json(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    output = tmp_path / "comparison.json"
    old.write_text(json.dumps({"findings": []}))
    new.write_text(json.dumps({"findings": [{"id": "new"}]}))
    result = CliRunner().invoke(reports_group, ["compare", str(old), str(new), "--json-output", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["added"][0]["id"] == "new"
