"""Tests de bout en bout : comparaison de rapports/cibles et commandes
expliquer/résumer/interroger avec porte de sévérité."""
import json
import struct

from click.testing import CliRunner

from cli.main import cli
from modules.diff import compare_reports, render_markdown, to_sarif


def finding(fid, **kw):
    base = {"id": fid, "type": "Memory Corruption", "severity": "HIGH", "confidence": 0.7,
            "target": "a.c", "description": "strcpy non contrôlé", "status": "needs-review"}
    base.update(kw)
    return base


def test_compare_reports_added_removed_changed():
    old = {"findings": [finding("k1"), finding("k2"), finding("k3")]}
    new = {"findings": [finding("k1"),
                        finding("k2", severity="CRITICAL"),
                        finding("k4")]}
    envelope = compare_reports(old, new)
    cmp_ = envelope["comparison"]
    assert [f["id"] for f in cmp_["added"]] == ["k4"]
    assert [f["id"] for f in cmp_["removed"]] == ["k3"]
    assert cmp_["changed"][0]["id"] == "k2"
    assert cmp_["changed"][0]["fields"]["severity"] == {"old": "HIGH", "new": "CRITICAL"}
    assert cmp_["risk_trend"] == "degrading"
    assert cmp_["counts"]["unchanged"] == 1


def test_compare_reports_deterministic_and_serializable():
    old = {"findings": [finding("a"), finding("b")]}
    new = {"findings": [finding("b", confidence=0.9), finding("c")]}
    e1 = compare_reports(old, new)
    e2 = compare_reports(old, new)
    del e1["comparison"]["generated_utc"], e2["comparison"]["generated_utc"]
    assert e1 == e2
    json.dumps(e1)


def test_markdown_and_sarif_exports():
    envelope = compare_reports({"findings": []}, {"findings": [finding("x", severity="CRITICAL")]})
    md = render_markdown(envelope)
    assert "Ajoutés" in md and "Memory Corruption" in md
    sarif = json.loads(to_sarif(envelope))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "r3con diff"


def make_elf(extra=b"") -> bytes:
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    return e_ident + struct.pack("<HHI", 2, 62, 1) + b"\x00" * 40 + extra


def test_cli_reports_compare_json_and_md(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"findings": [finding("k1"), finding("k2")]}))
    new.write_text(json.dumps({"findings": [finding("k1", severity="LOW"), finding("k3")]}))
    out = tmp_path / "cmp.json"
    r = CliRunner().invoke(cli, ["--no-banner", "reports", "compare", str(old), str(new),
                                 "--json-output", str(out)], catch_exceptions=False)
    assert r.exit_code == 0
    payload = json.loads(out.read_text())
    assert payload["added"] and payload["changed"]
    assert "Ajoutés : 1" in r.output
    r2 = CliRunner().invoke(cli, ["--no-banner", "reports", "compare", str(old), str(new),
                                  "--format", "md", "--output", str(tmp_path / "c.md")],
                            catch_exceptions=False)
    assert r2.exit_code == 0 and "Ajoutés" in (tmp_path / "c.md").read_text()


def test_cli_compare_targets_binary(tmp_path):
    old = tmp_path / "old.bin"
    new = tmp_path / "new.bin"
    old.write_bytes(make_elf())
    new.write_bytes(make_elf(b"added-string-abc"))
    out = tmp_path / "diff.json"
    r = CliRunner().invoke(cli, ["--no-banner", "compare", str(old), str(new),
                                 "--kind", "binary", "--output", str(out)],
                           catch_exceptions=False)
    assert r.exit_code == 0, r.output
    payload = json.loads(out.read_text())
    assert payload["status"] == "ok"
    assert payload["comparison"]["old"]["sha256"] != payload["comparison"]["new"]["sha256"]
    assert "protections" in payload["comparison"]
    assert "functions" in payload["comparison"]


def test_cli_compare_missing_target_is_rejected_cleanly(tmp_path):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"findings": []}))
    r = CliRunner().invoke(cli, ["--no-banner", "compare", str(old), str(tmp_path / "nope"),
                                 "--kind", "binary"], catch_exceptions=False)
    # click valide l'existence (exit_code 2) sans traceback.
    assert r.exit_code == 2
    assert "does not exist" in r.output or "Invalid value" in r.output
    # Au niveau bibliothèque, le résultat reste une enveloppe structurée.
    from modules.diff import compare_targets
    envelope = compare_targets(old, tmp_path / "nope")
    assert envelope["status"] == "invalid"
    assert envelope["error"] == "target_not_found"


def test_cli_explain_cites_evidence_and_uncertainty(tmp_path):
    report = tmp_path / "report.json"
    f = finding("deadbeef1234567890", tool="clang-sa", target_hash="abc",
                status="hypothesis", confidence=0.4, exploitability="theoretical",
                location={"file": "src/a.c", "line": 12},
                references={"cwe": ["CWE-120"]},
                evidence={"snippet": "strcpy(buf, argv[1])"},
                recommendation="utiliser snprintf")
    report.write_text(json.dumps({"profile": "source", "findings": [f]}))
    r = CliRunner().invoke(cli, ["--no-banner", "explain", f["id"], "--report", str(report)],
                           catch_exceptions=False)
    assert r.exit_code == 0
    assert "strcpy(buf, argv[1])" in r.output  # citation de la preuve
    assert "hypothèse" in r.output            # classe de résultat
    assert "CWE-120" in r.output              # référence

    r2 = CliRunner().invoke(cli, ["--no-banner", "explain", "dead", "--report", str(report),
                                  "--format", "json"], catch_exceptions=False)
    assert r2.exit_code == 0
    data = json.loads(r2.output)
    assert data["finding_id"] == f["id"]
    assert any(c["kind"] == "evidence" for c in data["citations"])
    assert data["uncertainty"]

    r3 = CliRunner().invoke(cli, ["--no-banner", "explain", "ffffffff", "--report", str(report)],
                            catch_exceptions=False)
    assert r3.exit_code != 0


def test_cli_summarize_and_ask(tmp_path):
    report = tmp_path / "r.json"
    shared = {"type": "Secret", "severity": "HIGH", "confidence": 0.8, "target": "app.py"}
    report.write_text(json.dumps({"findings": [
        {**shared, "id": "i1", "tool": "secret-scan", "tags": ["corroborated"],
         "corroboration": {"tools": ["secret-scan", "semgrep"], "count": 2}},
        {**shared, "id": "i2", "tool": "semgrep", "tags": ["corroborated"],
         "corroboration": {"tools": ["secret-scan", "semgrep"], "count": 2}},
        {"id": "i3", "type": "fmt", "severity": "INFO", "fallback": True,
         "tool": "local-fallback"},
    ]}))
    r = CliRunner().invoke(cli, ["--no-banner", "summarize", str(report), "--json"],
                           catch_exceptions=False)
    summary = json.loads(r.output)
    assert summary["total_findings"] == 3
    assert len(summary["corroborated_ids"]) == 2
    assert summary["fallback_ids"] == ["i3"]

    q = CliRunner().invoke(cli, ["--no-banner", "ask", str(report),
                                 "Quels risques sont corroborés par plusieurs outils ?"],
                           catch_exceptions=False)
    assert q.exit_code == 0
    assert "2 finding(s) corroboré" in q.output

    f = CliRunner().invoke(cli, ["--no-banner", "ask", str(report),
                                 "Quels résultats viennent d'un fallback ?"],
                           catch_exceptions=False)
    assert "repli" in f.output

    g = CliRunner().invoke(cli, ["--no-banner", "ask", str(report), "Quelle heure est-il ?"],
                           catch_exceptions=False)
    assert "filtres disponibles" in g.output.lower() or "filtres disponibles" in g.output


def test_cli_explain_ai_flag_without_provider_is_graceful(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"findings": [{"id": "abc123", "type": "x", "severity": "LOW"}]}))
    r = CliRunner().invoke(cli, ["--no-banner", "explain", "abc123", "--report", str(report), "--ai"],
                           catch_exceptions=False)
    assert r.exit_code == 0  # jamais d'échec à cause de l'IA


def make_scan_report(tmp_path, severity="HIGH"):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({
        "findings": [
            {"id": "1", "type": "Overflow", "severity": severity, "confidence": 0.9},
            {"id": "2", "type": "Style", "severity": "LOW", "confidence": 0.9},
        ]
    }))
    return report


def test_fail_on_gate(tmp_path):
    report = make_scan_report(tmp_path)
    from cli.groups.power import apply_fail_on
    findings = json.loads(report.read_text())["findings"]

    class Ctx:
        code = None

        def exit(self, c):
            self.code = c

    ctx = Ctx()
    apply_fail_on(ctx, findings, "critical")
    assert ctx.code is None  # HIGH < critical -> porte ouverte
    apply_fail_on(ctx, findings, "high")
    assert ctx.code == 2
    # Un faux positif marqué par la revue ne bloque pas la CI.
    ctx_fp = Ctx()
    apply_fail_on(ctx_fp, [{"id": "x", "type": "t", "severity": "CRITICAL",
                            "status": "false-positive"}], "critical")
    assert ctx_fp.code is None
