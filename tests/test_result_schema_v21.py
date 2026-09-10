"""Contract de résultat v2.1 : localisation, exploitabilité, références,
corroboration, classes de résultat et score borné."""
import json

from core.result_schema import (
    SCHEMA_VERSION,
    Finding,
    deduplicate_findings,
    finding_kind,
    make_result,
    normalize_exploitability,
    normalize_references,
    normalize_severity,
    summarize_findings,
)

# ── v2.1 additions ──────────────────────────────────────────────


def test_location_folds_legacy_flat_keys():
    finding = Finding.from_mapping({"type": "x", "file": "src/a.c", "line": 42,
                                    "function": "parse", "offset": "0x400"})
    assert finding.location["file"] == "src/a.c"
    assert finding.location["line"] == 42
    assert finding.location["function"] == "parse"
    assert finding.location["offset"] == "0x400"
    payload = finding.to_dict()
    assert payload["location"]["file"] == "src/a.c"
    json.dumps(payload)


def test_location_prefers_explicit_dict_over_evidence():
    finding = Finding.from_mapping({
        "type": "x",
        "location": {"file": "real.c", "line": 7},
        "evidence": {"file": "other.c", "line": 99},
    })
    assert finding.location["file"] == "real.c"
    assert finding.location["line"] == 7


def test_exploitability_normalization_and_bounds():
    assert normalize_exploitability("proven") == "confirmed"
    assert normalize_exploitability("UNVERIFIED") == "theoretical"
    assert normalize_exploitability("bogus") == "unknown"
    finding = Finding.from_mapping({"type": "x", "exploitability": "likely"})
    assert finding.exploitability == "likely"


def test_references_buckets_and_validation():
    refs = normalize_references({"cve": "2021-44228", "cwe": "79",
                                 "mitre": "t1195.002", "url": "https://acme.example/adv"})
    assert refs["cve"] == ["CVE-2021-44228"]
    assert refs["cwe"] == ["CWE-79"]
    assert refs["attack"] == ["T1195.002"]
    assert refs["ref"] == ["https://acme.example/adv"]
    # Malformed identifiers are dropped, not propagated.
    assert normalize_references({"cve": "CVE-99999"} )["cve"] == []
    assert normalize_references({"cwe": "not-a-cwe"})["cwe"] == []
    finding = Finding.from_mapping({"type": "x", "cwe": "CWE-120", "cve": "CVE-2018-18074"})
    assert "CWE-120" in finding.references["cwe"]
    assert "CVE-2018-18074" in finding.references["cve"]


def test_fallback_flag_and_kind_classification():
    assert finding_kind({"type": "x", "status": "hypothesis"}) == "hypothese"
    assert finding_kind({"type": "x", "status": "observation"}) == "observation"
    assert finding_kind({"type": "x", "status": "confirmed"}) == "confirme"
    assert finding_kind({"type": "x", "status": "false-positive"}) == "faux_positif"
    assert finding_kind({"type": "x", "provenance": {"fallback": True}}) == "fallback"
    # A false positive stays a false positive even when marked fallback.
    assert finding_kind({"type": "x", "status": "false_positive",
                         "fallback": True}) == "faux_positif"


def test_severity_alias_updates():
    assert normalize_severity("fatal") == "CRITICAL"
    assert normalize_severity("Information") == "INFO"
    assert normalize_severity("trivial") == "LOW"


def test_dedup_merges_references_and_locations_across_tools():
    common = {"type": "Use After Free", "target_hash": "t1", "evidence": {"file": "a.c", "line": 10}}
    merged = deduplicate_findings([
        {**common, "tool": "clang-sa", "cwe": "CWE-416"},
        {**common, "tool": "codeql", "references": {"attack": "T1190"}},
    ])
    assert len(merged) == 1
    assert merged[0]["references"]["cwe"] == ["CWE-416"]
    assert merged[0]["references"]["attack"] == ["T1190"]
    assert set(merged[0]["corroboration"]["tools"]) == {"clang-sa", "codeql"}
    assert merged[0]["corroboration"]["count"] == 2


def test_dedup_neutralizes_fallback_when_confirmed_by_real_tool():
    common = {"type": "Stack Overflow", "target_hash": "t2", "location": {"file": "b.c"}}
    merged = deduplicate_findings([
        {**common, "tool": "local-fallback", "fallback": True},
        {**common, "tool": "checksec", "fallback": False},
    ])
    assert len(merged) == 1
    assert merged[0]["fallback"] is False


def test_summary_counts_kinds_and_false_positives_are_excluded_from_score():
    payload = {"schema_version": SCHEMA_VERSION}
    del payload  # keep constant exercised for import-side effects
    findings = [
        {"type": "a", "severity": "CRITICAL", "confidence": 1.0, "status": "false-positive"},
        {"type": "b", "severity": "CRITICAL", "confidence": 1.0, "status": "confirmed",
         "exploitability": "confirmed"},
        {"type": "c", "severity": "low", "confidence": 0.4, "provenance": {"fallback": True}},
    ]
    summary = summarize_findings(findings)
    assert summary["counts"]["CRITICAL"] == 1  # the false positive is excluded
    assert summary["by_kind"]["faux_positif"] == 1
    assert summary["by_kind"]["fallback"] == 1
    assert summary["exploitable"] == 1
    assert summary["total"] == 3
    assert 0 <= summary["score"] <= 100


def test_score_is_monotonic_with_confirmed_exploitability():
    base = {"type": "x", "severity": "HIGH", "confidence": 0.8, "target_hash": "h"}
    plain = summarize_findings([base])["score"]
    boosted = summarize_findings([{**base, "exploitability": "confirmed"}])["score"]
    assert boosted > plain


def test_make_result_advertises_new_schema_version():
    assert make_result("ok")["schema_version"] == "2.1"


def test_finding_id_is_deterministic_across_instances():
    a = Finding.from_mapping({"type": "x", "target_hash": "z", "tool": "t",
                              "location": {"file": "f", "line": 3}})
    b = Finding.from_mapping({"type": "x", "target_hash": "z", "tool": "t",
                              "evidence": {"file": "f", "line": 3}})
    assert a.id == b.id
