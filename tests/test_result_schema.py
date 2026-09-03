import json

from core.result_schema import Finding, FindingStatus, deduplicate_findings, normalize_findings


def test_finding_has_stable_id_and_serializes_json():
    finding = Finding(finding_type="Buffer Overflow", target_hash="abc", tool="static")
    payload = finding.to_dict()
    assert payload["id"] == finding.id
    assert payload["finding_type"] == "Buffer Overflow"
    assert payload["type"] == "Buffer Overflow"
    assert 0 <= payload["confidence"] <= 1
    json.dumps(payload)


def test_finding_confidence_and_status_are_normalized():
    finding = Finding.from_mapping({"type": "x", "confidence": 4, "status": "bogus"})
    assert finding.confidence == 1.0
    assert finding.status == FindingStatus.NEEDS_REVIEW.value


def test_deduplication_preserves_independent_corroboration():
    base = {"type": "Buffer Overflow", "severity": "HIGH", "confidence": 0.7,
            "target_hash": "abc", "evidence": {"file_line": 12}}
    findings = normalize_findings([base, {**base, "tool": "radare2"}], target_hash="abc")
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert merged[0]["confidence"] > 0.7
    assert "corroborated" in merged[0]["tags"]
