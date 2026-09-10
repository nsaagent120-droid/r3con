"""Tests du module supply_chain : parseurs, politique offline, SBOM, CLI."""
import json

from click.testing import CliRunner

from cli.main import cli
from modules.supply_chain import SupplyChainScanner
from modules.supply_chain.policy import version_matches
from modules.supply_chain.sbom import build_cyclonedx


def make_project(root):
    (root / "requirements.txt").write_text(
        "requests==2.19.0\nflask>=2.0\n# comment\n-r other.txt\nlog4j? no: weird line ~\n"
    )
    (root / "package.json").write_text(json.dumps({
        "name": "demo", "dependencies": {"lodash": "^4.17.20"},
        "devDependencies": {"left-pad": "*"},
    }))
    (root / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/minimist": {"version": "1.2.5", "dev": True},
        },
    }))
    (root / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties>'
        "<log4j.version>2.14.1</log4j.version></properties>"
        "<dependencies>"
        "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
        "<version>${log4j.version}</version></dependency>"
        "</dependencies></project>"
    )
    (root / "go.mod").write_text("module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n")
    (root / "Cargo.toml").write_text('[dependencies]\nserde = "1.0.130"\nopenssl = { version = "0.10.36" }\n')
    (root / "Dockerfile").write_text("FROM python:3.11-slim\nFROM nginx:latest\n")
    (root / "main.tf").write_text('module "vpc" {\n  source  = "terraform-aws-modules/vpc/aws"\n}\n')
    (root / "app.py").write_text('AWS="AKIAABCDEFGHIJKLMNOP"\npassword = "sup3rs3cret!!passw0rd"\n')


def test_manifest_parsers_each_ecosystem(tmp_path):
    make_project(tmp_path)
    result = SupplyChainScanner(tmp_path, sbom_format="none").scan()
    components = result["components"]
    by_eco = {}
    for c in components:
        by_eco.setdefault(c["ecosystem"], set()).add(c["name"])
    assert "requests" in by_eco["pip"] and "flask" in by_eco["pip"]
    assert "lodash" in by_eco["npm"]
    assert "org.apache.logging.log4j:log4j-core" in by_eco["maven"]
    assert "github.com/gin-gonic/gin" in by_eco["go"]
    assert {"serde", "openssl"} <= by_eco["cargo"]
    assert {"python", "nginx"} <= by_eco["docker"]
    assert any("terraform-aws-modules" in n for n in by_eco["terraform"])
    assert result["status"] in {"ok", "partial"}


def test_lockfile_versions_take_precedence_and_transitive_scope(tmp_path):
    make_project(tmp_path)
    result = SupplyChainScanner(tmp_path, sbom_format="none").scan()
    minimist = [c for c in result["components"] if c["name"] == "minimist"]
    assert minimist and minimist[0]["source"] == "lockfile"
    assert minimist[0]["scope"] == "dev"
    lodash = [c for c in result["components"] if c["name"] == "lodash" and c["source"] == "lockfile"]
    assert lodash and lodash[0]["version"] == "4.17.20"


def test_policy_finds_known_vulnerabilities_offline(tmp_path):
    make_project(tmp_path)
    result = SupplyChainScanner(tmp_path, sbom_format="none").scan()
    types = {(f.get("type") or f.get("finding_type")) for f in result["findings"]}
    assert "vulnerable-dependency" in types
    assert "unpinned-dependency" in types
    assert "floating-container-tag" in types  # nginx:latest
    assert "unpinned-terraform-module" in types
    for f in result["findings"]:
        if f.get("type") == "vulnerable-dependency":
            assert f["status"] == "hypothesis"
            assert f["references"]["cve"]
    assert result["offline"] is True


def test_version_matching_heuristic_bounds():
    assert version_matches("2.14.1", "<2.17.1")
    assert not version_matches("2.17.1", "<2.17.1")
    assert version_matches("1.2.0", ">=1.0,<1.5")
    assert not version_matches("1.7.0", ">=1.0,<1.5")
    assert not version_matches("unknown", "<2.0")   # pas de faux positif sur version inconnue
    assert not version_matches("2.0", "garbage")


def test_sbom_formats_valid_and_deterministic(tmp_path):
    make_project(tmp_path)
    scanner = SupplyChainScanner(tmp_path, sbom_format="both")
    result = scanner.scan()
    cdx = result["sbom"]["cyclonedx"]
    spdx = result["sbom"]["spdx"]
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    assert cdx["serialNumber"].startswith("urn:uuid:")
    names = {c["name"] for c in cdx["components"]}
    assert "requests" in names and "lodash" in names
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["packages"] and spdx["packages"][0]["externalRefs"][0]["referenceType"] == "purl"
    described = [r for r in spdx["relationships"] if r["relationshipType"] == "DESCRIBES"]
    assert described and described[0]["relatedSpdxElement"] == spdx["packages"][0]["SPDXID"]
    # déterminisme hors horodatage
    other = build_cyclonedx(result["components"], str(tmp_path), deterministic=True)
    again = build_cyclonedx(result["components"], str(tmp_path), deterministic=True)
    assert other == again
    assert other["metadata"]["timestamp"] == "1970-01-01T00:00:00Z"


def test_secrets_option(tmp_path):
    make_project(tmp_path)
    result = SupplyChainScanner(tmp_path, sbom_format="none", scan_secrets=True).scan()
    secret_findings = [f for f in result["findings"]
                       if "supply-chain" in (f.get("tags") or []) and "secret" in str(f.get("type")).lower()
                       or "key" in str(f.get("type")).lower() or "password" in str(f.get("type")).lower()]
    assert secret_findings, "le scan de secrets optionnel doit signaler AWS AKIA / password"


def test_custom_policy_file(tmp_path):
    make_project(tmp_path)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"advisories": [
        {"id": "X-1", "ecosystem": "pip", "package": "requests", "affected": ">=2.0,<2.30",
         "severity": "CRITICAL", "description": "advisory local de test"},
    ], "deny_packages": [{"ecosystem": "npm", "package": "left-pad", "reason": "test"}]}))
    result = SupplyChainScanner(tmp_path, sbom_format="none", policy_path=str(policy)).scan()
    types = {f.get("type") for f in result["findings"]}
    assert result["policy"]["source"] == str(policy)
    assert any("advisory local de test" in f.get("description", "") for f in result["findings"])
    assert "denied-package" in types


def test_missing_policy_file_degrades_gracefully(tmp_path):
    make_project(tmp_path)
    result = SupplyChainScanner(tmp_path, sbom_format="none",
                                policy_path=str(tmp_path / "nope.json")).scan()
    assert result["status"] == "partial"
    assert any("introuvable" in w for w in result["warnings"])
    assert result["findings"], "les amorces intégrées restent actives"


def test_not_a_directory_and_corrupted_manifests(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x")
    assert SupplyChainScanner(f).scan()["status"] == "invalid"
    bad = tmp_path / "broken"
    bad.mkdir()
    (bad / "package.json").write_bytes(b"{not json ][")
    (bad / "pom.xml").write_bytes(b"<project><unclosed")
    result = SupplyChainScanner(bad, sbom_format="none").scan()
    assert result["status"] in {"ok", "partial"}  # jamais d'exception


def test_cli_supply_chain_scan_report(tmp_path):
    make_project(tmp_path)
    out = tmp_path / "sc-report.json"
    sbom_out = tmp_path / "sbom.json"
    r = CliRunner().invoke(cli, ["--no-banner", "supply-chain", "scan", str(tmp_path),
                                 "--sbom", "cyclonedx", "--dependencies", "--secrets",
                                 "--report", str(out), "--sbom-output", str(sbom_out)],
                           catch_exceptions=False)
    assert r.exit_code == 0, r.output
    payload = json.loads(out.read_text())
    assert payload["components_summary"]["total"] > 5
    assert payload["components"]
    sbom = json.loads(sbom_out.read_text())
    assert sbom["bomFormat"] == "CycloneDX"


def test_cli_fail_on_supply_chain(tmp_path):
    make_project(tmp_path)
    r = CliRunner().invoke(cli, ["--no-banner", "supply-chain", "scan", str(tmp_path),
                                 "--sbom", "none", "--fail-on", "critical"],
                           catch_exceptions=False)
    assert r.exit_code == 2  # log4shell + flask? au moins un CRITICAL via le pom
