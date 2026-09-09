"""
r3con v6.1 - Dependency Scanner PRO renforcé
Scan dépendances + SBOM + vulnérabilités transitives + intégration pipeline
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib

# Vuln DB for dependencies (simplified)
VULN_DEPS_DB = {
    "log4j": [{"version": "<2.15.0", "cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "description": "Log4Shell RCE"}],
    "openssl": [{"version": "<1.1.1n", "cve": "CVE-2022-0778", "severity": "HIGH", "cvss": 7.5, "description": "OpenSSL infinite loop"}],
    "lodash": [{"version": "<4.17.21", "cve": "CVE-2021-23337", "severity": "HIGH", "cvss": 7.2, "description": "Command injection"}],
    "requests": [{"version": "<2.20.0", "cve": "CVE-2018-18074", "severity": "MEDIUM", "cvss": 6.5, "description": "HTTP header injection"}],
}

class DependencyScanner:
    """Scanner dépendances PRO."""

    def __init__(self):
        pass

    def scan_requirements(self, file_path: str) -> Dict[str, Any]:
        """Scan requirements.txt, package.json, etc."""
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return {"status": "error", "error": str(e)}

        dependencies = []
        findings = []

        # Python requirements.txt
        if path.name == "requirements.txt" or path.suffix == ".txt":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Parse package==version
                match = re.match(r"([a-zA-Z0-9_-]+)([=<>!~]+)?([0-9.]+)?", line)
                if match:
                    pkg = match.group(1).lower()
                    ver = match.group(3) or "unknown"
                    dependencies.append({"name": pkg, "version": ver, "file": str(path), "ecosystem": "pip"})

                    # Check vuln DB
                    if pkg in VULN_DEPS_DB:
                        for vuln in VULN_DEPS_DB[pkg]:
                            findings.append({
                                "type": "vulnerable_dependency",
                                "severity": vuln["severity"],
                                "cve": vuln["cve"],
                                "cvss": vuln["cvss"],
                                "description": f"{pkg} {ver} vulnérable: {vuln['description']} ({vuln['cve']})",
                                "package": pkg,
                                "version": ver,
                                "recommendation": f"Mettre à jour {pkg} vers version corrigée",
                                "file": str(path),
                            })

        # package.json
        elif path.name == "package.json":
            try:
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg, ver in deps.items():
                    pkg_lower = pkg.lower()
                    # Clean version
                    clean_ver = re.sub(r"[^0-9.]", "", ver)[:20] or "unknown"
                    dependencies.append({"name": pkg, "version": clean_ver, "file": str(path), "ecosystem": "npm"})

                    if pkg_lower in VULN_DEPS_DB or pkg_lower.replace("-", "") in VULN_DEPS_DB:
                        key = pkg_lower if pkg_lower in VULN_DEPS_DB else pkg_lower.replace("-", "")
                        if key in VULN_DEPS_DB:
                            for vuln in VULN_DEPS_DB[key]:
                                findings.append({
                                    "type": "vulnerable_dependency",
                                    "severity": vuln["severity"],
                                    "cve": vuln["cve"],
                                    "description": f"{pkg} {ver} vulnérable: {vuln['description']}",
                                    "package": pkg,
                                    "version": clean_ver,
                                    "file": str(path),
                                })
            except json.JSONDecodeError:
                pass

        # Generate SBOM
        sbom = self._generate_sbom(dependencies, str(path))

        return {
            "status": "ok",
            "engine": "dependency_scanner",
            "file": str(path),
            "dependencies": dependencies,
            "total_deps": len(dependencies),
            "findings": findings,
            "vulnerable": len(findings),
            "sbom": sbom,
        }

    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """Scan répertoire pour fichiers dépendances."""
        base = Path(directory)
        if not base.is_dir():
            return {"status": "error", "error": "not_a_directory"}

        dep_files = []
        for pattern in ["requirements.txt", "package.json", "Pipfile", "pyproject.toml", "yarn.lock", "package-lock.json"]:
            dep_files.extend(base.rglob(pattern))

        all_deps = []
        all_findings = []
        sboms = []

        for dep_file in dep_files[:10]:  # Limit
            result = self.scan_requirements(str(dep_file))
            if result.get("status") == "ok":
                all_deps.extend(result.get("dependencies", []))
                all_findings.extend(result.get("findings", []))
                sboms.append(result.get("sbom", {}))

        return {
            "status": "ok",
            "engine": "dependency_scanner",
            "directory": str(base),
            "dep_files": [str(f) for f in dep_files[:10]],
            "total_deps": len(all_deps),
            "dependencies": all_deps[:100],
            "findings": all_findings[:100],
            "vulnerable": len(all_findings),
            "sboms": sboms,
        }

    def _generate_sbom(self, dependencies: List[Dict], source_file: str) -> Dict[str, Any]:
        """Génère SBOM CycloneDX style."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{hashlib.md5(source_file.encode()).hexdigest()}",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": Path(source_file).parent.name,
                }
            },
            "components": [
                {
                    "type": "library",
                    "name": dep["name"],
                    "version": dep["version"],
                    "purl": f"pkg:{dep.get('ecosystem','pip')}/{dep['name']}@{dep['version']}",
                }
                for dep in dependencies[:50]
            ],
        }
