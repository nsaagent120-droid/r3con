"""
r3con - Dependency Vulnerability Scanner
Analyse les dépendances d'un projet et détecte les CVEs connus.
Supporte: pip (requirements.txt), npm (package.json),
          Maven (pom.xml), Go (go.mod), Cargo (Cargo.toml)
Fonctionne 100% offline avec une base CVE locale.
"""

import re
import json
from pathlib import Path
from typing import List, Dict


# ── Base de données CVE locale (offline) ─────────────────────
# Format: {package_name: [(version_range, cve_id, severity, description)]}

CVE_DB = {
    # Python packages
    "requests": [
        ("< 2.20.0",  "CVE-2018-18074", "HIGH",     "CRLF injection via URL"),
        ("< 2.25.1",  "CVE-2021-22569", "HIGH",     "Redirect to URL with credential exposure"),
        ("< 2.31.0",  "CVE-2023-32681", "MEDIUM",   "Proxy-Authorization header leak on redirect"),
    ],
    "pillow": [
        ("< 9.0.0",   "CVE-2022-22815", "HIGH",     "Path traversal in ImageFont"),
        ("< 9.0.1",   "CVE-2022-22816", "HIGH",     "Buffer overflow in PcxImagePlugin"),
        ("< 10.0.0",  "CVE-2023-44271", "HIGH",     "Uncontrolled resource consumption"),
    ],
    "pyyaml": [
        ("< 5.4",     "CVE-2020-14343", "CRITICAL", "Arbitrary code execution via yaml.load()"),
        ("< 6.0",     "CVE-2021-28363", "HIGH",     "Remote code execution"),
    ],
    "urllib3": [
        ("< 1.26.5",  "CVE-2021-28363", "HIGH",     "CRLF injection"),
        ("< 2.0.7",   "CVE-2023-45803", "MEDIUM",   "Redirect with body exposure"),
        ("< 2.0.4",   "CVE-2023-43804", "HIGH",     "Cookie header leak"),
    ],
    "cryptography": [
        ("< 41.0.4",  "CVE-2023-49083", "HIGH",     "NULL ptr dereference in PKCS12 parsing"),
        ("< 42.0.0",  "CVE-2023-0286",  "HIGH",     "X.400 ASN.1 type confusion"),
    ],
    "flask": [
        ("< 2.2.5",   "CVE-2023-30861", "HIGH",     "Session cookie without SameSite attribute"),
        ("< 0.12.3",  "CVE-2018-1000656","HIGH",    "DoS via crafted JSON"),
    ],
    "django": [
        ("< 3.2.20",  "CVE-2023-36053", "HIGH",     "ReDoS in EmailValidator"),
        ("< 4.2.3",   "CVE-2023-36053", "HIGH",     "Potential ReDoS in validators"),
        ("< 3.2.24",  "CVE-2024-27351", "HIGH",     "Path traversal via django.core.files"),
    ],
    "paramiko": [
        ("< 2.10.1",  "CVE-2022-24302", "MEDIUM",   "Race condition in private key file"),
        ("< 3.4.0",   "CVE-2023-48795", "HIGH",     "Terrapin SSH attack"),
    ],
    "werkzeug": [
        ("< 3.0.3",   "CVE-2024-34069", "HIGH",     "Remote code execution via debugger"),
        ("< 2.3.8",   "CVE-2023-46136", "HIGH",     "DoS via multipart parsing"),
    ],
    "lxml": [
        ("< 4.9.3",   "CVE-2022-2309",  "HIGH",     "NULL pointer dereference"),
    ],
    "setuptools": [
        ("< 65.5.1",  "CVE-2022-40897", "HIGH",     "ReDoS via HTML parsing"),
    ],

    # Node.js packages
    "lodash": [
        ("< 4.17.21", "CVE-2021-23337", "HIGH",     "Command injection via template"),
        ("< 4.17.19", "CVE-2020-8203",  "HIGH",     "Prototype pollution"),
        ("< 4.17.11", "CVE-2018-3721",  "MEDIUM",   "Prototype pollution"),
    ],
    "axios": [
        ("< 0.21.1",  "CVE-2020-28168", "MEDIUM",   "SSRF via host header injection"),
        ("< 1.6.0",   "CVE-2023-45857", "HIGH",     "Cross-site request forgery"),
    ],
    "express": [
        ("< 4.17.3",  "CVE-2022-24999", "HIGH",     "Open redirect"),
    ],
    "moment": [
        ("< 2.29.4",  "CVE-2022-31129", "HIGH",     "ReDoS via crafted date string"),
        ("< 2.29.2",  "CVE-2022-24785", "HIGH",     "Path traversal"),
    ],
    "jsonwebtoken": [
        ("< 9.0.0",   "CVE-2022-23529", "CRITICAL", "Remote code execution via malformed token"),
        ("< 8.5.1",   "CVE-2022-23540", "HIGH",     "Signature validation bypass"),
    ],
    "minimist": [
        ("< 1.2.6",   "CVE-2021-44906", "CRITICAL", "Prototype pollution"),
        ("< 1.2.3",   "CVE-2020-7598",  "HIGH",     "Prototype pollution"),
    ],
    "tar": [
        ("< 6.1.9",   "CVE-2021-37701", "HIGH",     "Arbitrary file creation via symlink"),
        ("< 6.1.11",  "CVE-2021-37712", "HIGH",     "Arbitrary file creation via hardlink"),
    ],
    "semver": [
        ("< 7.5.2",   "CVE-2022-25883", "HIGH",     "ReDoS"),
    ],

    # Java packages (Maven)
    "log4j-core": [
        ("< 2.17.1",  "CVE-2021-44228", "CRITICAL", "Log4Shell — Remote code execution via JNDI"),
        ("< 2.16.0",  "CVE-2021-45046", "CRITICAL", "Incomplete Log4Shell fix — RCE"),
        ("< 2.17.0",  "CVE-2021-45105", "HIGH",     "Infinite recursion DoS"),
    ],
    "spring-core": [
        ("< 5.3.18",  "CVE-2022-22965", "CRITICAL", "Spring4Shell — Remote code execution"),
        ("< 5.3.20",  "CVE-2022-22968", "HIGH",     "Pattern DoS"),
    ],
    "struts2-core": [
        ("< 2.5.33",  "CVE-2023-50164", "CRITICAL", "File upload path traversal → RCE"),
        ("< 2.3.35",  "CVE-2018-11776", "CRITICAL", "Remote code execution"),
    ],
    "jackson-databind": [
        ("< 2.14.0",  "CVE-2022-42003", "HIGH",     "Deep wrapper array nesting DoS"),
        ("< 2.13.4",  "CVE-2022-42004", "HIGH",     "DoS via polymorphic typing"),
    ],
    "commons-text": [
        ("< 1.10.0",  "CVE-2022-42889", "CRITICAL", "Text4Shell — RCE via interpolation"),
    ],
    "h2": [
        ("< 2.1.210", "CVE-2022-45868", "HIGH",     "Remote code execution"),
    ],

    # Go packages
    "golang.org/x/crypto": [
        ("< 0.1.0",   "CVE-2021-43565", "HIGH",     "Unauthenticated attacker can panic SSH server"),
        ("< 0.0.0-20220314234724", "CVE-2021-33196", "HIGH", "Zip-Slip path traversal"),
    ],
    "github.com/gin-gonic/gin": [
        ("< 1.7.7",   "CVE-2023-26125", "HIGH",     "Path traversal"),
    ],

    # Rust crates
    "openssl": [
        ("< 0.10.48", "CVE-2023-0215",  "HIGH",     "Use after free in BIO_new_NDEF"),
    ],
    "hyper": [
        ("< 0.14.26", "CVE-2023-3462",  "HIGH",     "Memory corruption"),
    ],
}

# Fichiers de dépendances supportés
DEPENDENCY_FILES = {
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "requirements-test.txt": "pip",
    "Pipfile": "pipenv",
    "setup.py": "pip",
    "setup.cfg": "pip",
    "pyproject.toml": "pip",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "composer.json": "composer",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
}


class DependencyScanner:
    """Scan project dependencies for known vulnerabilities."""

    def __init__(self):
        self.cve_db = CVE_DB

    def scan_directory(self, directory: str) -> Dict:
        """
        Scan a directory for dependency files and vulnerabilities.

        Args:
            directory: Project root directory

        Returns:
            Dict with all findings, dependencies, and stats
        """
        base = Path(directory)
        results = {
            "directory":    directory,
            "files_found":  [],
            "dependencies": [],
            "findings":     [],
            "stats":        {},
        }

        # Find all dependency files
        for filename, pkg_manager in DEPENDENCY_FILES.items():
            dep_file = base / filename
            if dep_file.exists():
                results["files_found"].append(str(dep_file))
                deps = self._parse_file(dep_file, pkg_manager)
                results["dependencies"].extend(deps)

        # Scan recursively for nested projects
        for dep_file in base.rglob("requirements*.txt"):
            if str(dep_file) not in results["files_found"]:
                results["files_found"].append(str(dep_file))
                deps = self._parse_file(dep_file, "pip")
                results["dependencies"].extend(deps)

        # Check each dependency against CVE DB
        results["findings"] = self._check_dependencies(results["dependencies"])

        # Compute stats
        results["stats"] = self._compute_stats(results)

        return results

    def scan_file(self, filepath: str) -> Dict:
        """Scan a single dependency file."""
        path       = Path(filepath)
        pkg_manager = DEPENDENCY_FILES.get(path.name, "pip")
        deps       = self._parse_file(path, pkg_manager)
        findings   = self._check_dependencies(deps)

        return {
            "file":         filepath,
            "dependencies": deps,
            "findings":     findings,
            "stats":        self._compute_stats({"findings": findings, "dependencies": deps}),
        }

    def _parse_file(self, filepath: Path, pkg_manager: str) -> List[Dict]:
        """Parse dependency file and extract package + version."""
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            return []

        if pkg_manager == "pip":
            return self._parse_requirements(content)
        elif pkg_manager in ("npm", "yarn"):
            return self._parse_package_json(content)
        elif pkg_manager == "maven":
            return self._parse_pom_xml(content)
        elif pkg_manager == "go":
            return self._parse_go_mod(content)
        elif pkg_manager == "cargo":
            return self._parse_cargo_toml(content)
        elif pkg_manager == "bundler":
            return self._parse_gemfile(content)
        return []

    def _parse_requirements(self, content: str) -> List[Dict]:
        """Parse requirements.txt format."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Match: package==version, package>=version, package~=version
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>~!]+)\s*([\d\.]+)", line)
            if m:
                deps.append({
                    "name":       m.group(1).lower(),
                    "version":    m.group(3),
                    "operator":   m.group(2),
                    "manager":    "pip",
                    "raw":        line,
                })
            else:
                # Package without version constraint
                m2 = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*$", line)
                if m2:
                    deps.append({
                        "name":    m2.group(1).lower(),
                        "version": "unknown",
                        "operator": "",
                        "manager": "pip",
                        "raw":     line,
                    })
        return deps

    def _parse_package_json(self, content: str) -> List[Dict]:
        """Parse package.json format."""
        deps = []
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, version in data.get(section, {}).items():
                    # Clean version string (^1.0.0 → 1.0.0)
                    clean = re.sub(r"[^0-9\.]", "", version)
                    deps.append({
                        "name":    name.lower(),
                        "version": clean or version,
                        "manager": "npm",
                        "raw":     f"{name}: {version}",
                    })
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_pom_xml(self, content: str) -> List[Dict]:
        """Parse Maven pom.xml format."""
        deps = []
        # Find all <dependency> blocks
        blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
        for block in blocks:
            artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
            version  = re.search(r"<version>(.*?)</version>", block)
            if artifact:
                deps.append({
                    "name":    artifact.group(1).lower(),
                    "version": version.group(1) if version else "unknown",
                    "manager": "maven",
                    "raw":     artifact.group(1),
                })
        return deps

    def _parse_go_mod(self, content: str) -> List[Dict]:
        """Parse go.mod format."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            m = re.match(r"^\s+([\w\./\-]+)\s+v([\d\.]+)", line)
            if m:
                # Extract just the last part of the module path
                name = m.group(1).split("/")[-1].lower()
                deps.append({
                    "name":    name,
                    "version": m.group(2),
                    "manager": "go",
                    "raw":     line.strip(),
                    "module":  m.group(1),
                })
        return deps

    def _parse_cargo_toml(self, content: str) -> List[Dict]:
        """Parse Cargo.toml format."""
        deps = []
        in_deps = False
        for line in content.splitlines():
            if re.match(r"\[dependencies\]", line):
                in_deps = True
                continue
            if re.match(r"\[", line) and "dependencies" not in line:
                in_deps = False
                continue
            if in_deps:
                m = re.match(r'(\w+)\s*=\s*["\']?([\d\.]+)', line)
                if m:
                    deps.append({
                        "name":    m.group(1).lower(),
                        "version": m.group(2),
                        "manager": "cargo",
                        "raw":     line.strip(),
                    })
        return deps

    def _parse_gemfile(self, content: str) -> List[Dict]:
        """Parse Gemfile format."""
        deps = []
        for line in content.splitlines():
            m = re.match(r"gem\s+['\"]([^'\"]+)['\"],?\s*['\"]?([\d\.]+)?", line)
            if m:
                deps.append({
                    "name":    m.group(1).lower(),
                    "version": m.group(2) or "unknown",
                    "manager": "bundler",
                    "raw":     line.strip(),
                })
        return deps

    def _check_dependencies(self, deps: List[Dict]) -> List[Dict]:
        """Check dependencies against CVE database."""
        findings = []

        for dep in deps:
            name    = dep.get("name", "").lower()
            version = dep.get("version", "unknown")

            if name not in self.cve_db:
                continue

            for version_range, cve_id, severity, description in self.cve_db[name]:
                if self._version_matches(version, version_range):
                    findings.append({
                        "severity":    severity,
                        "type":        "Vulnerable Dependency",
                        "package":     name,
                        "version":     version,
                        "cve":         cve_id,
                        "cve_range":   version_range,
                        "description": f"{name} {version}: {description}",
                        "recommendation": f"Upgrade {name} to a version {version_range.replace('<', '>=')}",
                        "manager":     dep.get("manager", "unknown"),
                        "line":        None,
                    })

        return sorted(findings, key=lambda x:
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))

    def _version_matches(self, version: str, version_range: str) -> bool:
        """Check if a version matches a range like '< 2.0.0'."""
        if version == "unknown":
            return True  # Assume vulnerable if version unknown

        m = re.match(r"([<>=!]+)\s*([\d\.]+)", version_range)
        if not m:
            return False

        operator    = m.group(1)
        range_ver   = m.group(2)

        try:
            v_parts  = [int(x) for x in version.split(".")[:3]]
            r_parts  = [int(x) for x in range_ver.split(".")[:3]]

            # Pad to same length
            while len(v_parts) < 3: v_parts.append(0)
            while len(r_parts) < 3: r_parts.append(0)

            if operator == "<":
                return v_parts < r_parts
            elif operator == "<=":
                return v_parts <= r_parts
            elif operator == ">":
                return v_parts > r_parts
            elif operator == ">=":
                return v_parts >= r_parts
            elif operator == "==":
                return v_parts == r_parts
        except (ValueError, AttributeError):
            pass

        return False

    def _compute_stats(self, results: Dict) -> Dict:
        """Compute statistics."""
        findings = results.get("findings", [])
        deps     = results.get("dependencies", [])

        counts = {}
        for f in findings:
            s = f["severity"]
            counts[s] = counts.get(s, 0) + 1

        return {
            "total_dependencies": len(deps),
            "vulnerable":         len(findings),
            "by_severity":        counts,
            "critical_count":     counts.get("CRITICAL", 0),
            "high_count":         counts.get("HIGH", 0),
            "safe":               len(deps) - len(set(f["package"] for f in findings)),
        }


    def lookup_osv(self, package: str, version: str, ecosystem: str = "PyPI") -> Dict:
        """Query OSV and return current advisories with explicit provenance."""
        import json, urllib.request
        body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}, "version": version}).encode()
        request = urllib.request.Request("https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json", "User-Agent": "r3con/5.0.1"})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310 - endpoint HTTPS OSV constant
                data = json.loads(response.read().decode())
            return {"status": "ok", "source": "OSV", "package": package, "version": version, "vulnerabilities": data.get("vulns", [])}
        except Exception as exc:
            return {"status": "error", "source": "OSV", "package": package, "version": version, "vulnerabilities": [], "error": str(exc)}
