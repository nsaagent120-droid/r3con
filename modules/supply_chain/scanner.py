"""Orchestration du scan de chaîne d'approvisionnement — local et borné.

Parcours un projet, détecte manifestes et lockfiles, construit la liste des
composants (directs et transitifs via les lockfiles), applique la politique
offline, produit les SBOM CycloneDX/SPDX et — en option — un scan de secrets
borné. Aucun fichier du projet n'est envoyé vers un service distant.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

from core.result_schema import Status, make_result, normalize_findings

from .manifests import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_dockerfile,
    parse_go_mod,
    parse_gosum,
    parse_gradle,
    parse_k8s_yaml,
    parse_package_json,
    parse_package_lock,
    parse_pom,
    parse_pyproject,
    parse_requirements,
    parse_terraform,
    parse_yarn_lock,
)
from .policy import check_component, load_policy
from .sbom import build_cyclonedx, build_spdx

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", ".mypy_cache", ".pytest_cache", "build", "dist", "target",
             ".terraform", ".gradle", ".idea", ".vscode", "site-packages"}

# motif de fichier -> (écosystème, parseur, rôle)
MANIFEST_PATTERNS: list[tuple[str, str, Any, str]] = [
    ("requirements*.txt", "pip", parse_requirements, "manifest"),
    ("pyproject.toml", "pip", parse_pyproject, "manifest"),
    ("package.json", "npm", parse_package_json, "manifest"),
    ("package-lock.json", "npm", parse_package_lock, "lockfile"),
    ("yarn.lock", "npm", parse_yarn_lock, "lockfile"),
    ("pom.xml", "maven", parse_pom, "manifest"),
    ("build.gradle", "maven", parse_gradle, "manifest"),
    ("build.gradle.kts", "maven", parse_gradle, "manifest"),
    ("go.mod", "go", parse_go_mod, "manifest"),
    ("go.sum", "go", parse_gosum, "lockfile"),
    ("Cargo.toml", "cargo", parse_cargo_toml, "manifest"),
    ("Cargo.lock", "cargo", parse_cargo_lock, "lockfile"),
    ("Dockerfile", "docker", parse_dockerfile, "manifest"),
    ("Dockerfile.*", "docker", parse_dockerfile, "manifest"),
    ("*.tf", "terraform", parse_terraform, "manifest"),
    ("deployment*.yml", "k8s", parse_k8s_yaml, "manifest"),
    ("deployment*.yaml", "k8s", parse_k8s_yaml, "manifest"),
    ("kustomization.yml", "k8s", parse_k8s_yaml, "manifest"),
    ("kustomization.yaml", "k8s", parse_k8s_yaml, "manifest"),
]

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".yaml", ".yml",
                   ".json", ".toml", ".tf", ".sh", ".env"}

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024


def discover_manifests(root: Path, max_files: int = 20000) -> tuple[list[Path], int]:
    """Liste les fichiers de dépendances d'un projet, bornée et sûre."""
    matches: list[Path] = []
    visited = 0
    stack = [root]
    while stack and visited < max_files:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            visited += 1
            if visited >= max_files:
                break
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.is_symlink():
                    continue
                stack.append(entry)
            elif entry.is_file():
                for _pattern, _eco, _parser, _role in MANIFEST_PATTERNS:
                    if fnmatch.fnmatch(entry.name, _pattern):
                        matches.append(entry)
                        break
    return matches, visited


class SupplyChainScanner:
    """Scan supply chain hors ligne d'un répertoire projet."""

    def __init__(self, root: str | Path, *, policy_path: str | None = None,
                 scan_secrets: bool = False, sbom_format: str = "cyclonedx",
                 max_manifests: int = 200, max_secret_files: int = 400,
                 include_lockfiles: bool = True):
        self.root = Path(root)
        self.policy_path = policy_path
        self.scan_secrets = scan_secrets
        self.sbom_format = sbom_format
        self.max_manifests = max_manifests
        self.max_secret_files = max_secret_files
        self.include_lockfiles = include_lockfiles

    # ── collecte ──────────────────────────────────────────────────

    def _collect_components(self, warnings: list[str]) -> tuple[list[dict], list[str], int]:
        manifests, visited = discover_manifests(self.root)
        if len(manifests) > self.max_manifests:
            warnings.append(f"{len(manifests)} manifestes détectés, limite {self.max_manifests} "
                            f"appliquée : {len(manifests) - self.max_manifests} ignoré(s)")
            manifests = manifests[:self.max_manifests]
        components: list[dict] = []
        for path in manifests:
            role = "lockfile" if path.name in {"package-lock.json", "yarn.lock", "go.sum", "Cargo.lock"} else "manifest"
            if role == "lockfile" and not self.include_lockfiles:
                continue
            try:
                size = path.stat().st_size
                if size > MAX_MANIFEST_BYTES:
                    warnings.append(f"{path.name} ignoré (taille {size} > {MAX_MANIFEST_BYTES})")
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                warnings.append(f"lecture impossible {path}: {exc}")
                continue
            rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
            parsed = self._parse(path, text, rel, warnings)
            components.extend(parsed)
        return components, warnings, visited

    @staticmethod
    def _parse(path: Path, text: str, rel: str, warnings: list[str]) -> list[dict]:
        name = path.name
        try:
            if name.startswith("requirements") or name == "requirements.txt":
                return parse_requirements(text, rel, filename=name)
            if name == "pyproject.toml":
                return parse_pyproject(text, rel)
            if name == "package.json":
                return parse_package_json(text, rel)
            if name == "package-lock.json":
                return parse_package_lock(text, rel)
            if name == "yarn.lock":
                return parse_yarn_lock(text, rel)
            if name == "pom.xml":
                return parse_pom(text, rel)
            if name in {"build.gradle", "build.gradle.kts"}:
                return parse_gradle(text, rel)
            if name == "go.mod":
                return parse_go_mod(text, rel)
            if name == "go.sum":
                return parse_gosum(text, rel)
            if name == "Cargo.toml":
                return parse_cargo_toml(text, rel)
            if name == "Cargo.lock":
                return parse_cargo_lock(text, rel)
            if name.startswith("Dockerfile"):
                return parse_dockerfile(text, rel)
            if name.endswith(".tf"):
                return parse_terraform(text, rel)
            if name.endswith((".yml", ".yaml")):
                return parse_k8s_yaml(text, rel)
        except Exception as exc:  # noqa: BLE001 - un parseur ne doit jamais casser le scan
            warnings.append(f"analyse partielle de {rel} : {type(exc).__name__}: {str(exc)[:160]}")
        return []

    # ── scan ──────────────────────────────────────────────────────

    def scan(self) -> dict[str, Any]:
        warnings: list[str] = []
        if not self.root.is_dir():
            return make_result(Status.INVALID, target=str(self.root), error="not_a_directory")

        advisories, deny, policy_warnings = load_policy(self.policy_path)
        warnings.extend(policy_warnings)

        raw_components, warnings, visited = self._collect_components(warnings)
        components = self._merge(raw_components)

        direct_keys = {(c["ecosystem"], c["name"]) for c in components
                       if c["source"] == "manifest"}
        for component in components:
            if component["source"] == "lockfile" and (component["ecosystem"], component["name"]) not in direct_keys \
                    and component.get("scope") == "runtime":
                component["scope"] = "transitive"

        findings: list[dict] = []
        for component in components:
            findings.extend(check_component(component, advisories, deny))

        if self.scan_secrets:
            findings.extend(self._scan_secrets(warnings))

        findings = normalize_findings(
            findings, target=str(self.root), tool="r3con-supply-chain",
            tool_version="unknown", provenance={"mode": "offline"},
        )

        sbom: dict[str, Any] = {}
        if self.sbom_format in {"cyclonedx", "both"}:
            sbom["cyclonedx"] = build_cyclonedx(components, str(self.root))
        if self.sbom_format in {"spdx", "both"}:
            sbom["spdx"] = build_spdx(components, str(self.root))

        by_eco: dict[str, int] = {}
        for component in components:
            by_eco[component["ecosystem"]] = by_eco.get(component["ecosystem"], 0) + 1
        by_eco = dict(sorted(by_eco.items()))
        status = Status.OK.value if not policy_warnings else Status.PARTIAL.value
        if raw_components and not components:
            status = Status.PARTIAL.value
        return make_result(
            status,
            target=str(self.root),
            offline=True,
            policy={"advisories": len(advisories), "deny_packages": len(deny),
                     "builtin_only": self.policy_path is None, "source": self.policy_path or "r3con-builtin"},
            manifests_scanned=[c["manifest"] for c in components][:200],
            visited_entries=visited,
            components_summary={"total": len(components), "by_ecosystem": by_eco},
            components=components,
            warnings=warnings,
            findings=findings,
            sbom=sbom,
        )

    @staticmethod
    def _merge(components: list[dict]) -> list[dict]:
        """Déduplique (écosystème, nom, version) en préservant les sources."""
        merged: dict[tuple, dict] = {}
        for comp in components:
            key = (comp["ecosystem"], comp["name"].lower(), comp["version"])
            if key not in merged:
                merged[key] = {**comp, "manifests": [comp["manifest"]]}
                continue
            entry = merged[key]
            if comp["manifest"] not in entry["manifests"]:
                entry["manifests"].append(comp["manifest"])
            if comp["source"] == "lockfile":
                entry["source"] = "lockfile"
            if comp.get("scope") == "runtime" and entry.get("scope") != "runtime":
                entry["scope"] = "runtime"
        return sorted(merged.values(), key=lambda c: (c["ecosystem"], c["name"], c["version"]))

    def _scan_secrets(self, warnings: list[str]) -> list[dict]:
        """Scan de secrets borné sur les fichiers sources/manifestes."""
        try:
            from modules.audit.secret_scanner import SecretScanner
        except ImportError:  # pragma: no cover - dépendance interne stable
            warnings.append("secret_scanner indisponible : secrets non vérifiés")
            return []
        scanner = SecretScanner()
        findings: list[dict] = []
        count = 0
        stack = [self.root]
        while stack and count < self.max_secret_files:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if count >= self.max_secret_files:
                    break
                if entry.is_dir():
                    if entry.name not in SKIP_DIRS and not entry.is_symlink():
                        stack.append(entry)
                    continue
                if entry.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                count += 1
                try:
                    if entry.stat().st_size > MAX_SOURCE_BYTES:
                        continue
                    result = scanner.scan_file(str(entry))
                except OSError as exc:
                    warnings.append(f"secret scan ignoré pour {entry.name}: {exc}")
                    continue
                for item in result.get("findings", []) or []:
                    if isinstance(item, dict):
                        findings.append({**item,
                                         "type": item.get("type", "secret"),
                                         "tags": sorted(set(item.get("tags") or []) | {"supply-chain", "secrets"})})
        if count >= self.max_secret_files:
            warnings.append(f"scan de secrets interrompu à {self.max_secret_files} fichiers (limite)")
        return findings
