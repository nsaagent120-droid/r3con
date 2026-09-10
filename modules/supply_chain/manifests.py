"""Parseurs de manifestes et lockfiles de dépendances (stdlib uniquement).

Chaque parseur renvoie une liste de composants normalisés :
``{name, version, ecosystem, scope, source, purl, manifest, version_spec}``.
Les entrées malformées sont ignorées avec un avertissement plutôt que de
faire échouer l'analyse.
"""
from __future__ import annotations

import json
import re
from typing import Any

# ── helpers ───────────────────────────────────────────────────────

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<extras>\[[^\]]*\])?"
    r"\s*(?P<spec>[=<>!~]=?[^;#\s]+(?:\s*,\s*[=<>!~]=?[^;#\s]+)*)?"
)


def _component(name: str, version: str, ecosystem: str, scope: str, source: str,
               manifest: str, version_spec: str = "") -> dict[str, Any]:
    return {
        "name": str(name).strip(),
        "version": str(version or "").strip() or "unknown",
        "ecosystem": ecosystem,
        "scope": scope,
        "source": source,  # "manifest" | "lockfile"
        "purl": _purl(ecosystem, name, version or "", scope),
        "manifest": manifest,
        "version_spec": version_spec,
    }


def _purl(ecosystem: str, name: str, version: str, scope: str = "") -> str:
    ns = {"pip": "pypi", "npm": "npm", "maven": "maven", "gradle": "maven",
          "go": "golang", "cargo": "cargo", "docker": "docker", "k8s": "docker"}.get(ecosystem, ecosystem)
    name_clean = str(name).strip().lower() if ns in {"pypi", "npm"} else str(name).strip()
    suffix = "?package_type=Dev-Package%2CTest-Package" if (ns == "maven" and scope == "dev") else ""
    return f"pkg:{ns}/{name_clean}@{version or ''}{suffix}"


# ── Python ────────────────────────────────────────────────────────

def parse_requirements(text: str, manifest: str, filename: str = "requirements.txt") -> list[dict]:
    components, warnings = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if line.startswith(("-r ", "-c ", "--requirement", "--constraint")):
            continue
        m = _REQ_LINE.match(line)
        if not m or not m.group("name"):
            warnings.append(f"{filename}:{lineno}: ligne non reconnue : {line[:80]}")
            continue
        spec = (m.group("spec") or "").strip()
        name = m.group("name")
        version = "unknown"
        pinned = re.match(r"^[=~]=\s*([0-9][^\s;]*)", spec)
        if pinned:
            version = pinned.group(1).split(",")[0]
        components.append(_component(name, version, "pip", "runtime",
                                     "manifest", manifest, spec or "unpinned"))
    return components


def parse_pyproject(text: str, manifest: str) -> list[dict]:
    """Parse [project].dependencies et [tool.poetry.dependencies] (regex tolérante)."""
    components: list[dict] = []
    m = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if m:
        block = m.group(1)
        deps = re.search(r"dependencies\s*=\s*\[(.*?)\]", block, re.S)
        if deps:
            for entry in re.findall(r"[\"']([^\"']+)[\"']", deps.group(1)):
                line_m = _REQ_LINE.match(entry.strip())
                if line_m and line_m.group("name"):
                    spec = (line_m.group("spec") or "").strip()
                    version = "unknown"
                    pinned = re.match(r"^[=~]=\s*([0-9][^\s;]*)", spec)
                    if pinned:
                        version = pinned.group(1).split(",")[0]
                    components.append(_component(line_m.group("name"), version, "pip",
                                                 "runtime", "manifest", manifest, spec or "unpinned"))
    poetry = re.search(r"^\[tool\.poetry\.dependencies\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if poetry:
        for line in poetry.group(1).splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            km = re.match(r"^([A-Za-z0-9._-]+)\s*=\s*(.+)$", entry)
            if not km:
                continue
            name, value = km.group(1), km.group(2).strip()
            version, scope = "unknown", "runtime"
            vm = re.match(r"[\"']([^\"']+)[\"']", value)
            if vm:
                version = vm.group(1).lstrip("^~")
            elif value.startswith("{"):
                vmm = re.search(r"version\s*=\s*[\"']([^\"']+)[\"']", value)
                if vmm:
                    version = vmm.group(1).lstrip("^~")
                if "optional = true" in value or "dev = true" in value or "group = " in value:
                    scope = "dev"
                if "git" in value or "url" in value or "path" in value:
                    version = f"unpinned ({value[:40]})"
            components.append(_component(name, version, "pip", scope, "manifest", manifest, version))
    return components


# ── npm ───────────────────────────────────────────────────────────

def parse_package_json(text: str, manifest: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    components = []
    for field, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                         ("optionalDependencies", "runtime"), ("peerDependencies", "runtime")):
        for name, spec in (data.get(field) or {}).items():
            version = str(spec)
            pinned = re.match(r"^(\d+\.\d+\.\d+[^\s]*)$", version)
            components.append(_component(name, pinned.group(1) if pinned else "unknown",
                                         "npm", scope, "manifest", manifest, version))
    return components


def parse_package_lock(text: str, manifest: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    components = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, entry in packages.items():
            if not path or not path.startswith("node_modules/") or not isinstance(entry, dict):
                continue
            name = path[len("node_modules/"):]
            if name.startswith("node_modules/"):  # niche imbriquée
                name = name.rsplit("/", 1)[-1]
            if entry.get("dev"):
                scope = "dev"
            else:
                scope = "runtime"
            components.append(_component(name, entry.get("version", "unknown"), "npm",
                                         scope, "lockfile", manifest,
                                         "^" if not entry.get("version") else "=="))
        return components
    deps = data.get("dependencies")  # lockfileVersion 1
    if isinstance(deps, dict):
        for name, entry in deps.items():
            if isinstance(entry, dict):
                components.append(_component(name, entry.get("version", "unknown"), "npm",
                                             "runtime" if not entry.get("dev") else "dev",
                                             "lockfile", manifest, "=="))
    return components


def parse_yarn_lock(text: str, manifest: str) -> list[dict]:
    components = []
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r'^"?[^"#]+@', stripped) and ":" in stripped and not line.startswith(" "):
            current = stripped.split(":", 1)[0].strip('"').split("@")[0]
            if stripped.count("@") > 1 and current == "":
                current = stripped.split("@")[1].split(":")[0]
        elif line.startswith(" ") and current and stripped.startswith("version "):
            vm = re.match(r'version "?([^"\n]+)"?', stripped)
            if vm:
                components.append(_component(current, vm.group(1).strip('"'), "npm",
                                             "runtime", "lockfile", manifest, "=="))
                current = None
    return components


# ── Java (Maven / Gradle) ─────────────────────────────────────────

def parse_pom(text: str, manifest: str) -> list[dict]:
    import xml.etree.ElementTree as ET
    components = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    ns = ""
    m = re.match(r"\{[^}]+\}", root.tag)
    if m:
        ns = m.group(0)
    properties: dict[str, str] = {}
    for prop in root.findall(f".//{ns}properties/*"):
        properties[prop.tag.replace(ns, "")] = (prop.text or "").strip()
    for dep in root.iter(f"{ns}dependency"):
        gid = (dep.findtext(f"{ns}groupId") or "").strip()
        aid = (dep.findtext(f"{ns}artifactId") or "").strip()
        ver = (dep.findtext(f"{ns}version") or "").strip()
        scope = (dep.findtext(f"{ns}scope") or "runtime").strip()
        pm = re.match(r"^\$\{([^}]+)\}$", ver)
        if pm:
            ver = properties.get(pm.group(1), ver)
        if not aid:
            continue
        name = f"{gid}:{aid}" if gid else aid
        version = ver if ver and not ver.startswith("${") else "unknown"
        components.append(_component(name, version, "maven", scope if scope != "test" else "dev",
                                     "manifest", manifest, ver or "unpinned"))
    return components


_GRADLE_DEP = re.compile(
    r"(implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|annotationProcessor)"
    r"\s*[({]\s*[\"']([^\"']+)[\"']"
)


def parse_gradle(text: str, manifest: str) -> list[dict]:
    components = []
    for _config, coord in _GRADLE_DEP.findall(text):
        parts = coord.split(":")
        if len(parts) >= 3:
            name, version = f"{parts[0]}:{parts[1]}", parts[2]
        elif len(parts) == 2:
            name, version = f"{parts[0]}:{parts[1]}", "unknown"
        else:
            name, version = coord, "unknown"
        components.append(_component(name, version, "maven", "runtime", "manifest", manifest, version))
    return components


# ── Go ────────────────────────────────────────────────────────────

def parse_go_mod(text: str, manifest: str) -> list[dict]:
    components = []
    in_require = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        candidate = line[len("require "):].strip() if line.startswith("require ") else (line if in_require else "")
        if not candidate or candidate.startswith("//"):
            continue
        m = re.match(r"^([\w.\-./~+]+)\s+(v[\w.\-+]+)", candidate.split("//")[0])
        if m:
            version = m.group(2).split("+")[0]
            components.append(_component(m.group(1), version, "go", "runtime", "manifest", manifest, "==" ))
    return components


def parse_gosum(text: str, manifest: str) -> list[dict]:
    seen: set[str] = set()
    components = []
    for raw in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+?)(?:/go\.mod)?\s+h1:", raw.strip())
        if not m:
            continue
        module, version = m.group(1), m.group(2).split("+")[0]
        key = f"{module}@{version}"
        if key in seen:
            continue
        seen.add(key)
        components.append(_component(module, version, "go", "runtime", "lockfile", manifest, "=="))
    return components


# ── Rust ──────────────────────────────────────────────────────────

def parse_cargo_toml(text: str, manifest: str) -> list[dict]:
    components = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        m = re.search(rf"^\[{re.escape(section)}\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
        if not m:
            continue
        scope = "dev" if "dev" in section else "runtime"
        for line in m.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            km = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", line)
            if not km:
                continue
            name, value = km.group(1), km.group(2)
            vm = re.match(r'^"([^"]+)"', value.strip())
            version = "unknown"
            if vm:
                version = vm.group(1).lstrip("^~")
            elif value.strip().startswith("{"):
                vmm = re.search(r'version\s*=\s*"([^"]+)"', value)
                if vmm:
                    version = vmm.group(1).lstrip("^~")
                if re.search(r"\bgit\s*=", value):
                    version = f"git ({version})" if version != "unknown" else "git"
            components.append(_component(name, version, "cargo", scope, "manifest", manifest, version))
    return components


def parse_cargo_lock(text: str, manifest: str) -> list[dict]:
    components = []
    name = version = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if name:
                components.append(_component(name, version or "unknown", "cargo", "runtime",
                                             "lockfile", manifest, "=="))
            name = version = None
            continue
        nm = re.match(r'^name\s*=\s*"([^"]+)"', line)
        vm = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if nm:
            name = nm.group(1)
        elif vm:
            version = vm.group(1)
    if name:
        components.append(_component(name, version or "unknown", "cargo", "runtime", "lockfile",
                                     manifest, "=="))
    return components


# ── Conteneurs / IaC ──────────────────────────────────────────────

_FROM = re.compile(r"^\s*(?:FROM|RUN\s+FROM)\s+(?:--platform=\S+\s+)?(\S+)", re.M | re.I)


def parse_dockerfile(text: str, manifest: str) -> list[dict]:
    components = []
    for ref in _FROM.findall(text):
        if ref.startswith("scratch") or "$" in ref:
            continue
        repo, _, tag = ref.partition(":")
        components.append(_component(repo, tag or "latest", "docker", "runtime",
                                     "manifest", manifest, tag or "latest"))
    return components


_K8S_IMAGE = re.compile(r"^\s*(?:-\s+)?image:\s*(\S+)\s*$", re.M)


def parse_k8s_yaml(text: str, manifest: str) -> list[dict]:
    components = []
    for ref in _K8S_IMAGE.findall(text):
        repo, _, tag = ref.partition("@")
        repo2, _, tag2 = repo.partition(":")
        components.append(_component(repo2, tag or tag2 or "latest", "k8s", "runtime",
                                     "manifest", manifest, tag or tag2 or "latest"))
    return components


_TF_MODULE = re.compile(r"module\s+[\"']?([\w-]+)[\"']?\s*\{([^}]*)\}", re.S)


def parse_terraform(text: str, manifest: str) -> list[dict]:
    components = []
    for _name, body in _TF_MODULE.findall(text):
        sm = re.search(r'source\s*=\s*"([^"]+)"', body)
        vm = re.search(r'version\s*=\s*"([^"]+)"', body)
        if sm:
            components.append(_component(sm.group(1), vm.group(1) if vm else "unpinned",
                                         "terraform", "runtime", "manifest", manifest,
                                         vm.group(1) if vm else "unpinned"))
    return components


# ── Registre ──────────────────────────────────────────────────────

PARSERS: dict[str, list[tuple[str, Any]]] = {
    "python": [("requirements*.txt", parse_requirements), ("pyproject.toml", parse_pyproject)],
    "npm": [("package.json", parse_package_json), ("package-lock.json", parse_package_lock),
            ("yarn.lock", parse_yarn_lock)],
    "java": [("pom.xml", parse_pom), ("build.gradle", parse_gradle), ("build.gradle.kts", parse_gradle)],
    "go": [("go.mod", parse_go_mod), ("go.sum", parse_gosum)],
    "rust": [("Cargo.toml", parse_cargo_toml), ("Cargo.lock", parse_cargo_lock)],
    "docker": [("Dockerfile", parse_dockerfile), ("Dockerfile.*", parse_dockerfile)],
    "kubernetes": [("*deployment*.y*ml", parse_k8s_yaml), ("*service*.y*ml", parse_k8s_yaml),
                   ("kustomization.y*ml", parse_k8s_yaml)],
    "terraform": [("*.tf", parse_terraform)],
}
