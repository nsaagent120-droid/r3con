#!/usr/bin/env python3
"""Bump version in single source of truth."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
VERSION_FILE = ROOT / "core" / "__version__.py"
PYPROJECT = ROOT / "pyproject.toml"
DOCKERFILE = ROOT / "Dockerfile"

def get_version():
    text = VERSION_FILE.read_text()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not m:
        raise RuntimeError("Version not found")
    return m.group(1)

def bump(version: str, part: str) -> str:
    major, minor, patch = map(int, version.split("."))
    if part == "patch":
        patch += 1
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "major":
        major += 1
        minor = 0
        patch = 0
    else:
        raise ValueError(f"Unknown part {part}")
    return f"{major}.{minor}.{patch}"

def main():
    part = sys.argv[1] if len(sys.argv) > 1 else "patch"
    old = get_version()
    new = bump(old, part)
    print(f"Bumping {old} -> {new}")

    # Update __version__.py
    VERSION_FILE.write_text(f'"""Single source of truth for version."""\n__version__ = "{new}"\n__version_info__ = tuple(map(int, "{new}".split(".")))\n')

    # Update pyproject.toml
    pyproject = PYPROJECT.read_text()
    pyproject = re.sub(r'version = "[^"]+"', f'version = "{new}"', pyproject, count=1)
    PYPROJECT.write_text(pyproject)

    # Update Dockerfile
    docker = DOCKERFILE.read_text()
    docker = re.sub(r'org\.opencontainers\.image\.version="[^"]+"', f'org.opencontainers.image.version="{new}"', docker)
    docker = re.sub(r'r3con v[0-9.]+', f'r3con v{new}', docker)
    DOCKERFILE.write_text(docker)

    # Update cli/main.py VERSION constant
    main_py = ROOT / "cli" / "main.py"
    if main_py.exists():
        content = main_py.read_text()
        content = re.sub(r'VERSION\s*=\s*"[^"]+"', f'VERSION  = "{new}"', content)
        main_py.write_text(content)

    print(f"Done: {new}")

if __name__ == "__main__":
    main()
