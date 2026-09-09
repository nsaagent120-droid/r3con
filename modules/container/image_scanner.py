"""
r3con v7.0 - Container Image Scanner PRO
Docker image layer analysis, secret scanning, vuln detection
"""
from __future__ import annotations
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CRITICAL"),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key", "CRITICAL"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private Key", "CRITICAL"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT", "CRITICAL"),
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password", "HIGH"),
    (r"api_key\s*=\s*['\"][A-Za-z0-9-_]{20,}['\"]", "API Key", "HIGH"),
    (r"mongodb://[^:]+:[^@]+@|postgres://[^:]+:[^@]+@", "DB Connection String with Password", "HIGH"),
]

class ContainerScanner:
    """Container Scanner PRO."""

    def __init__(self):
        pass

    def scan_dockerfile(self, file_path: str) -> Dict[str, Any]:
        from modules.cloud.docker_analyzer import CloudAnalyzer
        analyzer = CloudAnalyzer()
        return analyzer.analyze_dockerfile(file_path)

    def scan_image_tar(self, tar_path: str) -> Dict[str, Any]:
        """Scan docker image tar (docker save)."""
        path = Path(tar_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "container_image_scanner",
            "path": str(path),
            "size": path.stat().st_size,
        }

        # Try to list layers if tar
        findings = []
        try:
            import tarfile
            with tarfile.open(str(path), 'r') as tar:
                members = tar.getmembers()
                result["layers"] = len([m for m in members if m.isfile()])
                result["files"] = [m.name for m in members[:100]]

                # Scan for secrets in layer files
                for member in members[:200]:
                    if member.isfile() and member.size < 5*1024*1024 and member.size > 0:
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode(errors="ignore")
                                for pattern, name, severity in SECRET_PATTERNS:
                                    try:
                                        if re.search(pattern, content, re.IGNORECASE):
                                            findings.append({
                                                "type": f"Container Secret: {name}",
                                                "severity": severity,
                                                "description": f"{name} found in layer file {member.name}",
                                                "file": member.name,
                                                "secret_type": name,
                                            })
                                    except re.error:
                                        continue
                        except Exception:
                            continue
        except Exception as e:
            result["tar_error"] = str(e)[:500]
            # Fallback: scan as binary for secrets
            try:
                content = path.read_bytes()[:10*1024*1024].decode(errors="ignore")
                for pattern, name, severity in SECRET_PATTERNS:
                    try:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                "type": f"Container Secret: {name}",
                                "severity": severity,
                                "description": f"{name} found in image",
                                "secret_type": name,
                            })
                    except re.error:
                        continue
            except Exception:
                pass

        result["findings"] = findings[:100]
        result["secret_count"] = len(findings)
        result["score"] = min(len(findings) * 10, 100)

        return result

    def scan_directory(self, dir_path: str) -> Dict[str, Any]:
        base = Path(dir_path)
        if not base.is_dir():
            return {"status": "error", "error": "not_a_directory"}

        all_findings = []
        files = []

        # Dockerfile
        for df in base.rglob("Dockerfile*"):
            res = self.scan_dockerfile(str(df))
            if res.get("status") == "ok":
                all_findings.extend(res.get("findings", []))
                files.append(str(df))

        # docker-compose
        for comp in base.rglob("docker-compose*.yaml"):
            try:
                content = comp.read_text(errors="ignore")
                # Check for secrets in compose
                for pattern, name, severity in SECRET_PATTERNS:
                    try:
                        if re.search(pattern, content, re.IGNORECASE):
                            all_findings.append({
                                "type": f"Compose Secret: {name}",
                                "severity": severity,
                                "description": f"{name} in {comp.name}",
                                "file": str(comp),
                            })
                    except re.error:
                        continue
                files.append(str(comp))
            except Exception:
                continue

        # .env files
        for env_file in base.rglob(".env*"):
            if env_file.is_file():
                all_findings.append({
                    "type": "Sensitive File: .env",
                    "severity": "MEDIUM",
                    "description": f".env file {env_file} should not be in image/context",
                    "file": str(env_file),
                })
                files.append(str(env_file))

        return {
            "status": "ok",
            "engine": "container_dir_scanner",
            "directory": str(base),
            "files_analyzed": files[:50],
            "findings": all_findings[:100],
            "count": len(all_findings),
            "score": min(len(all_findings) * 5, 100),
        }
