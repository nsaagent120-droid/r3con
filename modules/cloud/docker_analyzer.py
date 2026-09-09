"""
r3con v7.0 - Docker & Cloud Analyzer PRO
Dockerfile, docker-compose, K8s, Terraform, Cloud misconfig
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Dict, List, Any

DOCKERFILE_RULES = [
    (r"FROM.*:latest", "Docker: Latest Tag", "MEDIUM", "Using :latest is not reproducible and may be insecure"),
    (r"USER\s+root|USER\s+0", "Docker: Root User", "HIGH", "Container runs as root - privilege escalation risk"),
    (r"ADD\s+.*https?://|ADD\s+.*\.tar", "Docker: ADD with URL/tar", "MEDIUM", "ADD auto-extracts tar and fetches URLs - use COPY"),
    (r"RUN\s+.*apt-get.*update.*&&.*apt-get.*install.*&&.*rm.*apt.*lists|RUN.*yum.*install", "Docker: Good - Cleanup", "INFO", "Proper cleanup after install"),
    (r"RUN\s+.*apt-get\s+install.*\n(?!.*rm)", "Docker: No Cleanup", "MEDIUM", "apt-get install without cleanup - larger image"),
    (r"ENV.*PASSWORD|ENV.*SECRET|ENV.*KEY.*=", "Docker: Hardcoded Secret", "CRITICAL", "Hardcoded secret in ENV"),
    (r"EXPOSE\s+22|EXPOSE\s+2375", "Docker: Sensitive Port Exposed", "HIGH", "Exposing SSH or Docker daemon port"),
    (r"RUN\s+.*chmod\s+777|RUN\s+.*chmod\s+\+s", "Docker: Dangerous chmod", "HIGH", "chmod 777 or setuid - insecure"),
    (r"HEALTHCHECK\s+NONE|HEALTHCHECK.*NONE", "Docker: No Healthcheck", "LOW", "No healthcheck defined"),
    (r"COPY\s+.*\.env|COPY.*id_rsa|COPY.*\.aws", "Docker: Sensitive File Copied", "CRITICAL", "Copying sensitive files into image"),
]

K8S_RULES = [
    (r"privileged:\s*true", "K8s: Privileged Container", "CRITICAL", "Privileged container can access host"),
    (r"allowPrivilegeEscalation:\s*true", "K8s: Privilege Escalation Allowed", "HIGH", "Allows privilege escalation"),
    (r"runAsUser:\s*0|runAsUser:\s*root", "K8s: Run as Root", "HIGH", "Container runs as root"),
    (r"hostNetwork:\s*true", "K8s: Host Network", "HIGH", "Uses host network - breaks isolation"),
    (r"hostPID:\s*true|hostIPC:\s*true", "K8s: Host PID/IPC", "HIGH", "Shares host PID/IPC namespace"),
    (r"resources:\s*\{\s*\}|resources:\s*\n\s*limits:\s*\{\s*\}", "K8s: No Resource Limits", "MEDIUM", "No resource limits - DoS risk"),
    (r"image:\s*.*:latest", "K8s: Latest Tag", "MEDIUM", "Using :latest tag"),
    (r"readOnlyRootFilesystem:\s*false", "K8s: Writable Root FS", "MEDIUM", "Root filesystem writable"),
]

TERRAFORM_RULES = [
    (r"acl\s*=\s*\"public-read\"|acl.*public", "Terraform: Public S3 ACL", "CRITICAL", "S3 bucket publicly readable"),
    (r"ingress\s*\{[^}]*cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\][^}]*from_port\s*=\s*22", "Terraform: Open SSH", "CRITICAL", "Security group allows SSH from anywhere"),
    (r"ingress.*0\.0\.0\.0/0.*from_port.*3306|ingress.*0\.0\.0\.0/0.*from_port.*5432", "Terraform: Open DB", "CRITICAL", "Database open to internet"),
    (r"enable_encryption\s*=\s*false|encrypted\s*=\s*false", "Terraform: No Encryption", "HIGH", "Encryption disabled"),
    (r"password\s*=\s*\".*\"|secret.*=.*\".{4,}\"", "Terraform: Hardcoded Secret", "CRITICAL", "Hardcoded password/secret"),
]

class CloudAnalyzer:
    """Cloud Analyzer PRO - Dockerfile, K8s, Terraform."""

    def __init__(self):
        pass

    def analyze_dockerfile(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(errors="ignore")[:500000]
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        findings = []
        for pattern, name, severity, desc in DOCKERFILE_RULES:
            try:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches:
                    for m in matches[:3]:
                        findings.append({
                            "type": f"Docker: {name}",
                            "severity": severity,
                            "description": desc,
                            "pattern": pattern[:80],
                            "match": m.group(0)[:100],
                            "file": str(path),
                        })
            except re.error:
                continue

        return {
            "status": "ok",
            "engine": "docker_analyzer",
            "file": str(path),
            "findings": findings[:50],
            "count": len(findings),
            "score": self._calc_score(findings),
        }

    def analyze_k8s(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(errors="ignore")[:500000]
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        findings = []
        for pattern, name, severity, desc in K8S_RULES:
            try:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches:
                    for m in matches[:3]:
                        findings.append({
                            "type": f"K8s: {name}",
                            "severity": severity,
                            "description": desc,
                            "match": m.group(0)[:100],
                            "file": str(path),
                        })
            except re.error:
                continue

        return {
            "status": "ok",
            "engine": "k8s_analyzer",
            "file": str(path),
            "findings": findings[:50],
            "count": len(findings),
            "score": self._calc_score(findings),
        }

    def analyze_terraform(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        try:
            content = path.read_text(errors="ignore")[:500000]
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

        findings = []
        for pattern, name, severity, desc in TERRAFORM_RULES:
            try:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL))
                if matches:
                    for m in matches[:3]:
                        findings.append({
                            "type": f"Terraform: {name}",
                            "severity": severity,
                            "description": desc,
                            "match": m.group(0)[:200],
                            "file": str(path),
                        })
            except re.error:
                continue

        return {
            "status": "ok",
            "engine": "terraform_analyzer",
            "file": str(path),
            "findings": findings[:50],
            "count": len(findings),
            "score": self._calc_score(findings),
        }

    def analyze_directory(self, dir_path: str) -> Dict[str, Any]:
        base = Path(dir_path)
        if not base.is_dir():
            return {"status": "error", "error": "not_a_directory"}

        all_findings = []
        files_analyzed = []

        # Dockerfile
        for dockerfile in base.rglob("Dockerfile*"):
            result = self.analyze_dockerfile(str(dockerfile))
            if result.get("status") == "ok":
                all_findings.extend(result.get("findings", []))
                files_analyzed.append(str(dockerfile))

        # K8s YAML
        for yaml_file in base.rglob("*.yaml"):
            content = yaml_file.read_text(errors="ignore")[:1000]
            if "kind:" in content and ("Pod" in content or "Deployment" in content or "Service" in content):
                result = self.analyze_k8s(str(yaml_file))
                if result.get("status") == "ok":
                    all_findings.extend(result.get("findings", []))
                    files_analyzed.append(str(yaml_file))

        # Terraform
        for tf_file in base.rglob("*.tf"):
            result = self.analyze_terraform(str(tf_file))
            if result.get("status") == "ok":
                all_findings.extend(result.get("findings", []))
                files_analyzed.append(str(tf_file))

        return {
            "status": "ok",
            "engine": "cloud_analyzer_dir",
            "directory": str(base),
            "files_analyzed": files_analyzed[:50],
            "total_files": len(files_analyzed),
            "findings": all_findings[:100],
            "count": len(all_findings),
            "score": self._calc_score(all_findings),
        }

    def _calc_score(self, findings: List[Dict]) -> int:
        score = 0
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev == "CRITICAL":
                score += 20
            elif sev == "HIGH":
                score += 10
            elif sev == "MEDIUM":
                score += 5
            else:
                score += 1
        return min(score, 100)
