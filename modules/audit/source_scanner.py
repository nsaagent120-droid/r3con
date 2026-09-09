"""
r3con v7.2 - Source Scanner compatibility shim
Re-exports static_analyzer + secret_scanner
"""
from .static_analyzer import StaticAnalyzer
from .secret_scanner import SecretScanner

# Combined source scanner
class SourceScanner:
    """Unified source scanner - static + secrets."""

    def __init__(self, min_entropy: float = 4.5):
        self.static = StaticAnalyzer()
        self.secrets = SecretScanner(min_entropy=min_entropy)

    def scan_file(self, file_path: str) -> dict:
        static_result = {}
        secret_result = {}

        try:
            static_result = self.static.analyze_file(file_path)
        except Exception:
            static_result = {"status": "error", "engine": "static"}

        try:
            secret_result = self.secrets.scan_file(file_path)
        except Exception:
            secret_result = {"status": "error", "engine": "secrets"}

        # Merge findings
        all_findings = []
        all_findings.extend(static_result.get("findings", []))
        all_findings.extend(secret_result.get("findings", []))

        return {
            "status": "ok",
            "engine": "source_scanner",
            "file": file_path,
            "static": static_result,
            "secrets": secret_result,
            "findings": all_findings[:200],
            "count": len(all_findings),
        }

    def scan_directory(self, dir_path: str) -> dict:
        static_result = {}
        secret_result = {}

        try:
            static_result = self.static.analyze_directory(dir_path)
        except Exception as e:
            static_result = {"status": "error", "error": str(e)[:200]}

        try:
            secret_result = self.secrets.scan_directory(dir_path)
        except Exception as e:
            secret_result = {"status": "error", "error": str(e)[:200]}

        all_findings = []
        all_findings.extend(static_result.get("findings", []))
        all_findings.extend(secret_result.get("findings", []))

        return {
            "status": "ok",
            "engine": "source_scanner_dir",
            "directory": dir_path,
            "static": static_result,
            "secrets": secret_result,
            "findings": all_findings[:300],
            "count": len(all_findings),
        }

__all__ = ["SourceScanner", "StaticAnalyzer", "SecretScanner"]
