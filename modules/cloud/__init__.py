"""Cloud domain PRO v7.0."""
from .docker_analyzer import CloudAnalyzer

__all__ = ["CloudAnalyzer"]

def analyze_cloud(file_path: str = None, directory: str = None) -> dict:
    analyzer = CloudAnalyzer()
    if directory:
        return analyzer.analyze_directory(directory)
    if file_path:
        # Auto-detect type
        if "Dockerfile" in file_path:
            return analyzer.analyze_dockerfile(file_path)
        elif file_path.endswith((".yaml", ".yml")):
            return analyzer.analyze_k8s(file_path)
        elif file_path.endswith(".tf"):
            return analyzer.analyze_terraform(file_path)
        else:
            # Try all
            results = {}
            results["docker"] = analyzer.analyze_dockerfile(file_path)
            results["k8s"] = analyzer.analyze_k8s(file_path)
            results["terraform"] = analyzer.analyze_terraform(file_path)
            all_findings = []
            for r in results.values():
                if r.get("status") == "ok":
                    all_findings.extend(r.get("findings", []))
            results["findings"] = all_findings[:100]
            results["summary"] = {"total": len(all_findings)}
            return results
    return {"status": "error", "error": "file_path or directory required"}
