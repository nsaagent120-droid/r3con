"""Web scanner domain PRO v7.0."""
from .web_analyzer import WebAnalyzer
from .nuclei_wrapper import NucleiWrapper

__all__ = ["WebAnalyzer", "NucleiWrapper"]

def analyze_web(file_path: str = None, target_url: str = None) -> dict:
    results = {}

    if file_path:
        analyzer = WebAnalyzer()
        results["static"] = analyzer.analyze_file(file_path)
        results["pocs"] = analyzer.generate_pocs(results["static"].get("findings", []))

    if target_url:
        nuclei = NucleiWrapper(target_url)
        results["nuclei"] = nuclei.scan(target_url)

    # Aggregate
    all_findings = []
    for key in ["static", "nuclei"]:
        if key in results and isinstance(results[key], dict):
            findings = results[key].get("findings", [])
            all_findings.extend(findings)

    results["findings"] = all_findings[:100]
    results["summary"] = {
        "total_findings": len(all_findings),
        "by_category": results.get("static", {}).get("by_category", {}),
        "nuclei_count": results.get("nuclei", {}).get("count", 0),
    }

    return results
