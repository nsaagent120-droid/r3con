"""
r3con v6.2 - Network Analysis Domain PRO
Protocol, threat, flow, DNS, TLS, HTTP analyzers + external tools
"""
from .protocol_analyzer import ProtocolAnalyzer
from .threat_detector import ThreatDetector
from .flow_analyzer import FlowAnalyzer
from .dns_analyzer import DNSAnalyzer
from .tls_analyzer import TLSAnalyzer
from .http_analyzer import HTTPAnalyzer

__all__ = [
    "ProtocolAnalyzer",
    "ThreatDetector",
    "FlowAnalyzer",
    "DNSAnalyzer",
    "TLSAnalyzer",
    "HTTPAnalyzer",
]

def analyze_network(pcap_path: str) -> dict:
    """Pipeline complet network analysis."""
    results = {}

    # Protocol analyzer base
    pa = ProtocolAnalyzer(pcap_path)
    pa_result = pa.analyze()
    results["protocol"] = pa_result

    if pa_result.get("status") != "ok":
        return results

    flows = pa_result.get("flows", [])
    iocs = pa_result.get("iocs", {})

    # Threat detector
    td = ThreatDetector()
    results["threat"] = td.analyze_pcap_summary(pa_result)
    results["threat_ioc"] = td.analyze_iocs(iocs)

    # Flow analyzer
    fa = FlowAnalyzer()
    results["flow"] = fa.analyze_flows(flows)
    results["c2_channels"] = fa.detect_c2_channels(flows)

    # DNS analyzer
    dns = DNSAnalyzer()
    results["dns"] = dns.analyze_pcap_dns(pa_result)

    # TLS analyzer
    tls = TLSAnalyzer()
    results["tls"] = tls.analyze_pcap(pa_result)

    # HTTP analyzer
    http = HTTPAnalyzer()
    results["http"] = http.analyze_pcap_http(pa_result)

    # Aggregate
    all_findings = []
    for key in ["protocol", "threat", "threat_ioc", "flow", "dns", "tls", "http"]:
        if key in results and isinstance(results[key], dict):
            findings = results[key].get("findings", [])
            if isinstance(findings, list):
                all_findings.extend(findings)

    results["findings"] = all_findings[:200]
    results["summary"] = {
        "total_flows": len(flows),
        "total_findings": len(all_findings),
        "threat_count": results.get("threat", {}).get("threat_count", 0),
        "beacon_count": len(results.get("flow", {}).get("beacons", [])),
        "dga_count": results.get("dns", {}).get("dga_count", 0),
        "protocols": pa_result.get("protocols", {}),
        "ioc_count": sum(len(v) for v in iocs.values()) if isinstance(iocs, dict) else 0,
    }

    return results
