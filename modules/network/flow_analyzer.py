"""
r3con v6.2 - Flow Analyzer PRO
NetFlow-like analysis, beaconing, C2 detection, statistics
"""
from __future__ import annotations
from typing import Dict, List, Any
from collections import defaultdict, Counter
import statistics

class FlowAnalyzer:
    """Flow Analyzer PRO."""

    def __init__(self):
        pass

    def analyze_flows(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not flows:
            return {"status": "error", "error": "no_flows"}

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "flow_analyzer",
            "total_flows": len(flows),
        }

        # Basic stats
        total_packets = sum(f.get("packets", 0) for f in flows)
        total_bytes = sum(f.get("bytes", 0) for f in flows)
        result["stats"] = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packets_per_flow": total_packets // max(1, len(flows)),
            "avg_bytes_per_flow": total_bytes // max(1, len(flows)),
        }

        # Top talkers
        src_bytes = Counter()
        dst_bytes = Counter()
        for flow in flows:
            src = flow.get("src", "unknown")
            dst = flow.get("dst", "unknown")
            b = flow.get("bytes", 0)
            src_bytes[src] += b
            dst_bytes[dst] += b

        result["top_talkers"] = {
            "src": [{"ip": ip, "bytes": b} for ip, b in src_bytes.most_common(10)],
            "dst": [{"ip": ip, "bytes": b} for ip, b in dst_bytes.most_common(10)],
        }

        # Protocol distribution
        proto_counter = Counter(f.get("protocol", "unknown") for f in flows)
        result["protocols"] = dict(proto_counter)

        # Port distribution
        port_counter = Counter()
        for flow in flows:
            port = flow.get("dport", 0)
            if port:
                port_counter[port] += 1
        result["top_ports"] = [{"port": p, "count": c} for p, c in port_counter.most_common(20)]

        # Flow duration heuristics (if available)
        # Beaconing detection
        beacons = self._detect_beaconing(flows)
        result["beacons"] = beacons

        # Long flows
        long_flows = sorted(flows, key=lambda x: x.get("bytes", 0), reverse=True)[:10]
        result["long_flows"] = long_flows

        # Findings
        findings = []
        for beacon in beacons:
            findings.append({
                "type": f"Beaconing: {beacon['src']} -> {beacon['dst']}:{beacon['port']}",
                "severity": "HIGH",
                "description": f"Periodic beaconing detected: {beacon['count']} flows, interval ~{beacon.get('avg_interval','unknown')}",
                "src": beacon["src"],
                "dst": beacon["dst"],
            })

        # Large flows
        for flow in flows:
            if flow.get("bytes", 0) > 50 * 1024 * 1024:
                findings.append({
                    "type": "Large Flow - Possible Exfil",
                    "severity": "HIGH",
                    "description": f"Large flow {flow.get('bytes')} bytes {flow.get('src')} -> {flow.get('dst')}",
                    "flow": flow,
                })

        result["findings"] = findings[:50]

        return result

    def _detect_beaconing(self, flows: List[Dict]) -> List[Dict[str, Any]]:
        groups = defaultdict(list)
        for flow in flows:
            key = (flow.get("src"), flow.get("dst"), flow.get("dport"))
            groups[key].append(flow)

        beacons = []
        for (src, dst, port), group in groups.items():
            if len(group) >= 4:
                # Check regularity
                packets = [f.get("packets", 0) for f in group]
                bytes_list = [f.get("bytes", 0) for f in group]

                # Low variance = beaconing
                if len(group) >= 5:
                    try:
                        pkt_std = statistics.stdev(packets) if len(packets) > 1 else 0
                        byte_std = statistics.stdev(bytes_list) if len(bytes_list) > 1 else 0
                        pkt_mean = statistics.mean(packets) if packets else 0
                        byte_mean = statistics.mean(bytes_list) if bytes_list else 0

                        # If stddev is low relative to mean, it's regular
                        if pkt_mean > 0 and pkt_std / pkt_mean < 0.3 and byte_mean > 0 and byte_std / byte_mean < 0.5:
                            beacons.append({
                                "src": src,
                                "dst": dst,
                                "port": port,
                                "count": len(group),
                                "avg_packets": round(pkt_mean, 1),
                                "avg_bytes": round(byte_mean, 1),
                                "type": "periodic_beacon",
                            })
                    except statistics.StatisticsError:
                        continue

                    # Also simple check: same packets/bytes
                    if len(set(packets)) <= 2 and len(set(bytes_list)) <= 3:
                        if not any(b["src"] == src and b["dst"] == dst and b["port"] == port for b in beacons):
                            beacons.append({
                                "src": src,
                                "dst": dst,
                                "port": port,
                                "count": len(group),
                                "avg_packets": sum(packets) // len(packets) if packets else 0,
                                "avg_bytes": sum(bytes_list) // len(bytes_list) if bytes_list else 0,
                                "type": "identical_beacon",
                            })

        return beacons[:20]

    def detect_c2_channels(self, flows: List[Dict]) -> List[Dict[str, Any]]:
        """Detect potential C2 channels."""
        findings = []

        # Group by dst
        dst_groups = defaultdict(list)
        for flow in flows:
            dst = flow.get("dst")
            if dst:
                dst_groups[dst].append(flow)

        for dst, group in dst_groups.items():
            if len(group) >= 5:
                # Many small flows to same dst - C2
                small_flows = [f for f in group if f.get("bytes", 0) < 5000]
                if len(small_flows) >= 5 and len(small_flows) / len(group) > 0.7:
                    findings.append({
                        "type": "Potential C2 Channel",
                        "severity": "HIGH",
                        "description": f"Many small flows to {dst}: {len(small_flows)}/{len(group)} - possible C2",
                        "dst": dst,
                        "count": len(group),
                        "small_count": len(small_flows),
                    })

        return findings
