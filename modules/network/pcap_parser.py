"""
r3con v7.2 - PCAP Parser PRO - Compatibility shim + real parser
Parses pcap via tshark/scapy/heuristic
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
import shutil
import re
import json

def _run(cmd: List[str], timeout: int = 30) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=min(timeout, 120))
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except Exception:
        return None

class PcapParser:
    """PCAP Parser PRO - tshark + scapy + heuristic."""

    def __init__(self, pcap_path: str = None):
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.tshark = shutil.which("tshark") or shutil.which("wireshark")
        self.tcpdump = shutil.which("tcpdump")

    def parse_file(self, pcap_path: str) -> Dict[str, Any]:
        path = Path(pcap_path)
        if not path.is_file():
            return {"status": "error", "error": "file_not_found"}

        # Try tshark
        if self.tshark:
            try:
                # tshark -r file -T json
                cmd = ["tshark", "-r", str(path), "-T", "json", "-c", "1000"]
                out = _run(cmd, timeout=60)
                if out:
                    try:
                        packets = json.loads(out)
                        return self._parse_tshark_json(packets, str(path))
                    except Exception:
                        pass

                # tshark fields
                cmd = ["tshark", "-r", str(path), "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.port", "-e", "dns.qry.name", "-E", "separator=,", "-E", "occurrence=f"]
                out = _run(cmd, timeout=60)
                if out:
                    return self._parse_tshark_fields(out, str(path))
            except Exception as e:
                pass

        # Try scapy
        try:
            from scapy.all import rdpcap
            packets = rdpcap(str(path))
            return self._parse_scapy(packets, str(path))
        except ImportError:
            pass
        except Exception:
            pass

        # Heuristic fallback - read file and extract strings
        return self._heuristic_parse(path)

    def _parse_tshark_json(self, packets: List[Dict], source: str) -> Dict[str, Any]:
        flows = []
        dns_queries = []
        http_requests = []
        ips = set()
        domains = set()

        for pkt in packets[:1000]:
            try:
                layers = pkt.get("_source", {}).get("layers", {})
                if "ip.src" in layers:
                    src = layers["ip.src"][0] if isinstance(layers["ip.src"], list) else layers["ip.src"]
                    dst = layers["ip.dst"][0] if isinstance(layers["ip.dst"], list) else layers.get("ip.dst", "")
                    ips.add(src)
                    if dst:
                        ips.add(dst)
                    flows.append({"src": src, "dst": dst, "proto": "ip"})

                if "dns.qry.name" in layers:
                    qname = layers["dns.qry.name"][0] if isinstance(layers["dns.qry.name"], list) else layers["dns.qry.name"]
                    dns_queries.append(qname)
                    domains.add(qname)

                if "http.host" in layers:
                    host = layers["http.host"][0] if isinstance(layers["http.host"], list) else layers["http.host"]
                    http_requests.append(host)
                    domains.add(host)
            except Exception:
                continue

        return {
            "status": "ok",
            "engine": "tshark_json",
            "source": source,
            "packet_count": len(packets),
            "flows": flows[:200],
            "dns_queries": dns_queries[:100],
            "http_requests": http_requests[:100],
            "ips": sorted(list(ips))[:100],
            "domains": sorted(list(domains))[:100],
        }

    def _parse_tshark_fields(self, output: str, source: str) -> Dict[str, Any]:
        flows = []
        dns = []
        for line in output.splitlines()[:1000]:
            parts = line.split(",")
            if len(parts) >= 2:
                src, dst = parts[0].strip(), parts[1].strip()
                if src and dst:
                    flows.append({"src": src, "dst": dst})
            if len(parts) >= 4 and parts[3].strip():
                dns.append(parts[3].strip())

        return {
            "status": "ok",
            "engine": "tshark_fields",
            "source": source,
            "flows": flows[:200],
            "dns_queries": dns[:100],
            "packet_count": len(output.splitlines()),
        }

    def _parse_scapy(self, packets, source: str) -> Dict[str, Any]:
        flows = []
        dns = []
        ips = set()

        for pkt in packets[:1000]:
            try:
                if hasattr(pkt, 'haslayer'):
                    from scapy.layers.inet import IP
                    from scapy.layers.dns import DNS
                    if pkt.haslayer(IP):
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        ips.add(src)
                        ips.add(dst)
                        flows.append({"src": src, "dst": dst})

                    if pkt.haslayer(DNS) and pkt[DNS].qd:
                        qname = pkt[DNS].qd.qname.decode() if hasattr(pkt[DNS].qd.qname, 'decode') else str(pkt[DNS].qd.qname)
                        dns.append(qname)
            except Exception:
                continue

        return {
            "status": "ok",
            "engine": "scapy",
            "source": source,
            "packet_count": len(packets),
            "flows": flows[:200],
            "dns_queries": dns[:100],
            "ips": sorted(list(ips))[:100],
        }

    def _heuristic_parse(self, path: Path) -> Dict[str, Any]:
        """Heuristic parse - extract strings that look like IPs/domains."""
        try:
            data = path.read_bytes()[:5*1024*1024]
            text = data.decode(errors="ignore")

            # IPs
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ips = re.findall(ip_pattern, text)

            # Domains
            domain_pattern = r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|xyz)\b"
            domains = re.findall(domain_pattern, text, re.IGNORECASE)

            return {
                "status": "ok",
                "engine": "heuristic",
                "source": str(path),
                "packet_count": 0,
                "flows": [{"src": ip, "dst": "unknown"} for ip in ips[:20]],
                "dns_queries": domains[:50],
                "ips": sorted(set(ips))[:50],
                "domains": sorted(set(domains))[:50],
                "note": "Heuristic fallback - install tshark or scapy for full parsing",
            }
        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def parse(self, pcap_path: str = None) -> Dict[str, Any]:
        target = pcap_path or (str(self.pcap_path) if self.pcap_path else None)
        if not target:
            return {"status": "error", "error": "no_path"}
        return self.parse_file(target)

    def get_flows(self, pcap_path: str) -> List[Dict[str, Any]]:
        result = self.parse_file(pcap_path)
        return result.get("flows", [])

    def get_dns_queries(self, pcap_path: str) -> List[str]:
        result = self.parse_file(pcap_path)
        return result.get("dns_queries", [])
