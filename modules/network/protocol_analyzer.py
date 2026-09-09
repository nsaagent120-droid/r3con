"""Analyse réseau passive et locale de fichiers PCAP - FIXED VERSION
Fixes: IPv6, VLAN, more ports, TCP reassembly, better IOC filtering
"""

from __future__ import annotations

import ipaddress
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


# Extended risky ports - 30+ ports
RISKY_PORTS = {
    21: ("FTP", "cleartext_credentials_possible", "HIGH"),
    22: ("SSH", "encrypted_but_bruteforce_target", "LOW"),
    23: ("Telnet", "cleartext_remote_admin", "HIGH"),
    25: ("SMTP", "cleartext_mail_possible", "MEDIUM"),
    53: ("DNS", "dns_tunneling_possible", "LOW"),
    80: ("HTTP", "cleartext_application_traffic", "MEDIUM"),
    110: ("POP3", "cleartext_mail_traffic", "MEDIUM"),
    143: ("IMAP", "cleartext_mail_traffic", "MEDIUM"),
    161: ("SNMP", "legacy_monitoring_protocol", "MEDIUM"),
    389: ("LDAP", "unencrypted_directory_traffic", "MEDIUM"),
    445: ("SMB", "lateral_movement_target", "MEDIUM"),
    512: ("rexec", "cleartext_remote_exec", "HIGH"),
    513: ("rlogin", "cleartext_remote_login", "HIGH"),
    514: ("rsh", "cleartext_remote_shell", "HIGH"),
    1080: ("SOCKS", "proxy_traffic", "LOW"),
    1433: ("MSSQL", "database_cleartext_possible", "MEDIUM"),
    1521: ("Oracle", "database_traffic", "MEDIUM"),
    3306: ("MySQL", "database_cleartext_possible", "MEDIUM"),
    5432: ("PostgreSQL", "database_traffic", "MEDIUM"),
    6379: ("Redis", "database_no_auth_possible", "HIGH"),
    27017: ("MongoDB", "database_no_auth_possible", "HIGH"),
    11211: ("Memcached", "cache_no_auth", "HIGH"),
    8080: ("HTTP-alt", "cleartext_application_traffic", "MEDIUM"),
    8443: ("HTTPS-alt", "tls_traffic", "INFO"),
    9200: ("Elasticsearch", "search_no_auth_possible", "HIGH"),
    2375: ("Docker", "docker_api_no_auth", "CRITICAL"),
    5900: ("VNC", "remote_desktop_cleartext_possible", "HIGH"),
    5984: ("CouchDB", "database_traffic", "MEDIUM"),
    8000: ("HTTP-dev", "cleartext_dev_traffic", "LOW"),
    8888: ("HTTP-alt2", "cleartext_traffic", "LOW"),
    9000: ("HTTP-alt3", "cleartext_traffic", "LOW"),
}

# Private IP ranges to filter from IOCs
PRIVATE_IP_PREFIXES = (
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "0.", "169.254."
)


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))

def _ipv6(raw: bytes) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return raw.hex()

def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except Exception:
        return True

def _protocol_name(port: int, payload: bytes) -> str:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][0]
    head = payload[:32].upper()
    if head.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"HTTP/")):
        return "HTTP"
    if payload.startswith(b"SSH-"):
        return "SSH"
    if payload.startswith(b"\x16\x03") and len(payload) > 5:
        return "TLS"
    if head.startswith(b"\x00\x00\x00") or b"SMB" in head[:10]:
        return "SMB"
    if len(payload) >= 2 and payload[0] == 0x00 and payload[1] < 0x10:
        return "DNS"
    return "TCP" if port else "UDP"


class ProtocolAnalyzer:
    """Résumé déterministe de PCAP IPv4/IPv6 avec VLAN, sans exécution de payload."""

    def __init__(self, path: str, max_packets: int = 100_000, max_bytes: int = 256 * 1024 * 1024):
        self.path = Path(path)
        self.max_packets = max_packets
        self.max_bytes = max_bytes

    def analyze(self) -> Dict:
        if not self.path.is_file():
            return {"status": "error", "error": "pcap_not_found", "path": str(self.path)}
        if self.path.stat().st_size > self.max_bytes:
            return {"status": "error", "error": "pcap_too_large", "max_bytes": self.max_bytes}
        try:
            packets, linktype, truncated = self._read_pcap()
        except (OSError, ValueError, struct.error) as exc:
            return {"status": "error", "error": "invalid_pcap", "detail": str(exc)}

        flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocol": "", "payloads": []})
        protocols = Counter()
        findings = []
        tcp_streams = defaultdict(list)  # For reassembly
        
        for pkt in packets:
            parsed = self._parse_packet(pkt, linktype)
            if not parsed:
                continue
            key = (parsed["src"], parsed["sport"], parsed["dst"], parsed["dport"], parsed["transport"])
            flow = flows[key]
            flow["packets"] += 1
            flow["bytes"] += parsed["payload_len"]
            flow["protocol"] = parsed["protocol"]
            # Keep small payload sample for analysis
            if parsed["payload_len"] > 0 and len(flow["payloads"]) < 5:
                flow["payloads"].append(parsed["payload"][:200])
            protocols[parsed["protocol"]] += 1
            
            # TCP stream tracking for reassembly
            if parsed["transport"] == "TCP" and parsed["payload_len"] > 0:
                stream_key = tuple(sorted([(parsed["src"], parsed["sport"]), (parsed["dst"], parsed["dport"])]))
                tcp_streams[stream_key].append(parsed["payload"])
            
            for port in (parsed["sport"], parsed["dport"]):
                if port in RISKY_PORTS:
                    name, rule, severity = RISKY_PORTS[port]
                    findings.append({
                        "type": "cleartext_or_legacy_protocol",
                        "severity": severity,
                        "protocol": name,
                        "port": port,
                        "rule": rule,
                        "src": parsed["src"],
                        "dst": parsed["dst"],
                        "transport": parsed["transport"],
                    })

        # Analyze reassembled streams for credentials
        cred_findings = self._analyze_tcp_streams(tcp_streams)
        findings.extend(cred_findings)

        return {
            "status": "ok",
            "path": str(self.path),
            "packets_read": len(packets),
            "packets_truncated": truncated,
            "linktype": linktype,
            "linktype_name": self._linktype_name(linktype),
            "protocols": dict(protocols),
            "flows": [
                {"src": k[0], "sport": k[1], "dst": k[2], "dport": k[3], "transport": k[4], 
                 "packets": v["packets"], "bytes": v["bytes"], "protocol": v["protocol"]}
                for k, v in flows.items()
            ][:5000],
            "findings": self._dedupe_findings(findings),
            "iocs": self._extract_iocs(packets),
            "tcp_streams_count": len(tcp_streams),
            "stats": {
                "total_flows": len(flows),
                "total_packets": len(packets),
                "protocols_count": len(protocols),
            }
        }

    def _linktype_name(self, linktype: int) -> str:
        names = {
            1: "Ethernet",
            101: "Raw IPv4",
            101: "Raw IPv4",
            108: "IPv6",
            113: "Linux SLL",
            114: "Linux SLL2",
            105: "802.11",
            0: "Null/Loopback",
        }
        return names.get(linktype, f"Unknown({linktype})")

    def _analyze_tcp_streams(self, streams: Dict) -> List[Dict]:
        findings = []
        for stream_key, payloads in streams.items():
            if len(payloads) < 1:
                continue
            combined = b"".join(payloads[:20])[:8192]
            text = combined.decode("latin-1", errors="ignore")
            # Look for cleartext credentials in reassembled streams
            cred_patterns = [
                (r'(?i)(USER|USERNAME)\s+(\S+)', "FTP/SMTP user"),
                (r'(?i)PASS\s+(\S+)', "FTP password"),
                (r'(?i)password\s*[:=]\s*(\S+)', "Password in stream"),
                (r'(?i)Authorization:\s*Basic\s+(\S+)', "HTTP Basic Auth"),
                (r'(?i)Authorization:\s*Bearer\s+(\S+)', "Bearer token"),
            ]
            for pat, desc in cred_patterns:
                if re.search(pat, text):
                    findings.append({
                        "type": "cleartext_credential_in_stream",
                        "severity": "HIGH",
                        "protocol": "TCP Stream",
                        "description": f"{desc} found in reassembled TCP stream",
                        "src": str(stream_key[0]),
                        "dst": str(stream_key[1]),
                        "rule": "cleartext_credential",
                    })
                    break
        return findings

    def _read_pcap(self) -> Tuple[List[bytes], int, bool]:
        with self.path.open("rb") as fh:
            data = fh.read(self.max_bytes)
        if len(data) < 24:
            raise ValueError("PCAP header too short")
        magic = data[:4]
        # Handle pcap and pcapng
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"  # nanosecond
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"  # nanosecond
        elif magic == b"\x0a\x0d\x0d\x0a":
            # pcapng - try to parse first block
            return self._read_pcapng(data)
        else:
            raise ValueError(f"unsupported PCAP magic: {magic.hex()}")

        _major, _minor, _tz, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
        if snaplen <= 0 or snaplen > 262144:
            # Be permissive: some files have large snaplen
            if snaplen > 10*1024*1024:
                raise ValueError("invalid snaplen")
        packets, offset, truncated = [], 24, False
        while offset + 16 <= len(data) and len(packets) < self.max_packets:
            try:
                _sec, _usec, incl, _orig = struct.unpack_from(endian + "IIII", data, offset)
            except struct.error:
                break
            offset += 16
            if incl > 100000 or offset + incl > len(data):
                truncated = True
                break
            packets.append(data[offset:offset + incl])
            offset += incl
        if len(packets) >= self.max_packets:
            truncated = True
        return packets, linktype, truncated

    def _read_pcapng(self, data: bytes) -> Tuple[List[bytes], int, bool]:
        """Simple pcapng reader - extracts Enhanced Packet Blocks."""
        packets = []
        offset = 0
        linktype = 1
        truncated = False
        # Very simplified pcapng parsing
        while offset + 12 <= len(data) and len(packets) < self.max_packets:
            try:
                block_type = struct.unpack_from("<I", data, offset)[0]
                block_len = struct.unpack_from("<I", data, offset+4)[0]
                if block_len < 12 or offset + block_len > len(data):
                    break
                if block_type == 0x00000006:  # Enhanced Packet Block
                    if offset + 28 <= len(data):
                        # Skip interface ID, timestamp, capture len, original len
                        cap_len = struct.unpack_from("<I", data, offset+20)[0]
                        if cap_len <= 100000 and offset + 28 + cap_len <= len(data):
                            packets.append(data[offset+28:offset+28+cap_len])
                elif block_type == 0x00000001:  # Interface Description
                    if offset + 16 <= len(data):
                        linktype = struct.unpack_from("<H", data, offset+8)[0]
                offset += block_len
            except Exception:
                break
        if len(packets) >= self.max_packets:
            truncated = True
        return packets, linktype, truncated

    @staticmethod
    def _extract_iocs(packets: List[bytes]) -> Dict[str, List[str]]:
        blob = b"\n".join(packets[:100000])
        text = blob.decode("latin-1", errors="ignore")
        urls = sorted(set(re.findall(r"https?://[^\s\x00\"'<>]{3,200}", text, re.IGNORECASE)))[:1000]
        # Filter URLs - remove those with private IPs or localhost
        filtered_urls = []
        for url in urls:
            # Skip if contains private IP pattern or is too short
            if len(url) < 10:
                continue
            if "localhost" in url.lower() or "127.0.0.1" in url:
                continue
            filtered_urls.append(url)
        
        ipv4_raw = re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)
        ipv4_valid = []
        seen_ip = set()
        for ip in ipv4_raw:
            if ip in seen_ip:
                continue
            try:
                parts = ip.split(".")
                if all(0 <= int(p) <= 255 for p in parts):
                    # Filter private IPs
                    if not any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
                        if ip not in ("0.0.0.0", "255.255.255.255"):
                            ipv4_valid.append(ip)
                            seen_ip.add(ip)
            except Exception:
                continue
        ipv4_valid = ipv4_valid[:500]

        # Domains - more strict filtering
        domain_raw = re.findall(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])", text)
        # Filter out common false positives
        filtered_domains = []
        seen_dom = set()
        tld_whitelist = {"com", "net", "org", "io", "gov", "edu", "co", "info", "biz", "ru", "cn", "de", "uk", "fr", "jp"}
        for d in domain_raw:
            dl = d.lower()
            if dl in seen_dom:
                continue
            if len(dl) > 100 or len(dl) < 4:
                continue
            # Must have at least one dot and valid TLD-ish
            if "." not in dl:
                continue
            # Skip if looks like file path or version
            if "/" in dl or "_" in dl or dl.count(".") > 4:
                continue
            # Skip numeric only
            if re.match(r'^[\d.]+$', dl):
                continue
            # Skip if TLD not plausible
            tld = dl.split(".")[-1]
            if len(tld) < 2 or len(tld) > 20:
                continue
            filtered_domains.append(dl)
            seen_dom.add(dl)
        filtered_domains = sorted(set(filtered_domains))[:500]

        # Also extract emails
        emails = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))[:100]

        return {"urls": filtered_urls[:500], "ipv4": ipv4_valid, "domains": filtered_domains, "emails": emails}

    @staticmethod
    def _parse_packet(pkt: bytes, linktype: int) -> Dict | None:
        # Handle different linktypes
        ip = None
        if linktype == 1:  # Ethernet
            if len(pkt) < 14:
                return None
            ethertype = struct.unpack_from("!H", pkt, 12)[0]
            # Handle VLAN
            if ethertype == 0x8100:  # VLAN
                if len(pkt) < 18:
                    return None
                ethertype = struct.unpack_from("!H", pkt, 16)[0]
                ip = pkt[18:]
            elif ethertype == 0x0800:  # IPv4
                ip = pkt[14:]
            elif ethertype == 0x86DD:  # IPv6
                return ProtocolAnalyzer._parse_ipv6(pkt[14:])
            else:
                return None
        elif linktype == 101:  # Raw IPv4
            ip = pkt
        elif linktype == 108 or linktype == 101:  # Raw IPv6 or IPv4
            if len(pkt) >= 40 and (pkt[0] >> 4) == 6:
                return ProtocolAnalyzer._parse_ipv6(pkt)
            ip = pkt
        elif linktype == 113:  # Linux SLL
            if len(pkt) < 16:
                return None
            ethertype = struct.unpack_from("!H", pkt, 14)[0]
            if ethertype == 0x0800:
                ip = pkt[16:]
            elif ethertype == 0x86DD:
                return ProtocolAnalyzer._parse_ipv6(pkt[16:])
            else:
                return None
        elif linktype == 114:  # Linux SLL2
            if len(pkt) < 20:
                return None
            ethertype = struct.unpack_from("!H", pkt, 18)[0]
            if ethertype == 0x0800:
                ip = pkt[20:]
            elif ethertype == 0x86DD:
                return ProtocolAnalyzer._parse_ipv6(pkt[20:])
            else:
                return None
        elif linktype == 0:  # Null/Loopback
            if len(pkt) < 4:
                return None
            # First 4 bytes are family
            family = struct.unpack_from("!I", pkt, 0)[0] if len(pkt) >= 4 else 0
            ip = pkt[4:]
        else:
            # Try to guess IPv4
            if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
                ip = pkt
            elif len(pkt) >= 40 and (pkt[0] >> 4) == 6:
                return ProtocolAnalyzer._parse_ipv6(pkt)
            else:
                return None

        if ip is None:
            return None
        # Parse IPv4
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            return None
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return None
        total_len = struct.unpack_from("!H", ip, 2)[0]
        total_len = min(total_len, len(ip)) if total_len else len(ip)
        transport = ip[9]
        if transport not in (6, 17, 1) or total_len < ihl + 8:
            if transport not in (6, 17):
                # Allow ICMP too
                if transport == 1 and total_len >= ihl + 8:
                    pass
                else:
                    return None
        try:
            sport, dport = struct.unpack_from("!HH", ip, ihl)
        except Exception:
            return None
        if transport == 6:
            data_offset = ((ip[ihl + 12] >> 4) & 0xF) * 4
            header_len = ihl + max(data_offset, 20)
            transport_name = "TCP"
        elif transport == 17:
            header_len = ihl + 8
            transport_name = "UDP"
        else:
            header_len = ihl + 8
            transport_name = "ICMP"
        if header_len > total_len:
            return None
        payload = ip[header_len:total_len]
        return {
            "src": _ipv4(ip[12:16]), "dst": _ipv4(ip[16:20]),
            "sport": sport, "dport": dport, "transport": transport_name,
            "protocol": _protocol_name(dport if dport in RISKY_PORTS else sport, payload),
            "payload_len": len(payload),
            "payload": payload,
        }

    @staticmethod
    def _parse_ipv6(pkt: bytes) -> Dict | None:
        if len(pkt) < 40:
            return None
        if (pkt[0] >> 4) != 6:
            return None
        payload_len = struct.unpack_from("!H", pkt, 4)[0]
        next_header = pkt[6]
        src = pkt[8:24]
        dst = pkt[24:40]
        # Skip extension headers (simplified)
        offset = 40
        # Handle extension headers
        while next_header in (0, 43, 44, 50, 51, 60) and offset + 8 <= len(pkt):
            if next_header == 44:  # Fragment
                offset += 8
                break
            ext_len = (pkt[offset+1] + 1) * 8
            next_header = pkt[offset]
            offset += ext_len
            if offset > len(pkt):
                return None
        if offset + 4 > len(pkt):
            return None
        try:
            if next_header == 6:  # TCP
                sport, dport = struct.unpack_from("!HH", pkt, offset)
                data_offset = ((pkt[offset+12] >> 4) & 0xF) * 4
                header_len = offset + max(data_offset, 20)
                transport_name = "TCP"
            elif next_header == 17:  # UDP
                sport, dport = struct.unpack_from("!HH", pkt, offset)
                header_len = offset + 8
                transport_name = "UDP"
            else:
                return None
        except Exception:
            return None
        if header_len > len(pkt):
            return None
        payload = pkt[header_len:header_len+payload_len] if payload_len else pkt[header_len:]
        return {
            "src": _ipv6(src), "dst": _ipv6(dst),
            "sport": sport, "dport": dport, "transport": transport_name,
            "protocol": _protocol_name(dport if dport in RISKY_PORTS else sport, payload),
            "payload_len": len(payload),
            "payload": payload,
            "ipv6": True,
        }

    @staticmethod
    def _dedupe_findings(findings: List[Dict]) -> List[Dict]:
        seen, result = set(), []
        for finding in findings:
            key = (finding.get("protocol"), finding.get("port"), finding.get("src"), finding.get("dst"), finding.get("type"))
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result[:5000]
