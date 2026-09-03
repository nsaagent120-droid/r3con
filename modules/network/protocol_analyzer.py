"""Analyse réseau passive et locale de fichiers PCAP.

Aucune capture live, aucun scan et aucune connexion réseau ne sont effectués.
Le parseur couvre les PCAP classiques Ethernet/IPv4 avec TCP et UDP.
"""
from __future__ import annotations

import ipaddress
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


RISKY_PORTS = {
    21: ("FTP", "cleartext_credentials_possible", "HIGH"),
    23: ("Telnet", "cleartext_remote_admin", "HIGH"),
    80: ("HTTP", "cleartext_application_traffic", "MEDIUM"),
    110: ("POP3", "cleartext_mail_traffic", "MEDIUM"),
    143: ("IMAP", "cleartext_mail_traffic", "MEDIUM"),
    161: ("SNMP", "legacy_monitoring_protocol", "MEDIUM"),
    389: ("LDAP", "unencrypted_directory_traffic", "MEDIUM"),
    8080: ("HTTP-alt", "cleartext_application_traffic", "MEDIUM"),
}


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def _protocol_name(port: int, payload: bytes) -> str:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][0]
    head = payload[:16].upper()
    if head.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/")):
        return "HTTP"
    if payload.startswith(b"SSH-"):
        return "SSH"
    if payload.startswith(b"TLS") or (len(payload) > 3 and payload[0] == 0x16 and payload[1:3] == b"\x03\x03"):
        return "TLS"
    return "TCP" if port else "UDP"


class ProtocolAnalyzer:
    """Résumé déterministe de PCAP IPv4, sans exécution de payload."""

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

        flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocol": ""})
        protocols = Counter()
        findings = []
        for pkt in packets:
            parsed = self._parse_packet(pkt, linktype)
            if not parsed:
                continue
            key = (parsed["src"], parsed["sport"], parsed["dst"], parsed["dport"], parsed["transport"])
            flow = flows[key]
            flow["packets"] += 1
            flow["bytes"] += parsed["payload_len"]
            flow["protocol"] = parsed["protocol"]
            protocols[parsed["protocol"]] += 1
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
                    })

        return {
            "status": "ok",
            "path": str(self.path),
            "packets_read": len(packets),
            "packets_truncated": truncated,
            "linktype": linktype,
            "protocols": dict(protocols),
            "flows": [
                {"src": k[0], "sport": k[1], "dst": k[2], "dport": k[3], "transport": k[4], **v}
                for k, v in flows.items()
            ][:5000],
            "findings": self._dedupe_findings(findings),
            "iocs": self._extract_iocs(packets),
        }

    def _read_pcap(self) -> Tuple[List[bytes], int, bool]:
        with self.path.open("rb") as fh:
            data = fh.read(self.max_bytes)
        if len(data) < 24:
            raise ValueError("PCAP header too short")
        magic = data[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("unsupported PCAP magic")
        _major, _minor, _tz, _sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHIIII", data, 4)
        if snaplen <= 0:
            raise ValueError("invalid snaplen")
        packets, offset, truncated = [], 24, False
        while offset + 16 <= len(data) and len(packets) < self.max_packets:
            _sec, _usec, incl, _orig = struct.unpack_from(endian + "IIII", data, offset)
            offset += 16
            if incl > snaplen or offset + incl > len(data):
                truncated = True
                break
            packets.append(data[offset:offset + incl])
            offset += incl
        if len(packets) >= self.max_packets:
            truncated = True
        return packets, linktype, truncated

    @staticmethod
    def _extract_iocs(packets: List[bytes]) -> Dict[str, List[str]]:
        """Extraire des IOC textuels sans décoder ni exécuter le payload."""
        blob = b"\n".join(packets[:100000])
        text = blob.decode("latin-1", errors="ignore")
        urls = sorted(set(re.findall(r"https?://[^\s\x00\"']{3,200}", text, re.IGNORECASE)))[:1000]
        ipv4 = sorted(set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)))
        ipv4 = [x for x in ipv4 if all(int(part) <= 255 for part in x.split("."))][:1000]
        domains = sorted(set(re.findall(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])", text)))[:1000]
        return {"urls": urls, "ipv4": ipv4, "domains": domains}

    @staticmethod
    def _parse_packet(pkt: bytes, linktype: int) -> Dict | None:
        if linktype == 1:  # Ethernet
            if len(pkt) < 14:
                return None
            ethertype = struct.unpack_from("!H", pkt, 12)[0]
            if ethertype != 0x0800:
                return None
            ip = pkt[14:]
        elif linktype == 101:  # raw IPv4
            ip = pkt
        else:
            return None
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            return None
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            return None
        total_len = struct.unpack_from("!H", ip, 2)[0]
        total_len = min(total_len, len(ip)) if total_len else len(ip)
        transport = ip[9]
        if transport not in (6, 17) or total_len < ihl + 8:
            return None
        sport, dport = struct.unpack_from("!HH", ip, ihl)
        if transport == 6:
            data_offset = ((ip[ihl + 12] >> 4) & 0xF) * 4
            header_len = ihl + max(data_offset, 20)
            transport_name = "TCP"
        else:
            header_len = ihl + 8
            transport_name = "UDP"
        if header_len > total_len:
            return None
        payload = ip[header_len:total_len]
        return {
            "src": _ipv4(ip[12:16]), "dst": _ipv4(ip[16:20]),
            "sport": sport, "dport": dport, "transport": transport_name,
            "protocol": _protocol_name(dport if dport in RISKY_PORTS else sport, payload),
            "payload_len": len(payload),
        }

    @staticmethod
    def _dedupe_findings(findings: List[Dict]) -> List[Dict]:
        seen, result = set(), []
        for finding in findings:
            key = (finding["protocol"], finding["port"], finding["src"], finding["dst"])
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result[:5000]
