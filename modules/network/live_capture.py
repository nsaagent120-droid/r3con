"""Capture réseau live passive et locale via TShark.

Ce module ne fait ni scan, ni injection, ni émission de paquets applicatifs.
Il lit uniquement les paquets observés sur une interface locale, avec des
limites strictes de durée et de volume.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import shutil
import subprocess
import time
from typing import Any, Dict, Optional


class LiveCaptureAnalyzer:
    """Capture bornée et agrégation déterministe de métadonnées réseau."""

    FIELD_SPECS = (
        ("timestamp", "frame.time_epoch"),
        ("frame_len", "frame.len"),
        ("ip_src", "ip.src"),
        ("ip_dst", "ip.dst"),
        ("ipv6_src", "ipv6.src"),
        ("ipv6_dst", "ipv6.dst"),
        ("tcp_srcport", "tcp.srcport"),
        ("tcp_dstport", "tcp.dstport"),
        ("udp_srcport", "udp.srcport"),
        ("udp_dstport", "udp.dstport"),
        ("protocol", "_ws.col.Protocol"),
        ("dns_query", "dns.qry.name"),
        ("http_host", "http.host"),
        ("tls_sni", "tls.handshake.extensions_server_name"),
        ("tcp_stream", "tcp.stream"),
    )
    FIELD_NAMES = tuple(name for name, _ in FIELD_SPECS)

    def __init__(self, interface: str = "any", duration: int = 30,
                 max_packets: int = 10000, display_filter: Optional[str] = None,
                 timeout: int = 45):
        self.interface = interface
        self.duration = max(1, min(int(duration), 3600))
        self.max_packets = max(1, min(int(max_packets), 1_000_000))
        self.display_filter = display_filter
        self.timeout = max(self.duration + 10, int(timeout))

    def _command(self, exe: str) -> list[str]:
        cmd = [exe, "-n", "-l", "-i", self.interface, "-T", "fields",
               "-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f",
               "-a", f"duration:{self.duration}", "-c", str(self.max_packets)]
        if self.display_filter:
            cmd.extend(["-Y", self.display_filter])
        for _, tshark_field in self.FIELD_SPECS:
            cmd.extend(["-e", tshark_field])
        return cmd

    @staticmethod
    def _row(line: str) -> Dict[str, str]:
        values = line.rstrip("\n").split("\t")
        values += [""] * (len(LiveCaptureAnalyzer.FIELD_NAMES) - len(values))
        return dict(zip(LiveCaptureAnalyzer.FIELD_NAMES, values))

    @staticmethod
    def _first(*values: str) -> str:
        return next((value for value in values if value), "")

    def capture(self) -> Dict[str, Any]:
        exe = shutil.which("tshark")
        if not exe:
            return {"status": "unsupported", "tool": "tshark", "error": "tshark_not_installed"}
        if not self.interface.strip():
            return {"status": "invalid", "error": "empty_interface"}

        cmd = self._command(exe)
        started = time.time()
        packets = 0
        bytes_seen = 0
        protocols = Counter()
        flows: dict[tuple[str, str, str, str], dict[str, Any]] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "protocol": ""}
        )
        dns_queries: set[str] = set()
        http_hosts: set[str] = set()
        tls_sni: set[str] = set()
        errors: list[str] = []

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
        except OSError as exc:
            return {"status": "error", "tool": "tshark", "error": "capture_start_failed", "detail": str(exc)}

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if not line.strip():
                    continue
                row = self._row(line)
                packets += 1
                try:
                    frame_len = int(row["frame_len"] or 0)
                except ValueError:
                    frame_len = 0
                bytes_seen += frame_len
                protocol = row["protocol"] or "unknown"
                protocols[protocol] += 1
                src = self._first(row["ip_src"], row["ipv6_src"])
                dst = self._first(row["ip_dst"], row["ipv6_dst"])
                sport = self._first(row["tcp_srcport"], row["udp_srcport"])
                dport = self._first(row["tcp_dstport"], row["udp_dstport"])
                key = (src, dst, sport, dport)
                flow = flows[key]
                flow["packets"] += 1
                flow["bytes"] += frame_len
                flow["protocol"] = protocol
                if row["dns_query"]:
                    dns_queries.add(row["dns_query"])
                if row["http_host"]:
                    http_hosts.add(row["http_host"])
                if row["tls_sni"]:
                    tls_sni.add(row["tls_sni"])
        finally:
            try:
                proc.wait(timeout=max(1, self.timeout - int(time.time() - started)))
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            stderr = (proc.stderr.read() if proc.stderr else "")[-4000:]
            if proc.returncode not in (0, None) and stderr:
                errors.append(stderr)

        status = "ok" if proc.returncode == 0 else "partial" if packets else "error"
        if proc.returncode not in (0, None) and not packets and errors:
            status = "error"
        return {
            "status": status,
            "tool": "tshark",
            "interface": self.interface,
            "duration_requested": self.duration,
            "duration_actual": round(time.time() - started, 2),
            "max_packets": self.max_packets,
            "packets": packets,
            "bytes": bytes_seen,
            "protocols": dict(protocols),
            "flows": [
                {"src": key[0], "dst": key[1], "src_port": key[2], "dst_port": key[3], **value}
                for key, value in sorted(flows.items(), key=lambda item: item[1]["bytes"], reverse=True)[:500]
            ],
            "iocs": {
                "dns": sorted(dns_queries)[:500],
                "http_hosts": sorted(http_hosts)[:500],
                "tls_sni": sorted(tls_sni)[:500],
            },
            "stderr": errors,
        }
