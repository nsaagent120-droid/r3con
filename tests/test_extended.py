import struct
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.integration.tool_manager import ToolManager
from modules.network.external_analyzers import ExternalNetworkAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer


def _build_synthetic_pcap(path: Path, n_packets: int = 5) -> None:
    """Genere un PCAP Ethernet/IPv4/TCP minimal mais valide, sans
    dependance externe (pas de scapy) — remplace le pcap fixe attendu
    sur la machine d'origine (/home/ubuntu/r3con_audit/sample.pcap,
    absent de cette archive)."""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets = bytearray()
    for i in range(n_packets):
        eth = b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00"
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 40, 0, 0, 64, 6, 0,
            bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
        )
        tcp_header = struct.pack(
            "!HHLLBBHHH", 12345, 80, 0, 0, 0x50, 0x02, 0, 0, 0
        )
        frame = eth + ip_header + tcp_header
        pkt_header = struct.pack("<IIII", i, 0, len(frame), len(frame))
        packets += pkt_header + frame
    with open(path, "wb") as f:
        f.write(global_header)
        f.write(bytes(packets))


@pytest.fixture()
def synthetic_pcap():
    with tempfile.TemporaryDirectory() as d:
        pcap_path = Path(d) / "sample.pcap"
        _build_synthetic_pcap(pcap_path, n_packets=5)
        yield str(pcap_path)


def test_tool_manager_inventory_and_plan():
    manager = ToolManager()
    rows = manager.inspect()
    assert {row["key"] for row in rows} >= {"gdb", "tshark", "zeek"}
    plan = manager.install_plan(["tshark", "zeek", "unknown"])
    assert any(item["status"] == "unknown_tool" for item in plan)
    dry = manager.install(["tshark"], apply=False)
    assert dry["status"] == "plan_only"


def test_protocol_and_external_analyzers(synthetic_pcap):
    result = ProtocolAnalyzer(synthetic_pcap, max_packets=2).analyze()
    assert result["status"] == "ok" and result["packets_truncated"] is True
    assert "iocs" in result
    ext = ExternalNetworkAnalyzer(synthetic_pcap)
    assert ext.tshark_fields(["ip.src"])["status"] in {"unsupported", "ok", "error", "timeout", "partial"}
    assert ext.zeek_offline()["status"] in {"unsupported", "ok", "error", "timeout"}
