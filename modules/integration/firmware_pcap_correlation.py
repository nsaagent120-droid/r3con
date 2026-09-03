"""Corrélation passive entre chaînes firmware et IOCs PCAP."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from core.result_schema import Status, make_result
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer


def correlate(firmware_path: str, pcap_path: str, max_mb: int = 256) -> Dict[str, Any]:
    fw = Path(firmware_path)
    pc = Path(pcap_path)
    if not fw.is_file() or not pc.is_file():
        return make_result(Status.INVALID, engine="r3con.correlation", error="target_not_found")
    analyzer = FirmwareAnalyzer(str(fw))
    if not analyzer.load():
        return make_result(Status.ERROR, engine="r3con.correlation", error="firmware_load_failed")
    fw_strings = analyzer.extract_strings()
    fw_text = "\n".join(x.get("value", "") for x in fw_strings)
    network = ProtocolAnalyzer(str(pc), max_bytes=max_mb * 1024 * 1024).analyze()
    if network.get("status") != "ok":
        return make_result(Status.PARTIAL, engine="r3con.correlation", error="pcap_analysis_failed", observations={"network": network})
    iocs = network.get("iocs", {})
    matches = []
    for category, values in iocs.items():
        for value in values:
            if value and value.lower() in fw_text.lower():
                matches.append({"category": category, "value": value, "source": "firmware_strings_and_pcap_iocs"})
    return make_result(Status.OK, engine="r3con.correlation", observations={
        "firmware": {"path": str(fw), "string_count": len(fw_strings)},
        "pcap": {"path": str(pc), "ioc_counts": {k: len(v) for k, v in iocs.items()}},
        "matches": matches,
        "match_count": len(matches),
    })
