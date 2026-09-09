"""Corrélation passive entre chaînes firmware et IOCs PCAP - FIXED P3
Fixes: path validation, size limits, efficient search, match limits
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Set

from core.result_schema import Status, make_result
from modules.firmware.firmware_analyzer import FirmwareAnalyzer
from modules.network.protocol_analyzer import ProtocolAnalyzer

MAX_FW_SIZE = 500 * 1024 * 1024
MAX_PCAP_SIZE = 500 * 1024 * 1024
MAX_STRINGS = 10000
MAX_MATCHES = 500
MAX_VALUE_LEN = 253


def _validate_path(path_str: str, max_size: int) -> bool:
    """Validate path."""
    if not path_str or len(path_str) > 1024 or "\x00" in path_str:
        return False
    p = Path(path_str)
    try:
        if not p.exists() or not p.is_file():
            return False
        if p.stat().st_size > max_size or p.stat().st_size == 0:
            return False
    except (OSError, RuntimeError):
        return False
    return True


def _sanitize_ioc_value(value: str) -> bool:
    """Sanitize IOC value."""
    if not value or not isinstance(value, str):
        return False
    if len(value) > MAX_VALUE_LEN or len(value) < 3:
        return False
    if "\x00" in value:
        return False
    # Basic format check
    if not re.match(r'^[a-zA-Z0-9.\-_:/?=&%+@]+$', value):
        return False
    return True


def correlate(firmware_path: str, pcap_path: str, max_mb: int = 256) -> Dict[str, Any]:
    """Correlate firmware strings with PCAP IOCs - FIXED efficient, limited."""

    if not _validate_path(firmware_path, MAX_FW_SIZE):
        return make_result(Status.INVALID, engine="r3con.correlation", error="invalid_firmware_path")
    if not _validate_path(pcap_path, MAX_PCAP_SIZE):
        return make_result(Status.INVALID, engine="r3con.correlation", error="invalid_pcap_path")

    if not isinstance(max_mb, int) or max_mb < 1 or max_mb > 1024:
        max_mb = 256

    fw = Path(firmware_path)
    pc = Path(pcap_path)

    try:
        analyzer = FirmwareAnalyzer(str(fw))
        if not analyzer.load():
            return make_result(Status.ERROR, engine="r3con.correlation", error="firmware_load_failed")

        fw_strings = analyzer.extract_strings()
        # Limit strings
        if len(fw_strings) > MAX_STRINGS:
            fw_strings = fw_strings[:MAX_STRINGS]

        # Build efficient search structure: set of lowercased strings for O(1) lookup
        # Instead of joining all strings into one huge text and doing substring search for each IOC
        fw_text_set: Set[str] = set()
        fw_text_lower = ""
        try:
            # Create set of individual string values lowercased
            for item in fw_strings:
                val = item.get("value", "") if isinstance(item, dict) else str(item)
                if val and len(val) <= 500:
                    fw_text_set.add(val.lower())
            # Also create concatenated text but limited to 5MB for substring search
            fw_text = "\n".join(x.get("value", "") for x in fw_strings if isinstance(x, dict))[:5*1024*1024]
            fw_text_lower = fw_text.lower()
        except Exception:
            fw_text_set = set()
            fw_text_lower = ""

        network = ProtocolAnalyzer(str(pc), max_bytes=max_mb * 1024 * 1024).analyze()
        if network.get("status") != "ok":
            return make_result(Status.PARTIAL, engine="r3con.correlation", error="pcap_analysis_failed",
                               observations={"network": network})

        iocs = network.get("iocs", {})
        matches = []

        # Efficient matching: for each IOC, check if in set or substring
        for category, values in iocs.items():
            if not isinstance(values, (list, set)):
                continue
            if len(matches) >= MAX_MATCHES:
                break

            for value in values:
                if len(matches) >= MAX_MATCHES:
                    break
                if not _sanitize_ioc_value(value):
                    continue

                val_lower = value.lower()
                # Check exact match in set first (O(1))
                # Then substring search in limited text (O(n) but limited)
                if val_lower in fw_text_set or val_lower in fw_text_lower:
                    matches.append({
                        "category": str(category)[:50],
                        "value": value[:MAX_VALUE_LEN],
                        "source": "firmware_strings_and_pcap_iocs"
                    })

        return make_result(Status.OK, engine="r3con.correlation", observations={
            "firmware": {"path": str(fw), "string_count": len(fw_strings)},
            "pcap": {"path": str(pc), "ioc_counts": {k: len(v) if isinstance(v, (list, set)) else 0 for k, v in iocs.items()}},
            "matches": matches[:MAX_MATCHES],
            "match_count": len(matches),
            "limits": {"max_strings": MAX_STRINGS, "max_matches": MAX_MATCHES},
        })

    except Exception as exc:
        return make_result(Status.ERROR, engine="r3con.correlation", error=str(exc)[:500])
